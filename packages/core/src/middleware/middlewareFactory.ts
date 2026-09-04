import crypto from "crypto";
import type {
  RedisAdapter,
  AuthCoreConfig,
  ErrorFactory,
  AuditLogger,
  ObservabilitySink,
  CacheAdapter,
  User,
  SessionMetadata,
} from "../types.js";
import { resolveConfig, DEFAULTS, type ResolvedConfig } from "../config.js";
import { TokenManager } from "../tokens/backendToken.js";
import { TokenRevocation } from "../revocation/tokenRevocation.js";
import { AccountLockout } from "../lockout/accountLockout.js";
import { defaultErrors } from "../errors/index.js";
import {
  getClientIp,
  generateDeviceFingerprint,
  isPrivateIp,
  looksLikeServerToServerRequest,
  looksLikeServerToServerUA,
  validateSessionBinding,
} from "../session/sessionBinding.js";
import { AuditLog } from "../audit/auditLog.js";

export interface AuthRequest {
  user?: {
    id: string;
    email: string;
    role: string;
    name?: string | null;
    tokenJti?: string;
    sessionId?: string;
  };
  headers: Record<string, string | string[] | undefined>;
  ip?: string;
  socket?: { remoteAddress?: string };
  body?: Record<string, unknown>;
  params?: Record<string, unknown>;
  query?: Record<string, unknown>;
  path?: string;
  method?: string;
  originalUrl?: string;
  [key: string]: unknown;
}

interface JwtPayload {
  sub: string;
  email: string;
  role: string;
  jti: string;
  version: number;
  type: string;
  sessionId?: string;
}

export class MiddlewareFactory {
  private readonly config: ResolvedConfig;
  private readonly tokenManager: TokenManager;
  private readonly tokenRevocation: TokenRevocation;
  private readonly accountLockout: AccountLockout;
  private readonly errors: ErrorFactory;
  private readonly audit: AuditLog;
  private readonly observability?: ObservabilitySink;
  private readonly cache?: CacheAdapter;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private sessionTimeoutManager: any = null;

  constructor(rawConfig: AuthCoreConfig) {
    this.config = resolveConfig(rawConfig);
    this.tokenManager = new TokenManager(rawConfig.jwt);
    this.tokenRevocation = new TokenRevocation(rawConfig.redis, this.config.keyPrefix);
    this.accountLockout = new AccountLockout(rawConfig.redis, {
      maxFailures: this.config.lockoutMaxFailures,
      lockoutSeconds: this.config.lockoutSeconds,
      windowSeconds: this.config.lockoutWindowSeconds,
      prefix: `${this.config.keyPrefix}lockout`,
    });
    this.errors = rawConfig.errors ?? defaultErrors;
    this.audit = new AuditLog(rawConfig.auditLogger);
    this.observability = rawConfig.observability;
    this.cache = rawConfig.cache;
  }

  getTokenManager(): TokenManager {
    return this.tokenManager;
  }

  getTokenRevocation(): TokenRevocation {
    return this.tokenRevocation;
  }

  getAuditLog(): AuditLog {
    return this.audit;
  }

  getRedis(): RedisAdapter {
    return this.config.redis;
  }

  getConfig(): ResolvedConfig {
    return this.config;
  }

  /**
   * Invalidate cached user data. Call this after banning/unbanning a user,
   * changing their role, or unverifying their email. Without this, stale
   * cached user data (bannedAt, role, emailVerified) persists for up to 30
   * minutes, allowing banned users to retain access.
   */
  async invalidateUserCache(userId: string): Promise<void> {
    await this.cache?.delete(`auth:user:${userId}`);
  }

  /**
   * Fully revoke a session: mark it revoked, remove from tracking, and
   * clear the auth:result cache for the provided access-token JTI.
   *
   * Use this instead of calling TokenRevocation/SessionManager directly —
   * those lower-level methods don't clear the auth:result cache, leaving
   * revoked tokens usable for up to 5 minutes via the cached auth path.
   */
  async revokeSession(userId: string, sessionId: string, accessTokenJti?: string): Promise<void> {
    await this.tokenRevocation.markSessionRevoked(sessionId);
    await this.config.redis.srem(`${this.config.keyPrefix}user:sessions:${userId}`, sessionId);
    await this.config.redis.del(`${this.config.keyPrefix}session:metadata:${sessionId}`);
    if (accessTokenJti && this.cache) {
      await this.cache.delete(`auth:result:${accessTokenJti}`).catch(() => {});
    }
  }

  async enforceSessionBinding(
    req: AuthRequest,
    decoded: JwtPayload,
  ): Promise<Error | null> {
    if (!decoded.sessionId) return null;

    const redis = this.config.redis;
    const metadataKey = `${this.config.keyPrefix}session:metadata:${decoded.sessionId}`;
    const storedMetadata = await redis.get(metadataKey);
    if (!storedMetadata) return null;

    let metadata: SessionMetadata;
    try {
      metadata = JSON.parse(storedMetadata);
    } catch {
      return null;
    }
    // Server-to-server bypass: require x-server-secret when configured.
    // Without a configured secret, fall back to header heuristics (backward
    // compatible but weaker — see AuthCoreConfig.serverSecret docs).
    const isServerRequest = this.config.serverSecret
      ? (req.headers["x-server-secret"] as string) === this.config.serverSecret
      : looksLikeServerToServerRequest(req);
    if (isServerRequest) return null;

    if (metadata.deviceId == null || looksLikeServerToServerUA(metadata.userAgent)) {
      metadata.deviceId = generateDeviceFingerprint(req);
      metadata.ipAddress = getClientIp(req, this.config.trustedProxies);
      metadata.userAgent = (req.headers["user-agent"] as string) || "unknown";
      metadata.lastActivity = Date.now();
      this.audit.log("SESSION_BOUND", {
        userId: decoded.sub,
        sessionId: decoded.sessionId,
        ip: metadata.ipAddress,
        userAgent: metadata.userAgent,
      });
    } else {
      const bindingValidation = validateSessionBinding(req, metadata, this.config.trustedProxies);
      const currentIp = getClientIp(req, this.config.trustedProxies);

      if (!bindingValidation.valid) {
        const isSameIpDeviceChange =
          bindingValidation.reason === "DEVICE_MISMATCH" &&
          (currentIp === metadata.ipAddress ||
            isPrivateIp(currentIp) ||
            isPrivateIp(metadata.ipAddress));

        if (isSameIpDeviceChange) {
          metadata.deviceId = generateDeviceFingerprint(req);
          metadata.userAgent = (req.headers["user-agent"] as string) || "unknown";
          this.audit.log("SESSION_REBOUND", {
            userId: decoded.sub,
            sessionId: decoded.sessionId,
            ip: currentIp,
            userAgent: metadata.userAgent,
          });
        } else {
          if (decoded.jti) {
            const expiry = this.tokenManager.getAccessTokenExpiry();
            const ttlSeconds = TokenManager.parseExpiry(expiry) / 1000;
            await this.tokenRevocation.revokeAccessToken(decoded.jti, ttlSeconds).catch(() => {});
          }
          await this.tokenRevocation.markSessionRevoked(decoded.sessionId).catch(() => {});
          await this.tokenRevocation.revokeAllRefreshTokens(decoded.sub);
          if (decoded.jti && this.cache) {
            await this.cache.delete(`auth:result:${decoded.jti}`);
          }
          this.audit.log("SESSION_HIJACK_DETECTED", {
            userId: decoded.sub,
            sessionId: decoded.sessionId,
            reason: bindingValidation.reason,
            ip: currentIp,
            userAgent: req.headers["user-agent"],
          });
          return this.errors.SessionHijackError(bindingValidation.reason);
        }
      }
    }

    metadata.lastActivity = Date.now();
    await redis.setex(metadataKey, this.config.sessionMetadataTtl, JSON.stringify(metadata));
    return null;
  }

  createAuthenticateMiddleware() {
    const self = this;
    return async function authenticate(req: AuthRequest, res: { status(code: number): { json(data: unknown): unknown } }, next: (err?: Error) => void) {
      try {
        const authHeader = req.headers.authorization;
        if (typeof authHeader !== "string" || !authHeader.startsWith("Bearer ")) {
          return next(self.errors.UnauthorizedError("Authentication required", "NO_TOKEN"));
        }

        const token = authHeader.slice(7).trim();
        if (!token) {
          return next(self.errors.UnauthorizedError("Authentication required", "NO_TOKEN"));
        }

        let decoded: JwtPayload;
        try {
          decoded = self.tokenManager.verifyToken(token) as unknown as JwtPayload;
        } catch (err: unknown) {
          if ((err as { name?: string }).name === "TokenExpiredError") {
            return next(self.errors.TokenExpiredError());
          }
          return next(self.errors.InvalidTokenError());
        }

        if (decoded.jti && self.cache) {
          const cacheKey = `auth:result:${decoded.jti}`;
          const cachedResult = await self.cache.get<{ userId: string; valid: boolean }>(cacheKey);

          if (cachedResult) {
            if (!cachedResult.valid) return next(self.errors.InvalidTokenError("INVALID_TOKEN_CACHED"));
            const bindingError = await self.enforceSessionBinding(req, decoded);
            if (bindingError) return next(bindingError);

            const user = await self.loadUser(decoded.sub);
            if (!user) return next(self.errors.UnauthorizedError("User not found", "USER_NOT_FOUND"));
            if (!user.emailVerified) return next(self.errors.EmailNotVerifiedError());
            if (user.bannedAt) return next(self.errors.AccountBannedError(user.banReason, user.bannedAt));

            self.assignUser(req, user, decoded);
            return next();
          }
        }

        if (decoded.version !== self.config.currentVersion) {
          return next(self.errors.InvalidTokenError("TOKEN_VERSION_MISMATCH"));
        }
        if (decoded.type !== "access") {
          return next(self.errors.InvalidTokenError("INVALID_TOKEN_TYPE"));
        }

        const [isRevoked, sessionWasRevoked] = await Promise.all([
          decoded.jti ? self.tokenRevocation.isAccessTokenRevoked(decoded.jti) : Promise.resolve(false),
          decoded.sessionId ? self.tokenRevocation.isSessionRevoked(decoded.sessionId) : Promise.resolve(false),
        ]);
        if (isRevoked) return next(self.errors.TokenRevokedError());
        if (sessionWasRevoked) return next(self.errors.TokenRevokedError());

        const [bindingError, cachedUser] = await Promise.all([
          self.enforceSessionBinding(req, decoded),
          self.cache?.get<User>(`auth:user:${decoded.sub}`),
        ]);
        if (bindingError) return next(bindingError);

        const user = cachedUser ?? (await self.loadUser(decoded.sub));
        if (!user) return next(self.errors.UnauthorizedError("User not found", "USER_NOT_FOUND"));
        if (!user.emailVerified) return next(self.errors.EmailNotVerifiedError());
        if (user.bannedAt) return next(self.errors.AccountBannedError(user.banReason, user.bannedAt));

        if (!cachedUser && user && self.cache) {
          const { password, twoFactorSecret, ...safeUser } = user as unknown as Record<string, unknown>;
          void self.cache.set(`auth:user:${decoded.sub}`, safeUser, 30 * 60).catch(() => {});
        }

        if (decoded.jti && self.cache) {
          void self.cache.set(`auth:result:${decoded.jti}`, { userId: decoded.sub, valid: true }, 5 * 60).catch(() => {});
        }

        self.assignUser(req, user, decoded);
        self.observability?.setUserContext?.({ id: user.id, email: user.email });
        self.observability?.addBreadcrumb?.({
          message: "User authenticated successfully",
          data: { userId: user.id, email: user.email, role: user.role },
        });

        next();
      } catch (err) {
        console.error("Unexpected authentication error:", err);
        self.observability?.captureException?.(err as Error, { context: "authentication" });
        next(err as Error);
      }
    };
  }

  createAuthorizeMiddleware(...roles: string[]) {
    const self = this;
    return function authorize(req: AuthRequest, res: { status(code: number): { json(data: unknown): unknown } }, next: (err?: Error) => void) {
      if (!req.user) {
        return next(self.errors.UnauthorizedError("Authentication required", "NOT_AUTHENTICATED"));
      }
      if (!roles.includes(req.user.role)) {
        return next(self.errors.ForbiddenError("Insufficient permissions"));
      }
      next();
    };
  }

  createCsrfMiddleware() {
    const self = this;
    const CSRF_TOKEN_LENGTH = 32;
    const CSRF_TOKEN_TTL = 3600;

    return {
      generateToken: async (userId: string, sessionId: string): Promise<string> => {
        const token = crypto.randomBytes(CSRF_TOKEN_LENGTH).toString("base64url");
        const key = `${self.config.keyPrefix}csrf:${userId}:${sessionId}`;
        await self.config.redis.setex(key, CSRF_TOKEN_TTL, token);
        return token;
      },
      validateToken: async (userId: string, sessionId: string, token: string): Promise<boolean> => {
        if (!token) return false;
        const key = `${self.config.keyPrefix}csrf:${userId}:${sessionId}`;
        const storedToken = await self.config.redis.get(key);
        if (!storedToken) return false;
        try {
          return crypto.timingSafeEqual(Buffer.from(token, "base64url"), Buffer.from(storedToken, "base64url"));
        } catch {
          return false;
        }
      },
      middleware() {
        return async (req: AuthRequest, res: { status(code: number): { json(data: unknown): unknown }; end(): unknown }, next: (err?: Error) => void) => {
          if (["GET", "HEAD", "OPTIONS"].includes(req.method ?? "")) return next();
          if (req.path?.startsWith("/webhooks/") || req.path?.includes("/callback")) return next();

          const csrfToken = req.headers["x-csrf-token"] as string;
          if (!req.user?.id) {
            return res.status(401).json({ success: false, message: "Authentication required", code: "NOT_AUTHENTICATED" });
          }

          const sessionId = req.user.sessionId || "default";
          const stored = await self.config.redis.get(`${self.config.keyPrefix}csrf:${req.user.id}:${sessionId}`);
          if (!stored || !csrfToken) return res.status(403).json({ success: false, message: "Invalid CSRF token", code: "CSRF_VALIDATION_FAILED" });

          let isValid = false;
          try {
            isValid = crypto.timingSafeEqual(Buffer.from(csrfToken, "base64url"), Buffer.from(stored, "base64url"));
          } catch {
            isValid = false;
          }

          if (!isValid) {
            return res.status(403).json({ success: false, message: "Invalid CSRF token", code: "CSRF_VALIDATION_FAILED" });
          }
          next();
        };
      },
    };
  }

  createRateLimitMiddleware() {
    const self = this;
    return (max: number, windowSeconds: number, keyFn?: (req: AuthRequest) => string | undefined, options?: { failOpen?: boolean }) => {
      return async (req: AuthRequest, res: { status(code: number): { json(data: unknown): unknown } }, next: (err?: Error) => void) => {
        const ip = getClientIp(req, self.config.trustedProxies);
        const userKey = keyFn?.(req);
        const key = userKey ? `${self.config.keyPrefix}rl:user:${userKey}` : `${self.config.keyPrefix}rl:backend:${ip}`;

        try {
          const redis = self.config.redis;
          const countKey = `${key}:count`;
          const count = await redis.incr(countKey);
          if (count === 1) await redis.expire(countKey, windowSeconds);

          if (count > max) {
            return res.status(429).json({ success: false, message: "Too many requests", code: "RATE_LIMIT_EXCEEDED", retryAfter: windowSeconds });
          }

          next();
        } catch (error) {
          if (options?.failOpen) return next();
          return res.status(429).json({ success: false, message: "Rate limit service unavailable", code: "RATE_LIMIT_SERVICE_UNAVAILABLE", retryAfter: windowSeconds });
        }
      };
    };
  }

  createSessionTimeoutMiddleware() {
    const self = this;
    return async (req: AuthRequest, res: { status(code: number): { json(data: unknown): unknown } }, next: (err?: Error) => void) => {
      const sessionId = req.user?.sessionId;
      if (!sessionId) return next();

      if (!self.sessionTimeoutManager) {
        const { SessionTimeoutManager } = await import("./sessionTimeout.js");
        self.sessionTimeoutManager = new SessionTimeoutManager(self.config.redis, {
          inactivityTimeout: self.config.inactivityTimeout,
          absoluteTimeout: self.config.absoluteTimeout,
          prefix: self.config.keyPrefix,
        });
      }

      const tracked = await self.sessionTimeoutManager.isTracked(sessionId);
      if (!tracked) return next();

      const inactive = await self.sessionTimeoutManager.isInactive(sessionId);
      if (inactive) {
        return res.status(401).json({ success: false, code: "SESSION_TIMEOUT", message: "Session expired" });
      }

      await self.sessionTimeoutManager.updateActivity(sessionId);
      next();
    };
  }

  createExchangeHandler() {
    const self = this;
    return async (req: AuthRequest, res: { status(code: number): { json(data: unknown): unknown } }) => {
      const ip = getClientIp(req, self.config.trustedProxies);
      const { userId, email, role, sessionId, timestamp, signature } = req.body as Record<string, string>;

      const age = Date.now() - Number(timestamp);
      if (age > 60_000 || age < 0) {
        self.audit.log("EXCHANGE_FAILED", { userId, email, ip, reason: "Proof expired" });
        throw self.errors.UnauthorizedError("Exchange proof expired", "PROOF_EXPIRED");
      }

      const proofPayload = `${userId}${email}${role}${sessionId}${timestamp}`;
      const expected = crypto.createHmac("sha256", self.config.hmacSecret).update(proofPayload).digest("hex");

      let valid = false;
      try {
        if (signature) {
          valid = crypto.timingSafeEqual(Buffer.from(signature, "hex"), Buffer.from(expected, "hex"));
        }
      } catch {
        valid = false;
      }

      if (!valid) {
        self.audit.log("EXCHANGE_FAILED", { userId, email, ip, reason: "Invalid signature" });
        throw self.errors.UnauthorizedError("Invalid exchange proof", "INVALID_SIGNATURE");
      }

      const idempotencyKey = `exchange:idempotent:${userId}:${sessionId}:${timestamp}`;
      const existing = await self.config.redis.get(idempotencyKey);
      if (existing) {
        return res.status(200).json(JSON.parse(existing));
      }

      const user = await self.config.userStore.findById(userId!);
      if (!user) {
        self.audit.log("EXCHANGE_FAILED", { userId, email, ip, reason: "User not found" });
        throw self.errors.UnauthorizedError("User not found", "USER_NOT_FOUND");
      }

      if (user.email.toLowerCase() !== email!.toLowerCase()) {
        self.audit.log("EXCHANGE_FAILED", { userId, email, ip, reason: "Email mismatch" });
        throw self.errors.UnauthorizedError("Email mismatch", "EMAIL_MISMATCH");
      }

      if (!user.emailVerified) {
        self.audit.log("EXCHANGE_FAILED", { userId, email, ip, reason: "Email not verified" });
        throw self.errors.UnauthorizedError("Email not verified", "EMAIL_NOT_VERIFIED");
      }

      if (user.bannedAt) {
        self.audit.log("EXCHANGE_FAILED", { userId, email, ip, reason: "Account banned" });
        throw self.errors.AccountBannedError(user.banReason, user.bannedAt);
      }

      const lockStatus = await self.accountLockout.isAccountLocked(user.email);
      if (lockStatus.locked) {
        self.audit.log("EXCHANGE_FAILED", { userId, email, ip, reason: "Account locked" });
        throw self.errors.UnauthorizedError("Account locked", "ACCOUNT_LOCKED");
      }

      const sid = sessionId || crypto.randomUUID();
      const tokens = self.tokenManager.createTokenPair({
        id: user.id,
        email: user.email,
        role: user.role,
        sessionId: sid,
      });

      const refreshTtlSeconds = self.tokenManager.getRefreshTokenExpiry() === "7d"
        ? 7 * 24 * 60 * 60
        : TokenManager.parseExpiry(self.tokenManager.getRefreshTokenExpiry()) / 1000;

      await self.tokenRevocation.storeRefreshToken(user.id, TokenManager.extractJti(tokens.refreshToken), refreshTtlSeconds);

      const sseToken = self.tokenManager.createSseToken(user.id);
      const sseTtlSeconds = TokenManager.parseExpiry(self.tokenManager.getSseTokenExpiry()) / 1000;
      await self.tokenRevocation.storeSseToken(TokenManager.extractJti(sseToken), user.id, sseTtlSeconds);

      await self.config.redis.setex(
        `${self.config.keyPrefix}session:created:${sid}`,
        self.config.absoluteTimeout,
        Date.now().toString(),
      );
      await self.config.redis.setex(
        `${self.config.keyPrefix}session:activity:${sid}`,
        self.config.inactivityTimeout,
        Date.now().toString(),
      );

      await self.config.redis.setex(idempotencyKey, 90, JSON.stringify(tokens));

      self.audit.log("EXCHANGE_SUCCESS", { userId: user.id, email: user.email, ip });
      return res.status(200).json(tokens);
    };
  }

  createRefreshHandler() {
    const self = this;
    return async (req: AuthRequest, res: { status(code: number): { json(data: unknown): unknown } }) => {
      const { refreshToken } = req.body as { refreshToken: string };
      if (!refreshToken) throw self.errors.BadRequestError("Refresh token required");

      let decoded;
      try {
        decoded = self.tokenManager.verifyToken(refreshToken, "refresh");
      } catch {
        throw self.errors.UnauthorizedError("Invalid refresh token", "INVALID_TOKEN");
      }

      const redis = self.config.redis;
      const lockKey = `${self.config.keyPrefix}refresh:lock:${decoded.sessionId}`;
      const lockResult = await redis.set(lockKey, "1", "EX", 45, "NX");

      if (lockResult !== "OK") {
        throw self.errors.BadRequestError("Refresh already in progress", "REFRESH_IN_PROGRESS");
      }

      try {
        const dedupeKey = `${self.config.keyPrefix}refresh:dedupe:${decoded.id}:${decoded.jti}`;
        const cached = await redis.get(dedupeKey);
        if (cached) return res.status(200).json(JSON.parse(cached));

        const sessionRevokedKey = `${self.config.keyPrefix}session:revoked:${decoded.sessionId}`;
        if ((await redis.get(sessionRevokedKey)) === "1") {
          throw self.errors.UnauthorizedError("Session revoked", "SESSION_REVOKED");
        }

        const createdKey = `${self.config.keyPrefix}session:created:${decoded.sessionId}`;
        if ((await redis.exists(createdKey)) !== 1) {
          throw self.errors.UnauthorizedError("Session expired", "SESSION_TIMEOUT");
        }

        const newTokens = self.tokenManager.createTokenPair({
          id: decoded.id,
          email: decoded.email,
          role: decoded.role,
          sessionId: decoded.sessionId,
        });

        const refreshTtlSeconds = TokenManager.parseExpiry(self.tokenManager.getRefreshTokenExpiry()) / 1000;
        await self.tokenRevocation.rotateRefreshToken(
          decoded.id,
          decoded.jti,
          TokenManager.extractJti(newTokens.refreshToken),
          refreshTtlSeconds,
        );

        const newSseToken = self.tokenManager.createSseToken(decoded.id);
        const sseTtlSeconds = TokenManager.parseExpiry(self.tokenManager.getSseTokenExpiry()) / 1000;
        await self.tokenRevocation.storeSseToken(TokenManager.extractJti(newSseToken), decoded.id, sseTtlSeconds);

        const response = { ...newTokens, sseToken: newSseToken };
        await redis.setex(dedupeKey, 30, JSON.stringify(response));

        self.audit.log("TOKEN_REFRESHED", { userId: decoded.id, sessionId: decoded.sessionId });
        return res.status(200).json(response);
      } finally {
        await redis.del(lockKey);
      }
    };
  }

  createLogoutHandler() {
    const self = this;
    return async (req: AuthRequest, res: { status(code: number): { json(data: unknown): unknown } }) => {
      const { logoutAll } = req.body as { logoutAll?: boolean };
      const userId = req.user?.id;
      const sessionId = req.user?.sessionId;

      if (req.user?.tokenJti) {
        const token = (req.headers.authorization as string)?.slice(7);
        if (token) {
          const expiry = self.tokenManager.getAccessTokenExpiry();
          const ttlSeconds = TokenManager.parseExpiry(expiry) / 1000;
          await self.tokenRevocation.revokeAccessToken(req.user.tokenJti, ttlSeconds);
          // Drop the auth-result cache so the revoked token is rejected immediately
          // instead of surviving up to 5 min via the cached path.
          if (self.cache) {
            await self.cache.delete(`auth:result:${req.user.tokenJti}`).catch(() => {});
          }
        }
      }

      if (logoutAll && userId) {
        await self.tokenRevocation.revokeAllRefreshTokens(userId);
        await self.config.redis.setex(
          `${self.config.keyPrefix}session:revoked:${sessionId}`,
          DEFAULTS.revokedSessionTtl,
          "1",
        );
        self.audit.log("LOGOUT_ALL_DEVICES", { userId });
      } else if (userId && sessionId) {
        await self.tokenRevocation.markSessionRevoked(sessionId);
        await self.config.redis.srem(`${self.config.keyPrefix}user:sessions:${userId}`, sessionId);
        await self.config.redis.del(`${self.config.keyPrefix}session:metadata:${sessionId}`);
        self.audit.log("LOGOUT", { userId, sessionId });
      }

      return res.status(200).json({ success: true, message: "Logged out" });
    };
  }

  private async loadUser(id: string): Promise<User | null> {
    try {
      return await this.config.userStore.findById(id);
    } catch {
      return null;
    }
  }

  private assignUser(req: AuthRequest, user: User, decoded: JwtPayload): void {
    req.user = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      tokenJti: decoded.jti,
      sessionId: decoded.sessionId,
    };
  }
}
