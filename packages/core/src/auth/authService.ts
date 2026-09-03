import crypto from "crypto";
import type {
  AuthCoreConfig,
  TokenPair,
  User,
  AuditEventType,
  SessionMetadata,
} from "../types.js";
import { resolveConfig, DEFAULTS, type ResolvedConfig } from "../config.js";
import { TokenManager } from "../tokens/backendToken.js";
import { TokenRevocation } from "../revocation/tokenRevocation.js";
import { SessionManager } from "../session/sessionManager.js";
import { AccountLockout } from "../lockout/accountLockout.js";
import { AuditLog } from "../audit/auditLog.js";
import { TotpManager } from "../totp/totp.js";
import { defaultErrors } from "../errors/index.js";
import type { ErrorFactory } from "../types.js";
import {
  generateDeviceFingerprint,
  validateSessionBinding,
  getClientIp,
} from "../session/sessionBinding.js";

export interface ExchangeInput {
  userId: string;
  email: string;
  role: string;
  sessionId?: string;
  timestamp: number;
  signature: string;
}

export interface ExchangeResult extends TokenPair {
  sseToken: string;
  sessionId: string;
}

export interface VerifyTokenInput {
  token: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface VerifyTokenResult {
  user: User;
  payload: {
    id: string;
    email: string;
    role: string;
    jti: string;
    sessionId?: string;
  };
}

export interface RefreshInput {
  refreshToken: string;
}

export interface RefreshResult extends TokenPair {
  sseToken: string;
}

export interface LogoutInput {
  accessToken?: string;
  accessTokenJti?: string;
  userId?: string;
  sessionId?: string;
  logoutAll?: boolean;
}

export interface TwoFactorSetupResult {
  secret: string;
  uri: string;
}

export interface TwoFactorVerifyInput {
  token: string;
  secret: string;
}

export class AuthService {
  readonly tokenManager: TokenManager;
  readonly tokenRevocation: TokenRevocation;
  readonly sessionManager: SessionManager;
  readonly accountLockout: AccountLockout;
  readonly totpManager: TotpManager;
  readonly audit: AuditLog;
  readonly errors: ErrorFactory;

  private readonly config: ResolvedConfig;
  private readonly userStore: AuthCoreConfig["userStore"];

  constructor(rawConfig: AuthCoreConfig) {
    this.config = resolveConfig(rawConfig);
    this.userStore = rawConfig.userStore;
    this.errors = rawConfig.errors ?? defaultErrors;

    this.tokenManager = new TokenManager(rawConfig.jwt);
    this.tokenRevocation = new TokenRevocation(rawConfig.redis, this.config.keyPrefix);
    this.sessionManager = new SessionManager(
      rawConfig.redis,
      this.tokenRevocation,
      rawConfig.auditLogger,
      this.config.keyPrefix,
      this.config.maxConcurrentSessions,
    );
    this.accountLockout = new AccountLockout(rawConfig.redis, {
      maxFailures: this.config.lockoutMaxFailures,
      lockoutSeconds: this.config.lockoutSeconds,
      windowSeconds: this.config.lockoutWindowSeconds,
      prefix: `${this.config.keyPrefix}lockout`,
    });
    this.totpManager = new TotpManager(rawConfig.jwt.issuer ?? "Auth");
    this.audit = new AuditLog(rawConfig.auditLogger);
  }

  getConfig(): ResolvedConfig {
    return this.config;
  }

  getRedis(): AuthCoreConfig["redis"] {
    return this.config.redis;
  }

  async exchange(input: ExchangeInput): Promise<ExchangeResult> {
    const age = Date.now() - input.timestamp;
    if (age > 60_000 || age < 0) {
      this.audit.log("EXCHANGE_FAILED", { userId: input.userId, reason: "Proof expired" });
      throw this.errors.UnauthorizedError("Exchange proof expired", "PROOF_EXPIRED");
    }

    const proofPayload = `${input.userId}${input.email}${input.role}${input.sessionId}${input.timestamp}`;
    const expected = crypto.createHmac("sha256", this.config.hmacSecret).update(proofPayload).digest("hex");

    let valid = false;
    try {
      if (input.signature) {
        valid = crypto.timingSafeEqual(Buffer.from(input.signature, "hex"), Buffer.from(expected, "hex"));
      }
    } catch {
      valid = false;
    }

    if (!valid) {
      this.audit.log("EXCHANGE_FAILED", { userId: input.userId, reason: "Invalid signature" });
      throw this.errors.UnauthorizedError("Invalid exchange proof", "INVALID_SIGNATURE");
    }

    const idempotencyKey = `exchange:idempotent:${input.userId}:${input.sessionId}:${input.timestamp}`;
    const existing = await this.config.redis.get(idempotencyKey);
    if (existing) {
      return JSON.parse(existing) as ExchangeResult;
    }

    const user = await this.userStore.findById(input.userId);
    if (!user) {
      this.audit.log("EXCHANGE_FAILED", { userId: input.userId, reason: "User not found" });
      throw this.errors.UnauthorizedError("User not found", "USER_NOT_FOUND");
    }

    if (user.email.toLowerCase() !== input.email.toLowerCase()) {
      this.audit.log("EXCHANGE_FAILED", { userId: input.userId, reason: "Email mismatch" });
      throw this.errors.UnauthorizedError("Email mismatch", "EMAIL_MISMATCH");
    }

    if (!user.emailVerified) {
      this.audit.log("EXCHANGE_FAILED", { userId: input.userId, reason: "Email not verified" });
      throw this.errors.UnauthorizedError("Email not verified", "EMAIL_NOT_VERIFIED");
    }

    const sessionId = input.sessionId || crypto.randomUUID();
    const tokens = this.tokenManager.createTokenPair({
      id: user.id,
      email: user.email,
      role: user.role,
      sessionId,
    });

    const refreshTtlSeconds = TokenManager.parseExpiry(this.tokenManager.getRefreshTokenExpiry()) / 1000;
    await this.tokenRevocation.storeRefreshToken(user.id, TokenManager.extractJti(tokens.refreshToken), refreshTtlSeconds);

    const sseToken = this.tokenManager.createSseToken(user.id);
    const sseTtlSeconds = TokenManager.parseExpiry(this.tokenManager.getSseTokenExpiry()) / 1000;
    await this.tokenRevocation.storeSseToken(TokenManager.extractJti(sseToken), user.id, sseTtlSeconds);

    await this.config.redis.setex(
      `${this.config.keyPrefix}session:created:${sessionId}`,
      this.config.absoluteTimeout,
      Date.now().toString(),
    );
    await this.config.redis.setex(
      `${this.config.keyPrefix}session:activity:${sessionId}`,
      this.config.inactivityTimeout,
      Date.now().toString(),
    );

    await this.sessionManager.trackUserSession(user.id, sessionId);

    const result: ExchangeResult = { ...tokens, sseToken, sessionId };
    await this.config.redis.setex(idempotencyKey, 90, JSON.stringify(result));

    this.audit.log("EXCHANGE_SUCCESS", { userId: user.id, email: user.email });
    return result;
  }

  async verifyToken(input: VerifyTokenInput): Promise<VerifyTokenResult> {
    let decoded;
    try {
      decoded = this.tokenManager.verifyToken(input.token) as {
        id: string;
        email: string;
        role: string;
        jti: string;
        type: string;
        version: number;
        sessionId?: string;
      };
    } catch (err: unknown) {
      if ((err as { name?: string }).name === "TokenExpiredError") {
        throw this.errors.TokenExpiredError();
      }
      throw this.errors.InvalidTokenError();
    }

    if (decoded.version !== this.config.currentVersion) {
      throw this.errors.InvalidTokenError("TOKEN_VERSION_MISMATCH");
    }
    if (decoded.type !== "access") {
      throw this.errors.InvalidTokenError("INVALID_TOKEN_TYPE");
    }

    const [isRevoked, sessionWasRevoked] = await Promise.all([
      decoded.jti ? this.tokenRevocation.isAccessTokenRevoked(decoded.jti) : Promise.resolve(false),
      decoded.sessionId ? this.tokenRevocation.isSessionRevoked(decoded.sessionId) : Promise.resolve(false),
    ]);
    if (isRevoked) throw this.errors.TokenRevokedError();
    if (sessionWasRevoked) throw this.errors.TokenRevokedError();

    if (decoded.sessionId && input.ipAddress && input.userAgent) {
      const metadataKey = `${this.config.keyPrefix}session:metadata:${decoded.sessionId}`;
      const storedMetadata = await this.config.redis.get(metadataKey);
      if (storedMetadata) {
        let metadata: SessionMetadata;
        try {
          metadata = JSON.parse(storedMetadata);
        } catch {
          metadata = { deviceId: null, ipAddress: input.ipAddress, userAgent: input.userAgent, lastActivity: Date.now() };
        }

        if (metadata.deviceId == null) {
          metadata.deviceId = crypto.createHash("sha256")
            .update(`${input.userAgent}|${input.ipAddress}`)
            .digest("hex")
            .substring(0, 32);
          metadata.ipAddress = input.ipAddress;
          metadata.userAgent = input.userAgent;
          metadata.lastActivity = Date.now();
          await this.config.redis.setex(metadataKey, this.config.sessionMetadataTtl, JSON.stringify(metadata));
        } else {
          const req = { headers: { "user-agent": input.userAgent }, ip: input.ipAddress } as Parameters<typeof generateDeviceFingerprint>[0];
          const binding = validateSessionBinding(req, metadata);
          if (!binding.valid) {
            await this.tokenRevocation.revokeAllRefreshTokens(decoded.id);
            this.audit.log("SESSION_HIJACK_DETECTED", {
              userId: decoded.id,
              sessionId: decoded.sessionId,
              reason: binding.reason,
            });
            throw this.errors.SessionHijackError(binding.reason);
          }
          metadata.lastActivity = Date.now();
          await this.config.redis.setex(metadataKey, this.config.sessionMetadataTtl, JSON.stringify(metadata));
        }
      }
    }

    const user = await this.userStore.findById(decoded.id);
    if (!user) throw this.errors.UnauthorizedError("User not found", "USER_NOT_FOUND");
    if (!user.emailVerified) throw this.errors.EmailNotVerifiedError();
    if (user.bannedAt) throw this.errors.AccountBannedError(user.banReason, user.bannedAt);

    return {
      user,
      payload: {
        id: decoded.id,
        email: decoded.email,
        role: decoded.role,
        jti: decoded.jti,
        sessionId: decoded.sessionId,
      },
    };
  }

  async refresh(input: RefreshInput): Promise<RefreshResult> {
    let decoded;
    try {
      decoded = this.tokenManager.verifyToken(input.refreshToken, "refresh") as {
        id: string;
        email: string;
        role: string;
        jti: string;
        sessionId: string;
      };
    } catch {
      throw this.errors.UnauthorizedError("Invalid refresh token", "INVALID_TOKEN");
    }

    const lockKey = `${this.config.keyPrefix}refresh:lock:${decoded.sessionId}`;
    const lockResult = await this.config.redis.set(lockKey, "1", "EX", DEFAULTS.refreshLockTtlSeconds, "NX");

    if (lockResult !== "OK") {
      throw this.errors.BadRequestError("Refresh already in progress", "REFRESH_IN_PROGRESS");
    }

    try {
      const dedupeKey = `${this.config.keyPrefix}refresh:dedupe:${decoded.id}:${decoded.jti}`;
      const cached = await this.config.redis.get(dedupeKey);
      if (cached) return JSON.parse(cached) as RefreshResult;

      const sessionRevokedKey = `${this.config.keyPrefix}session:revoked:${decoded.sessionId}`;
      if ((await this.config.redis.get(sessionRevokedKey)) === "1") {
        throw this.errors.UnauthorizedError("Session revoked", "SESSION_REVOKED");
      }

      const createdKey = `${this.config.keyPrefix}session:created:${decoded.sessionId}`;
      if ((await this.config.redis.exists(createdKey)) !== 1) {
        throw this.errors.UnauthorizedError("Session expired", "SESSION_TIMEOUT");
      }

      const newTokens = this.tokenManager.createTokenPair({
        id: decoded.id,
        email: decoded.email,
        role: decoded.role,
        sessionId: decoded.sessionId,
      });

      const refreshTtlSeconds = TokenManager.parseExpiry(this.tokenManager.getRefreshTokenExpiry()) / 1000;
      await this.tokenRevocation.rotateRefreshToken(
        decoded.id,
        decoded.jti,
        TokenManager.extractJti(newTokens.refreshToken),
        refreshTtlSeconds,
      );

      const newSseToken = this.tokenManager.createSseToken(decoded.id);
      const sseTtlSeconds = TokenManager.parseExpiry(this.tokenManager.getSseTokenExpiry()) / 1000;
      await this.tokenRevocation.storeSseToken(TokenManager.extractJti(newSseToken), decoded.id, sseTtlSeconds);

      const response: RefreshResult = { ...newTokens, sseToken: newSseToken };
      await this.config.redis.setex(dedupeKey, DEFAULTS.refreshDedupeTtlSeconds, JSON.stringify(response));

      this.audit.log("TOKEN_REFRESHED", { userId: decoded.id, sessionId: decoded.sessionId });
      return response;
    } finally {
      await this.config.redis.del(lockKey);
    }
  }

  async logout(input: LogoutInput): Promise<void> {
    if (input.accessTokenJti && input.accessToken) {
      const expiry = this.tokenManager.getAccessTokenExpiry();
      const ttlSeconds = TokenManager.parseExpiry(expiry) / 1000;
      await this.tokenRevocation.revokeAccessToken(input.accessTokenJti, ttlSeconds);
    }

    if (input.logoutAll && input.userId) {
      await this.tokenRevocation.revokeAllRefreshTokens(input.userId);
      if (input.sessionId) {
        await this.config.redis.setex(
          `${this.config.keyPrefix}session:revoked:${input.sessionId}`,
          DEFAULTS.revokedSessionTtl,
          "1",
        );
      }
      await this.sessionManager.revokeUserSession(input.userId, input.sessionId ?? "");
      this.audit.log("LOGOUT_ALL_DEVICES", { userId: input.userId });
    } else if (input.userId && input.sessionId) {
      await this.sessionManager.revokeUserSession(input.userId, input.sessionId);
      this.audit.log("LOGOUT", { userId: input.userId, sessionId: input.sessionId });
    }
  }

  async getActiveSessions(userId: string) {
    return this.sessionManager.getUserActiveSessions(userId);
  }

  async revokeSession(userId: string, sessionId: string): Promise<void> {
    await this.sessionManager.revokeUserSession(userId, sessionId);
    await this.tokenRevocation.markSessionRevoked(sessionId);
    this.audit.log("SESSION_REVOKED", { userId, sessionId });
  }

  generateTwoFactor(): TwoFactorSetupResult {
    const secret = this.totpManager.generateSecret();
    const uri = this.totpManager.createUri(secret, "");
    return { secret, uri };
  }

  createTwoFactorUri(secret: string, email: string): string {
    return this.totpManager.createUri(secret, email);
  }

  async verifyTwoFactor(input: TwoFactorVerifyInput): Promise<boolean> {
    return this.totpManager.verify(input.token, input.secret);
  }

  async recordLoginFailure(email: string): Promise<{ locked: boolean; unlocksAt?: Date; attempts: number }> {
    return this.accountLockout.recordFailedAttempt(email);
  }

  async clearLoginFailures(email: string): Promise<void> {
    return this.accountLockout.clearFailedAttempts(email);
  }

  async isAccountLocked(email: string): Promise<{ locked: boolean; unlocksAt?: Date }> {
    return this.accountLockout.isAccountLocked(email);
  }

  log(event: AuditEventType, data: Record<string, unknown>): void {
    this.audit.log(event, data);
  }
}
