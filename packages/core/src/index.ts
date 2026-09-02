export type {
  RedisAdapter,
  RedisPipeline,
  UserStore,
  User,
  CacheAdapter,
  AuditLogger,
  ObservabilitySink,
  ErrorFactory,
  SessionLifecycle,
  RateLimiterFactory,
  ZodSchema,
  TokenConfig,
  LockoutConfig,
  SessionConfig,
  AuthCoreConfig,
  TokenPayload,
  TokenPair,
  DeviceFingerprint,
  SessionMetadata,
  AuditEventType,
  AuditSeverity,
} from "./types.js";

export { TokenManager } from "./tokens/index.js";
export { TokenRevocation } from "./revocation/index.js";
export { RefreshLock } from "./refresh/index.js";
export { SessionManager } from "./session/index.js";
export {
  generateDeviceFingerprint,
  validateSessionBinding,
  createSessionMetadata,
  getClientIp,
  isPrivateIp,
  looksLikeServerToServerRequest,
  looksLikeServerToServerUA,
  normalizeUserAgent,
} from "./session/index.js";
export { AccountLockout } from "./lockout/index.js";
export { AuditLog } from "./audit/index.js";
export { TotpManager } from "./totp/index.js";
export { SessionTimeoutManager } from "./middleware/sessionTimeout.js";
export { MiddlewareFactory } from "./middleware/middlewareFactory.js";
export type { AuthRequest } from "./middleware/middlewareFactory.js";
export { exchangeSchema, refreshSchema, logoutSchema } from "./validation/auth.validation.js";
export {
  UnauthorizedError,
  TokenExpiredError,
  InvalidTokenError,
  TokenRevokedError,
  EmailNotVerifiedError,
  AccountBannedError,
  ForbiddenError,
  SessionHijackError,
  BadRequestError,
  ValidationError,
  defaultErrors,
} from "./errors/index.js";
export { DEFAULTS, resolveConfig, AUDIT_SEVERITY } from "./config.js";
export type { ResolvedConfig } from "./config.js";
