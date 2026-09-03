// @focura-prod/auth-core — Default error classes

export class UnauthorizedError extends Error {
  public readonly code: string;
  public readonly statusCode = 401;
  constructor(message = "Unauthorized", code = "UNAUTHORIZED") {
    super(message);
    this.name = "UnauthorizedError";
    this.code = code;
  }
}

export class TokenExpiredError extends Error {
  public readonly code = "TOKEN_EXPIRED";
  public readonly statusCode = 401;
  constructor(message = "Token expired") {
    super(message);
    this.name = "TokenExpiredError";
  }
}

export class InvalidTokenError extends Error {
  public readonly code: string;
  public readonly statusCode = 401;
  constructor(code = "INVALID_TOKEN") {
    super("Invalid token");
    this.name = "InvalidTokenError";
    this.code = code;
  }
}

export class TokenRevokedError extends Error {
  public readonly code = "TOKEN_REVOKED";
  public readonly statusCode = 401;
  constructor(message = "Token has been revoked") {
    super(message);
    this.name = "TokenRevokedError";
  }
}

export class EmailNotVerifiedError extends Error {
  public readonly code = "EMAIL_NOT_VERIFIED";
  public readonly statusCode = 403;
  constructor(message = "Email not verified") {
    super(message);
    this.name = "EmailNotVerifiedError";
  }
}

export class AccountBannedError extends Error {
  public readonly code = "ACCOUNT_BANNED";
  public readonly statusCode = 403;
  public readonly bannedAt?: Date;
  constructor(reason?: string | null, bannedAt?: Date | null) {
    super(reason ?? "Account has been banned");
    this.name = "AccountBannedError";
    this.bannedAt = bannedAt ?? undefined;
  }
}

export class ForbiddenError extends Error {
  public readonly code = "FORBIDDEN";
  public readonly statusCode = 403;
  constructor(message = "Forbidden") {
    super(message);
    this.name = "ForbiddenError";
  }
}

export class SessionHijackError extends Error {
  public readonly code = "SESSION_HIJACK_DETECTED";
  public readonly statusCode = 401;
  constructor(reason?: string) {
    super(reason ?? "Session hijack detected");
    this.name = "SessionHijackError";
  }
}

export class BadRequestError extends Error {
  public readonly code: string;
  public readonly statusCode = 400;
  constructor(message = "Bad request", code = "BAD_REQUEST") {
    super(message);
    this.name = "BadRequestError";
    this.code = code;
  }
}

export class ValidationError extends Error {
  public readonly code: string;
  public readonly statusCode = 400;
  public readonly details?: unknown[];
  constructor(message = "Validation failed", details?: unknown[], code = "VALIDATION_ERROR") {
    super(message);
    this.name = "ValidationError";
    this.code = code;
    this.details = details;
  }
}

import type { ErrorFactory } from "../types.js";

export const defaultErrors: ErrorFactory = {
  UnauthorizedError: (msg, code) => new UnauthorizedError(msg, code),
  TokenExpiredError: () => new TokenExpiredError(),
  InvalidTokenError: (code) => new InvalidTokenError(code),
  TokenRevokedError: () => new TokenRevokedError(),
  EmailNotVerifiedError: () => new EmailNotVerifiedError(),
  AccountBannedError: (reason, at) => new AccountBannedError(reason, at),
  ForbiddenError: (msg) => new ForbiddenError(msg),
  SessionHijackError: (reason) => new SessionHijackError(reason),
  BadRequestError: (msg, code) => new BadRequestError(msg, code),
  ValidationError: (msg, details, code) => new ValidationError(msg, details, code),
};
