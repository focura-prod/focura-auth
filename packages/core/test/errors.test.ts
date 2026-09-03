import { describe, it, expect } from "vitest";
import {
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
} from "../src/errors/index.js";

describe("Error Classes", () => {
  describe("UnauthorizedError", () => {
    it("should create with defaults", () => {
      const err = new UnauthorizedError();
      expect(err.message).toBe("Unauthorized");
      expect(err.code).toBe("UNAUTHORIZED");
      expect(err.statusCode).toBe(401);
      expect(err.name).toBe("UnauthorizedError");
      expect(err).toBeInstanceOf(Error);
    });
    it("should accept custom message and code", () => {
      const err = new UnauthorizedError("No", "X");
      expect(err.message).toBe("No");
      expect(err.code).toBe("X");
    });
  });

  describe("TokenExpiredError", () => {
    it("should have correct defaults", () => {
      const err = new TokenExpiredError();
      expect(err.message).toBe("Token expired");
      expect(err.code).toBe("TOKEN_EXPIRED");
      expect(err.statusCode).toBe(401);
    });
  });

  describe("InvalidTokenError", () => {
    it("should use default code", () => {
      expect(new InvalidTokenError().code).toBe("INVALID_TOKEN");
    });
    it("should accept custom code", () => {
      expect(new InvalidTokenError("V_MISMATCH").code).toBe("V_MISMATCH");
    });
  });

  describe("TokenRevokedError", () => {
    it("should have correct defaults", () => {
      const err = new TokenRevokedError();
      expect(err.code).toBe("TOKEN_REVOKED");
      expect(err.statusCode).toBe(401);
    });
  });

  describe("EmailNotVerifiedError", () => {
    it("should have 403 status", () => {
      const err = new EmailNotVerifiedError();
      expect(err.code).toBe("EMAIL_NOT_VERIFIED");
      expect(err.statusCode).toBe(403);
    });
  });

  describe("AccountBannedError", () => {
    it("should use default message", () => {
      expect(new AccountBannedError().message).toBe("Account has been banned");
    });
    it("should accept reason and date", () => {
      const d = new Date("2024-06-01");
      const err = new AccountBannedError("spam", d);
      expect(err.message).toBe("spam");
      expect(err.bannedAt).toBe(d);
    });
    it("should handle null values", () => {
      const err = new AccountBannedError(null, null);
      expect(err.bannedAt).toBeUndefined();
    });
  });

  describe("ForbiddenError", () => {
    it("should default to 403", () => {
      const err = new ForbiddenError();
      expect(err.code).toBe("FORBIDDEN");
      expect(err.statusCode).toBe(403);
    });
    it("should accept custom message", () => {
      expect(new ForbiddenError("Nope").message).toBe("Nope");
    });
  });

  describe("SessionHijackError", () => {
    it("should default message", () => {
      expect(new SessionHijackError().message).toBe("Session hijack detected");
    });
    it("should accept custom reason", () => {
      expect(new SessionHijackError("mismatch").message).toBe("mismatch");
    });
  });

  describe("BadRequestError", () => {
    it("should default", () => {
      const err = new BadRequestError();
      expect(err.code).toBe("BAD_REQUEST");
      expect(err.statusCode).toBe(400);
    });
    it("should accept custom values", () => {
      const err = new BadRequestError("Rate", "RL");
      expect(err.message).toBe("Rate");
      expect(err.code).toBe("RL");
    });
  });

  describe("ValidationError", () => {
    it("should default", () => {
      const err = new ValidationError();
      expect(err.code).toBe("VALIDATION_ERROR");
      expect(err.statusCode).toBe(400);
      expect(err.details).toBeUndefined();
    });
    it("should accept details", () => {
      const d = [{ field: "email" }];
      const err = new ValidationError("bad", d, "X");
      expect(err.details).toEqual(d);
      expect(err.code).toBe("X");
    });
  });

  describe("defaultErrors factory", () => {
    it("should create each error type", () => {
      expect(defaultErrors.UnauthorizedError("m", "c")).toBeInstanceOf(UnauthorizedError);
      expect(defaultErrors.TokenExpiredError()).toBeInstanceOf(TokenExpiredError);
      expect(defaultErrors.InvalidTokenError("c")).toBeInstanceOf(InvalidTokenError);
      expect(defaultErrors.TokenRevokedError()).toBeInstanceOf(TokenRevokedError);
      expect(defaultErrors.EmailNotVerifiedError()).toBeInstanceOf(EmailNotVerifiedError);
      expect(defaultErrors.AccountBannedError("r")).toBeInstanceOf(AccountBannedError);
      expect(defaultErrors.ForbiddenError("m")).toBeInstanceOf(ForbiddenError);
      expect(defaultErrors.SessionHijackError("r")).toBeInstanceOf(SessionHijackError);
      expect(defaultErrors.BadRequestError("m", "c")).toBeInstanceOf(BadRequestError);
      expect(defaultErrors.ValidationError("m", [], "c")).toBeInstanceOf(ValidationError);
    });
  });
});
