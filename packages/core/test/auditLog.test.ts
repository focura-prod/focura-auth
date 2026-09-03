import { describe, it, expect, vi, beforeEach } from "vitest";
import { AuditLog } from "../src/audit/auditLog.js";

describe("AuditLog", () => {
  let spy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    spy = vi.spyOn(console, "info").mockImplementation(() => {});
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  it("should call logger.log when provided", async () => {
    const logger = { log: vi.fn(async () => {}) };
    const audit = new AuditLog(logger);
    audit.log("LOGIN_SUCCESS", { userId: "u1" });
    // logger.log is called asynchronously
    await new Promise((r) => setTimeout(r, 10));
    expect(logger.log).toHaveBeenCalledWith("LOGIN_SUCCESS", { userId: "u1" });
  });

  it("should log info events to console.info", () => {
    const audit = new AuditLog();
    audit.log("LOGIN_SUCCESS", { userId: "u1" });
    expect(spy).toHaveBeenCalled();
  });

  it("should log warn events to console.warn", () => {
    const audit = new AuditLog();
    audit.log("LOGIN_FAILED", { userId: "u1" });
    expect(console.warn).toHaveBeenCalled();
  });

  it("should log critical events to console.error", () => {
    const audit = new AuditLog();
    audit.log("TOKEN_REPLAY_DETECTED", { userId: "u1" });
    expect(console.error).toHaveBeenCalled();
  });

  it("should handle logger failure gracefully", async () => {
    const logger = { log: vi.fn(async () => { throw new Error("logger fail"); }) };
    const audit = new AuditLog(logger);
    audit.log("LOGIN_SUCCESS", { userId: "u1" });
    // should not throw
    await new Promise((r) => setTimeout(r, 10));
    expect(logger.log).toHaveBeenCalled();
  });

  it("should log persistence errors outside test env", async () => {
    const prev = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      const logger = { log: vi.fn(async () => { throw new Error("logger fail"); }) };
      const audit = new AuditLog(logger);
      audit.log("LOGIN_SUCCESS", { userId: "u1" });
      await new Promise((r) => setTimeout(r, 10));
      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining("[AuditLog] Failed to persist audit event:"),
        expect.anything(),
      );
    } finally {
      process.env.NODE_ENV = prev;
    }
  });

  it("should work without a logger", () => {
    const audit = new AuditLog();
    expect(() => audit.log("LOGOUT", { userId: "u1" })).not.toThrow();
  });

  it("should default unknown events to info severity", () => {
    const audit = new AuditLog();
    expect(() => audit.log("UNKNOWN_EVENT" as never, { userId: "u1" })).not.toThrow();
    expect(console.info).toHaveBeenCalled();
  });
});
