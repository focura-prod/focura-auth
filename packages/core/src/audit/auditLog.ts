import type { AuditEventType, AuditLogger, AuditSeverity } from "../types.js";
import { AUDIT_SEVERITY } from "../config.js";

export class AuditLog {
  constructor(private readonly logger?: AuditLogger) {}

  log(
    event: AuditEventType,
    data: Omit<Record<string, unknown>, "event" | "timestamp" | "severity">,
  ): void {
    const severity: AuditSeverity = AUDIT_SEVERITY[event] ?? "info";
    const entry = { event, severity, timestamp: new Date().toISOString(), ...data };
    const output = JSON.stringify(entry);

    if (severity === "critical") {
      console.error(`[AUDIT:CRITICAL] ${output}`);
    } else if (severity === "warn") {
      console.warn(`[AUDIT:WARN] ${output}`);
    } else {
      console.info(`[AUDIT:INFO] ${output}`);
    }

    if (this.logger) {
      void this.logger.log(event, data).catch((err) => {
        if (process.env.NODE_ENV !== "test") {
          console.error("[AuditLog] Failed to persist audit event:", (err as Error)?.message ?? err);
        }
      });
    }
  }
}
