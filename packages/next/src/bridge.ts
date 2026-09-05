import crypto from "crypto";
import type { FailedAttemptResult } from "./types.js";

export async function callInternal<T = Record<string, unknown>>(
  path: string,
  fields: Record<string, unknown>,
  config: { backendUrl: string; hmacSecret: string },
): Promise<T | null> {
  if (process.env.NODE_ENV === "test") return null;
  try {
    const timestamp = Date.now();
    const payload = JSON.stringify({ ...fields, timestamp });
    const signature = crypto
      .createHmac("sha256", config.hmacSecret)
      .update(payload)
      .digest("hex");
    const res = await fetch(`${config.backendUrl}/api/v1/internal${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...fields, timestamp, signature }),
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

export async function recordLoginFailure(
  email: string,
  config: { backendUrl: string; hmacSecret: string },
): Promise<FailedAttemptResult | null> {
  const result = await callInternal<FailedAttemptResult>("/failed-attempt", { email }, config);
  void callInternal("/audit", { event: "LOGIN_FAILED", email, reason: "Invalid credentials", meta: { attempts: result?.attempts ?? 0 } }, config);
  return result;
}
