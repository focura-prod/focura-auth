import crypto from "crypto";
import type { TokenResponse } from "./types.js";

export function createExchangeProof(
  userId: string,
  email: string,
  role: string,
  sessionId: string,
  hmacSecret: string,
) {
  const timestamp = Date.now();
  const payload = `${userId}${email}${role}${sessionId}${timestamp}`;
  const signature = crypto.createHmac("sha256", hmacSecret).update(payload).digest("hex");
  return { timestamp, signature };
}

export async function exchangeForTokens(
  user: { id: string; email: string; role: string },
  sessionId: string,
  config: { backendUrl: string; hmacSecret: string },
): Promise<TokenResponse | null> {
  try {
    const { timestamp, signature } = createExchangeProof(
      user.id,
      user.email,
      user.role,
      sessionId,
      config.hmacSecret,
    );
    const res = await fetch(`${config.backendUrl}/api/v1/auth/exchange`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        userId: user.id,
        email: user.email,
        role: user.role,
        sessionId,
        timestamp,
        signature,
      }),
    });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}
