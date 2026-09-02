import type { TokenResponse, RefreshResult } from "./types.js";

const refreshLocks = new Map<string, Promise<RefreshResult>>();

export async function silentRefresh(
  sessionId: string,
  refreshToken: string,
  backendUrl: string,
): Promise<RefreshResult> {
  const existing = refreshLocks.get(sessionId);
  if (existing) return existing.catch(() => ({ ok: false } as RefreshResult));

  let resolve!: (value: RefreshResult) => void;
  const promise = new Promise<RefreshResult>((res) => { resolve = res; });
  refreshLocks.set(sessionId, promise);

  try {
    const res = await fetch(`${backendUrl}/api/v1/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken }),
    });

    if (res.ok) {
      const tokens: TokenResponse = await res.json();
      const result: RefreshResult = { ok: true, tokens };
      resolve(result);
      return result;
    }

    let code: string | undefined;
    try {
      const body = (await res.json()) as { code?: string };
      code = body?.code;
    } catch {}
    const result: RefreshResult = { ok: false, code };
    resolve(result);
    return result;
  } catch {
    const result: RefreshResult = { ok: false };
    resolve(result);
    return result;
  } finally {
    refreshLocks.delete(sessionId);
  }
}
