import type { RedisAdapter } from "../types.js";
import { DEFAULTS } from "../config.js";

export class TokenRevocation {
  constructor(
    private readonly redis: RedisAdapter,
    private readonly prefix: string = DEFAULTS.keyPrefix,
  ) {}

  private refreshIndexKey(userId: string): string {
    return `${this.prefix}refresh:index:${userId}`;
  }

  private refreshTokenKey(userId: string, jti: string): string {
    return `${this.prefix}refresh:${userId}:${jti}`;
  }

  private revokedAccessKey(jti: string): string {
    return `${this.prefix}revoked:access:${jti}`;
  }

  private sseKey(jti: string): string {
    return `${this.prefix}sse:${jti}`;
  }

  private sessionRevokedKey(sessionId: string): string {
    return `${this.prefix}session:revoked:${sessionId}`;
  }

  async revokeAccessToken(jti: string, expiresInSeconds: number): Promise<void> {
    try {
      await this.redis.setex(this.revokedAccessKey(jti), expiresInSeconds, "1");
    } catch (err) {
      console.error("[TokenRevocation] Failed to revoke access token:", err);
    }
  }

  async isAccessTokenRevoked(jti: string): Promise<boolean> {
    try {
      const val = await this.redis.get(this.revokedAccessKey(jti));
      return val === "1";
    } catch (err) {
      console.error("[TokenRevocation] Failed to check revoked access token:", err);
      return false;
    }
  }

  async storeRefreshToken(userId: string, jti: string, expiresInSeconds: number): Promise<void> {
    try {
      const tokenKey = this.refreshTokenKey(userId, jti);
      await this.redis.setex(tokenKey, expiresInSeconds, JSON.stringify({ jti, createdAt: Date.now() }));
      await this.redis.sadd(this.refreshIndexKey(userId), tokenKey);
    } catch (err) {
      console.error("[TokenRevocation] Failed to store refresh token:", err);
    }
  }

  async isRefreshTokenValid(userId: string, jti: string): Promise<boolean> {
    try {
      const val = await this.redis.get(this.refreshTokenKey(userId, jti));
      return val !== null;
    } catch (err) {
      console.error("[TokenRevocation] Failed to check refresh token validity:", err);
      return false;
    }
  }

  async revokeRefreshToken(userId: string, jti: string): Promise<void> {
    try {
      const tokenKey = this.refreshTokenKey(userId, jti);
      await this.redis.del(tokenKey);
      await this.redis.srem(this.refreshIndexKey(userId), tokenKey);
    } catch (err) {
      console.error("[TokenRevocation] Failed to revoke refresh token:", err);
    }
  }

  async revokeAllRefreshTokens(userId: string): Promise<void> {
    try {
      const idxKey = this.refreshIndexKey(userId);
      let keys = await this.redis.smembers(idxKey);

      if (keys.length === 0) {
        let cursor = "0";
        const pattern = `${this.prefix}refresh:${userId}:*`;
        do {
          const [nextCursor, found] = await this.redis.scan(cursor, "MATCH", pattern, "COUNT", "100");
          cursor = nextCursor;
          keys.push(...found);
        } while (cursor !== "0");
      }

      if (keys.length > 0) await this.redis.del(...keys);
      await this.redis.del(idxKey);
    } catch (err) {
      console.error("[TokenRevocation] Failed to revoke all refresh tokens:", err);
    }
  }

  async rotateRefreshToken(
    userId: string,
    oldJti: string,
    newJti: string,
    expiresInSeconds: number,
  ): Promise<boolean> {
    const oldKey = this.refreshTokenKey(userId, oldJti);
    const newKey = this.refreshTokenKey(userId, newJti);
    const indexKey = this.refreshIndexKey(userId);

    try {
      const result = await this.redis.eval<number>(
        `if redis.call("EXISTS", KEYS[1]) == 1 then
          redis.call("DEL", KEYS[1])
          redis.call("SETEX", KEYS[2], ARGV[1], ARGV[2])
          redis.call("SREM", KEYS[3], KEYS[1])
          redis.call("SADD", KEYS[3], KEYS[2])
          return 1
        else
          return 0
        end`,
        3,
        oldKey,
        newKey,
        indexKey,
        expiresInSeconds.toString(),
        JSON.stringify({ jti: newJti, createdAt: Date.now() }),
      );

      return result === 1;
    } catch (error: unknown) {
      const err = error as { name?: string };
      if (err?.name === "MaxRetriesPerRequestError") {
        throw new Error("Redis service temporarily unavailable");
      }
      throw error;
    }
  }

  async storeSseToken(jti: string, userId: string, ttlSeconds: number): Promise<void> {
    try {
      await this.redis.setex(this.sseKey(jti), ttlSeconds, userId);
    } catch (error: unknown) {
      const err = error as { name?: string };
      if (err?.name === "MaxRetriesPerRequestError") {
        throw new Error("Redis service temporarily unavailable");
      }
      throw error;
    }
  }

  async consumeSseToken(jti: string): Promise<string | null> {
    const key = this.sseKey(jti);
    try {
      const userId = await this.redis.eval<string | null>(
        `local v = redis.call("GET", KEYS[1])
         if v then redis.call("DEL", KEYS[1]) end
         return v`,
        1,
        key,
      );
      return typeof userId === "string" ? userId : null;
    } catch (error: unknown) {
      const err = error as { name?: string };
      if (err?.name === "MaxRetriesPerRequestError") {
        throw new Error("Redis service temporarily unavailable");
      }
      throw error;
    }
  }

  async markSessionRevoked(sessionId: string): Promise<void> {
    try {
      await this.redis.setex(this.sessionRevokedKey(sessionId), DEFAULTS.revokedSessionTtl, "1");
    } catch (err) {
      console.error("[TokenRevocation] Failed to mark session revoked:", err);
    }
  }

  async isSessionRevoked(sessionId: string): Promise<boolean> {
    try {
      const val = await this.redis.get(this.sessionRevokedKey(sessionId));
      return val === "1";
    } catch (err) {
      console.error("[TokenRevocation] Failed to check revoked session:", err);
      return false;
    }
  }
}
