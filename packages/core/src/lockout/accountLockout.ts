import type { RedisAdapter } from "../types.js";
import { DEFAULTS } from "../config.js";

export class AccountLockout {
  private readonly maxFailures: number;
  private readonly lockoutSeconds: number;
  private readonly windowSeconds: number;
  private readonly prefix: string;

  constructor(
    private readonly redis: RedisAdapter,
    config?: { maxFailures?: number; lockoutSeconds?: number; windowSeconds?: number; prefix?: string },
  ) {
    this.maxFailures = config?.maxFailures ?? DEFAULTS.lockoutMaxFailures;
    this.lockoutSeconds = config?.lockoutSeconds ?? DEFAULTS.lockoutSeconds;
    this.windowSeconds = config?.windowSeconds ?? DEFAULTS.lockoutWindowSeconds;
    this.prefix = config?.prefix ?? `${DEFAULTS.keyPrefix}lockout`;
  }

  async recordFailedAttempt(
    identifier: string,
  ): Promise<{ locked: boolean; unlocksAt?: Date; attempts: number }> {
    if (!identifier) return { locked: false, attempts: 0 };
    try {
      const failKey = `${this.prefix}:failures:${identifier}`;
      const lockKey = `${this.prefix}:locked:${identifier}`;

      const existingLock = await this.redis.get(lockKey);
      if (existingLock) {
        return { locked: true, unlocksAt: new Date(Number(existingLock)), attempts: this.maxFailures };
      }

      const pipe = this.redis.pipeline();
      pipe.incr(failKey);
      pipe.expire(failKey, this.windowSeconds);
      const results = await pipe.exec();
      const attempts = (results?.[0]?.[1] as number) ?? 1;

      if (attempts >= this.maxFailures) {
        const unlocksAt = Date.now() + this.lockoutSeconds * 1000;
        await this.redis.setex(lockKey, this.lockoutSeconds, String(unlocksAt));
        return { locked: true, unlocksAt: new Date(unlocksAt), attempts };
      }

      return { locked: false, attempts };
    } catch (err) {
      console.error("[AccountLockout] Failed to record failed attempt:", err);
      return { locked: false, attempts: 0 };
    }
  }

  async clearFailedAttempts(identifier: string): Promise<void> {
    try {
      await this.redis.del(`${this.prefix}:failures:${identifier}`, `${this.prefix}:locked:${identifier}`);
    } catch (err) {
      console.error("[AccountLockout] Failed to clear failed attempts:", err);
    }
  }

  async isAccountLocked(identifier: string): Promise<{ locked: boolean; unlocksAt?: Date }> {
    if (!identifier) return { locked: false };
    try {
      const lockedUntil = await this.redis.get(`${this.prefix}:locked:${identifier}`);
      if (!lockedUntil) return { locked: false };
      return { locked: true, unlocksAt: new Date(Number(lockedUntil)) };
    } catch (err) {
      console.error("[AccountLockout] Failed to check account lock status:", err);
      return { locked: false };
    }
  }
}
