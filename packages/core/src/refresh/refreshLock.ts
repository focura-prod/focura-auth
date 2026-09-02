import type { RedisAdapter } from "../types.js";
import { DEFAULTS } from "../config.js";

export class RefreshLock {
  constructor(
    private readonly redis: RedisAdapter,
    private readonly prefix: string = DEFAULTS.keyPrefix,
  ) {}

  private lockKey(sessionId: string): string {
    return `${this.prefix}refresh:lock:${sessionId}`;
  }

  async acquire(sessionId: string): Promise<boolean> {
    try {
      const result = await this.redis.setnx(
        this.lockKey(sessionId),
        "1",
      );
      return result === 1;
    } catch (err) {
      console.error("[RefreshLock] Failed to acquire lock:", err);
      return false;
    }
  }

  async release(sessionId: string): Promise<void> {
    try {
      await this.redis.del(this.lockKey(sessionId));
    } catch (err) {
      console.error("[RefreshLock] Failed to release lock:", err);
    }
  }

  async isLocked(sessionId: string): Promise<boolean> {
    try {
      const val = await this.redis.get(this.lockKey(sessionId));
      return !!val;
    } catch (err) {
      console.error("[RefreshLock] Failed to check lock status:", err);
      return false;
    }
  }
}
