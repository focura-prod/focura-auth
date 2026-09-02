import type { RedisAdapter, SessionLifecycle } from "../types.js";
import { DEFAULTS } from "../config.js";

export class SessionTimeoutManager implements SessionLifecycle {
  private readonly inactivityTimeout: number;
  private readonly absoluteTimeout: number;
  private readonly prefix: string;

  constructor(
    private readonly redis: RedisAdapter,
    config?: { inactivityTimeout?: number; absoluteTimeout?: number; prefix?: string },
  ) {
    this.inactivityTimeout = config?.inactivityTimeout ?? DEFAULTS.inactivityTimeout;
    this.absoluteTimeout = config?.absoluteTimeout ?? DEFAULTS.absoluteTimeout;
    this.prefix = config?.prefix ?? DEFAULTS.keyPrefix;
  }

  private createdKey(sessionId: string): string {
    return `${this.prefix}session:created:${sessionId}`;
  }

  private activityKey(sessionId: string): string {
    return `${this.prefix}session:activity:${sessionId}`;
  }

  async recordCreation(sessionId: string): Promise<void> {
    const now = Date.now();
    await this.redis.setex(this.createdKey(sessionId), this.absoluteTimeout, now.toString());
    await this.redis.setex(this.activityKey(sessionId), this.inactivityTimeout, now.toString());
  }

  async invalidate(sessionId: string): Promise<void> {
    await this.redis.del(this.createdKey(sessionId), this.activityKey(sessionId));
  }

  async isTracked(sessionId: string): Promise<boolean> {
    return (await this.redis.exists(this.createdKey(sessionId))) === 1;
  }

  async isInactive(sessionId: string): Promise<boolean> {
    const exists = await this.redis.exists(this.activityKey(sessionId));
    return exists !== 1;
  }

  async updateActivity(sessionId: string): Promise<boolean> {
    try {
      const result = await this.redis.setex(this.activityKey(sessionId), this.inactivityTimeout, Date.now().toString());
      return result === "OK";
    } catch {
      return false;
    }
  }
}
