import type { RedisAdapter, AuditLogger, SessionMetadata } from "../types.js";
import { DEFAULTS } from "../config.js";

export class SessionManager {
  private readonly maxConcurrent: number;

  constructor(
    private readonly redis: RedisAdapter,
    private readonly tokenRevocation: { markSessionRevoked(id: string): Promise<void> },
    private readonly auditLogger?: AuditLogger,
    prefix: string = DEFAULTS.keyPrefix,
    maxConcurrent?: number,
  ) {
    this.prefix = prefix;
    this.maxConcurrent = maxConcurrent ?? DEFAULTS.maxConcurrentSessions;
  }

  private readonly prefix: string;

  private sessionKey(userId: string): string {
    return `${this.prefix}user:sessions:${userId}`;
  }

  private metadataKey(sessionId: string): string {
    return `${this.prefix}session:metadata:${sessionId}`;
  }

  async trackUserSession(userId: string, sessionId: string): Promise<void> {
    try {
      const key = this.sessionKey(userId);
      const members = await this.redis.smembers(key);

      if (members.length >= this.maxConcurrent) {
        this.auditLogger?.log("MAX_SESSIONS_REACHED", {
          userId,
          sessionCount: members.length,
          limit: this.maxConcurrent,
        });
        const evictedSession = await this.pickLeastActiveSession(members);
        await this.redis.srem(key, evictedSession);
        await this.redis.del(this.metadataKey(evictedSession));
        await this.tokenRevocation.markSessionRevoked(evictedSession);
      }

      await this.redis.sadd(key, sessionId);
      await this.redis.expire(key, DEFAULTS.sessionMetadataTtl);
    } catch (err) {
      console.error(`[SessionManager] Failed to track session for user ${userId}:`, err);
    }
  }

  private async pickLeastActiveSession(members: string[]): Promise<string> {
    let leastActive = members[0]!;
    let leastActiveAt = Infinity;
    for (const member of members) {
      let lastActivity = 0;
      try {
        const meta = await this.redis.get(this.metadataKey(member));
        if (meta) lastActivity = JSON.parse(meta).lastActivity ?? 0;
      } catch {
        lastActivity = 0;
      }
      if (lastActivity < leastActiveAt) {
        leastActiveAt = lastActivity;
        leastActive = member;
      }
    }
    return leastActive;
  }

  async revokeUserSession(userId: string, sessionId: string): Promise<void> {
    try {
      await this.redis.srem(this.sessionKey(userId), sessionId);
      await this.redis.del(this.metadataKey(sessionId));
    } catch (err) {
      console.error(`[SessionManager] Failed to revoke session for user ${userId}:`, err);
    }
  }

  async getUserActiveSessions(userId: string): Promise<
    Array<{
      sessionId: string;
      deviceInfo: string;
      ipAddress?: string;
      lastActivity: string;
      createdAt: string;
    }>
  > {
    try {
      const sessionIds = await this.redis.smembers(this.sessionKey(userId));
      const sessions = [];
      for (const sessionId of sessionIds) {
        const metadata = await this.redis.get(this.metadataKey(sessionId));
        if (metadata) {
          try {
            const parsed: SessionMetadata & { createdAt?: number } = JSON.parse(metadata);
            sessions.push({
              sessionId,
              deviceInfo: parsed.userAgent ?? "",
              ipAddress: parsed.ipAddress,
              lastActivity: new Date(parsed.lastActivity).toISOString(),
              createdAt: new Date(parsed.createdAt ?? parsed.lastActivity).toISOString(),
            });
          } catch {
            console.warn(`[SessionManager] Corrupted metadata for session ${sessionId}, skipping`);
          }
        }
      }
      return sessions;
    } catch (err) {
      console.error(`[SessionManager] Failed to get sessions for user ${userId}:`, err);
      return [];
    }
  }
}
