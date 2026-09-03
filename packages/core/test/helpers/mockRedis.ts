import type { RedisAdapter, RedisPipeline } from "../src/types.js";

export class MockRedisPipeline implements RedisPipeline {
  private commands: Array<{ fn: string; args: unknown[] }> = [];

  constructor(private readonly redis: MockRedis) {}

  setex(key: string, ttl: number, value: string): this {
    this.commands.push({ fn: "setex", args: [key, ttl, value] });
    return this;
  }

  incr(key: string): this {
    this.commands.push({ fn: "incr", args: [key] });
    return this;
  }

  expire(key: string, seconds: number): this {
    this.commands.push({ fn: "expire", args: [key, seconds] });
    return this;
  }

  async exec(): Promise<[Error | null, unknown][]> {
    const results: [Error | null, unknown][] = [];
    for (const cmd of this.commands) {
      if (cmd.fn === "setex") {
        const [key, ttl, value] = cmd.args as [string, number, string];
        await this.redis.setex(key, ttl, value);
        results.push([null, "OK"]);
      } else if (cmd.fn === "incr") {
        const [key] = cmd.args as [string];
        const val = await this.redis.incr(key);
        results.push([null, val]);
      } else if (cmd.fn === "expire") {
        const [key, seconds] = cmd.args as [string, number];
        await this.redis.expire(key, seconds);
        results.push([null, 1]);
      }
    }
    this.commands = [];
    return results;
  }
}

export class MockRedis implements RedisAdapter {
  private store = new Map<string, { value: string; expiresAt?: number }>();
  private sets = new Map<string, Set<string>>();

  async get(key: string): Promise<string | null> {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  async set(key: string, value: string, ...args: unknown[]): Promise<"OK" | null> {
    if (args.length >= 2 && args[0] === "EX") {
      const ttl = args[1] as number;
      if (args.includes("NX") && this.store.has(key)) return null;
      this.store.set(key, { value, expiresAt: Date.now() + ttl * 1000 });
    } else if (args.includes("NX")) {
      if (this.store.has(key)) return null;
      this.store.set(key, { value });
    } else {
      this.store.set(key, { value });
    }
    return "OK";
  }

  async setex(key: string, ttl: number, value: string): Promise<"OK" | null> {
    this.store.set(key, { value, expiresAt: Date.now() + ttl * 1000 });
    return "OK";
  }

  async setnx(key: string, value: string): Promise<number> {
    if (this.store.has(key)) return 0;
    this.store.set(key, { value });
    return 1;
  }

  async del(...keys: string[]): Promise<number> {
    let count = 0;
    for (const key of keys) {
      if (this.store.delete(key)) count++;
      if (this.sets.delete(key)) count++;
    }
    return count;
  }

  async exists(key: string): Promise<0 | 1> {
    const entry = this.store.get(key);
    if (entry) {
      if (entry.expiresAt && Date.now() > entry.expiresAt) {
        this.store.delete(key);
        return 0;
      }
      return 1;
    }
    return this.sets.has(key) ? 1 : 0;
  }

  async expire(_key: string, _seconds: number): Promise<0 | 1> {
    return 1;
  }

  async ttl(_key: string): Promise<number> {
    return -1;
  }

  async sadd(key: string, ...members: string[]): Promise<number> {
    if (!this.sets.has(key)) this.sets.set(key, new Set());
    const set = this.sets.get(key)!;
    let added = 0;
    for (const m of members) {
      if (!set.has(m)) {
        set.add(m);
        added++;
      }
    }
    return added;
  }

  async srem(key: string, ...members: string[]): Promise<number> {
    const set = this.sets.get(key);
    if (!set) return 0;
    let removed = 0;
    for (const m of members) {
      if (set.delete(m)) removed++;
    }
    return removed;
  }

  async smembers(key: string): Promise<string[]> {
    const set = this.sets.get(key);
    return set ? Array.from(set) : [];
  }

  async incr(key: string): Promise<number> {
    const entry = this.store.get(key);
    const val = entry ? parseInt(entry.value, 10) + 1 : 1;
    this.store.set(key, { value: String(val) });
    return val;
  }

  async scan(_cursor: string, ...args: string[]): Promise<[string, string[]]> {
    const matchIdx = args.indexOf("MATCH");
    const pattern = matchIdx >= 0 ? args[matchIdx + 1] : "*";
    const regex = new RegExp(
      "^" + (pattern ?? "*").replace(/\*/g, ".*").replace(/\?/g, ".") + "$"
    );
    const keys = Array.from(this.store.keys()).filter((k) => regex.test(k));
    return ["0", keys];
  }

  async eval<T = unknown>(script: string, numKeys: number, ...args: string[]): Promise<T> {
    // Lua: consume SSE token (GET + DEL atomic)
    if (script.includes('redis.call("GET", KEYS[1])') && script.includes('redis.call("DEL", KEYS[1])')) {
      const key = args[0]!;
      const entry = this.store.get(key);
      if (entry && !(entry.expiresAt && Date.now() > entry.expiresAt)) {
        this.store.delete(key);
        return entry.value as T;
      }
      return null as T;
    }
    // Lua: rotate refresh token (EXISTS + DEL + SETEX + SREM + SADD)
    if (script.includes('redis.call("EXISTS", KEYS[1])')) {
      const oldKey = args[0]!;
      const newKey = args[1]!;
      const ttl = parseInt(args[numKeys]!, 10);
      const value = args[numKeys + 1]!;
      if (this.store.has(oldKey)) {
        this.store.delete(oldKey);
        this.store.set(newKey, { value, expiresAt: Date.now() + ttl * 1000 });
        const idxKey = args[2]!;
        const idxSet = this.sets.get(idxKey);
        if (idxSet) {
          idxSet.delete(oldKey);
          idxSet.add(newKey);
        }
        return 1 as T;
      }
      return 0 as T;
    }
    return null as T;
  }

  pipeline(): RedisPipeline {
    return new MockRedisPipeline(this);
  }

  /** Test helpers */
  _has(key: string): boolean {
    const entry = this.store.get(key);
    if (!entry) return false;
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return false;
    }
    return true;
  }

  _clear(): void {
    this.store.clear();
    this.sets.clear();
  }
}
