# Focura Auth

Production-ready authentication for full-stack applications. Dual-token RS256 JWT architecture with session binding, token rotation, 2FA, account lockout, and audit logging.

## Packages

| Package | Description |
|---|---|
| [`@focura-prod/auth-core`](./packages/core) | Express.js backend auth — JWT, sessions, middleware |
| [`@focura-prod/auth-next`](./packages/next) | Next.js frontend — NextAuth, components, hooks |

## Features

- **Dual-token RS256** — 15min access + 7d refresh with asymmetric keys
- **Token exchange** — HMAC-SHA256 signed proof between services
- **Refresh token rotation** — Atomic Redis Lua script, distributed lock
- **Session binding** — Device fingerprint + IP validation with hijack detection
- **Max concurrent sessions** — Configurable limit with LRU eviction
- **Account lockout** — Configurable failure threshold with timed unlock
- **2FA (TOTP)** — Google Authenticator compatible
- **Email verification** — Token-based with 24h expiry
- **Password reset** — Email delivery with 1h expiry
- **CSRF protection** — Redis-backed with timing-safe validation
- **Rate limiting** — Sliding window, per-route configurable
- **Audit logging** — 50+ event types with severity levels
- **Cache layer** — Auth result + user profile caching (5min/30min TTL)

## Architecture

```
Browser → NextAuth (Next.js) → HMAC proof → Express Backend
              ↓                                    ↓
         Credentials                          Token Exchange
         Google OAuth                         RS256 JWTs
         2FA (TOTP)                           Session Tracking
              ↓                                    ↓
         NextAuth Session ←──── accessToken + refreshToken + sseToken
```

## Quick Start

### Backend (Express)

```bash
npm install @focura-prod/auth-core express ioredis
```

```typescript
import { MiddlewareFactory } from "@focura-prod/auth-core";
import Redis from "ioredis";

const redis = new Redis(process.env.REDIS_URL!);
const auth = new MiddlewareFactory({
  redis,
  userStore: { findById, findByEmail, update, updateEmailVerified },
  hmacSecret: process.env.NEXTAUTH_SECRET!,
  jwt: { privateKey: fs.readFileSync("keys/private.pem", "utf8"), publicKey: fs.readFileSync("keys/public.pem", "utf8") },
});

app.post("/api/v1/auth/exchange", auth.createExchangeHandler());
app.post("/api/v1/auth/refresh", auth.createRefreshHandler());
app.post("/api/v1/auth/logout", auth.createLogoutHandler());
app.get("/api/v1/profile", auth.createAuthenticateMiddleware(), handler);
```

### Frontend (Next.js)

```bash
npm install @focura-prod/auth-next next-auth
```

```typescript
// app/api/auth/[...nextauth]/route.ts
import { createAuthOptions } from "@focura-prod/auth-next";

const authOptions = createAuthOptions({
  hmacSecret: process.env.NEXTAUTH_SECRET!,
  userStore: { findByEmail, findById },
});

export const GET = authOptions.handlers.GET;
export const POST = authOptions.handlers.POST;
```

```tsx
// app/auth/login/page.tsx
import { AuthPage } from "@focura-prod/auth-next/components";
export default function Login() { return <AuthPage />; }
```

## Development

```bash
git clone https://github.com/gaziraihan1/focura-auth.git
cd focura-auth
pnpm install
pnpm build
```

## License

MIT
