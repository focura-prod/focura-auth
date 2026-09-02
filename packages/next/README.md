# @focura/auth-next

Production-ready Next.js authentication with NextAuth.js. Drop-in auth with credentials, Google OAuth, 2FA, email verification, and password reset.

## Features

- **NextAuth.js** with JWT strategy
- **Credentials + Google OAuth** providers
- **2FA (TOTP)** for both credential and OAuth logins
- **Email verification** with token-based flow
- **Password reset** with email delivery
- **Token exchange** — HMAC-signed proof to backend
- **Silent refresh** — Automatic token renewal
- **Pre-built UI components** — Login, register, forgot/reset password, email verification
- **React hooks** — Form handling with Zod validation
- **API route handlers** — Ready-to-use Next.js route handlers

## Installation

```bash
npm install @focura/auth-next next-auth
```

## Quick Start

### 1. Create API route

```typescript
// app/api/auth/[...nextauth]/route.ts
import { createAuthOptions } from "@focura/auth-next";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import { prisma } from "@/lib/prisma";

const authOptions = createAuthOptions({
  hmacSecret: process.env.NEXTAUTH_SECRET!,
  backendUrl: process.env.BACKEND_URL,
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  },
  prismaAdapter: PrismaAdapter(prisma),
  userStore: {
    findByEmail: (email) => prisma.user.findUnique({ where: { email } }),
    findById: (id) => prisma.user.findUnique({ where: { id } }),
    update: (id, data) => prisma.user.update({ where: { id }, data }),
  },
  pages: {
    signIn: "/auth/login",
    error: "/auth/error",
  },
});

export const GET = authOptions.handlers.GET;
export const POST = authOptions.handlers.POST;
```

### 2. Add auth pages

```tsx
// app/auth/login/page.tsx
import { AuthPage } from "@focura/auth-next/components";

export default function Login() {
  return <AuthPage callbackUrl="/dashboard" />;
}
```

```tsx
// app/auth/forgot-password/page.tsx
import { ForgotPasswordPage } from "@focura/auth-next/components";

export default function ForgotPassword() {
  return <ForgotPasswordPage />;
}
```

```tsx
// app/auth/reset-password/page.tsx
"use client";
import { ResetPasswordPage } from "@focura/auth-next/components";
import { useSearchParams } from "next/navigation";

export default function ResetPassword() {
  const params = useSearchParams();
  return <ResetPasswordPage token={params.get("token")} />;
}
```

### 3. Register API routes

```typescript
// app/api/auth/register/route.ts
import { handleRegister } from "@focura/auth-next/api";
import { prisma } from "@/lib/prisma";
import * as argon2 from "argon2";
import { sendVerificationEmail } from "@focura/auth-next/email";

export async function POST(req: Request) {
  return handleRegister(req, { prisma, argon2, sendVerificationEmail });
}
```

## Configuration

```typescript
interface AuthNextConfig {
  backendUrl?: string;        // Backend URL (default: env.BACKEND_URL)
  hmacSecret: string;         // Required — shared with backend
  google?: {                  // Optional — enables Google OAuth
    clientId: string;
    clientSecret: string;
  };
  pages?: {                   // Optional — custom NextAuth pages
    signIn?: string;
    error?: string;
  };
  prismaAdapter?: unknown;    // Optional — PrismaAdapter instance
  userStore: {                // Required — database queries
    findByEmail(email: string): Promise<User | null>;
    findById(id: string): Promise<User | null>;
    update?(id: string, data: Record<string, unknown>): Promise<void>;
  };
  sessionMaxAge?: number;     // Default: 7 days
  sessionUpdateAge?: number;  // Default: 24 hours
}
```

## Environment Variables

```env
NEXTAUTH_SECRET=your-shared-secret
NEXTAUTH_URL=https://your-app.com
BACKEND_URL=http://localhost:5000

# Google OAuth (optional)
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...

# Email
EMAIL_SERVER_HOST=smtp.example.com
EMAIL_SERVER_PORT=587
EMAIL_SERVER_USER=...
EMAIL_SERVER_PASSWORD=...
EMAIL_FROM=noreply@example.com
```

## License

MIT
