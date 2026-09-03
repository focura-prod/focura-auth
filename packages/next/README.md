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
- **ORM-agnostic** — Works with Prisma, Drizzle, MongoDB, or any custom backend

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

const authOptions = await createAuthOptions({
  hmacSecret: process.env.AUTH_SECRET!,
  nextAuthSecret: process.env.NEXTAUTH_SECRET,  // optional — separate JWT signing secret
  backendUrl: process.env.BACKEND_URL,
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  },
  adapter: PrismaAdapter(prisma),
  dataStore: {
    findUserByEmail: (email) => prisma.user.findUnique({ where: { email } }),
    createUser: (data) => prisma.user.create({ data }),
    updateUserByEmail: (email, data) => prisma.user.update({ where: { email }, data }),
    createVerificationToken: (data) => prisma.verificationToken.create({ data }),
    findVerificationToken: (token) => prisma.verificationToken.findUnique({ where: { token } }),
    deleteVerificationToken: (token, identifier) =>
      prisma.verificationToken.delete({ where: { token_identifier: { token, identifier } } }),
    createPasswordResetToken: (data) => prisma.passwordResetToken.create({ data }),
    findPasswordResetToken: (token) => prisma.passwordResetToken.findFirst({ where: { token, expires: { gt: new Date() } } }),
    deletePasswordResetToken: (email) => prisma.passwordResetToken.delete({ where: { email } }),
  },
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

// You provide this function — send emails however you like
async function sendVerificationEmail(email: string, token: string) {
  await resend.emails.send({
    from: "noreply@yourapp.com",
    to: email,
    subject: "Verify your email",
    html: `Click <a href="https://yourapp.com/auth/verify-email?token=${token}">here</a> to verify.`,
  });
}

export async function POST(req: Request) {
  return handleRegister(req, {
    dataStore: {
      findUserByEmail: (email) => prisma.user.findUnique({ where: { email } }),
      createUser: (data) => prisma.user.create({ data }),
      updateUserByEmail: (email, data) => prisma.user.update({ where: { email }, data }),
      createVerificationToken: (data) => prisma.verificationToken.create({ data }),
      findVerificationToken: (token) => prisma.verificationToken.findUnique({ where: { token } }),
      deleteVerificationToken: (token, identifier) =>
        prisma.verificationToken.delete({ where: { token_identifier: { token, identifier } } }),
      createPasswordResetToken: (data) => prisma.passwordResetToken.create({ data }),
      findPasswordResetToken: (token) => prisma.passwordResetToken.findFirst({ where: { token, expires: { gt: new Date() } } }),
      deletePasswordResetToken: (email) => prisma.passwordResetToken.delete({ where: { email } }),
    },
    argon2,
    sendVerificationEmail,
  });
}
```

## DataStore

The `dataStore` is required and makes the package ORM-agnostic. You implement 9 methods that map to your database:

```typescript
interface DataStore {
  // User operations
  findUserByEmail(email: string): Promise<{ id: string; email: string; name?: string | null; password?: string | null; emailVerified?: Date | null } | null>;
  createUser(data: { name?: string; email: string; password?: string }): Promise<{ id: string }>;
  updateUserByEmail(email: string, data: Record<string, unknown>): Promise<void>;

  // Email verification tokens
  createVerificationToken(data: { identifier: string; token: string; expires: Date }): Promise<void>;
  findVerificationToken(token: string): Promise<{ identifier: string; expires: Date } | null>;
  deleteVerificationToken(token: string, identifier: string): Promise<void>;

  // Password reset tokens
  createPasswordResetToken(data: { email: string; token: string; expires: Date }): Promise<void>;
  findPasswordResetToken(token: string): Promise<{ email: string; token: string } | null>;
  deletePasswordResetToken(email: string): Promise<void>;
}
```

### Drizzle Example

```typescript
import { drizzle } from "drizzle-orm/postgres-js";
import { users, verificationTokens, passwordResetTokens } from "@/db/schema";
import { eq } from "drizzle-orm";

const db = drizzle(process.env.DATABASE_URL!);

const dataStore = {
  findUserByEmail: (email) => db.select().from(users).where(eq(users.email, email)).then(r => r[0] ?? null),
  createUser: async (data) => {
    const [user] = await db.insert(users).values(data).returning({ id: users.id });
    return user!;
  },
  updateUserByEmail: (email, data) => db.update(users).set(data).where(eq(users.email, email)),
  createVerificationToken: (data) => db.insert(verificationTokens).values(data),
  findVerificationToken: (token) =>
    db.select().from(verificationTokens).where(eq(verificationTokens.token, token)).then(r => r[0] ?? null),
  deleteVerificationToken: (token, identifier) =>
    db.delete(verificationTokens).where(eq(verificationTokens.token, token)),
  createPasswordResetToken: (data) => db.insert(passwordResetTokens).values(data),
  findPasswordResetToken: (token) =>
    db.select().from(passwordResetTokens).where(eq(passwordResetTokens.token, token)).then(r => r[0] ?? null),
  deletePasswordResetToken: (email) => db.delete(passwordResetTokens).where(eq(passwordResetTokens.email, email)),
};
```

### MongoDB Example

```typescript
import { MongoClient, ObjectId } from "mongodb";

const client = new MongoClient(process.env.MONGODB_URL!);
const db = client.db("myapp");

const dataStore = {
  findUserByEmail: (email) => db.collection("users").findOne({ email }),
  createUser: async (data) => {
    const result = await db.collection("users").insertOne(data);
    return { id: result.insertedId.toString() };
  },
  updateUserByEmail: (email, data) => db.collection("users").updateOne({ email }, { $set: data }),
  createVerificationToken: (data) => db.collection("verificationTokens").insertOne(data),
  findVerificationToken: (token) => db.collection("verificationTokens").findOne({ token }),
  deleteVerificationToken: (token) => db.collection("verificationTokens").deleteOne({ token }),
  createPasswordResetToken: (data) => db.collection("passwordResetTokens").insertOne(data),
  findPasswordResetToken: (token) => db.collection("passwordResetTokens").findOne({ token, expires: { $gt: new Date() } }),
  deletePasswordResetToken: (email) => db.collection("passwordResetTokens").deleteOne({ email }),
};
```

## Configuration

```typescript
interface AuthNextConfig {
  backendUrl?: string;          // Backend URL (default: env.BACKEND_URL)
  hmacSecret: string;           // Required — shared with backend for token exchange
  nextAuthSecret?: string;      // Optional — separate secret for NextAuth JWT signing (defaults to hmacSecret)
  google?: {                    // Optional — enables Google OAuth
    clientId: string;
    clientSecret: string;
  };
  pages?: {                     // Optional — custom NextAuth pages
    signIn?: string;
    error?: string;
  };
  adapter?: unknown;            // Optional — PrismaAdapter, DrizzleAdapter, MongoDBAdapter, etc.
  dataStore: DataStore;         // Required — database operations (see above)
  userStore: {                  // Required — user queries for auth
    findByEmail(email: string): Promise<User | null>;
    findById(id: string): Promise<User | null>;
    update?(id: string, data: Record<string, unknown>): Promise<void>;
  };
  sessionMaxAge?: number;       // Default: 7 days (seconds)
  sessionUpdateAge?: number;    // Default: 24 hours (seconds)
}
```

## Environment Variables

```env
AUTH_SECRET=your-shared-secret-with-backend
NEXTAUTH_SECRET=your-nextauth-jwt-secret   # optional — defaults to AUTH_SECRET
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
