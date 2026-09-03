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
- **React hooks** — Build your own custom UI with form logic
- **API route handlers** — Ready-to-use Next.js route handlers
- **ORM-agnostic** — Works with Prisma, Drizzle, MongoDB, or any custom backend

## NextAuth.js Compatibility

This package is built for **NextAuth.js v4** (`next-auth@^4.0.0`).

| NextAuth Version | Status |
|------------------|--------|
| v4.x (stable) | ✅ Fully supported |
| v5.x (Auth.js beta) | ❌ Not compatible — different API |

We use NextAuth v4 because it is the latest stable release with production-ready
JWT strategy, credentials provider, and callback system. v5 (Auth.js) is a
complete rewrite with a different architecture and is still in beta.

## Why Not Just Use NextAuth Directly?

NextAuth handles session management and OAuth. This package adds what NextAuth
does not provide out of the box:

| Feature | NextAuth alone | With @focura/auth-next |
|---------|---------------|----------------------|
| HMAC token exchange to backend | ❌ Manual | ✅ Built-in |
| Silent token refresh with dedup | ❌ Manual | ✅ Built-in |
| 2FA (TOTP) | ❌ Requires third-party adapter | ✅ Built-in |
| Email verification | ❌ Manual | ✅ API handler + UI |
| Password reset | ❌ Manual | ✅ API handler + UI |
| Rate limiting on auth routes | ❌ Manual | ✅ Built-in |
| Pre-built login/register UI | ❌ Build yourself | ✅ Drop-in components |
| Custom UI hooks | ❌ N/A | ✅ useAuthForm, etc. |
| Account lockout | ❌ Manual | ✅ Via backend |
| Session binding (fingerprint) | ❌ Manual | ✅ Via backend |

**In short:** NextAuth gives you sessions + OAuth. We give you the rest —
token exchange, 2FA, email flows, UI, and security hardening — all wired
together so you do not have to build it yourself.

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
  nextAuthSecret: process.env.NEXTAUTH_SECRET,
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
import { sendVerificationEmail } from "@focura/auth-next/email";

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

---

## Two Ways to Use

The package gives you **two paths** — pick what fits your project:

### Option A: Pre-built Components (Drop-in)

Use the ready-made pages. They handle all logic, styling, and state internally.

```tsx
import { AuthPage, ForgotPasswordPage, ResetPasswordPage, VerifyEmailPage } from "@focura/auth-next/components";

// That's it — full auth UI with zero custom code
```

### Option B: Custom UI (Hooks Only)

Build your own components while the package handles form logic, validation, API calls, and routing.

```tsx
"use client";
import { useAuthForm } from "@focura/auth-next/hooks";

export default function MyCustomLogin() {
  const { register, handleSubmit, errors, isSubmitting, onSubmit, handleGoogle } = useAuthForm({
    mode: "login",
    callbackUrl: "/dashboard",
  });

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <input {...register("email")} placeholder="Email" />
      {errors.email && <span>{errors.email.message}</span>}

      <input {...register("password")} type="password" placeholder="Password" />
      {errors.password && <span>{errors.password.message}</span>}

      <button type="submit" disabled={isSubmitting}>
        {isSubmitting ? "Signing in..." : "Sign in"}
      </button>

      <button type="button" onClick={handleGoogle}>
        Continue with Google
      </button>
    </form>
  );
}
```

---

## Pre-built Components

All components are imported from `@focura/auth-next/components`.

### AuthPage

Full-screen login/register page with toggle.

```tsx
import { AuthPage } from "@focura/auth-next/components";

<AuthPage callbackUrl="/dashboard" />
```

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `callbackUrl` | `string` | `"/dashboard"` | URL to redirect after successful login |

### AuthForm

The form itself (without the full-screen wrapper). Use when you want to embed the form in your own layout.

```tsx
import { AuthForm } from "@focura/auth-next/components";

<AuthForm mode="login" onModeChange={setMode} callbackUrl="/dashboard" />
```

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `mode` | `"login" \| "register"` | required | Current form mode |
| `onModeChange` | `(mode: "login" \| "register") => void` | `undefined` | Called when user toggles login/register |
| `callbackUrl` | `string` | `"/dashboard"` | URL to redirect after login |

### AuthFormSkeleton

Loading placeholder that matches the form layout.

```tsx
import { AuthFormSkeleton } from "@focura/auth-next/components";

<AuthFormSkeleton />
```

No props. Pure presentational.

### AuthFormHeader

Title and subtitle. Changes text based on mode.

```tsx
import { AuthFormHeader } from "@focura/auth-next/components";

<AuthFormHeader mode="login" />
```

| Prop | Type | Description |
|------|------|-------------|
| `mode` | `"login" \| "register"` | Shows "Welcome back" for login, "Create account" for register |

### AuthFormFields

Email, password, and optional name fields with validation errors.

```tsx
import { AuthFormFields } from "@focura/auth-next/components";

<AuthFormFields register={register} errors={errors} mode="login" />
```

| Prop | Type | Description |
|------|------|-------------|
| `register` | `UseFormRegister<T>` | From `react-hook-form` |
| `errors` | `FieldErrors<T>` | From `react-hook-form` |
| `mode` | `"login" \| "register"` | Shows name field only in register mode |

### AuthFormButtons

Submit button and Google OAuth button.

```tsx
import { AuthFormButtons } from "@focura/auth-next/components";

<AuthFormButtons
  isSubmitting={isSubmitting}
  isGoogleLoading={isGoogleLoading}
  isLoading={isLoading}
  mode="login"
  onGoogle={handleGoogle}
/>
```

| Prop | Type | Description |
|------|------|-------------|
| `isSubmitting` | `boolean` | Disables buttons during submission |
| `isGoogleLoading` | `boolean` | Shows loading state on Google button |
| `isLoading` | `boolean` | General loading state |
| `mode` | `"login" \| "register"` | Button text changes per mode |
| `onGoogle` | `() => void` | Google sign-in handler |

### AuthFormFooter

Toggle link between login and register.

```tsx
import { AuthFormFooter } from "@focura/auth-next/components";

<AuthFormFooter mode="login" onModeChange={setMode} />
```

| Prop | Type | Description |
|------|------|-------------|
| `mode` | `"login" \| "register"` | Shows "Don't have an account?" or "Already have an account?" |
| `onModeChange` | `(mode: "login" \| "register") => void` | Called when toggle is clicked |

### ForgotPasswordPage

Full-page forgot password form.

```tsx
import { ForgotPasswordPage } from "@focura/auth-next/components";

<ForgotPasswordPage />
```

No props. Shows email input, sends reset link, shows success message.

### ResetPasswordPage

Full-page password reset form.

```tsx
import { ResetPasswordPage } from "@focura/auth-next/components";

<ResetPasswordPage token={searchParams.get("token")} />
```

| Prop | Type | Description |
|------|------|-------------|
| `token` | `string \| null` | Reset token from URL query params |

### VerifyEmailPage

Full-page email verification. Auto-verifies on mount.

```tsx
import { VerifyEmailPage } from "@focura/auth-next/components";

<VerifyEmailPage token={searchParams.get("token")} />
```

| Prop | Type | Description |
|------|------|-------------|
| `token` | `string \| null` | Verification token from URL query params |

---

## Hooks

All hooks are imported from `@focura/auth-next/hooks`. Use these to build custom UI.

### useAuthForm

Handles login and register form logic.

```tsx
"use client";
import { useAuthForm } from "@focura/auth-next/hooks";

function MyForm() {
  const {
    register,          // UseFormRegister — spread onto inputs
    handleSubmit,      // UseFormSubmitHandler — wrap your form's onSubmit
    errors,            // FieldErrors — display validation errors
    isSubmitting,      // boolean — true during API call
    isGoogleLoading,   // boolean — true during Google OAuth
    isLoading,         // boolean — isSubmitting || isGoogleLoading
    onSubmit,          // (values) => Promise<void> — form submit handler
    handleGoogle,      // () => Promise<void> — Google sign-in handler
    formError,         // string | null — server/API error message
    clearFormError,    // () => void — dismiss the error
  } = useAuthForm({
    mode: "login",     // "login" | "register"
    callbackUrl: "/dashboard",
  });

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <input {...register("email")} />
      {errors.email && <span>{errors.email.message}</span>}

      <input {...register("password")} type="password" />
      {errors.password && <span>{errors.password.message}</span>}

      {mode === "register" && (
        <>
          <input {...register("name")} />
          {errors.name && <span>{errors.name.message}</span>}
        </>
      )}

      {formError && <div>{formError} <button onClick={clearFormError}>dismiss</button></div>}

      <button type="submit" disabled={isLoading}>
        {isSubmitting ? "Loading..." : mode === "login" ? "Sign in" : "Create account"}
      </button>

      <button type="button" onClick={handleGoogle} disabled={isGoogleLoading}>
        {isGoogleLoading ? "Loading..." : "Google"}
      </button>
    </form>
  );
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `mode` | `"login" \| "register"` | Yes | Form mode |
| `callbackUrl` | `string` | No | Redirect URL after login (default: `"/dashboard"`) |

| Return | Type | Description |
|--------|------|-------------|
| `register` | `UseFormRegister` | Spread onto `<input>` elements |
| `handleSubmit` | `UseFormSubmitHandler` | Wrap your `<form onSubmit>` |
| `errors` | `FieldErrors` | Validation error messages |
| `isSubmitting` | `boolean` | True during form submission |
| `isGoogleLoading` | `boolean` | True during Google OAuth |
| `isLoading` | `boolean` | Combined loading state |
| `onSubmit` | `(values) => Promise<void>` | Pass to `handleSubmit` |
| `handleGoogle` | `() => Promise<void>` | Call on Google button click |
| `formError` | `string \| null` | Server error message |
| `clearFormError` | `() => void` | Dismiss error |

**Validation schemas:**

- Login: `email` (valid email), `password` (min 6 chars)
- Register: `email` (valid email), `password` (min 8 chars), `name` (min 4 chars)

### useForgetPasswordPage

Handles forgot password form logic.

```tsx
"use client";
import { useForgetPasswordPage } from "@focura/auth-next/hooks";

function MyForgotPassword() {
  const { error, success, register, handleSubmit, errors, isSubmitting, onSubmit } = useForgetPasswordPage();

  if (success) return <div>Reset link sent! Check your email.</div>;

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      {error && <div>{error}</div>}
      <input {...register("email")} type="email" placeholder="you@example.com" />
      {errors.email && <span>{errors.email.message}</span>}
      <button type="submit" disabled={isSubmitting}>
        {isSubmitting ? "Sending..." : "Send Reset Link"}
      </button>
    </form>
  );
}
```

| Return | Type | Description |
|--------|------|-------------|
| `error` | `string` | Error message (empty string if none) |
| `success` | `boolean` | True after email sent successfully |
| `register` | `UseFormRegister` | Spread onto email input |
| `handleSubmit` | `UseFormSubmitHandler` | Wrap form onSubmit |
| `errors` | `FieldErrors` | Validation errors |
| `isSubmitting` | `boolean` | True during API call |
| `onSubmit` | `(values) => Promise<void>` | Pass to `handleSubmit` |

### useResetPasswordPage

Handles password reset form logic.

```tsx
"use client";
import { useResetPasswordPage } from "@focura/auth-next/hooks";

function MyResetPassword({ token }: { token: string | null }) {
  const { error, success, register, handleSubmit, errors, isSubmitting, onSubmit } = useResetPasswordPage({ token });

  if (success) return <div>Password reset! Redirecting to login...</div>;

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      {error && <div>{error}</div>}
      <input {...register("password")} type="password" placeholder="New password" />
      {errors.password && <span>{errors.password.message}</span>}
      <input {...register("confirmPassword")} type="password" placeholder="Confirm password" />
      {errors.confirmPassword && <span>{errors.confirmPassword.message}</span>}
      <button type="submit" disabled={isSubmitting}>
        {isSubmitting ? "Resetting..." : "Reset Password"}
      </button>
    </form>
  );
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | `string \| null` | Yes | Reset token from URL |

| Return | Type | Description |
|--------|------|-------------|
| `error` | `string` | Error message |
| `success` | `boolean` | True after password reset |
| `register` | `UseFormRegister` | Spread onto inputs |
| `handleSubmit` | `UseFormSubmitHandler` | Wrap form onSubmit |
| `errors` | `FieldErrors` | Validation errors |
| `isSubmitting` | `boolean` | True during API call |
| `onSubmit` | `(values) => Promise<void>` | Pass to `handleSubmit` |

**Validation:** `password` (min 8 chars), `confirmPassword` (must match password)

### useVerifyEmail

Auto-verifies email on mount.

```tsx
"use client";
import { useVerifyEmail } from "@focura/auth-next/hooks";

function MyVerifyEmail({ token }: { token: string | null }) {
  const { status, message } = useVerifyEmail({ token });

  if (status === "loading") return <div>Verifying...</div>;
  if (status === "error") return <div>{message}</div>;
  return <div>{message}</div>;
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | `string \| null` | Yes | Verification token from URL |

| Return | Type | Description |
|--------|------|-------------|
| `status` | `"loading" \| "success" \| "error"` | Current verification state |
| `message` | `string` | Status message |

---

## API Route Handlers

All handlers are imported from `@focura/auth-next/api`.

### handleRegister

```typescript
import { handleRegister } from "@focura/auth-next/api";

export async function POST(req: Request) {
  return handleRegister(req, {
    dataStore,
    argon2,
    sendVerificationEmail,
    limiter,         // optional — rate limiter
    rateLimitKey,    // optional — rate limit key
  });
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `req` | `Request` | Yes | Next.js request object |
| `deps.dataStore` | `DataStore` | Yes | Database operations |
| `deps.argon2` | `{ hash: (pwd: string) => Promise<string> }` | Yes | Password hasher |
| `deps.sendVerificationEmail` | `(email: string, token: string) => Promise<void>` | Yes | Email sender |
| `deps.limiter` | `{ check: (key: string) => Promise<boolean> }` | No | Rate limiter |
| `deps.rateLimitKey` | `string` | No | Rate limit key |

**Request body:** `{ name: string, email: string, password: string }`
**Response:** `201 { message: "Registration successful" }` | `400` | `409` | `429` | `500`

### handleForgotPassword

```typescript
import { handleForgotPassword } from "@focura/auth-next/api";

export async function POST(req: Request) {
  return handleForgotPassword(req, { dataStore, sendPasswordResetEmail });
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `req` | `Request` | Yes | Next.js request object |
| `deps.dataStore` | `DataStore` | Yes | Database operations |
| `deps.sendPasswordResetEmail` | `(email: string, token: string) => Promise<void>` | Yes | Email sender |

**Request body:** `{ email: string }`
**Response:** `{ message: "If an account exists, a reset link was sent" }` (always — prevents email enumeration)

### handleResetPassword

```typescript
import { handleResetPassword } from "@focura/auth-next/api";

export async function POST(req: Request) {
  return handleResetPassword(req, { dataStore, argon2 });
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `req` | `Request` | Yes | Next.js request object |
| `deps.dataStore` | `DataStore` | Yes | Database operations |
| `deps.argon2` | `{ hash: (pwd: string) => Promise<string> }` | Yes | Password hasher |

**Request body:** `{ token: string, password: string }`
**Response:** `200 { message: "Password reset successfully" }` | `400` | `500`

### handleVerifyEmail

```typescript
import { handleVerifyEmail } from "@focura/auth-next/api";

export async function POST(req: Request) {
  return handleVerifyEmail(req, { dataStore });
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `req` | `Request` | Yes | Next.js request object |
| `deps.dataStore` | `DataStore` | Yes | Database operations |

**Request body:** `{ token: string }`
**Response:** `200 { message: "Email verified successfully" }` | `400` | `500`

---

## Email Functions

Imported from `@focura/auth-next/email`. Uses nodemailer with environment variable config.

```typescript
import { sendVerificationEmail, sendPasswordResetEmail } from "@focura/auth-next/email";

// Use as dependency in API handlers or call directly
await sendVerificationEmail("user@example.com", "verification-token");
await sendPasswordResetEmail("user@example.com", "reset-token");
```

| Function | Signature | Description |
|----------|-----------|-------------|
| `sendVerificationEmail` | `(email: string, token: string) => Promise<void>` | Sends verification email with link |
| `sendPasswordResetEmail` | `(email: string, token: string) => Promise<void>` | Sends reset email with link (1hr expiry) |

**Requires environment variables:**
- `EMAIL_SERVER_HOST` — SMTP host
- `EMAIL_SERVER_PORT` — SMTP port
- `EMAIL_SERVER_USER` — SMTP username
- `EMAIL_SERVER_PASSWORD` — SMTP password
- `EMAIL_FROM` — Sender email address
- `NEXTAUTH_URL` — Your app URL (for email links)

---

## DataStore

The `dataStore` is required and makes the package ORM-agnostic. You implement 9 methods:

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

### Prisma Example

```typescript
const dataStore = {
  findUserByEmail: (email) => prisma.user.findUnique({ where: { email } }),
  createUser: (data) => prisma.user.create({ data }),
  updateUserByEmail: (email, data) => prisma.user.update({ where: { email }, data }),
  createVerificationToken: (data) => prisma.verificationToken.create({ data }),
  findVerificationToken: (token) => prisma.verificationToken.findUnique({ where: { token } }),
  deleteVerificationToken: (token, identifier) =>
    prisma.verificationToken.delete({ where: { token_identifier: { token, identifier } } }),
  createPasswordResetToken: (data) => prisma.passwordResetToken.create({ data }),
  findPasswordResetToken: (token) =>
    prisma.passwordResetToken.findFirst({ where: { token, expires: { gt: new Date() } } }),
  deletePasswordResetToken: (email) => prisma.passwordResetToken.delete({ where: { email } }),
};
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
  deleteVerificationToken: (token) => db.delete(verificationTokens).where(eq(verificationTokens.token, token)),
  createPasswordResetToken: (data) => db.insert(passwordResetTokens).values(data),
  findPasswordResetToken: (token) =>
    db.select().from(passwordResetTokens).where(eq(passwordResetTokens.token, token)).then(r => r[0] ?? null),
  deletePasswordResetToken: (email) => db.delete(passwordResetTokens).where(eq(passwordResetTokens.email, email)),
};
```

### MongoDB Example

```typescript
import { MongoClient } from "mongodb";

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
  findPasswordResetToken: (token) =>
    db.collection("passwordResetTokens").findOne({ token, expires: { $gt: new Date() } }),
  deletePasswordResetToken: (email) => db.collection("passwordResetTokens").deleteOne({ email }),
};
```

---

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
  callbackRoutes?: {            // Optional — customize redirect routes
    success?: string;           // After login (default: "/authentication/success")
    login?: string;             // Sign-in page (default: "/authentication/login")
    register?: string;          // Register page (default: "/authentication/login")
    twoFactor?: string;         // 2FA page (default: "/authentication/2fa")
    verifyEmail?: string;       // After email verified (default: "/authentication/login")
    forgotPassword?: string;    // Forgot password (default: "/authentication/forgot-password")
    resetPassword?: string;     // Reset password (default: "/authentication/reset-password")
    error?: string;             // Error page (default: "/authentication/error")
  };
  sessionMaxAge?: number;       // Default: 7 days (seconds)
  sessionUpdateAge?: number;    // Default: 24 hours (seconds)
}
```

## Redirect Routes

After login, the package redirects users to a success page. After password reset, it redirects to the login page. These routes are **configurable** so you do not need to create pages at fixed paths.

### Default Routes

| Event | Default Route | Configurable Via |
|-------|---------------|------------------|
| Login success | `/authentication/success` | `callbackRoutes.success` |
| 2FA required | `/authentication/2fa` | `callbackRoutes.twoFactor` |
| Registration success | `/authentication/login` | `callbackRoutes.login` |
| Email verified | `/authentication/login` | `callbackRoutes.verifyEmail` |
| Password reset | `/authentication/login` | `callbackRoutes.login` |

### Custom Routes Example

```typescript
const authOptions = await createAuthOptions({
  // ...existing config
  callbackRoutes: {
    success: "/dashboard",           // redirect here after login
    login: "/auth/signin",           // custom sign-in page
    twoFactor: "/auth/2fa",          // custom 2FA page
    verifyEmail: "/auth/verify",     // custom verify page
    forgotPassword: "/auth/forgot",  // custom forgot password
    resetPassword: "/auth/reset",    // custom reset password
    error: "/auth/error",            // custom error page
  },
});
```

If you do not set `callbackRoutes`, the package uses the defaults above. You only need to configure this if your auth pages are not at `/authentication/*`.

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

## Token Exchange & Refresh Utilities

Imported from `@focura/auth-next`. Used internally by `createAuthOptions` but available for advanced use cases.

### createExchangeProof

Creates an HMAC-SHA256 signed proof for backend token exchange.

```typescript
import { createExchangeProof } from "@focura/auth-next";

const { timestamp, signature } = createExchangeProof(
  userId,
  email,
  role,
  sessionId,
  hmacSecret,
);
```

### exchangeForTokens

Exchanges an HMAC proof for JWT tokens from your backend.

```typescript
import { exchangeForTokens } from "@focura/auth-next";

const tokens = await exchangeForTokens(
  { id: user.id, email: user.email, role: user.role },
  sessionId,
  { backendUrl: process.env.BACKEND_URL!, hmacSecret: process.env.AUTH_SECRET! },
);

// tokens.accessToken, tokens.refreshToken, tokens.sseToken
```

### silentRefresh

Refreshes tokens with built-in deduplication (prevents concurrent refresh races).

```typescript
import { silentRefresh } from "@focura/auth-next";

const result = await silentRefresh(sessionId, refreshToken, backendUrl);

if (result.ok) {
  // result.tokens.accessToken, result.tokens.refreshToken
} else {
  // result.code — error code from backend
}
```

### logout

Calls the backend logout endpoint (best-effort, no error thrown).

```typescript
import { logout } from "@focura/auth-next";

await logout(backendUrl, backendToken, false);  // single session
await logout(backendUrl, backendToken, true);   // all sessions
```

### recordLoginFailure

Records a failed login attempt via the backend internal API.

```typescript
import { recordLoginFailure } from "@focura/auth-next";

const result = await recordLoginFailure(email, { backendUrl, hmacSecret });

if (result?.locked) {
  console.log(`Account locked until ${result.unlocksAt}`);
}
```

---

## Import Paths

| What | Import |
|------|--------|
| Main config | `import { createAuthOptions } from "@focura/auth-next"` |
| Route config | `import { getRoutes, type ResolvedRoutes } from "@focura/auth-next"` |
| Token utilities | `import { createExchangeProof, exchangeForTokens, silentRefresh, logout, recordLoginFailure } from "@focura/auth-next"` |
| Components | `import { AuthPage } from "@focura/auth-next/components"` |
| Hooks | `import { useAuthForm } from "@focura/auth-next/hooks"` |
| API handlers | `import { handleRegister } from "@focura/auth-next/api"` |
| Email functions | `import { sendVerificationEmail } from "@focura/auth-next/email"` |

## License

MIT
