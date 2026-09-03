import type { NextAuthOptions } from "next-auth";
import type { AuthNextConfig, TokenResponse, DataStore } from "./types.js";
import { exchangeForTokens } from "./exchange.js";
import { silentRefresh } from "./refresh.js";
import { callInternal, recordLoginFailure } from "./bridge.js";
import crypto from "crypto";

const DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$ZHVtbXloYXNo";

export async function createAuthOptions(config: AuthNextConfig): Promise<NextAuthOptions> {
  const backendUrl = config.backendUrl || process.env.BACKEND_URL || "http://localhost:5000";
  const exchangeConfig = { backendUrl, hmacSecret: config.hmacSecret };
  const isProd = process.env.NODE_ENV === "production";

  const providers: NextAuthOptions["providers"] = [];

  if (config.google) {
    const mod = await import("next-auth/providers/google");
    const GoogleProvider = mod.default;
    providers.push(
      GoogleProvider({
        clientId: config.google.clientId,
        clientSecret: config.google.clientSecret,
        authorization: {
          params: { prompt: "consent", access_type: "offline", response_type: "code" },
        },
        allowDangerousEmailAccountLinking: true,
        httpOptions: { timeout: 10000 },
      }),
    );
  }

  const credMod = await import("next-auth/providers/credentials");
  const CredentialsProvider = credMod.default;
  providers.push(
    CredentialsProvider({
      id: "credentials",
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
        totpCode: { label: "TOTP Code", type: "text" },
      },
      async authorize(credentials: Record<string, string> | undefined) {
        if (!credentials?.email || !credentials?.password) {
          throw new Error("Invalid login attempt.");
        }
        const email = credentials.email.toLowerCase().trim();
        const argon2 = await import("argon2");
        const { verifySync: verifyTOTP } = await import("otplib");

        const user = await config.userStore.findByEmail(email);
        if (!user || !user.password) {
          await argon2.verify(DUMMY_HASH, "invalid");
          throw new Error("Invalid credentials.");
        }
        if (!user.emailVerified) throw new Error("Please verify your email to log in.");

        const isValid = await argon2.verify(user.password, credentials.password);
        if (!isValid) {
          const lock = await recordLoginFailure(email, exchangeConfig);
          if (lock?.locked) {
            const unlocksAt = Date.parse(lock.unlocksAt ?? "") || Date.now();
            const minutes = Math.max(1, Math.ceil((unlocksAt - Date.now()) / 60_000));
            void callInternal("/audit", { event: "LOGIN_BLOCKED", email, reason: "Account locked", meta: { unlocksAt: lock.unlocksAt ?? null } }, exchangeConfig);
            throw new Error(`Account temporarily locked. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`);
          }
          throw new Error("Invalid credentials.");
        }

        if (user.twoFactorEnabled) {
          if (!credentials.totpCode) throw new Error("2FA_REQUIRED");
          if (!user.twoFactorSecret) throw new Error("2FA not configured.");
          try {
            const result = verifyTOTP({ token: credentials.totpCode, secret: user.twoFactorSecret });
            if (!result.valid) throw new Error("Invalid verification code.");
          } catch {
            throw new Error("Invalid verification code.");
          }
        }

        if (config.userStore.update) {
          await config.userStore.update(user.id, { lastLoginAt: new Date() });
        }

        void callInternal("/clear-attempts", { email }, exchangeConfig);
        void callInternal("/audit", { event: "LOGIN_SUCCESS", email, userId: user.id, reason: "credentials" }, exchangeConfig);

        const {
          password: _pw,
          twoFactorSecret: _secret,
          twoFactorEnabled: _2fa,
          emailVerified: _ev,
          lastLoginAt: _ll,
          bannedAt: _ban,
          banReason: _br,
          ...safeUser
        } = user;
        return { ...safeUser, role: safeUser.role ?? "USER" };
      },
    }),
  );

  // Store resolved routes for hooks
  resolveRoutes(config.callbackRoutes);

  return {
    ...(config.adapter ? { adapter: config.adapter as NextAuthOptions["adapter"] } : {}),
    providers,
    events: {
      async linkAccount({ user, account }) {
        if (account?.provider === "google" && config.userStore.update) {
          await config.userStore.update(user.id!, { emailVerified: new Date() });
        }
      },
    },
    session: {
      strategy: "jwt",
      maxAge: config.sessionMaxAge ?? 7 * 24 * 60 * 60,
      updateAge: config.sessionUpdateAge ?? 24 * 60 * 60,
    },
    secret: config.nextAuthSecret || config.hmacSecret,
    callbacks: {
      async jwt({ token, user, account, trigger }) {
        if (token.twoFactorPending) {
          if (trigger === "update") {
            const check = await callInternal<{ verified?: boolean }>("/2fa-check", { userId: token.id }, exchangeConfig);
            if (check?.verified) {
              const tokens = await exchangeForTokens(
                { id: token.id as string, email: (token.email as string) ?? "", role: (token.role as string) ?? "USER" },
                token.sessionId as string,
                exchangeConfig,
              );
              if (tokens) {
                token.twoFactorPending = false;
                token.backendToken = tokens.accessToken;
                token.backendTokenExpiry = tokens.accessTokenExpiry;
                token.refreshToken = tokens.refreshToken;
                token.refreshTokenExpiry = tokens.refreshTokenExpiry;
                token.sseToken = tokens.sseToken;
              }
            }
          }
          return token;
        }

        if (user && !token.backendToken) {
          const sessionId = crypto.randomUUID();
          token.id = user.id;
          token.role = (user as { role?: string }).role ?? "USER";
          token.sessionId = sessionId;

          if (account?.provider === "google") {
            const dbUser = await config.userStore.findById(user.id!);
            if (dbUser?.twoFactorEnabled) {
              token.twoFactorPending = true;
              token.email = user.email ?? "";
              return token;
            }
          }

          const tokens = await exchangeForTokens(
            { id: user.id!, email: user.email!, role: (user as { role?: string }).role ?? "USER" },
            sessionId,
            exchangeConfig,
          );
          if (tokens) {
            token.backendToken = tokens.accessToken;
            token.backendTokenExpiry = tokens.accessTokenExpiry;
            token.refreshToken = tokens.refreshToken;
            token.refreshTokenExpiry = tokens.refreshTokenExpiry;
            token.sseToken = tokens.sseToken;
          }
          return token;
        }

        const now = Date.now();
        const nearExpiry = !token.backendTokenExpiry || now > (token.backendTokenExpiry as number) - 60_000;
        if (nearExpiry && token.refreshToken) {
          const tokenStillValid = !!token.backendTokenExpiry && now < (token.backendTokenExpiry as number);
          const lastAttempt = (token.lastRefreshAttempt as number) ?? 0;
          if (tokenStillValid && now - lastAttempt < 30_000) return token;
          token.lastRefreshAttempt = now;

          const refresh = await silentRefresh(token.sessionId as string, token.refreshToken as string, backendUrl);
          if (refresh.ok) {
            token.backendToken = refresh.tokens.accessToken;
            token.backendTokenExpiry = refresh.tokens.accessTokenExpiry;
            token.refreshToken = refresh.tokens.refreshToken;
            token.refreshTokenExpiry = refresh.tokens.refreshTokenExpiry;
            token.sseToken = refresh.tokens.sseToken;
          } else {
            const refreshExpired = !token.refreshTokenExpiry || Date.now() > (token.refreshTokenExpiry as number);
            const serverRejected = !!refresh.code && ["TOKEN_REVOKED", "SESSION_TIMEOUT", "TOKEN_REPLAY_DETECTED", "INVALID_TOKEN", "TOKEN_EXPIRED"].includes(refresh.code);
            if (refreshExpired || serverRejected) {
              token.error = "SESSION_EXPIRED";
              token.backendToken = "";
              token.backendTokenExpiry = 0;
              token.refreshToken = "";
              token.refreshTokenExpiry = 0;
              token.sseToken = "";
            }
          }
        }
        return token;
      },
      async session({ session, token }) {
        session.user.id = token.id as string;
        session.user.role = token.role as string;
        session.backendToken = token.twoFactorPending ? "" : (token.backendToken as string);
        session.sseToken = token.sseToken as string;
        session.sessionId = token.sessionId as string;
        session.error = token.error as string | undefined;
        session.twoFactorPending = token.twoFactorPending === true;
        return session;
      },
      async signIn({ user, account, profile }) {
        if (account?.provider === "google") {
          try {
            const gp = profile as { email_verified?: boolean; verified_email?: boolean };
            const isVerified = gp?.email_verified === true || gp?.verified_email === true;
            const existing = await config.userStore.findByEmail(user.email!);
            if (existing) {
              if (!isVerified && existing.password) return false;
              if (config.userStore.update) {
                await config.userStore.update(existing.id, {
                  lastLoginAt: new Date(),
                  emailVerified: isVerified ? (existing.emailVerified ?? new Date()) : existing.emailVerified,
                  name: existing.name || user.name,
                  image: existing.image || user.image,
                });
              }
            }
            void callInternal("/clear-attempts", { email: user.email! }, exchangeConfig);
            void callInternal("/audit", { event: "LOGIN_SUCCESS", email: user.email!, userId: user.id, reason: "google_oauth" }, exchangeConfig);
            return true;
          } catch {
            return true;
          }
        }
        return true;
      },
    },
    pages: {
      signIn: config.pages?.signIn ?? config.callbackRoutes?.login ?? "/authentication/login",
      error: config.pages?.error ?? config.callbackRoutes?.error ?? "/authentication/error",
    },
    debug: !isProd && process.env.NEXTAUTH_DEBUG === "true",
  };
}

// --- Route Store ---
// Allows hooks to read configured routes without prop drilling.

export type ResolvedRoutes = {
  success: string;
  login: string;
  register: string;
  twoFactor: string;
  verifyEmail: string;
  forgotPassword: string;
  resetPassword: string;
  error: string;
};

const DEFAULT_ROUTES: ResolvedRoutes = {
  success: "/authentication/success",
  login: "/authentication/login",
  register: "/authentication/login",
  twoFactor: "/authentication/2fa",
  verifyEmail: "/authentication/login",
  forgotPassword: "/authentication/forgot-password",
  resetPassword: "/authentication/reset-password",
  error: "/authentication/error",
};

let _routes: ResolvedRoutes = { ...DEFAULT_ROUTES };

export function resolveRoutes(callbackRoutes?: AuthNextConfig["callbackRoutes"]): ResolvedRoutes {
  _routes = { ...DEFAULT_ROUTES, ...callbackRoutes };
  return _routes;
}

export function getRoutes(): ResolvedRoutes {
  return _routes;
}
