export interface GoogleProfile {
  email_verified?: boolean;
  verified_email?: boolean;
}

export type TokenResponse = {
  accessToken: string;
  refreshToken: string;
  sseToken: string;
  accessTokenExpiry: number;
  refreshTokenExpiry: number;
};

export type RefreshResult =
  | { ok: true; tokens: TokenResponse }
  | { ok: false; code?: string };

export type FailedAttemptResult = {
  success?: boolean;
  locked?: boolean;
  unlocksAt?: string;
  attempts?: number;
};

export interface DataStore {
  findUserByEmail(email: string): Promise<{
    id: string;
    email: string;
    name?: string | null;
    password?: string | null;
    emailVerified?: Date | null;
  } | null>;
  createUser(data: { name?: string; email: string; password?: string }): Promise<{ id: string }>;
  updateUserByEmail(email: string, data: Record<string, unknown>): Promise<void>;
  createVerificationToken(data: { identifier: string; token: string; expires: Date }): Promise<void>;
  findVerificationToken(token: string): Promise<{ identifier: string; expires: Date } | null>;
  deleteVerificationToken(token: string, identifier: string): Promise<void>;
  createPasswordResetToken(data: { email: string; token: string; expires: Date }): Promise<void>;
  findPasswordResetToken(token: string): Promise<{ email: string; token: string } | null>;
  deletePasswordResetToken(email: string): Promise<void>;
}

export interface AuthNextConfig {
  backendUrl?: string;
  hmacSecret: string;
  nextAuthSecret?: string;
  google?: {
    clientId: string;
    clientSecret: string;
  };
  pages?: {
    signIn?: string;
    error?: string;
  };
  adapter?: unknown;
  dataStore: DataStore;
  userStore: {
    findByEmail(email: string): Promise<{
      id: string;
      email: string;
      name?: string | null;
      role?: string | null;
      password?: string | null;
      emailVerified?: Date | null;
      twoFactorEnabled?: boolean;
      twoFactorSecret?: string | null;
      image?: string | null;
      lastLoginAt?: Date | null;
      bannedAt?: Date | null;
      banReason?: string | null;
    } | null>;
    findById(id: string): Promise<{
      id: string;
      email: string;
      name?: string | null;
      role?: string | null;
      twoFactorEnabled?: boolean;
      emailVerified?: Date | null;
      bannedAt?: Date | null;
      banReason?: string | null;
    } | null>;
    update?(id: string, data: Record<string, unknown>): Promise<void>;
  };
  sessionMaxAge?: number;
  sessionUpdateAge?: number;
  issuer?: string;
  audience?: string;
  callbackRoutes?: {
    success?: string;
    login?: string;
    register?: string;
    twoFactor?: string;
    verifyEmail?: string;
    forgotPassword?: string;
    resetPassword?: string;
    error?: string;
  };
}

declare module "next-auth" {
  interface Session {
    backendToken?: string;
    sseToken?: string;
    sessionId?: string;
    error?: string;
    twoFactorPending?: boolean;
    user: {
      id: string;
      role: string;
      name?: string | null;
      email?: string | null;
      image?: string | null;
    };
  }

  interface User {
    role?: string;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    id?: string;
    role?: string;
    backendToken?: string;
    backendTokenExpiry?: number;
    refreshToken?: string;
    refreshTokenExpiry?: number;
    sseToken?: string;
    sessionId?: string;
    twoFactorPending?: boolean;
    error?: string;
    lastRefreshAttempt?: number;
  }
}
