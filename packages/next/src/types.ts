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

export interface AuthNextConfig {
  backendUrl?: string;
  hmacSecret: string;
  google?: {
    clientId: string;
    clientSecret: string;
  };
  pages?: {
    signIn?: string;
    error?: string;
  };
  prismaAdapter?: unknown;
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
    } | null>;
    findById(id: string): Promise<{
      id: string;
      email: string;
      name?: string | null;
      role?: string | null;
      twoFactorEnabled?: boolean;
      emailVerified?: Date | null;
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
  };
}
