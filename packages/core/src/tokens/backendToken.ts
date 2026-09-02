import jwt from "jsonwebtoken";
import crypto from "crypto";
import type { TokenPair, TokenPayload, TokenConfig } from "../types.js";
import { DEFAULTS } from "../config.js";

export class TokenManager {
  private readonly privateKey: string;
  private readonly publicKey: string;
  private readonly issuer: string;
  private readonly audience: string;
  private readonly accessTokenExpiry: string;
  private readonly refreshTokenExpiry: string;
  private readonly sseTokenExpiry: string;
  private readonly currentVersion: number;

  constructor(config: TokenConfig) {
    this.privateKey = config.privateKey;
    this.publicKey = config.publicKey;
    this.issuer = config.issuer ?? DEFAULTS.issuer;
    this.audience = config.audience ?? DEFAULTS.audience;
    this.accessTokenExpiry = config.accessTokenExpiry ?? DEFAULTS.accessTokenExpiry;
    this.refreshTokenExpiry = config.refreshTokenExpiry ?? DEFAULTS.refreshTokenExpiry;
    this.sseTokenExpiry = config.sseTokenExpiry ?? DEFAULTS.sseTokenExpiry;
    this.currentVersion = config.currentVersion ?? DEFAULTS.currentVersion;
  }

  createAccessToken(p: { id: string; email: string; role: string; sessionId: string }): string {
    return jwt.sign(
      {
        sub: p.id,
        email: p.email,
        role: p.role,
        type: "access",
        version: this.currentVersion,
        jti: crypto.randomUUID(),
        sessionId: p.sessionId,
      },
      this.privateKey,
      {
        algorithm: "RS256",
        expiresIn: this.accessTokenExpiry as jwt.SignOptions["expiresIn"],
        issuer: this.issuer,
        audience: this.audience,
      },
    );
  }

  createRefreshToken(p: { id: string; email: string; role: string; sessionId: string }): string {
    return jwt.sign(
      {
        sub: p.id,
        email: p.email,
        role: p.role,
        type: "refresh",
        version: this.currentVersion,
        jti: crypto.randomUUID(),
        sessionId: p.sessionId,
      },
      this.privateKey,
      {
        algorithm: "RS256",
        expiresIn: this.refreshTokenExpiry as jwt.SignOptions["expiresIn"],
        issuer: this.issuer,
        audience: this.audience,
      },
    );
  }

  createTokenPair(p: { id: string; email: string; role: string; sessionId?: string }): TokenPair {
    const sessionId = p.sessionId || crypto.randomUUID();
    const payload = { ...p, sessionId };
    return {
      accessToken: this.createAccessToken(payload),
      refreshToken: this.createRefreshToken(payload),
      accessTokenExpiry: Date.now() + TokenManager.parseExpiry(this.accessTokenExpiry),
      refreshTokenExpiry: Date.now() + TokenManager.parseExpiry(this.refreshTokenExpiry),
    };
  }

  createSseToken(userId: string): string {
    return jwt.sign(
      {
        sub: userId,
        type: "sse",
        version: this.currentVersion,
        jti: crypto.randomUUID(),
      },
      this.privateKey,
      {
        algorithm: "RS256",
        expiresIn: this.sseTokenExpiry as jwt.SignOptions["expiresIn"],
        issuer: this.issuer,
        audience: this.audience,
      },
    );
  }

  verifyToken(token: string, expectedType?: TokenPayload["type"]): TokenPayload {
    const decoded = jwt.verify(token, this.publicKey, {
      algorithms: ["RS256"],
      issuer: this.issuer,
      audience: this.audience,
    }) as jwt.JwtPayload;

    if (decoded.version !== this.currentVersion) throw new Error("Token version mismatch");
    if (expectedType && decoded.type !== expectedType) throw new Error(`Expected '${expectedType}', got '${decoded.type}'`);

    return {
      id: decoded.sub ?? "",
      email: decoded.email,
      role: decoded.role,
      type: decoded.type,
      version: decoded.version,
      jti: decoded.jti ?? "",
      sessionId: decoded.sessionId,
    };
  }

  getPublicKey(): string {
    return this.publicKey;
  }

  getAccessTokenExpiry(): string {
    return this.accessTokenExpiry;
  }

  getRefreshTokenExpiry(): string {
    return this.refreshTokenExpiry;
  }

  getSseTokenExpiry(): string {
    return this.sseTokenExpiry;
  }

  getCurrentVersion(): number {
    return this.currentVersion;
  }

  getIssuer(): string {
    return this.issuer;
  }

  getAudience(): string {
    return this.audience;
  }

  static parseExpiry(expiry: string): number {
    const match = expiry.match(/^(\d+)([smhd])$/);
    if (!match) throw new Error(`Invalid expiry: ${expiry}`);
    const unit = match[2]!;
    const multipliers: Record<string, number> = { s: 1000, m: 60000, h: 3600000, d: 86400000 };
    return parseInt(match[1]!, 10) * multipliers[unit]!;
  }

  static extractJti(token: string): string {
    try {
      const payload = JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString("utf-8"));
      return payload.jti ?? "";
    } catch {
      return "";
    }
  }
}
