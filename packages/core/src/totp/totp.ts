import { generateSecret, generateURI, verify } from "otplib";

export class TotpManager {
  private readonly issuer: string;

  constructor(issuer = "Auth") {
    this.issuer = issuer;
  }

  generateSecret(): string {
    return generateSecret();
  }

  createUri(secret: string, email: string): string {
    return generateURI({ issuer: this.issuer, label: email, secret });
  }

  async verify(token: string, secret: string): Promise<boolean> {
    try {
      // otplib v13 `verify` is async; awaiting also ensures rejections are caught here
      const result = await verify({ token, secret });
      const normalized = result as unknown as boolean | { valid: boolean };
      if (typeof normalized === "boolean") return normalized;
      return normalized.valid === true;
    } catch {
      return false;
    }
  }
}
