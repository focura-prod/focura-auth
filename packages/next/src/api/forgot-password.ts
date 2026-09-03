import crypto from "crypto";
import type { DataStore } from "../types.js";

export async function handleForgotPassword(req: Request, deps: {
  dataStore: DataStore;
  sendPasswordResetEmail: (email: string, token: string) => Promise<void>;
}) {
  try {
    const { email } = await req.json();
    if (!email) return Response.json({ message: "If an account exists, a reset link was sent" });

    const normalizedEmail = email.toLowerCase().trim();
    const user = await deps.dataStore.findUserByEmail(normalizedEmail);

    if (user) {
      const resetToken = crypto.randomUUID();
      const expires = new Date(Date.now() + 60 * 60 * 1000);

      await deps.dataStore.createPasswordResetToken({ email: normalizedEmail, token: resetToken, expires });

      try {
        await deps.sendPasswordResetEmail(normalizedEmail, resetToken);
      } catch {
        console.error("Failed to send reset email");
      }
    }

    return Response.json({ message: "If an account exists, a reset link was sent" });
  } catch (error) {
    console.error("Forgot password error:", error);
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}
