import type { DataStore } from "../types.js";

export async function handleResetPassword(req: Request, deps: {
  dataStore: DataStore;
  argon2: { hash: (pwd: string) => Promise<string> };
}) {
  try {
    const { token, password } = await req.json();
    if (!token || !password) return Response.json({ error: "Token and password required" }, { status: 400 });
    if (password.length < 8) return Response.json({ error: "Password must be at least 8 characters" }, { status: 400 });

    const resetToken = await deps.dataStore.findPasswordResetToken(token);
    if (!resetToken) return Response.json({ error: "Invalid or expired token" }, { status: 400 });

    const hashedPassword = await deps.argon2.hash(password);
    await deps.dataStore.updateUserByEmail(resetToken.email, { password: hashedPassword, lastPasswordChange: new Date() });
    await deps.dataStore.deletePasswordResetToken(resetToken.email);

    return Response.json({ message: "Password reset successfully" });
  } catch (error) {
    console.error("Reset password error:", error);
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}
