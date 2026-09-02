import crypto from "crypto";

export async function handleForgotPassword(req: Request, deps: {
  prisma: {
    user: { findUnique: (args: { where: { email: string } }) => Promise<{ email: string } | null> };
    passwordResetToken: {
      create: (args: { data: { email: string; token: string; expires: Date; createdAt: Date } }) => Promise<unknown>;
    };
  };
  sendPasswordResetEmail: (email: string, token: string) => Promise<void>;
}) {
  try {
    const { email } = await req.json();
    if (!email) return Response.json({ message: "If an account exists, a reset link was sent" });

    const normalizedEmail = email.toLowerCase().trim();
    const user = await deps.prisma.user.findUnique({ where: { email: normalizedEmail } });

    if (user) {
      const resetToken = crypto.randomUUID();
      const expires = new Date(Date.now() + 60 * 60 * 1000);

      await deps.prisma.passwordResetToken.create({
        data: { email: normalizedEmail, token: resetToken, expires, createdAt: new Date() },
      });

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
