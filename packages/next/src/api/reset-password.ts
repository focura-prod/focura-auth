import crypto from "crypto";

export async function handleResetPassword(req: Request, deps: {
  prisma: {
    passwordResetToken: {
      findFirst: (args: { where: { token: string; expires: { gt: Date } } }) => Promise<{ email: string; token: string } | null>;
      delete: (args: { where: { email: string } }) => Promise<unknown>;
    };
    user: {
      update: (args: { where: { email: string }; data: { password: string; lastPasswordChange: Date } }) => Promise<unknown>;
    };
  };
  argon2: { hash: (pwd: string) => Promise<string> };
}) {
  try {
    const { token, password } = await req.json();
    if (!token || !password) return Response.json({ error: "Token and password required" }, { status: 400 });
    if (password.length < 8) return Response.json({ error: "Password must be at least 8 characters" }, { status: 400 });

    const resetToken = await deps.prisma.passwordResetToken.findFirst({
      where: { token, expires: { gt: new Date() } },
    });
    if (!resetToken) return Response.json({ error: "Invalid or expired token" }, { status: 400 });

    const hashedPassword = await deps.argon2.hash(password);
    await deps.prisma.user.update({
      where: { email: resetToken.email },
      data: { password: hashedPassword, lastPasswordChange: new Date() },
    });
    await deps.prisma.passwordResetToken.delete({ where: { email: resetToken.email } });

    return Response.json({ message: "Password reset successfully" });
  } catch (error) {
    console.error("Reset password error:", error);
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}
