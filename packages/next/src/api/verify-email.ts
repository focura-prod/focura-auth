export async function handleVerifyEmail(req: Request, deps: {
  prisma: {
    verificationToken: {
      findUnique: (args: { where: { token: string } }) => Promise<{ identifier: string; expires: Date } | null>;
      delete: (args: { where: { token_identifier: { token: string; identifier: string } } }) => Promise<unknown>;
    };
    user: {
      update: (args: { where: { email: string }; data: { emailVerified: Date } }) => Promise<unknown>;
    };
  };
}) {
  try {
    const { token } = await req.json();
    if (!token) return Response.json({ error: "Token required" }, { status: 400 });

    const verificationToken = await deps.prisma.verificationToken.findUnique({ where: { token } });
    if (!verificationToken) return Response.json({ error: "Invalid token" }, { status: 400 });
    if (new Date() > verificationToken.expires) {
      return Response.json({ error: "Token expired" }, { status: 400 });
    }

    await deps.prisma.user.update({
      where: { email: verificationToken.identifier },
      data: { emailVerified: new Date() },
    });
    await deps.prisma.verificationToken.delete({
      where: { token_identifier: { token, identifier: verificationToken.identifier } },
    });

    return Response.json({ message: "Email verified successfully" });
  } catch (error) {
    console.error("Email verification error:", error);
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}
