import { z } from "zod";

const registerSchema = z.object({
  name: z.string().min(4, "Name must be at least 4 characters"),
  email: z.string().email("Invalid email format"),
  password: z.string().min(8, "Password must be at least 8 characters"),
});

export async function handleRegister(req: Request, deps: {
  prisma: { user: { findUnique: (args: { where: { email: string } }) => Promise<unknown | null>; create: (args: unknown) => Promise<unknown> }; verificationToken: { create: (args: unknown) => Promise<unknown> } };
  argon2: { hash: (pwd: string) => Promise<string> };
  sendVerificationEmail: (email: string, token: string) => Promise<void>;
  limiter?: { check?: (key: string) => Promise<boolean> };
  rateLimitKey?: string;
}) {
  try {
    if (deps.limiter?.check && deps.rateLimitKey) {
      const allowed = await deps.limiter.check(deps.rateLimitKey);
      if (!allowed) return Response.json({ error: "Too many requests" }, { status: 429 });
    }

    const body = await req.json();
    const parsed = registerSchema.safeParse(body);
    if (!parsed.success) {
      return Response.json({ error: parsed.error.issues[0]?.message || "Invalid input" }, { status: 400 });
    }

    const { name, email, password } = parsed.data;
    const normalizedEmail = email.toLowerCase().trim();

    const existing = await deps.prisma.user.findUnique({ where: { email: normalizedEmail } });
    if (existing) {
      return Response.json({ error: "An account with this email already exists" }, { status: 409 });
    }

    const hashedPassword = await deps.argon2.hash(password);
    const verificationToken = crypto.randomUUID();
    const expires = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await deps.prisma.user.create({
      data: { name, email: normalizedEmail, password: hashedPassword },
    });
    await deps.prisma.verificationToken.create({
      data: { identifier: normalizedEmail, token: verificationToken, expires },
    });

    try {
      await deps.sendVerificationEmail(normalizedEmail, verificationToken);
    } catch {
      console.error("Failed to send verification email, but account was created");
    }

    return Response.json({ message: "Registration successful" }, { status: 201 });
  } catch (error) {
    console.error("Registration error:", error);
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}
