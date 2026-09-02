import nodemailer from "nodemailer";

function createTransporter() {
  const { EMAIL_SERVER_HOST, EMAIL_SERVER_PORT, EMAIL_SERVER_USER, EMAIL_SERVER_PASSWORD } = process.env;
  if (!EMAIL_SERVER_HOST || !EMAIL_SERVER_PORT || !EMAIL_SERVER_USER || !EMAIL_SERVER_PASSWORD) {
    throw new Error("Missing email environment variables");
  }
  return nodemailer.createTransport({
    host: EMAIL_SERVER_HOST,
    port: Number(EMAIL_SERVER_PORT),
    secure: Number(EMAIL_SERVER_PORT) === 465,
    auth: { user: EMAIL_SERVER_USER, pass: EMAIL_SERVER_PASSWORD },
    tls: { rejectUnauthorized: process.env.NODE_ENV === "production" },
  });
}

let _transporter: ReturnType<typeof nodemailer.createTransport> | null = null;

function getTransporter() {
  if (!_transporter) _transporter = createTransporter();
  return _transporter;
}

export async function sendVerificationEmail(email: string, token: string): Promise<void> {
  const baseUrl = process.env.NEXTAUTH_URL;
  if (!baseUrl) throw new Error("Missing NEXTAUTH_URL");
  const url = `${baseUrl}/authentication/verify-email?token=${token}`;
  const from = process.env.EMAIL_FROM;
  if (!from) throw new Error("Missing EMAIL_FROM");

  await getTransporter().sendMail({
    from,
    to: email,
    subject: "Verify your email",
    html: `<p>Click <a href="${url}">here</a> to verify your email. Link expires in 24 hours.</p>`,
  });
}

export async function sendPasswordResetEmail(email: string, token: string): Promise<void> {
  const baseUrl = process.env.NEXTAUTH_URL;
  if (!baseUrl) throw new Error("Missing NEXTAUTH_URL");
  const url = `${baseUrl}/authentication/reset-password?token=${token}`;
  const from = process.env.EMAIL_FROM;
  if (!from) throw new Error("Missing EMAIL_FROM");

  await getTransporter().sendMail({
    from,
    to: email,
    subject: "Reset your password",
    html: `<p>Click <a href="${url}">here</a> to reset your password. Link expires in 1 hour.</p>`,
  });
}
