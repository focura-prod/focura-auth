import type { DataStore } from "../types.js";

export async function handleVerifyEmail(req: Request, deps: {
  dataStore: DataStore;
}) {
  try {
    const { token } = await req.json();
    if (!token) return Response.json({ error: "Token required" }, { status: 400 });

    const verificationToken = await deps.dataStore.findVerificationToken(token);
    if (!verificationToken) return Response.json({ error: "Invalid token" }, { status: 400 });
    if (new Date() > verificationToken.expires) {
      return Response.json({ error: "Token expired" }, { status: 400 });
    }

    await deps.dataStore.updateUserByEmail(verificationToken.identifier, { emailVerified: new Date() });
    await deps.dataStore.deleteVerificationToken(token, verificationToken.identifier);

    return Response.json({ message: "Email verified successfully" });
  } catch (error) {
    console.error("Email verification error:", error);
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}
