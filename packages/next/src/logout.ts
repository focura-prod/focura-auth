export async function logout(
  backendUrl: string,
  backendToken?: string,
  logoutAll = false,
): Promise<void> {
  try {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (backendToken) headers["Authorization"] = `Bearer ${backendToken}`;
    await fetch(`${backendUrl}/api/v1/auth/logout`, {
      method: "POST",
      headers,
      body: JSON.stringify({ logoutAll }),
    });
  } catch {
    // best-effort
  }
}
