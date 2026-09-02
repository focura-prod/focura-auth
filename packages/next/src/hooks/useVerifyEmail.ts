import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

type VerifyStatus = "loading" | "success" | "error";

export function useVerifyEmail({ token }: { token: string | null }) {
  const router = useRouter();
  const [status, setStatus] = useState<VerifyStatus>("loading");
  const [message, setMessage] = useState("");

  useEffect(() => {
    let cancelled = false;
    let redirectTimer: ReturnType<typeof setTimeout> | undefined;

    const verify = async () => {
      if (!token) {
        if (!cancelled) { setStatus("error"); setMessage("Invalid verification link"); }
        return;
      }
      try {
        const res = await fetch("/api/auth/verify-email", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token }),
        });
        if (res.ok) {
          const data = await res.json().catch(() => null);
          if (cancelled) return;
          setStatus("success");
          setMessage(data?.message || "Email verified!");
          redirectTimer = setTimeout(() => router.push("/authentication/login"), 3000);
        } else {
          const data = await res.json().catch(() => null);
          if (cancelled) return;
          setStatus("error");
          setMessage(data?.error || "Verification failed");
        }
      } catch {
        if (cancelled) return;
        setStatus("error");
        setMessage("Something went wrong.");
      }
    };
    verify();
    return () => { cancelled = true; if (redirectTimer) clearTimeout(redirectTimer); };
  }, [token, router]);

  return { status, message };
}
