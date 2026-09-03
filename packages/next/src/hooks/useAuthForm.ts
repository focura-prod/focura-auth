import { signIn } from "next-auth/react";
import { useRouter, useSearchParams } from "next/navigation";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useState, useCallback } from "react";
import { getRoutes } from "../config.js";

const loginSchema = z.object({
  email: z.string().email("Invalid email format"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

const registerSchema = z.object({
  email: z.string().email("Invalid email format"),
  password: z.string().min(8, "Password must be at least 8 characters"),
  name: z.string().min(4, "Name must be at least 4 characters"),
});

type LoginFormData = z.infer<typeof loginSchema>;
type RegisterFormData = z.infer<typeof registerSchema>;
type AuthFormData = LoginFormData | RegisterFormData;

interface UseAuthFormProps {
  mode: "login" | "register";
  callbackUrl?: string;
}

export function useAuthForm({ mode, callbackUrl: inputCallbackUrl }: UseAuthFormProps) {
  const [isGoogleLoading, setIsGoogleLoading] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [toastFn, setToastFn] = useState<any>(null);

  const router = useRouter();
  const searchParams = useSearchParams();
  const callbackUrl = inputCallbackUrl || searchParams?.get("callbackUrl") || "/dashboard";

  const toast = useCallback(async () => {
    if (!toastFn) {
      try {
        const mod = await import("react-hot-toast");
        setToastFn(mod.default ?? mod);
        return mod.default ?? mod;
      } catch {
        return { success: () => {}, error: () => {}, default: { success: () => {}, error: () => {} } };
      }
    }
    return toastFn;
  }, [toastFn]);

  const schema = mode === "login" ? loginSchema : registerSchema;

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<AuthFormData>({ resolver: zodResolver(schema) });

  const onSubmit = async (values: AuthFormData) => {
    setFormError(null);
    const t = await toast();
    const routes = getRoutes();
    try {
      if (mode === "login") {
        const result = await signIn("credentials", {
          redirect: false,
          email: values.email,
          password: values.password,
        });
        if (result?.error) {
          if (result.error === "2FA_REQUIRED") {
            (t as unknown as { (msg: string, opts?: unknown): void })?.("", { icon: "\u{1F510}" });
            router.push(`${routes.twoFactor}?email=${encodeURIComponent(values.email)}`);
            return;
          }
          const errorMessage = "Invalid email or password.";
          setFormError(errorMessage);
          t.error(errorMessage);
          return;
        }
        if (result?.ok) {
          t.success("Welcome back!");
          router.push(callbackUrl !== "/dashboard" ? `${routes.success}?callbackUrl=${encodeURIComponent(callbackUrl)}` : routes.success);
        }
      } else {
        const v = values as RegisterFormData;
        const res = await fetch("/api/auth/register", {
          method: "POST",
          body: JSON.stringify({ name: v.name, email: v.email, password: v.password }),
          headers: { "Content-Type": "application/json" },
        });
        if (!res.ok) {
          const data = await res.json().catch(() => null);
          const errorMessage = res.status === 429 ? "Too many attempts." : data?.error || "Registration failed.";
          setFormError(errorMessage);
          t.error(errorMessage);
          return;
        }
        t.success("Registration successful! Check your email.");
        router.push(`${routes.login}?verifyEmail=true`);
      }
    } catch {
      const errorMessage = "Something went wrong.";
      setFormError(errorMessage);
      (t as unknown as { error: (msg: string) => void })?.error(errorMessage);
    }
  };

  const handleGoogle = async () => {
    setIsGoogleLoading(true);
    try {
      const routes = getRoutes();
      const googleCallback = callbackUrl !== "/dashboard" ? `${routes.success}?callbackUrl=${encodeURIComponent(callbackUrl)}` : routes.success;
      await signIn("google", { callbackUrl: googleCallback });
    } catch {
      const t = await toast();
      (t as unknown as { error: (msg: string) => void })?.error("Google sign-in failed.");
    } finally {
      setIsGoogleLoading(false);
    }
  };

  return {
    register,
    handleSubmit,
    errors,
    isSubmitting,
    isGoogleLoading,
    isLoading: isSubmitting || isGoogleLoading,
    onSubmit,
    handleGoogle,
    formError,
    clearFormError: () => setFormError(null),
  };
}
