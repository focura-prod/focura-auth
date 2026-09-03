import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { getRoutes } from "../config.js";

const schema = z.object({
  password: z.string().min(8, "Password must be at least 8 characters"),
  confirmPassword: z.string().min(8, "Please confirm your password"),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

type FormData = z.infer<typeof schema>;

export function useResetPasswordPage({ token }: { token: string | null }) {
  const router = useRouter();
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<FormData>({
    resolver: zodResolver(schema),
  });

  const onSubmit = async (values: FormData) => {
    setError(""); setSuccess(false);
    if (!token) { setError("Invalid reset link"); return; }
    try {
      const res = await fetch("/api/auth/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, password: values.password }),
      });
      if (res.ok) {
        setSuccess(true);
        const routes = getRoutes();
        setTimeout(() => router.push(routes.login), 3000);
      } else {
        const data = await res.json().catch(() => null);
        setError(data?.error || "Failed to reset password");
      }
    } catch {
      setError("Something went wrong.");
    }
  };

  return { register, handleSubmit, errors, isSubmitting, error, success, onSubmit };
}
