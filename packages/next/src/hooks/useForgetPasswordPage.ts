import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useState } from "react";
import { useForm } from "react-hook-form";

const schema = z.object({ email: z.string().email("Invalid email format") });
type FormData = z.infer<typeof schema>;

export function useForgetPasswordPage() {
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<FormData>({
    resolver: zodResolver(schema),
  });

  const onSubmit = async (values: FormData) => {
    setError(""); setSuccess(false);
    try {
      const res = await fetch("/api/auth/forgot-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: values.email }),
      });
      if (res.ok) setSuccess(true);
      else {
        const data = await res.json().catch(() => null);
        setError(data?.error || "Failed to send reset email");
      }
    } catch {
      setError("Something went wrong.");
    }
  };

  return { error, success, register, handleSubmit, errors, isSubmitting, onSubmit };
}
