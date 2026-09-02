"use client";

import { useState } from "react";
import { AuthForm } from "./AuthForm.js";

interface AuthPageProps {
  callbackUrl?: string;
}

export function AuthPage({ callbackUrl }: AuthPageProps) {
  const [mode, setMode] = useState<"login" | "register">("login");

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-950 px-4">
      <div className="w-full max-w-md">
        <AuthForm mode={mode} onModeChange={setMode} callbackUrl={callbackUrl} />
      </div>
    </div>
  );
}
