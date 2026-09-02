"use client";

import { useAuthForm } from "../../hooks/useAuthForm.js";
import { AuthFormHeader } from "./AuthForm/AuthFormHeader.js";
import { AuthFormFields } from "./AuthForm/AuthFormFields.js";
import { AuthFormButtons } from "./AuthForm/AuthFormButtons.js";
import { AuthFormFooter } from "./AuthForm/AuthFormFooter.js";

interface AuthFormProps {
  mode: "login" | "register";
  onModeChange?: (mode: "login" | "register") => void;
  callbackUrl?: string;
}

export function AuthForm({ mode, onModeChange, callbackUrl }: AuthFormProps) {
  const {
    register,
    handleSubmit,
    errors,
    isSubmitting,
    isGoogleLoading,
    isLoading,
    onSubmit,
    handleGoogle,
    formError,
    clearFormError,
  } = useAuthForm({ mode, callbackUrl });

  return (
    <div className="bg-white dark:bg-gray-900 rounded-2xl shadow-xl p-8 border border-gray-200 dark:border-gray-800">
      {formError && (
        <div role="alert" className="mb-4 p-3 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800 rounded-lg text-red-700 dark:text-red-400 text-sm">
          {formError}
          <button onClick={clearFormError} className="ml-2 underline">dismiss</button>
        </div>
      )}

      <AuthFormHeader mode={mode} />

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-4 mt-6">
        <AuthFormFields register={register} errors={errors} mode={mode} />
        <AuthFormButtons
          isSubmitting={isSubmitting}
          isGoogleLoading={isGoogleLoading}
          isLoading={isLoading}
          mode={mode}
          onGoogle={handleGoogle}
        />
      </form>

      <AuthFormFooter mode={mode} onModeChange={onModeChange} />
    </div>
  );
}
