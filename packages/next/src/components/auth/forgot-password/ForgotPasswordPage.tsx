"use client";

import { useForgetPasswordPage } from "../../../hooks/useForgetPasswordPage.js";

export function ForgotPasswordPage() {
  const { error, success, register, handleSubmit, errors: formErrors, isSubmitting, onSubmit } = useForgetPasswordPage();

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-950 px-4">
      <div className="w-full max-w-md bg-white dark:bg-gray-900 rounded-2xl shadow-xl p-8 border border-gray-200 dark:border-gray-800">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white text-center">Forgot password?</h1>
        <p className="mt-2 text-sm text-gray-600 dark:text-gray-400 text-center">Enter your email to receive a reset link</p>

        {success ? (
          <div className="mt-6 p-4 bg-green-50 dark:bg-green-950/30 border border-green-200 dark:border-green-800 rounded-lg text-green-700 dark:text-green-400 text-sm">
            Reset link sent! Check your email.
          </div>
        ) : (
          <form onSubmit={handleSubmit(onSubmit)} className="mt-6 space-y-4">
            {error && <div className="p-3 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800 rounded-lg text-red-700 dark:text-red-400 text-sm">{error}</div>}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Email</label>
              <input {...register("email")} type="email" placeholder="you@example.com" className="w-full px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500" />
              {formErrors.email && <p className="mt-1 text-sm text-red-600">{formErrors.email.message}</p>}
            </div>
            <button type="submit" disabled={isSubmitting} className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-medium rounded-lg transition-colors">
              {isSubmitting ? "Sending..." : "Send Reset Link"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
