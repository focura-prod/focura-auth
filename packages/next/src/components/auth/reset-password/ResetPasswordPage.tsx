"use client";

import { useResetPasswordPage } from "../../../hooks/useResetPasswordPage.js";

interface ResetPasswordPageProps {
  token: string | null;
}

export function ResetPasswordPage({ token }: ResetPasswordPageProps) {
  const { error, success, register, handleSubmit, errors: formErrors, isSubmitting, onSubmit } = useResetPasswordPage({ token });

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-950 px-4">
      <div className="w-full max-w-md bg-white dark:bg-gray-900 rounded-2xl shadow-xl p-8 border border-gray-200 dark:border-gray-800">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white text-center">Reset password</h1>
        <p className="mt-2 text-sm text-gray-600 dark:text-gray-400 text-center">Enter your new password below</p>

        {success ? (
          <div className="mt-6 p-4 bg-green-50 dark:bg-green-950/30 border border-green-200 dark:border-green-800 rounded-lg text-green-700 dark:text-green-400 text-sm">
            Password reset successfully! Redirecting to login...
          </div>
        ) : (
          <form onSubmit={handleSubmit(onSubmit)} className="mt-6 space-y-4">
            {error && <div className="p-3 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800 rounded-lg text-red-700 dark:text-red-400 text-sm">{error}</div>}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">New Password</label>
              <input {...register("password")} type="password" placeholder="••••••••" className="w-full px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500" />
              {formErrors.password && <p className="mt-1 text-sm text-red-600">{formErrors.password.message}</p>}
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Confirm Password</label>
              <input {...register("confirmPassword")} type="password" placeholder="••••••••" className="w-full px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500" />
              {formErrors.confirmPassword && <p className="mt-1 text-sm text-red-600">{formErrors.confirmPassword.message}</p>}
            </div>
            <button type="submit" disabled={isSubmitting} className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-medium rounded-lg transition-colors">
              {isSubmitting ? "Resetting..." : "Reset Password"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
