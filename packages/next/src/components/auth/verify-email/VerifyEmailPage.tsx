"use client";

import { useVerifyEmail } from "../../../hooks/useVerifyEmail.js";

interface VerifyEmailPageProps {
  token: string | null;
}

export function VerifyEmailPage({ token }: VerifyEmailPageProps) {
  const { status, message } = useVerifyEmail({ token });

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-950 px-4">
      <div className="w-full max-w-md bg-white dark:bg-gray-900 rounded-2xl shadow-xl p-8 border border-gray-200 dark:border-gray-800 text-center">
        {status === "loading" && (
          <div className="animate-spin h-10 w-10 border-4 border-blue-600 border-t-transparent rounded-full mx-auto" />
        )}
        {status === "success" && (
          <div>
            <div className="h-14 w-14 bg-green-100 dark:bg-green-900/30 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg className="h-8 w-8 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
            </div>
            <p className="text-green-700 dark:text-green-400">{message}</p>
          </div>
        )}
        {status === "error" && (
          <div>
            <div className="h-14 w-14 bg-red-100 dark:bg-red-900/30 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg className="h-8 w-8 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
            </div>
            <p className="text-red-700 dark:text-red-400">{message}</p>
            <a href="/authentication/login" className="mt-4 inline-block text-blue-600 hover:text-blue-500">Go to Login</a>
          </div>
        )}
      </div>
    </div>
  );
}
