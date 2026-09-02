interface AuthFormHeaderProps {
  mode: "login" | "register";
}

export function AuthFormHeader({ mode }: AuthFormHeaderProps) {
  return (
    <div className="text-center">
      <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
        {mode === "login" ? "Welcome back" : "Create account"}
      </h1>
      <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
        {mode === "login"
          ? "Sign in to your account"
          : "Start your journey with us"}
      </p>
    </div>
  );
}
