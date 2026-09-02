interface AuthFormFooterProps {
  mode: "login" | "register";
  onModeChange?: (mode: "login" | "register") => void;
}

export function AuthFormFooter({ mode, onModeChange }: AuthFormFooterProps) {
  return (
    <p className="mt-6 text-center text-sm text-gray-600 dark:text-gray-400">
      {mode === "login" ? (
        <>
          Don&apos;t have an account?{" "}
          <button type="button" onClick={() => onModeChange?.("register")} className="text-blue-600 hover:text-blue-500 dark:text-blue-400 font-medium">
            Create one
          </button>
        </>
      ) : (
        <>
          Already have an account?{" "}
          <button type="button" onClick={() => onModeChange?.("login")} className="text-blue-600 hover:text-blue-500 dark:text-blue-400 font-medium">
            Sign in
          </button>
        </>
      )}
    </p>
  );
}
