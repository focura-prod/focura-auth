import type { UseFormRegister, FieldErrors, FieldValues, Path } from "react-hook-form";

interface AuthFormFieldsProps<T extends FieldValues = FieldValues> {
  register: UseFormRegister<T>;
  errors: FieldErrors<T>;
  mode: "login" | "register";
}

export function AuthFormFields<T extends FieldValues = FieldValues>({ register, errors, mode }: AuthFormFieldsProps<T>) {
  return (
    <>
      {mode === "register" && (
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name</label>
          <input
            {...register("name" as Path<T>)}
            type="text"
            placeholder="Your name"
            className="w-full px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
          {errors.name && <p className="mt-1 text-sm text-red-600">{(errors.name.message as string) ?? ""}</p>}
        </div>
      )}
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Email</label>
        <input
          {...register("email" as Path<T>)}
          type="email"
          placeholder="you@example.com"
          className="w-full px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
        />
        {errors.email && <p className="mt-1 text-sm text-red-600">{(errors.email.message as string) ?? ""}</p>}
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Password</label>
        <input
          {...register("password" as Path<T>)}
          type="password"
          placeholder="••••••••"
          className="w-full px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
        />
        {errors.password && <p className="mt-1 text-sm text-red-600">{(errors.password.message as string) ?? ""}</p>}
      </div>
      {mode === "login" && (
        <div className="text-right">
          <a href="/authentication/forgot-password" className="text-sm text-blue-600 hover:text-blue-500 dark:text-blue-400">
            Forgot password?
          </a>
        </div>
      )}
    </>
  );
}
