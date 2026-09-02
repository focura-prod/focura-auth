export function AuthFormSkeleton() {
  return (
    <div className="bg-white dark:bg-gray-900 rounded-2xl shadow-xl p-8 border border-gray-200 dark:border-gray-800 animate-pulse">
      <div className="text-center space-y-2 mb-6">
        <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded w-3/4 mx-auto" />
        <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/2 mx-auto" />
      </div>
      <div className="space-y-4">
        <div className="h-10 bg-gray-200 dark:bg-gray-700 rounded" />
        <div className="h-10 bg-gray-200 dark:bg-gray-700 rounded" />
        <div className="h-10 bg-gray-200 dark:bg-gray-700 rounded" />
        <div className="h-10 bg-gray-200 dark:bg-gray-700 rounded" />
      </div>
    </div>
  );
}
