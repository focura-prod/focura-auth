import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/components/index.ts", "src/hooks/index.ts", "src/api/index.ts", "src/email/index.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  splitting: true,
  treeshake: true,
  minify: false,
  target: "es2022",
  outDir: "dist",
  external: ["next", "next-auth", "next-auth/react", "next-auth/providers/credentials", "next-auth/providers/google", "react", "react-dom", "react-hook-form", "@hookform/resolvers/zod", "zod", "argon2", "otplib", "react-hot-toast", "nodemailer"],
});
