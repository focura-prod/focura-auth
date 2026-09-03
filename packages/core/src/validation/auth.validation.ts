import { z } from "zod";

export const exchangeSchema = z.object({
  userId: z.string().uuid(),
  email: z.string().email(),
  role: z.string(),
  sessionId: z.string().uuid(),
  timestamp: z
    .union([z.string(), z.number()])
    .transform((val) => (typeof val === "string" ? Number(val) : val))
    .pipe(z.number().int())
    .refine(
      (val) => {
        const age = Date.now() - val;
        return age >= 0 && age <= 60_000;
      },
      { message: "Proof must be between 0 and 60 seconds old" },
    ),
  signature: z.string(),
});

export const refreshSchema = z.object({
  refreshToken: z.string().min(1),
});

export const logoutSchema = z.object({
  logoutAll: z.boolean().optional(),
});
