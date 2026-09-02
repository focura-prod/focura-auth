import { z } from "zod";

export const exchangeSchema = z.object({
  userId: z.string().uuid(),
  email: z.string().email(),
  role: z.string(),
  sessionId: z.string().uuid(),
  timestamp: z.string().or(z.number()),
  signature: z.string(),
});

export const refreshSchema = z.object({
  refreshToken: z.string().min(1),
});

export const logoutSchema = z.object({
  logoutAll: z.boolean().optional(),
});
