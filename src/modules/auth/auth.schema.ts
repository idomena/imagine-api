import { z } from 'zod'

// ---------------------------------------------------------------------------
// Request body schemas — parse + validate in controllers before passing to
// services. Zod throws ZodError on failure, caught by the error handler.
// ---------------------------------------------------------------------------

export const RegisterBodySchema = z.object({
  email: z.string().email('Invalid email address').toLowerCase(),
  // bcrypt silently truncates at 72 bytes — cap here to avoid silent data loss
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(72, 'Password must be at most 72 characters'),
  displayName: z.string().min(1).max(100).optional(),
})

export const LoginBodySchema = z.object({
  email: z.string().email('Invalid email address').toLowerCase(),
  password: z.string().min(1, 'Password is required'),
})

export const RefreshBodySchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token is required'),
})

export const GoogleAuthBodySchema = z.object({
  googleId: z.string().min(1),
  email:    z.string().email().toLowerCase(),
  name:     z.string().optional(),
  picture:  z.string().url().optional(),
})

export type RegisterBody    = z.infer<typeof RegisterBodySchema>
export type LoginBody       = z.infer<typeof LoginBodySchema>
export type RefreshBody     = z.infer<typeof RefreshBodySchema>
export type GoogleAuthBody  = z.infer<typeof GoogleAuthBodySchema>
