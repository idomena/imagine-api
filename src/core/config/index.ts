import { z } from 'zod'

// ---------------------------------------------------------------------------
// Environment schema — every value is validated at startup.
// If any required variable is missing or malformed the process exits.
// ---------------------------------------------------------------------------

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  // Railway injects PORT automatically; fallback to 8080 for other platforms.
  PORT: z.coerce.number().int().positive().default(8080),
  HOST: z.string().default('0.0.0.0'),

  // Database
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),

  // JWT
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  JWT_REFRESH_SECRET: z.string().min(32, 'JWT_REFRESH_SECRET must be at least 32 characters'),
  JWT_ACCESS_EXPIRY: z.string().default('15m'),
  JWT_REFRESH_EXPIRY: z.string().default('7d'),

  // Redis — optional; workers are disabled when not set
  REDIS_URL: z.string().optional(),

  // Object storage (optional at boot — validated when first used)
  S3_BUCKET: z.string().optional(),
  S3_REGION: z.string().optional(),
  S3_ENDPOINT: z.string().url().optional(),
  S3_ACCESS_KEY_ID: z.string().optional(),
  S3_SECRET_ACCESS_KEY: z.string().optional(),

  // Cloudinary
  CLOUDINARY_CLOUD_NAME: z.string().min(1, 'CLOUDINARY_CLOUD_NAME is required'),
  CLOUDINARY_API_KEY:    z.string().min(1, 'CLOUDINARY_API_KEY is required'),
  CLOUDINARY_API_SECRET: z.string().min(1, 'CLOUDINARY_API_SECRET is required'),

  // ── Security (new) ────────────────────────────────────────────────────────

  // Google Web Risk API — URL threat scanning on app submit/approve
  // Get from: Google Cloud Console → APIs & Services → Web Risk API
  // Leave unset in development to skip scanning (a warning is logged)
  GOOGLE_WEB_RISK_API_KEY: z.string().optional(),

  // CORS — comma-separated list of allowed origins, or * for any
  CORS_ORIGIN: z.string().optional(),

  // Admin panel secret — used to authenticate /admin-dashboard sessions
  ADMIN_PANEL_SECRET: z.string().min(12).optional(),
})

export type Env = z.infer<typeof envSchema>

const result = envSchema.safeParse(process.env)

if (!result.success) {
  console.error('❌  Invalid environment configuration — fix these before starting:\n')
  const formatted = result.error.format()
  for (const [key, value] of Object.entries(formatted)) {
    if (key === '_errors') continue
    const errors = (value as { _errors: string[] })._errors
    if (errors.length) console.error(`  ${key}: ${errors.join(', ')}`)
  }
  process.exit(1)
}

// Warn in production if security-relevant optional vars are missing
if (result.data.NODE_ENV === 'production') {
  if (!result.data.GOOGLE_WEB_RISK_API_KEY) {
    console.warn('⚠️  GOOGLE_WEB_RISK_API_KEY is not set — URL threat scanning is disabled')
  }
  if (!result.data.REDIS_URL) {
    console.warn('⚠️  REDIS_URL is not set — rate limiting will use in-process store (not suitable for multi-instance)')
  }
}

export const config: Env = result.data
