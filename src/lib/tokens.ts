import { createHash, randomBytes } from 'crypto'
import type { FastifyInstance } from 'fastify'
// Importing @fastify/jwt ensures FastifyInstance.jwt type augmentation is in scope
import '@fastify/jwt'
import type { JwtPayload } from '../plugins/auth.plugin'
import { config } from '../core/config'

// ---------------------------------------------------------------------------
// Access token — short-lived, signed JWT
// ---------------------------------------------------------------------------

export function generateAccessToken(app: FastifyInstance, payload: JwtPayload): string {
  return app.jwt.sign(payload)
}

// ---------------------------------------------------------------------------
// Refresh token — long-lived opaque token
//
// The raw token is sent to the client (never stored).
// Only the SHA-256 hash is persisted in the database.
// ---------------------------------------------------------------------------

export function generateRefreshToken(): { raw: string; hash: string } {
  const raw = randomBytes(64).toString('hex')
  return { raw, hash: hashToken(raw) }
}

export function hashToken(raw: string): string {
  return createHash('sha256').update(raw).digest('hex')
}

// ---------------------------------------------------------------------------
// Expiry helpers
// ---------------------------------------------------------------------------

const DURATION_MS = {
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
} as const satisfies Record<string, number>

type DurationUnit = keyof typeof DURATION_MS

/**
 * Compute an absolute expiry Date from the JWT_REFRESH_EXPIRY config string.
 * Supports formats: "7d", "24h", "3600s".
 * Defaults to 7 days if the string is unparseable.
 */
export function getRefreshTokenExpiry(): Date {
  const match = /^(\d+)([smhd])$/.exec(config.JWT_REFRESH_EXPIRY)

  if (!match || !match[1] || !match[2]) {
    return new Date(Date.now() + DURATION_MS.d * 7)
  }

  const value = parseInt(match[1], 10)
  const unit = match[2]
  const isValidUnit = (u: string): u is DurationUnit => u in DURATION_MS
  const multiplier = isValidUnit(unit) ? DURATION_MS[unit] : DURATION_MS.d

  return new Date(Date.now() + value * multiplier)
}
