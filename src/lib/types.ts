import type { User, Creator } from '@prisma/client'

/**
 * User safe for API responses — no password hash, no soft-delete marker.
 */
export type SafeUser = Omit<User, 'passwordHash' | 'deletedAt'>

/**
 * Creator safe for API responses — all fields are public.
 */
export type SafeCreator = Creator

/**
 * Strip sensitive fields from a full User record before including it in a response.
 * Call this in every service method that returns user data.
 */
export function sanitizeUser(user: User): SafeUser {
  // Destructure away sensitive fields — prefixed with _ to satisfy TS "no unused vars"
  const { passwordHash: _pw, deletedAt: _del, ...safe } = user
  return safe
}
