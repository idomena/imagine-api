import type { User, Creator } from '@prisma/client'

/**
 * User safe for API responses — no password hash, no soft-delete marker.
 */
export type SafeUser = Omit<User, 'passwordHash' | 'deletedAt'> & {
  displayName: string | null
}

/**
 * Creator safe for API responses — all fields are public.
 */
export type SafeCreator = Creator

type UserWithCreator = User & {
  creator?: Pick<Creator, 'displayName' | 'avatarUrl'> | null
}

/**
 * Strip sensitive fields from a full User record before including it in a response.
 * Merges Creator.displayName and Creator.avatarUrl (preferred over User.avatarUrl).
 */
export function sanitizeUser(user: UserWithCreator): SafeUser {
  const { passwordHash: _pw, deletedAt: _del, creator, ...safe } = user
  return {
    ...safe,
    displayName: creator?.displayName ?? null,
    avatarUrl:   creator?.avatarUrl  ?? safe.avatarUrl,
  }
}
