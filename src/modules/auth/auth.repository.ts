import { db } from '../../core/db'
import { UserRole } from '@prisma/client'

// ---------------------------------------------------------------------------
// Auth repository — raw DB access, no business logic.
// ---------------------------------------------------------------------------

export const authRepository = {
  async findByEmail(email: string) {
    return db.user.findFirst({
      where:   { email, deletedAt: null },
      include: { creator: { select: { displayName: true, avatarUrl: true } } },
    })
  },

  async findById(id: string) {
    return db.user.findFirst({
      where:   { id, deletedAt: null },
      include: { creator: { select: { displayName: true, avatarUrl: true } } },
    })
  },

  /**
   * Create a new user with CREATOR role and automatically provision a Creator
   * profile, all in a single transaction so they are always in sync.
   */
  async findByGoogleId(googleId: string) {
    return db.user.findFirst({ where: { googleId, deletedAt: null } })
  },

  /**
   * Find-or-create a user from Google OAuth. Always ensures a Creator profile
   * exists and keeps avatarUrl in sync with the latest Google picture.
   */
  async upsertGoogleUser(data: {
    googleId: string
    email:    string
    name:     string
    picture?: string
  }) {
    return db.$transaction(async (tx) => {
      // Try to find by googleId first, then fall back to email
      let user = await tx.user.findFirst({
        where: { OR: [{ googleId: data.googleId }, { email: data.email }], deletedAt: null },
      })

      if (user) {
        // Sync googleId and avatarUrl on existing account
        user = await tx.user.update({
          where: { id: user.id },
          data: {
            googleId:      data.googleId,
            avatarUrl:     data.picture,
            emailVerified: true,
            role:          UserRole.CREATOR,
          },
        })
        // Ensure Creator profile exists and name/avatar are up-to-date
        const creator = await tx.creator.findUnique({ where: { userId: user.id } })
        if (!creator) {
          await tx.creator.create({ data: { userId: user.id, displayName: data.name, avatarUrl: data.picture } })
        } else {
          await tx.creator.update({
            where: { id: creator.id },
            data: {
              displayName: data.name,
              ...(data.picture ? { avatarUrl: data.picture } : {}),
            },
          })
        }
      } else {
        // Brand-new account via Google
        user = await tx.user.create({
          data: {
            email:         data.email,
            googleId:      data.googleId,
            avatarUrl:     data.picture,
            role:          UserRole.CREATOR,
            emailVerified: true,
          },
        })
        await tx.creator.create({
          data: { userId: user.id, displayName: data.name, avatarUrl: data.picture },
        })
      }

      // Return user with creator so sanitizeUser can merge displayName
      return tx.user.findFirstOrThrow({
        where:   { id: user.id },
        include: { creator: { select: { displayName: true, avatarUrl: true } } },
      })
    })
  },

  async create(email: string, passwordHash: string, displayName: string) {
    return db.$transaction(async (tx) => {
      const user = await tx.user.create({
        data: { email, passwordHash, role: UserRole.CREATOR },
      })
      await tx.creator.create({
        data: { userId: user.id, displayName },
      })
      return tx.user.findFirstOrThrow({
        where:   { id: user.id },
        include: { creator: { select: { displayName: true, avatarUrl: true } } },
      })
    })
  },

  async saveRefreshToken(userId: string, tokenHash: string, expiresAt: Date) {
    return db.refreshToken.create({
      data: { userId, tokenHash, expiresAt },
    })
  },

  /**
   * Look up a refresh token by its SHA-256 hash.
   * Includes the owning User so callers can build a new JWT payload without
   * a second round-trip.
   */
  async findRefreshToken(tokenHash: string) {
    return db.refreshToken.findUnique({
      where:   { tokenHash },
      include: { user: { include: { creator: { select: { displayName: true, avatarUrl: true } } } } },
    })
  },

  async revokeRefreshToken(tokenHash: string) {
    // Silently ignore if token is already gone or was already revoked.
    return db.refreshToken
      .update({ where: { tokenHash }, data: { revokedAt: new Date() } })
      .catch(() => undefined)
  },
}
