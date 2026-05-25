import { Prisma, UserRole } from '@prisma/client'
import { db } from '../../core/db'

// ---------------------------------------------------------------------------
// Creators repository — raw DB access, no business logic.
// ---------------------------------------------------------------------------

export const creatorsRepository = {
  async findUserById(id: string) {
    return db.user.findFirst({
      where: { id, deletedAt: null },
    })
  },

  async findByUserId(userId: string) {
    return db.creator.findUnique({
      where: { userId },
    })
  },

  async findByUserIdWithApps(userId: string) {
    return db.creator.findUnique({
      where:   { userId },
      include: { user: { select: { id: true, email: true, role: true } } },
    })
  },

  async update(userId: string, data: Prisma.CreatorUpdateInput) {
    return db.creator.update({ where: { userId }, data })
  },

  /**
   * Atomically promote the user to CREATOR role and insert a Creator profile.
   * Using a transaction guarantees the two writes succeed or fail together.
   */
  async onboard(
    userId: string,
    displayName: string,
    bio?: string,
    website?: string,
  ) {
    return db.$transaction(async (tx) => {
      const user = await tx.user.update({
        where: { id: userId },
        data: { role: UserRole.CREATOR },
      })

      const creator = await tx.creator.create({
        data: { userId, displayName, bio, website },
      })

      return { user, creator }
    })
  },
}
