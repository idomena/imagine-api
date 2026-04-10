import { db } from '../../core/db'

// ---------------------------------------------------------------------------
// Users repository — raw DB access, no business logic.
// ---------------------------------------------------------------------------

export const usersRepository = {
  async findById(id: string) {
    return db.user.findFirst({
      where: { id, deletedAt: null },
    })
  },

  async findByEmail(email: string) {
    return db.user.findFirst({
      where: { email, deletedAt: null },
    })
  },

  async update(id: string, data: { email?: string }) {
    return db.user.update({
      where: { id },
      data,
    })
  },

  async findCreatorByUserId(userId: string) {
    return db.creator.findUnique({
      where: { userId },
    })
  },
}
