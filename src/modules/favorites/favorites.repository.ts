import { db } from '../../core/db'

// ---------------------------------------------------------------------------
// Favorites repository — raw DB access, no business logic.
// ---------------------------------------------------------------------------

export const favoritesRepository = {
  /**
   * Return all favorites for a user, including the full App record so the
   * response is useful without a second round-trip.
   */
  async findByUser(userId: string, opts: { take: number; skip: number }) {
    const where = { userId }
    const [items, total] = await db.$transaction([
      db.favorite.findMany({
        where,
        take: opts.take,
        skip: opts.skip,
        orderBy: { createdAt: 'desc' },
        include: { app: true },
      }),
      db.favorite.count({ where }),
    ])
    return { items, total }
  },

  async findOne(userId: string, appId: string) {
    return db.favorite.findUnique({
      where: { userId_appId: { userId, appId } },
    })
  },

  async add(userId: string, appId: string) {
    return db.favorite.create({ data: { userId, appId } })
  },

  async remove(userId: string, appId: string) {
    return db.favorite.delete({
      where: { userId_appId: { userId, appId } },
    })
  },
}
