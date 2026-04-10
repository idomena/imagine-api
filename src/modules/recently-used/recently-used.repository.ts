import { db } from '../../core/db'

// ---------------------------------------------------------------------------
// Recently-used repository — raw DB access, no business logic.
// ---------------------------------------------------------------------------

export const recentlyUsedRepository = {
  /**
   * Return a user's recently-used apps ordered newest-first.
   * The App record is included so callers get useful data in one query.
   */
  async findByUser(userId: string, opts: { take: number; skip: number }) {
    const where = { userId }
    const [items, total] = await db.$transaction([
      db.recentlyUsed.findMany({
        where,
        take: opts.take,
        skip: opts.skip,
        orderBy: { launchedAt: 'desc' },
        include: { app: true },
      }),
      db.recentlyUsed.count({ where }),
    ])
    return { items, total }
  },

  /**
   * Record (or refresh) a launch.
   *
   * RecentlyUsed uses a composite PK so each user/app pair has exactly one
   * row. On repeat launches we update `launchedAt` rather than inserting a
   * duplicate, which keeps the list clean and the ORDER BY correct.
   */
  async upsert(userId: string, appId: string) {
    return db.recentlyUsed.upsert({
      where: { userId_appId: { userId, appId } },
      update: { launchedAt: new Date() },
      create: { userId, appId },
    })
  },
}
