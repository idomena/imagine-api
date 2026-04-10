import { db } from '../../core/db'

// ---------------------------------------------------------------------------
// Reviews repository — raw DB access, no business logic.
// ---------------------------------------------------------------------------

const userSelect = {
  id:        true,
  email:     true,
  avatarUrl: true,
} as const

export const reviewsRepository = {
  async findByApp(appId: string, opts: { take: number; skip: number }) {
    const where = { appId }

    const [items, total, agg] = await Promise.all([
      db.appReview.findMany({
        where,
        take:    opts.take,
        skip:    opts.skip,
        orderBy: { createdAt: 'desc' },
        include: { user: { select: userSelect } },
      }),
      db.appReview.count({ where }),
      db.appReview.aggregate({ where, _avg: { rating: true } }),
    ])

    return {
      items,
      total,
      avgRating: agg._avg.rating ?? null,
    }
  },

  async upsert(appId: string, userId: string, data: { rating: number; comment: string }) {
    return db.appReview.upsert({
      where:   { appId_userId: { appId, userId } },
      create:  { appId, userId, ...data },
      update:  data,
      include: { user: { select: userSelect } },
    })
  },
}
