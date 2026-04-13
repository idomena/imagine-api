import { AppStatus, Prisma, ReviewStatus } from '@prisma/client'
import { db } from '../../core/db'
import type { CreateAppBody } from './apps.schema'

// ---------------------------------------------------------------------------
// Apps repository — raw DB access, no business logic.
// ---------------------------------------------------------------------------

export const appsRepository = {
  async findById(id: string) {
    return db.app.findUnique({ where: { id } })
  },

  async findBySlug(slug: string) {
    return db.app.findUnique({ where: { slug } })
  },

  async findCreatorByUserId(userId: string) {
    return db.creator.findUnique({ where: { userId } })
  },

  async findManyPublished(opts: { categoryId?: string; take: number; skip: number }) {
    const where: Prisma.AppWhereInput = {
      status: AppStatus.PUBLISHED,
      ...(opts.categoryId ? { categoryId: opts.categoryId } : {}),
    }
    const [items, total] = await db.$transaction([
      db.app.findMany({
        where,
        take: opts.take,
        skip: opts.skip,
        orderBy: { publishedAt: 'desc' },
      }),
      db.app.count({ where }),
    ])
    return { items, total }
  },

  async findManyForAdmin(opts: { status?: AppStatus; take: number; skip: number }) {
    const where: Prisma.AppWhereInput = opts.status ? { status: opts.status } : {}
    const [items, total] = await db.$transaction([
      db.app.findMany({
        where,
        take: opts.take,
        skip: opts.skip,
        orderBy: { createdAt: 'desc' },
      }),
      db.app.count({ where }),
    ])
    return { items, total }
  },

  async findManyByCreator(creatorId: string, opts: { take: number; skip: number }) {
    const where: Prisma.AppWhereInput = { creatorId }
    const [items, total] = await db.$transaction([
      db.app.findMany({
        where,
        take: opts.take,
        skip: opts.skip,
        orderBy: { createdAt: 'desc' },
        include: {
          _count: { select: { launchEvents: true } },
          securityAuditReport: { select: { safetyScore: true, decision: true } },
        },
      }),
      db.app.count({ where }),
    ])
    return { items, total }
  },

  /** Security override: revert a PUBLISHED app back to SUBMITTED.
   *  Bypasses the normal state machine — only called by the background scanner. */
  async securityRevert(appId: string) {
    return db.app.update({
      where: { id: appId },
      data:  { status: AppStatus.SUBMITTED, publishedAt: null },
    })
  },

  async create(creatorId: string, data: CreateAppBody) {
    return db.app.create({
      data: {
        creatorId,
        description: '',
        status:      AppStatus.DRAFT,   // starts as DRAFT; submit route drives DRAFT → SUBMITTED → PUBLISHED
        ...data,
      },
    })
  },

  async update(id: string, data: Prisma.AppUpdateInput) {
    return db.app.update({ where: { id }, data })
  },

  /**
   * Apply a status transition patch. Only the service layer should call this —
   * callers must validate the transition before invoking.
   */
  async transition(id: string, patch: Prisma.AppUpdateInput) {
    return db.app.update({ where: { id }, data: patch })
  },

  /**
   * Create a moderation review record as part of an approve / reject transition.
   * This gives a full audit trail of every moderation decision.
   */
  async createModerationReview(data: {
    appId: string
    reviewerId: string
    status: ReviewStatus
    rejectionReason?: string
    notes?: string
  }) {
    return db.moderationReview.create({
      data: {
        ...data,
        completedAt: new Date(),
      },
    })
  },

  async delete(id: string) {
    return db.$transaction(async tx => {
      await tx.appAsset.deleteMany({ where: { appId: id } })
      await tx.appTag.deleteMany({ where: { appId: id } })
      await tx.launchEvent.deleteMany({ where: { appId: id } })
      await tx.favorite.deleteMany({ where: { appId: id } })
      await tx.recentlyUsed.deleteMany({ where: { appId: id } })
      await tx.moderationReview.deleteMany({ where: { appId: id } })
      return tx.app.delete({ where: { id } })
    })
  },
}
