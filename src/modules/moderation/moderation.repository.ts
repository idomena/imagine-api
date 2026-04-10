import { AppStatus, ReviewStatus } from '@prisma/client'
import { db } from '../../core/db'

// ---------------------------------------------------------------------------
// Moderation repository — raw DB access, no business logic.
// ---------------------------------------------------------------------------

export const moderationRepository = {
  /**
   * SUBMITTED apps ordered oldest-first (FIFO) so moderators work the queue
   * in the order apps arrived. Includes creator + user so the queue response
   * contains enough context to start a review without extra round-trips.
   */
  async findSubmittedApps(opts: { take: number; skip: number }) {
    const where = { status: AppStatus.SUBMITTED }
    const [items, total] = await db.$transaction([
      db.app.findMany({
        where,
        take: opts.take,
        skip: opts.skip,
        orderBy: { submittedAt: 'asc' },
        include: {
          creator: { include: { user: true } },
          _count:  { select: { reviews: true } },
        },
      }),
      db.app.count({ where }),
    ])
    return { items, total }
  },

  /**
   * Open reviews are IN_PROGRESS records — used to find the active review
   * for an app so we can complete it when a decision is submitted.
   */
  async findActiveReview(appId: string) {
    return db.moderationReview.findFirst({
      where: { appId, status: ReviewStatus.IN_PROGRESS },
      orderBy: { createdAt: 'desc' },
    })
  },

  /** Create the IN_PROGRESS review record when a moderator claims an app. */
  async createInProgressReview(appId: string, reviewerId: string) {
    return db.moderationReview.create({
      data: { appId, reviewerId, status: ReviewStatus.IN_PROGRESS },
    })
  },

  /** Close the IN_PROGRESS review once the decision is submitted. */
  async closeReview(id: string, data: { status: ReviewStatus; rejectionReason?: string; notes?: string }) {
    return db.moderationReview.update({
      where: { id },
      data: { ...data, completedAt: new Date() },
    })
  },

  /**
   * Fetch the creator with their user record so we can include the email
   * address in the notification job payload.
   */
  async findCreatorWithUser(creatorId: string) {
    return db.creator.findUnique({
      where: { id: creatorId },
      include: { user: true },
    })
  },

  /** Full review history for an app — newest first. */
  async findReviewsByApp(appId: string) {
    return db.moderationReview.findMany({
      where: { appId },
      orderBy: { createdAt: 'desc' },
      include: { reviewer: { select: { id: true, email: true } } },
    })
  },
}
