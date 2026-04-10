import { Prisma, PromotionStatus, RunStatus } from '@prisma/client'
import { db } from '../../core/db'

// ---------------------------------------------------------------------------
// Promotions repository — raw DB access, no business logic.
// ---------------------------------------------------------------------------

export const promotionsRepository = {
  // ── PromotionJob ──────────────────────────────────────────────────────────

  async findById(id: string) {
    return db.promotionJob.findUnique({
      where: { id },
      include: {
        app:  { select: { id: true, name: true, status: true, creatorId: true } },
        runs: { orderBy: { createdAt: 'desc' } },
      },
    })
  },

  async findMany(opts: {
    appId?:         string
    requestedById?: string
    status?:        PromotionStatus
    take:           number
    skip:           number
  }) {
    const where: Prisma.PromotionJobWhereInput = {
      ...(opts.appId         ? { appId:         opts.appId         } : {}),
      ...(opts.requestedById ? { requestedById: opts.requestedById } : {}),
      ...(opts.status        ? { status:         opts.status        } : {}),
    }

    const [items, total] = await db.$transaction([
      db.promotionJob.findMany({
        where,
        take:    opts.take,
        skip:    opts.skip,
        orderBy: { createdAt: 'desc' },
        include: { runs: { orderBy: { createdAt: 'desc' }, take: 1 } },
      }),
      db.promotionJob.count({ where }),
    ])

    return { items, total }
  },

  async create(data: {
    appId:          string
    requestedById:  string
    channel:        string
    metadata?:      Record<string, unknown>
    scheduledFor?:  Date
  }) {
    return db.promotionJob.create({
      data: {
        appId:         data.appId,
        requestedById: data.requestedById,
        channel:       data.channel,
        metadata:      data.metadata as Prisma.InputJsonValue | undefined,
        scheduledFor:  data.scheduledFor,
        status:        PromotionStatus.PENDING_APPROVAL,
      },
    })
  },

  async updateStatus(
    id:   string,
    status: PromotionStatus,
    extra?: {
      approvedById?:    string
      approvedAt?:      Date
      rejectedAt?:      Date
      rejectionReason?: string
    },
  ) {
    return db.promotionJob.update({
      where: { id },
      data:  { status, ...extra },
    })
  },

  // ── PromotionRun ──────────────────────────────────────────────────────────

  async createRun(data: {
    jobId:           string
    attemptNumber:   number
    status:          RunStatus
    startedAt?:      Date
    requestPayload?: Record<string, unknown>
  }) {
    return db.promotionRun.create({
      data: {
        jobId:          data.jobId,
        attemptNumber:  data.attemptNumber,
        status:         data.status,
        startedAt:      data.startedAt,
        requestPayload: data.requestPayload as Prisma.InputJsonValue | undefined,
      },
    })
  },

  async updateRun(
    id: string,
    data: {
      status:           RunStatus
      completedAt?:     Date
      errorMessage?:    string
      responsePayload?: Record<string, unknown>
    },
  ) {
    return db.promotionRun.update({
      where: { id },
      data: {
        status:          data.status,
        completedAt:     data.completedAt,
        errorMessage:    data.errorMessage,
        responsePayload: data.responsePayload as Prisma.InputJsonValue | undefined,
      },
    })
  },
}
