import { AppStatus, PromotionStatus } from '@prisma/client'
import { promotionsRepository } from './promotions.repository'
import { appsRepository } from '../apps/apps.repository'
import { auditService } from '../audit/audit.service'
import { promotionsQueue } from '../../core/queue'
import { logger } from '../../core/logger'
import {
  BadRequestError,
  ForbiddenError,
  NotFoundError,
  UnprocessableError,
} from '../../core/errors'
import type { CreatePromotionJobBody, ListPromotionsQuery, RejectPromotionBody } from './promotions.schema'

// ---------------------------------------------------------------------------
// Promotion status machine
//
// Valid transitions — enforced in service methods, never in the router.
// ---------------------------------------------------------------------------

const CANCELLABLE_STATUSES: PromotionStatus[] = [
  PromotionStatus.PENDING_APPROVAL,
  PromotionStatus.APPROVED,
]

function withPages(result: { items: unknown[]; total: number }, page: number, limit: number) {
  return { ...result, page, limit, pages: Math.ceil(result.total / limit) }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export const promotionsService = {
  // ── Queries ───────────────────────────────────────────────────────────────

  async list(requestingUserId: string, isAdmin: boolean, query: ListPromotionsQuery) {
    const skip = (query.page - 1) * query.limit

    // Resolve the optional status filter string → PromotionStatus enum value.
    let statusFilter: PromotionStatus | undefined
    if (query.status) {
      if (!Object.values(PromotionStatus).includes(query.status as PromotionStatus)) {
        throw new BadRequestError(`Invalid status filter: '${query.status}'`)
      }
      statusFilter = query.status as PromotionStatus
    }

    const result = await promotionsRepository.findMany({
      appId:          query.appId,
      // Non-admins can only see their own requests.
      requestedById:  isAdmin ? undefined : requestingUserId,
      status:         statusFilter,
      take:           query.limit,
      skip,
    })

    return withPages(result, query.page, query.limit)
  },

  async get(jobId: string, requestingUserId: string, isAdmin: boolean) {
    const job = await promotionsRepository.findById(jobId)
    if (!job) throw new NotFoundError('PromotionJob', jobId)

    // Non-admins may only inspect their own jobs.
    if (!isAdmin && job.requestedById !== requestingUserId) throw new ForbiddenError()

    return job
  },

  // ── Create ────────────────────────────────────────────────────────────────

  /**
   * Request a promotion for a PUBLISHED app.
   *
   * Creators may only promote apps they own.
   * Admins may promote any published app.
   */
  async createJob(
    requestingUserId: string,
    isAdmin: boolean,
    body: CreatePromotionJobBody,
  ) {
    const app = await appsRepository.findById(body.appId)
    if (!app) throw new NotFoundError('App', body.appId)

    if (app.status !== AppStatus.PUBLISHED) {
      throw new UnprocessableError('Only PUBLISHED apps can be promoted', {
        current: app.status,
      })
    }

    // Creators must own the app.
    if (!isAdmin) {
      const creator = await appsRepository.findCreatorByUserId(requestingUserId)
      if (!creator || creator.id !== app.creatorId) throw new ForbiddenError()
    }

    const job = await promotionsRepository.create({
      appId:         body.appId,
      requestedById: requestingUserId,
      channel:       body.channel,
      metadata:      body.metadata ?? {},
      scheduledFor:  body.scheduledFor ? new Date(body.scheduledFor) : undefined,
    })

    // Audit — fire-and-forget
    void auditService.log({
      action:        'promotion.job_created',
      entityType:    'PromotionJob',
      entityId:      job.id,
      performedById: requestingUserId,
      after:         { status: job.status, channel: job.channel, appId: job.appId },
    })

    return job
  },

  // ── Approve ───────────────────────────────────────────────────────────────

  /**
   * Admin approves the promotion job and immediately enqueues it for execution.
   * Transition: PENDING_APPROVAL → APPROVED (enqueued).
   */
  async approve(jobId: string, adminUserId: string) {
    const job = await promotionsRepository.findById(jobId)
    if (!job) throw new NotFoundError('PromotionJob', jobId)

    if (job.status !== PromotionStatus.PENDING_APPROVAL) {
      throw new UnprocessableError(
        `Cannot approve a job with status '${job.status}'`,
        { current: job.status, required: PromotionStatus.PENDING_APPROVAL },
      )
    }

    const updated = await promotionsRepository.updateStatus(jobId, PromotionStatus.APPROVED, {
      approvedById: adminUserId,
      approvedAt:   new Date(),
    })

    // Enqueue for the promotion worker — fire-and-forget so a Redis outage
    // doesn't roll back the approval that is already committed in Postgres.
    promotionsQueue
      .add(
        'run-promotion',
        {
          promotionJobId: job.id,
          appId:          job.appId,
          appName:        job.app?.name ?? job.appId,
          channel:        job.channel,
          metadata:       (job.metadata as Record<string, unknown>) ?? {},
        },
        // Use the DB job ID as the BullMQ job ID so it's traceable across systems.
        { jobId: job.id },
      )
      .catch((err: unknown) => {
        logger.error(
          { err, promotionJobId: job.id },
          'Failed to enqueue promotion job — DB approval committed, manual re-queue needed',
        )
      })

    // Audit
    void auditService.log({
      action:        'promotion.job_approved',
      entityType:    'PromotionJob',
      entityId:      job.id,
      performedById: adminUserId,
      before:        { status: PromotionStatus.PENDING_APPROVAL },
      after:         { status: PromotionStatus.APPROVED, approvedById: adminUserId },
    })

    return updated
  },

  // ── Reject ────────────────────────────────────────────────────────────────

  /**
   * Admin rejects a pending promotion request.
   * Transition: PENDING_APPROVAL → REJECTED.
   */
  async reject(jobId: string, adminUserId: string, body: RejectPromotionBody) {
    const job = await promotionsRepository.findById(jobId)
    if (!job) throw new NotFoundError('PromotionJob', jobId)

    if (job.status !== PromotionStatus.PENDING_APPROVAL) {
      throw new UnprocessableError(
        `Cannot reject a job with status '${job.status}'`,
        { current: job.status, required: PromotionStatus.PENDING_APPROVAL },
      )
    }

    const updated = await promotionsRepository.updateStatus(jobId, PromotionStatus.REJECTED, {
      rejectedAt:      new Date(),
      rejectionReason: body.reason,
    })

    // Audit
    void auditService.log({
      action:        'promotion.job_rejected',
      entityType:    'PromotionJob',
      entityId:      job.id,
      performedById: adminUserId,
      before:        { status: PromotionStatus.PENDING_APPROVAL },
      after:         { status: PromotionStatus.REJECTED, rejectionReason: body.reason },
    })

    return updated
  },

  // ── Cancel ────────────────────────────────────────────────────────────────

  /**
   * Creator or admin cancels a job that hasn't started yet.
   * Transition: PENDING_APPROVAL | APPROVED → CANCELLED.
   */
  async cancel(jobId: string, requestingUserId: string, isAdmin: boolean) {
    const job = await promotionsRepository.findById(jobId)
    if (!job) throw new NotFoundError('PromotionJob', jobId)

    if (!isAdmin && job.requestedById !== requestingUserId) throw new ForbiddenError()

    if (!CANCELLABLE_STATUSES.includes(job.status)) {
      throw new UnprocessableError(
        `Cannot cancel a job with status '${job.status}'`,
        { current: job.status, cancellable: CANCELLABLE_STATUSES },
      )
    }

    const updated = await promotionsRepository.updateStatus(jobId, PromotionStatus.CANCELLED)

    // Audit
    void auditService.log({
      action:        'promotion.job_cancelled',
      entityType:    'PromotionJob',
      entityId:      job.id,
      performedById: requestingUserId,
      before:        { status: job.status },
      after:         { status: PromotionStatus.CANCELLED },
    })

    return updated
  },
}
