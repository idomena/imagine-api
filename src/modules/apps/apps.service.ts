import { AppStatus, ReviewStatus, type App } from '@prisma/client'
import { appsRepository } from './apps.repository'
import {
  ConflictError,
  ForbiddenError,
  NotFoundError,
  UnprocessableError,
} from '../../core/errors'
import { moderationQueue } from '../../core/queue'
import { logger } from '../../core/logger'
import type { CreateAppBody, RejectAppBody, RenameAppBody, UpdateAppBody } from './apps.schema'

// ---------------------------------------------------------------------------
// App state machine
//
// Status transitions are the single source of truth for allowed moves.
// The service layer is the ONLY place that may change app.status — routers
// must never pass a `status` field to update().
// ---------------------------------------------------------------------------

const ALLOWED_TRANSITIONS: Partial<Record<AppStatus, AppStatus[]>> = {
  [AppStatus.DRAFT]:     [AppStatus.SUBMITTED],
  [AppStatus.SUBMITTED]: [AppStatus.IN_REVIEW, AppStatus.PUBLISHED, AppStatus.REJECTED],
  [AppStatus.IN_REVIEW]: [AppStatus.APPROVED, AppStatus.REJECTED],
  [AppStatus.APPROVED]:  [AppStatus.PUBLISHED],
  [AppStatus.PUBLISHED]: [AppStatus.ARCHIVED],
  // REJECTED and ARCHIVED are terminal — no forward transition.
  // A rejected app requires a new submission workflow (Phase 4).
}

function assertTransition(app: App, target: AppStatus): void {
  const allowed = ALLOWED_TRANSITIONS[app.status] ?? []
  if (!allowed.includes(target)) {
    throw new UnprocessableError(
      `Cannot transition app from '${app.status}' to '${target}'`,
      { current: app.status, requested: target, allowed },
    )
  }
}

// ---------------------------------------------------------------------------
// Ownership guard — throws ForbiddenError if the creator doesn't own the app.
// ---------------------------------------------------------------------------

function assertCreatorOwns(app: App, creatorId: string): void {
  if (app.creatorId !== creatorId) throw new ForbiddenError()
}

// ---------------------------------------------------------------------------
// Pagination helper
// ---------------------------------------------------------------------------

function paginate(page: number, limit: number) {
  return { take: limit, skip: (page - 1) * limit }
}

function withPages(result: { items: unknown[]; total: number }, page: number, limit: number) {
  return { ...result, page, limit, pages: Math.ceil(result.total / limit) }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export const appsService = {
  // ── Queries ───────────────────────────────────────────────────────────────

  async listPublished(opts: { categoryId?: string; page: number; limit: number }) {
    const result = await appsRepository.findManyPublished({
      categoryId: opts.categoryId,
      ...paginate(opts.page, opts.limit),
    })
    return withPages(result, opts.page, opts.limit)
  },

  async listForAdmin(opts: { status?: AppStatus; page: number; limit: number }) {
    const result = await appsRepository.findManyForAdmin({
      status: opts.status,
      ...paginate(opts.page, opts.limit),
    })
    return withPages(result, opts.page, opts.limit)
  },

  async listByCreator(creatorId: string, opts: { page: number; limit: number }) {
    const result = await appsRepository.findManyByCreator(creatorId, paginate(opts.page, opts.limit))
    return withPages(result, opts.page, opts.limit)
  },

  async get(idOrSlug: string) {
    // Accept either a UUID or a slug so live-page links can use human-readable slugs.
    const app = await appsRepository.findById(idOrSlug)
      ?? await appsRepository.findBySlug(idOrSlug)
    if (!app) throw new NotFoundError('App', idOrSlug)
    return app
  },

  // ── Creator CRUD ──────────────────────────────────────────────────────────

  /**
   * Resolve the Creator record for the given User ID.
   * Throws ForbiddenError if no profile exists (shouldn't happen after onboard,
   * but guards against inconsistent state).
   */
  async resolveCreator(userId: string) {
    if (!userId) {
      throw new ForbiddenError('Not authenticated — user ID is missing from token')
    }
    const creator = await appsRepository.findCreatorByUserId(userId)
    if (!creator) {
      throw new ForbiddenError(
        'Creator profile not found. Please sign out and sign back in to complete your account setup.',
      )
    }
    return creator
  },

  async create(creatorId: string, body: CreateAppBody) {
    const slugConflict = await appsRepository.findBySlug(body.slug)
    if (slugConflict) throw new ConflictError(`Slug '${body.slug}' is already taken`)
    return appsRepository.create(creatorId, body)
  },

  async update(appId: string, creatorId: string, body: UpdateAppBody) {
    const app = await appsService.get(appId)
    assertCreatorOwns(app, creatorId)
    return appsRepository.update(appId, body)
  },

  async rename(appId: string, creatorId: string, body: RenameAppBody) {
    const app = await appsService.get(appId)
    assertCreatorOwns(app, creatorId)
    return appsRepository.update(appId, { name: body.name })
  },

  async updateIcon(appId: string, creatorId: string, iconUrl: string) {
    const app = await appsService.get(appId)
    assertCreatorOwns(app, creatorId)
    return appsRepository.update(appId, { iconUrl })
  },

  async creatorArchive(appId: string, creatorId: string) {
    const app = await appsService.get(appId)
    assertCreatorOwns(app, creatorId)
    assertTransition(app, AppStatus.ARCHIVED)
    return appsRepository.transition(appId, {
      status: AppStatus.ARCHIVED,
      archivedAt: new Date(),
    })
  },

  async delete(appId: string, creatorId: string) {
    const app = await appsService.get(appId)
    assertCreatorOwns(app, creatorId)
    await appsRepository.delete(appId)
  },

  // ── State transitions ─────────────────────────────────────────────────────
  // Each method follows the same pattern:
  //   1. Fetch app & validate it exists
  //   2. Assert the transition is allowed (throws if not)
  //   3. Apply the patch — status + lifecycle timestamp
  //   4. Optionally write a ModerationReview audit record

  async submit(appId: string, creatorId: string) {
    const app = await appsService.get(appId)
    assertCreatorOwns(app, creatorId)
    assertTransition(app, AppStatus.SUBMITTED)

    const updated = await appsRepository.transition(appId, {
      status: AppStatus.SUBMITTED,
      submittedAt: new Date(),
    })

    // Enqueue a moderation job so the review queue reflects the submission.
    // This is intentionally fire-and-forget: a Redis outage must never block
    // a creator from submitting their app.
    moderationQueue
      .add('app-submitted', {
        appId:       updated.id,
        appName:     updated.name,
        creatorId,
        submittedAt: updated.submittedAt?.toISOString() ?? new Date().toISOString(),
      })
      .catch((err: unknown) => {
        logger.error({ err, appId }, 'Failed to enqueue app-submitted job — app transition succeeded')
      })

    return updated
  },

  async startReview(appId: string) {
    const app = await appsService.get(appId)
    assertTransition(app, AppStatus.IN_REVIEW)
    return appsRepository.transition(appId, { status: AppStatus.IN_REVIEW })
  },

  async approve(appId: string, reviewerId: string) {
    const app = await appsService.get(appId)
    assertTransition(app, AppStatus.APPROVED)
    const [updated] = await Promise.all([
      appsRepository.transition(appId, {
        status: AppStatus.APPROVED,
        approvedAt: new Date(),
      }),
      appsRepository.createModerationReview({
        appId,
        reviewerId,
        status: ReviewStatus.APPROVED,
      }),
    ])
    return updated
  },

  async reject(appId: string, reviewerId: string, body: RejectAppBody) {
    const app = await appsService.get(appId)
    assertTransition(app, AppStatus.REJECTED)
    const [updated] = await Promise.all([
      appsRepository.transition(appId, {
        status: AppStatus.REJECTED,
        rejectedAt: new Date(),
      }),
      appsRepository.createModerationReview({
        appId,
        reviewerId,
        status: ReviewStatus.REJECTED,
        rejectionReason: body.reason,
      }),
    ])
    return updated
  },

  async publish(appId: string) {
    const app = await appsService.get(appId)
    assertTransition(app, AppStatus.PUBLISHED)
    return appsRepository.transition(appId, {
      status: AppStatus.PUBLISHED,
      publishedAt: new Date(),
    })
  },

  async archive(appId: string) {
    const app = await appsService.get(appId)
    assertTransition(app, AppStatus.ARCHIVED)
    return appsRepository.transition(appId, {
      status: AppStatus.ARCHIVED,
      archivedAt: new Date(),
    })
  },

  // ── Admin panel shortcuts ─────────────────────────────────────────────────
  // Direct SUBMITTED → PUBLISHED bypass for the simple admin panel.

  async adminApprove(appId: string) {
    const app = await appsService.get(appId)
    assertTransition(app, AppStatus.PUBLISHED)
    return appsRepository.transition(appId, {
      status:      AppStatus.PUBLISHED,
      approvedAt:  new Date(),
      publishedAt: new Date(),
    })
  },

  async adminReject(appId: string) {
    const app = await appsService.get(appId)
    assertTransition(app, AppStatus.REJECTED)
    return appsRepository.transition(appId, {
      status:     AppStatus.REJECTED,
      rejectedAt: new Date(),
    })
  },

  /** Security override: silently revert a PUBLISHED app back to SUBMITTED.
   *  Called only by the background scanner when a malicious script is found.
   *  Bypasses the state machine intentionally — this is a security action. */
  async securityRevert(appId: string) {
    return appsRepository.securityRevert(appId)
  },
}
