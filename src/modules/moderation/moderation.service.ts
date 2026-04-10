import { ReviewStatus } from '@prisma/client'
import { moderationRepository } from './moderation.repository'
import { appsService } from '../apps/apps.service'
import { notificationsQueue } from '../../core/queue'
import { logger } from '../../core/logger'
import { NotFoundError } from '../../core/errors'
import type { SubmitDecisionBody } from './moderation.schema'

// ---------------------------------------------------------------------------
// Moderation service — orchestrates the reviewer workflow.
//
// Flow:
//   1. Moderator views the review queue  →  getQueue()
//   2. Moderator claims an app           →  claim()
//      • Transitions app: SUBMITTED → IN_REVIEW
//      • Creates an IN_PROGRESS ModerationReview (records who claimed it)
//   3. Moderator submits a decision      →  submitDecision()
//      • Calls appsService.approve/reject (transitions app, creates the
//        APPROVED/REJECTED ModerationReview owned by the state machine)
//      • Closes the open IN_PROGRESS review from step 2
//      • Enqueues a 'decision-made' notification job
// ---------------------------------------------------------------------------

function withPages(result: { items: unknown[]; total: number }, page: number, limit: number) {
  return { ...result, page, limit, pages: Math.ceil(result.total / limit) }
}

export const moderationService = {
  // ── Queue listing ─────────────────────────────────────────────────────────

  async getQueue(opts: { page: number; limit: number }) {
    const skip = (opts.page - 1) * opts.limit
    const result = await moderationRepository.findSubmittedApps({ take: opts.limit, skip })
    return withPages(result, opts.page, opts.limit)
  },

  // ── Review history for a single app ──────────────────────────────────────

  async getReviewHistory(appId: string) {
    const app = await appsService.get(appId) // throws NotFoundError if missing
    const reviews = await moderationRepository.findReviewsByApp(appId)
    return { app, reviews }
  },

  // ── Claim ─────────────────────────────────────────────────────────────────

  /**
   * Assign the app to the calling moderator.
   *
   * Two writes happen here:
   *   1. App status: SUBMITTED → IN_REVIEW  (via appsService to enforce state machine)
   *   2. ModerationReview created: IN_PROGRESS, reviewerId = caller
   *
   * The review record from this step tracks *who* claimed the app and *when*.
   * It is separate from the decision review created in submitDecision.
   */
  async claim(appId: string, reviewerId: string) {
    const updatedApp = await appsService.startReview(appId)

    await moderationRepository.createInProgressReview(appId, reviewerId)

    return updatedApp
  },

  // ── Submit decision ───────────────────────────────────────────────────────

  /**
   * Record the moderator's verdict and dispatch a creator notification.
   *
   * Calls appsService.approve / appsService.reject so the state machine
   * (ALLOWED_TRANSITIONS, timestamps, ModerationReview for the decision)
   * runs in one place — no duplication here.
   *
   * The IN_PROGRESS review created during claim() is also closed so the
   * history shows both the assignment and the final verdict.
   */
  async submitDecision(appId: string, reviewerId: string, body: SubmitDecisionBody) {
    // 1. Transition app + create decision ModerationReview (via existing service)
    const updatedApp =
      body.decision === 'APPROVED'
        ? await appsService.approve(appId, reviewerId)
        : await appsService.reject(appId, reviewerId, { reason: body.reason! })

    // 2. Close the open claim review (if one exists — gracefully skip if not)
    const openReview = await moderationRepository.findActiveReview(appId)
    if (openReview) {
      await moderationRepository.closeReview(openReview.id, {
        status:          body.decision === 'APPROVED' ? ReviewStatus.APPROVED : ReviewStatus.REJECTED,
        rejectionReason: body.reason,
        notes:           body.notes,
      })
    }

    // 3. Enqueue notification — fire-and-forget; a Redis outage must not
    //    roll back a moderation decision that is already committed.
    const creator = await moderationRepository.findCreatorWithUser(updatedApp.creatorId)

    if (creator) {
      notificationsQueue
        .add('decision-made', {
          appId:        updatedApp.id,
          appName:      updatedApp.name,
          decision:     body.decision,
          reason:       body.reason,
          creatorId:    creator.id,
          creatorEmail: creator.user.email,
        })
        .catch((err: unknown) => {
          logger.error(
            { err, appId, decision: body.decision },
            'Failed to enqueue decision-made notification — decision was committed',
          )
        })
    } else {
      logger.warn({ appId }, 'Creator not found when enqueuing decision notification')
    }

    return updatedApp
  },
}
