import { Queue } from 'bullmq'
import { redisConnection } from './connection'

// ---------------------------------------------------------------------------
// Shared job options — retry with exponential back-off, keep a rolling
// window of completed / failed jobs for debugging.
// ---------------------------------------------------------------------------

const defaultJobOptions = {
  attempts: 3,
  backoff: { type: 'exponential' as const, delay: 5_000 },
  removeOnComplete: { count: 1_000 },
  removeOnFail:     { count: 5_000 },
}

// ---------------------------------------------------------------------------
// Job payload types
//
// Defined here (not in individual modules) so the queues file is the single
// source of truth for what flows through the message bus.
// ---------------------------------------------------------------------------

/** Enqueued by apps.service.ts when a creator submits an app for review. */
export interface AppSubmittedPayload {
  appId:       string
  appName:     string
  creatorId:   string
  submittedAt: string // ISO-8601
}

/** Enqueued by moderation.service.ts after a reviewer approves or rejects. */
export interface DecisionMadePayload {
  appId:        string
  appName:      string
  decision:     'APPROVED' | 'REJECTED'
  reason?:      string
  creatorId:    string
  creatorEmail: string
}

/** Enqueued by promotions.service.ts when an admin approves a promotion job. */
export interface RunPromotionPayload {
  /** PromotionJob.id in the database. */
  promotionJobId: string
  appId:          string
  appName:        string
  channel:        string
  /** Channel-specific request data passed through from the creator's request. */
  metadata:       Record<string, unknown>
}

// ---------------------------------------------------------------------------
// Named queues
// ---------------------------------------------------------------------------

/**
 * Receives an 'app-submitted' job every time a creator submits an app.
 * Moderators poll this queue through the moderation API endpoints.
 */
export const moderationQueue = new Queue<AppSubmittedPayload>('moderation', {
  connection: redisConnection,
  defaultJobOptions,
})

/**
 * Receives a 'decision-made' job every time a moderator approves or rejects.
 * The notification worker processes these and (currently) logs a simulated email.
 */
export const notificationsQueue = new Queue<DecisionMadePayload>('notifications', {
  connection: redisConnection,
  defaultJobOptions,
})

/**
 * Receives a 'run-promotion' job when an admin approves a promotion request.
 * The promotion worker simulates the external channel API call and updates
 * PromotionJob / PromotionRun status in the database.
 *
 * Retry config is intentionally conservative: external promotion APIs are
 * idempotent in the real integration, but we don't want to spam a channel.
 */
export const promotionsQueue = new Queue<RunPromotionPayload>('promotions', {
  connection: redisConnection,
  defaultJobOptions: {
    ...defaultJobOptions,
    attempts: 3,
    backoff: { type: 'exponential' as const, delay: 10_000 },
  },
})
