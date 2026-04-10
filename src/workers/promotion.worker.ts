import { Worker, type Job } from 'bullmq'
import { PromotionStatus, RunStatus } from '@prisma/client'
import { redisConnection } from '../core/queue'
import type { RunPromotionPayload } from '../core/queue'
import { promotionsRepository } from '../modules/promotions/promotions.repository'
import { auditService } from '../modules/audit/audit.service'
import { logger } from '../core/logger'

// ---------------------------------------------------------------------------
// Promotion worker — processes 'run-promotion' jobs from the promotions queue.
//
// Each BullMQ job execution maps to one PromotionRun row so every attempt
// (including retries after failure) is independently tracked in the database.
//
// Lifecycle per attempt:
//   1. Create PromotionRun  (status: RUNNING)
//   2. Update PromotionJob  (status: IN_PROGRESS)
//   3. Simulate external API call (10 s delay — replace with real SDK call)
//   4a. Success → PromotionRun SUCCEEDED, PromotionJob COMPLETED
//   4b. Failure → PromotionRun FAILED, re-throw so BullMQ can retry
//       After final retry → PromotionJob FAILED (handled in 'failed' listener)
//
// STUB: the external API call is simulated with a setTimeout.
// Replace the stub block with the real OpenClaw / Paperclip SDK call.
// ---------------------------------------------------------------------------

const SIMULATED_CALL_DURATION_MS = 10_000

/** Build a deterministic fake external ID so the stub is realistic. */
function fakeExternalId(channel: string, jobId: string): string {
  return `${channel.toUpperCase()}_${jobId.slice(0, 8).toUpperCase()}_${Date.now()}`
}

async function processor(job: Job<RunPromotionPayload>): Promise<void> {
  const { promotionJobId, appId, appName, channel, metadata } = job.data
  const attemptNumber = job.attemptsMade + 1

  logger.info(
    { jobId: job.id, promotionJobId, appId, channel, attempt: attemptNumber },
    `[PromotionWorker] Starting attempt #${attemptNumber} for "${appName}" on ${channel}`,
  )

  // 1. Create a PromotionRun row for this attempt.
  const run = await promotionsRepository.createRun({
    jobId:          promotionJobId,
    attemptNumber,
    status:         RunStatus.RUNNING,
    startedAt:      new Date(),
    requestPayload: { appId, channel, metadata },
  })

  // 2. Mark the parent PromotionJob as actively running.
  await promotionsRepository.updateStatus(promotionJobId, PromotionStatus.IN_PROGRESS)

  try {
    // ── STUB ─────────────────────────────────────────────────────────────
    // Replace the block below with your real channel API call, e.g.:
    //
    //   import { OpenClawClient } from '@openclaw/sdk'
    //   const client = new OpenClawClient({ apiKey: config.OPENCLAW_API_KEY })
    //   const response = await client.promote({ appId, ...metadata })
    //
    logger.info(
      { promotionJobId, channel },
      `[PromotionWorker] Calling ${channel} API… (simulated ${SIMULATED_CALL_DURATION_MS / 1000}s)`,
    )
    await new Promise<void>((resolve) => setTimeout(resolve, SIMULATED_CALL_DURATION_MS))

    const responsePayload = {
      externalId: fakeExternalId(channel, promotionJobId),
      channel,
      status:     'submitted',
      message:    `App "${appName}" successfully submitted to ${channel}.`,
      submittedAt: new Date().toISOString(),
    }
    // ─────────────────────────────────────────────────────────────────────

    // 4a. Success — persist results and advance job to COMPLETED.
    await promotionsRepository.updateRun(run.id, {
      status:          RunStatus.SUCCESS,
      completedAt:     new Date(),
      responsePayload,
    })

    await promotionsRepository.updateStatus(promotionJobId, PromotionStatus.COMPLETED)

    // Audit the successful completion.
    void auditService.log({
      action:     'promotion.run_completed',
      entityType: 'PromotionJob',
      entityId:   promotionJobId,
      after:      { status: PromotionStatus.COMPLETED, runId: run.id, responsePayload },
    })

    logger.info(
      { promotionJobId, channel, runId: run.id },
      `[PromotionWorker] Promotion completed for "${appName}"`,
    )
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err)

    // 4b. Failure — record the error on the run, then re-throw so BullMQ
    //     retries according to the queue's backoff config.
    await promotionsRepository.updateRun(run.id, {
      status:       RunStatus.FAILED,
      completedAt:  new Date(),
      errorMessage,
    })

    logger.error(
      { promotionJobId, channel, attempt: attemptNumber, err },
      `[PromotionWorker] Attempt #${attemptNumber} failed for "${appName}"`,
    )

    // Re-throw so BullMQ knows this attempt failed.
    throw err
  }
}

export function createPromotionWorker(): Worker<RunPromotionPayload> {
  const worker = new Worker<RunPromotionPayload>('promotions', processor, {
    connection:  redisConnection,
    concurrency: 2, // Low concurrency — external APIs are typically rate-limited.
  })

  worker.on('completed', (job) => {
    logger.info(
      { bullJobId: job.id, promotionJobId: job.data.promotionJobId },
      '[PromotionWorker] BullMQ job completed',
    )
  })

  /**
   * 'failed' fires after EVERY failed attempt (not just the last).
   * We only mark the PromotionJob as FAILED once all retries are exhausted.
   */
  worker.on('failed', (job, err) => {
    if (!job) return

    const attemptsExhausted = job.attemptsMade >= (job.opts.attempts ?? 1)

    logger.error(
      {
        bullJobId:      job.id,
        promotionJobId: job.data.promotionJobId,
        attempt:        job.attemptsMade,
        attemptsExhausted,
        err,
      },
      '[PromotionWorker] BullMQ job attempt failed',
    )

    if (attemptsExhausted) {
      // All retries consumed — permanently mark the PromotionJob as FAILED.
      promotionsRepository
        .updateStatus(job.data.promotionJobId, PromotionStatus.FAILED)
        .then(() => {
          void auditService.log({
            action:     'promotion.run_failed',
            entityType: 'PromotionJob',
            entityId:   job.data.promotionJobId,
            after:      { status: PromotionStatus.FAILED, attempts: job.attemptsMade },
            metadata:   { errorMessage: err.message },
          })
        })
        .catch((dbErr: unknown) => {
          logger.error(
            { dbErr, promotionJobId: job.data.promotionJobId },
            '[PromotionWorker] Could not mark PromotionJob as FAILED after exhausted retries',
          )
        })
    }
  })

  worker.on('error', (err) => {
    logger.error({ err }, '[PromotionWorker] Worker error')
  })

  logger.info('[PromotionWorker] Started — listening on queue: promotions')

  return worker
}
