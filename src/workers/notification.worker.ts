import { Worker, type Job } from 'bullmq'
import { redisConnection } from '../core/queue'
import type { DecisionMadePayload } from '../core/queue'
import { logger } from '../core/logger'

// ---------------------------------------------------------------------------
// Notification worker — processes 'decision-made' jobs from the notifications
// queue and dispatches creator emails.
//
// STUB: currently logs a simulated email to the console.
//
// To activate real email delivery, replace the stub block inside the
// processor with a call to your transactional email provider (Resend,
// SendGrid, Postmark, etc.).  The payload shape is already production-ready.
// ---------------------------------------------------------------------------

function buildEmailBody(payload: DecisionMadePayload): string {
  if (payload.decision === 'APPROVED') {
    return (
      `Your app "${payload.appName}" has been approved. ` +
      `An admin will publish it shortly.`
    )
  }

  return (
    `Your app "${payload.appName}" was not approved. ` +
    `Reason: ${payload.reason ?? 'No reason provided.'} ` +
    `Please address the feedback and resubmit.`
  )
}

async function processor(job: Job<DecisionMadePayload>): Promise<void> {
  const { appId, appName, decision, creatorEmail } = job.data
  const body = buildEmailBody(job.data)

  // ── STUB ────────────────��────────────────────────────────���────────────
  // Replace with your email SDK call, e.g.:
  //
  //   await resend.emails.send({
  //     from:    'noreply@appmarket.dev',
  //     to:      creatorEmail,
  //     subject: decision === 'APPROVED'
  //       ? `✅ "${appName}" approved`
  //       : `❌ "${appName}" was not approved`,
  //     html:    renderEmailTemplate(job.data),
  //   })
  //
  logger.info(
    { jobId: job.id, appId, appName, decision, to: creatorEmail },
    `[NotificationWorker] Email sent to creator: ${body}`,
  )
  // ────────────────────────────────────────────────────��─────────────────
}

export function createNotificationWorker(): Worker<DecisionMadePayload> {
  const worker = new Worker<DecisionMadePayload>('notifications', processor, {
    connection: redisConnection,
    concurrency: 5,
  })

  worker.on('completed', (job) => {
    logger.info({ jobId: job.id, jobName: job.name }, '[NotificationWorker] Job completed')
  })

  worker.on('failed', (job, err) => {
    logger.error({ jobId: job?.id, jobName: job?.name, err }, '[NotificationWorker] Job failed')
  })

  worker.on('error', (err) => {
    logger.error({ err }, '[NotificationWorker] Worker error')
  })

  logger.info('[NotificationWorker] Started — listening on queue: notifications')

  return worker
}
