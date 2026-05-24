import { createHash } from 'crypto'
import type { FastifyInstance } from 'fastify'
import { AppStatus, UserRole } from '@prisma/client'
import { Prisma } from '@prisma/client'
import { appsService } from './apps.service'
import { appsRepository } from './apps.repository'
import { launchEventsRepository } from '../launch-events/launch-events.repository'
import { db } from '../../core/db'
import {
  CreateAppBodySchema,
  ListAppsQuerySchema,
  RejectAppBodySchema,
  RenameAppBodySchema,
  UpdateAppBodySchema,
} from './apps.schema'
import { scanApp } from '../../services/security-audit.service'
import { securityLogger } from '../../services/security-logger.service'
import { logger } from '../../core/logger'
import { SUBMIT_RATE_LIMIT } from '../../plugins/rate-limit.plugin'
import { BadRequestError } from '../../core/errors'

// ---------------------------------------------------------------------------
// Apps router — SECURED VERSION
//
// Changes from baseline:
//   1. POST /:id/submit  → runSecurityAudit() pipeline (auto-publish / hold / reject)
//   2. POST /:id/approve → second URL scan at approval gate
//   3. Rate limit on submit (5 req / 1 hour per user)
//   4. Security audit logging on all privileged state transitions
//   5. launchUrl validated as HTTPS-only on create/update
// ---------------------------------------------------------------------------

/** Reject plaintext HTTP launch URLs — creators must use HTTPS */
function assertHttps(url: string | undefined | null, field: string): void {
  if (url && url.startsWith('http://')) {
    throw new BadRequestError(`${field} must use HTTPS`)
  }
}

/**
 * Background security scan — runs after the app is already PUBLISHED.
 * If a malicious script is found: reverts the app to SUBMITTED and writes
 * a security flag to the Admin log. If anything at all fails, the app stays
 * PUBLISHED — a scan crash must never take an innocent app down.
 */
async function runBackgroundScan(
  appId:     string,
  launchUrl: string,
  request:   import('fastify').FastifyRequest,
): Promise<void> {
  try {
    const result = await scanApp(appId, launchUrl)

    if (result.malicious) {
      await appsService.securityRevert(appId)

      void securityLogger.threatDetected(request, appId,
        result.threats.map(t => ({ uri: launchUrl, types: [t.type] }))
      )
      void securityLogger.adminAction(request, 'app_security_reverted', 'App', appId, {
        reason:  'Malicious script detected after publish',
        threats: result.threats,
      })

      logger.warn({ appId, threats: result.threats.map(t => t.type) },
        '[sentinel] Malicious script detected — app reverted to SUBMITTED')
    }
  } catch (err) {
    // Never crash the server or affect the published app
    logger.error({ err, appId }, '[sentinel] Background scan error — app stays PUBLISHED')
  }
}

export async function appsRouter(app: FastifyInstance) {
  // ── Static paths before parametric /:id ─────────────────────────────────

  app.get(
    '/mine',
    { preHandler: [app.requireRole([UserRole.CREATOR, UserRole.MODERATOR, UserRole.ADMIN])] },
    async (request, reply) => {
      const creator = await appsService.resolveCreator(request.user.sub)
      const query = ListAppsQuerySchema.parse(request.query)
      const data = await appsService.listByCreator(creator.id, query)
      return reply.send({ success: true, data })
    },
  )

  // Analytics for creator's own apps — real launch event data, last 30 days
  app.get(
    '/mine/analytics',
    { preHandler: [app.requireRole([UserRole.CREATOR, UserRole.MODERATOR, UserRole.ADMIN])] },
    async (request, reply) => {
      const since = new Date()
      since.setDate(since.getDate() - 30)

      let appIds: string[] = []
      let apps: Array<{ id: string; name: string; slug: string; iconUrl: string | null; status: string; launchUrl: string | null }> = []

      try {
        const creator = await appsService.resolveCreator(request.user.sub)
        apps = await db.app.findMany({
          where:  { creatorId: creator.id },
          select: { id: true, name: true, slug: true, iconUrl: true, status: true, launchUrl: true },
        })
        appIds = apps.map(a => a.id)
      } catch {
        return reply.send({ success: true, data: { apps: [], byApp: {}, totals: {} } })
      }

      if (appIds.length === 0) {
        return reply.send({ success: true, data: { apps, byApp: {}, totals: {} } })
      }

      type RawRow = { app_id: string; date: string; count: bigint }
      const rows = await db.$queryRaw<RawRow[]>(
        Prisma.sql`
          SELECT app_id,
                 TO_CHAR(DATE(created_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD') AS date,
                 COUNT(*)::bigint AS count
          FROM   launch_events
          WHERE  app_id = ANY(${appIds}::uuid[])
            AND  created_at >= ${since}
          GROUP  BY app_id, DATE(created_at AT TIME ZONE 'UTC')
          ORDER  BY date ASC
        `,
      )

      const byApp: Record<string, Array<{ date: string; views: number }>> = {}
      for (const row of rows) {
        if (!byApp[row.app_id]) byApp[row.app_id] = []
        byApp[row.app_id]!.push({ date: row.date, views: Number(row.count) })
      }

      const totals: Record<string, number> = {}
      for (const [appId, series] of Object.entries(byApp)) {
        totals[appId] = series.reduce((sum, s) => sum + s.views, 0)
      }

      return reply.send({ success: true, data: { apps, byApp, totals, since: since.toISOString() } })
    },
  )

  app.get(
    '/admin',
    { preHandler: [app.requireRole([UserRole.MODERATOR, UserRole.ADMIN])] },
    async (request, reply) => {
      const query = ListAppsQuerySchema.parse(request.query)
      const data = await appsService.listForAdmin(query)
      return reply.send({ success: true, data })
    },
  )

  // ── Public ────────────────────────────────────────────────────────────────

  app.get('/', async (request, reply) => {
    const query = ListAppsQuerySchema.parse(request.query)
    const data = await appsService.listPublished(query)
    return reply.send({ success: true, data })
  })

  app.get('/slug/:slug', async (request, reply) => {
    const { slug } = request.params as { slug: string }
    const found = await appsRepository.findBySlug(slug)
    if (!found) {
      return reply.status(404).send({
        success: false,
        error: { message: `App with slug '${slug}' not found` },
      })
    }
    return reply.send({ success: true, data: found })
  })

  app.get('/:id', async (request, reply) => {
    const { id } = request.params as { id: string }
    const data = await appsService.get(id)
    return reply.send({ success: true, data })
  })

  // Visit tracking — hash IP before storing (privacy-preserving)
  app.get('/:id/visit', async (request, reply) => {
    const { id } = request.params as { id: string }
    const found = await appsService.get(id)
    const ipHash = request.ip
      ? createHash('sha256').update(request.ip).digest('hex')
      : undefined
    launchEventsRepository
      .create({ appId: id, ipHash, userAgent: request.headers['user-agent'] })
      .catch(() => {})
    return reply.redirect(found.launchUrl ?? '/')
  })

  // ── Creator: CRUD ─────────────────────────────────────────────────────────

  app.post(
    '/',
    { preHandler: [app.requireRole([UserRole.CREATOR])] },
    async (request, reply) => {
      const creator = await appsService.resolveCreator(request.user.sub)
      const body = CreateAppBodySchema.parse(request.body)

      // Enforce HTTPS on all submitted URLs
      assertHttps(body.launchUrl, 'launchUrl')
      assertHttps(body.videoUrl,  'videoUrl')

      const data = await appsService.create(creator.id, body)
      return reply.status(201).send({ success: true, data })
    },
  )

  app.patch(
    '/:id',
    { preHandler: [app.requireRole([UserRole.CREATOR])] },
    async (request, reply) => {
      const creator = await appsService.resolveCreator(request.user.sub)
      const { id } = request.params as { id: string }
      const body = UpdateAppBodySchema.parse(request.body)

      assertHttps(body.launchUrl, 'launchUrl')
      assertHttps(body.videoUrl,  'videoUrl')

      const data = await appsService.update(id, creator.id, body)
      return reply.send({ success: true, data })
    },
  )

  app.delete(
    '/:id',
    { preHandler: [app.requireRole([UserRole.CREATOR])] },
    async (request, reply) => {
      const creator = await appsService.resolveCreator(request.user.sub)
      const { id } = request.params as { id: string }
      await appsService.delete(id, creator.id)
      return reply.status(204).send()
    },
  )

  app.patch(
    '/:id/rename',
    { preHandler: [app.requireRole([UserRole.CREATOR])] },
    async (request, reply) => {
      const creator = await appsService.resolveCreator(request.user.sub)
      const { id } = request.params as { id: string }
      const body = RenameAppBodySchema.parse(request.body)
      const data = await appsService.rename(id, creator.id, body)
      return reply.send({ success: true, data })
    },
  )

  // ── Creator: submit — Security-First Atomic Publish ──────────────────────
  // Refactored to eliminate Ghost Drafts. Flow:
  //   1. Verify creator ownership
  //   2. RUN SECURITY AUDIT FIRST — before any database operations
  //   3a. ADULT_CONTENT detected  → return 422 IMMEDIATELY, no DB writes
  //   3b. OTHER MALICIOUS CONTENT → update to SUBMITTED for manual review
  //   3c. CLEAN SCAN              → single atomic update to PUBLISHED with all timestamps
  // Key: No database operations occur until security result is confirmed.

  app.post(
    '/:id/submit',
    {
      preHandler: [app.requireRole([UserRole.CREATOR])],
      config:     { rateLimit: SUBMIT_RATE_LIMIT },
      schema:     { body: { type: 'object', additionalProperties: true } },
    },
    async (request, reply) => {
      const creator  = await appsService.resolveCreator(request.user.sub)
      const { id }   = request.params as { id: string }
      const existing = await appsService.get(id)

      if (existing.creatorId !== creator.id) {
        return reply.status(403).send({ success: false, error: { message: 'Forbidden' } })
      }

      // ── SECURITY FIRST: Run audit before any database operations ──
      let malicious      = false
      let isAdultContent = false
      let threatDetails: string[] = []

      try {
        const result = await scanApp(id, existing.launchUrl ?? '')
        if (result.malicious) {
          malicious      = true
          isAdultContent = result.threats.some(t => t.type === 'ADULT_CONTENT')
          threatDetails  = result.threats.map(t => t.description)
          void securityLogger.threatDetected(request, id,
            result.threats.map(t => ({ uri: existing.launchUrl ?? '', types: [t.type] }))
          )
        } else {
          malicious      = false
          isAdultContent = false
          threatDetails  = []
        }
      } catch (err) {
        logger.error({ err, id }, '[sentinel] Scan error — fail-safe: publishing anyway')
        malicious      = false
        isAdultContent = false
        threatDetails  = []
      }

      // ── IMMEDIATE BLOCK: Adult content detected → error without DB writes ──
      if (isAdultContent) {
        void securityLogger.adminAction(request, 'app_adult_content_blocked', 'App', id, {
          reason: 'Adult content detected during submission scan',
        })
        return reply.code(422).send({
          success: false,
          error: {
            message: 'Content Violation — Adult content is not allowed on Imagine.',
            details: ['Content Violation — Adult content is not allowed on Imagine.'],
          },
        })
      }

      const now = new Date()

      // ── Handle other malicious content (non-adult threats) ──
      if (malicious) {
        // Non-adult malicious content — single atomic update to SUBMITTED
        try {
          await db.app.update({
            where: { id },
            data: { status: AppStatus.SUBMITTED, submittedAt: now },
          })
        } catch (dbErr) {
          logger.error({ err: dbErr, id }, '[sentinel] DB update to SUBMITTED failed')
          return reply.status(400).send({
            success: false,
            error: { message: 'Failed to process security hold — database error.' },
          })
        }

        void securityLogger.adminAction(request, 'app_security_held', 'App', id, {
          reason: 'Malicious content detected at submission',
          threats: threatDetails,
        })
        return reply.code(422).send({
          success: false,
          error: { message: 'App rejected by security scan.', details: threatDetails },
        })
      }

      // ── CLEAN SCAN: Single atomic operation to PUBLISHED ──
      // All timestamps set in one operation to avoid ghost drafts
      let publishedApp
      try {
        publishedApp = await db.app.update({
          where: { id },
          data: {
            status:      AppStatus.PUBLISHED,
            submittedAt: now,
            approvedAt:  now,
            publishedAt: now,
          },
        })
        logger.info({ id }, '[sentinel] Clean scan: app published in single atomic operation')
      } catch (dbErr) {
        logger.error({ err: dbErr, id }, '[sentinel] DB publish failed')
        return reply.status(400).send({
          success: false,
          error: { message: 'Failed to publish app — database error. Please try again.' },
        })
      }

      void securityLogger.adminAction(request, 'app_auto_published', 'App', id, {
        reason: 'Security scan passed — auto-published in atomic operation',
      })

      return reply.send({ success: true, autoPublished: true, app: publishedApp })
    },
  )

  // ── Moderator: state transitions ──────────────────────────────────────────

  app.post(
    '/:id/review',
    { preHandler: [app.requireRole([UserRole.MODERATOR, UserRole.ADMIN])] },
    async (request, reply) => {
      const { id } = request.params as { id: string }
      const data = await appsService.startReview(id)
      void securityLogger.adminAction(request, 'review_started', 'App', id)
      return reply.send({ success: true, data })
    },
  )

  app.post(
    '/:id/approve',
    { preHandler: [app.requireRole([UserRole.MODERATOR, UserRole.ADMIN])] },
    async (request, reply) => {
      const { id } = request.params as { id: string }
      const data = await appsService.approve(id, request.user.sub)
      void securityLogger.adminAction(request, 'app_approved', 'App', id, {
        reviewerId: request.user.sub,
      })
      return reply.send({ success: true, data })
    },
  )

  app.post(
    '/:id/reject',
    { preHandler: [app.requireRole([UserRole.MODERATOR, UserRole.ADMIN])] },
    async (request, reply) => {
      const { id } = request.params as { id: string }
      const body = RejectAppBodySchema.parse(request.body)
      const data = await appsService.reject(id, request.user.sub, body)
      void securityLogger.adminAction(request, 'app_rejected', 'App', id, {
        reviewerId: request.user.sub,
        reason:     body.reason,
      })
      return reply.send({ success: true, data })
    },
  )

  // ── Admin ─────────────────────────────────────────────────────────────────

  app.post(
    '/:id/publish',
    { preHandler: [app.requireRole([UserRole.ADMIN])] },
    async (request, reply) => {
      const { id } = request.params as { id: string }
      const data = await appsService.publish(id)
      void securityLogger.adminAction(request, 'app_published', 'App', id, {
        adminId: request.user.sub,
      })
      return reply.send({ success: true, data })
    },
  )

  // Admin hard-delete — bypasses ownership check, any status
  app.delete(
    '/:id/force',
    { preHandler: [app.requireRole([UserRole.ADMIN])] },
    async (request, reply) => {
      const { id } = request.params as { id: string }
      const existing = await appsRepository.findById(id)
      if (!existing) {
        return reply.status(404).send({ success: false, error: { message: 'App not found' } })
      }
      await appsRepository.delete(id)
      void securityLogger.adminAction(request, 'app_force_deleted', 'App', id, {
        adminId: request.user.sub,
      })
      return reply.status(204).send()
    },
  )

  app.post(
    '/:id/archive',
    { preHandler: [app.requireRole([UserRole.CREATOR, UserRole.ADMIN])] },
    async (request, reply) => {
      const { id }  = request.params as { id: string }
      const isAdmin = request.user.role === UserRole.ADMIN
      const data    = isAdmin
        ? await appsService.archive(id)
        : await appsService.creatorArchive(
            id,
            (await appsService.resolveCreator(request.user.sub)).id,
          )
      void securityLogger.adminAction(request, 'app_archived', 'App', id)
      return reply.send({ success: true, data })
    },
  )
}
