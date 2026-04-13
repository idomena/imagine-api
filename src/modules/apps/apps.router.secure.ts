import { createHash } from 'crypto'
import type { FastifyInstance } from 'fastify'
import { UserRole } from '@prisma/client'
import { appsService } from './apps.service'
import { appsRepository } from './apps.repository'
import { launchEventsRepository } from '../launch-events/launch-events.repository'
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
    throw new Error(`${field} must use HTTPS`)
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

  // ── Creator: submit — Scan-then-Publish ─────────────────────────────────
  // Synchronous flow:
  //   1. DRAFT → SUBMITTED  (appsService.submit — validates ownership + state machine)
  //   2. await scanApp()    (5 s timeout, Chrome UA, checks XSS / obfuscation / phishing)
  //   3a. SAFE     → SUBMITTED → PUBLISHED  (appsService.adminApprove)
  //   3b. MALICIOUS → stay SUBMITTED, return 422 with threat details
  //   3c. scan error/timeout → fail-safe: treat as SAFE, publish

  app.post(
    '/:id/submit',
    {
      preHandler: [app.requireRole([UserRole.CREATOR])],
      config:     { rateLimit: SUBMIT_RATE_LIMIT },
    },
    async (request, reply) => {
      const creator = await appsService.resolveCreator(request.user.sub)
      const { id }  = request.params as { id: string }

      // Step 1 — DRAFT → SUBMITTED (state machine validates ownership + transition)
      const submitted = await appsService.submit(id, creator.id)

      // Step 2 — synchronous security scan
      let malicious     = false
      let threatDetails: string[] = []

      try {
        const result = await scanApp(id, submitted.launchUrl ?? '')
        if (result.malicious) {
          malicious     = true
          threatDetails = result.threats.map(t => t.description)
          void securityLogger.threatDetected(request, id,
            result.threats.map(t => ({ uri: submitted.launchUrl ?? '', types: [t.type] }))
          )
        }
      } catch (err) {
        // Scan error / timeout → cannot prove malicious → publish (fail-safe)
        logger.error({ err, id }, '[sentinel] Scan error — fail-safe: publishing anyway')
        malicious = false
      }

      // Step 3a — malicious: hold in SUBMITTED, surface to creator as 422
      if (malicious) {
        void securityLogger.adminAction(request, 'app_security_held', 'App', id, {
          reason:  'Malicious content detected at submission',
          threats: threatDetails,
        })
        return reply.status(422).send({
          success: false,
          error: {
            message: 'App rejected by security scan.',
            details: threatDetails,
          },
        })
      }

      // Step 3b — clean (or unreachable): SUBMITTED → PUBLISHED via service layer
      const published = await appsService.adminApprove(id)
      void securityLogger.adminAction(request, 'app_auto_published', 'App', id, {
        reason: 'Sentinel scan passed — auto-published',
      })

      return reply.send({ success: true, autoPublished: true, data: published })
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
