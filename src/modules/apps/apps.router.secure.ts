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
import { runSecurityAudit } from '../../services/security-audit.service'
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

  // ── Creator: submit — WITH threat scan + rate limit ───────────────────────

  app.post(
    '/:id/submit',
    {
      preHandler: [app.requireRole([UserRole.CREATOR])],
      config:     { rateLimit: SUBMIT_RATE_LIMIT },
    },
    async (request, reply) => {
      const creator = await appsService.resolveCreator(request.user.sub)
      const { id } = request.params as { id: string }

      // Fetch the app to extract its launchUrl for the audit pipeline
      const appData = await appsService.get(id)

      // ── Autonomous Security Audit Pipeline ────────────────────────────────
      // Runs all three phases (domain reputation + content analysis + scoring).
      // On failure the pipeline fails-open: the app is submitted normally and
      // held for manual review — an audit error never blocks the creator.
      let auditResult: Awaited<ReturnType<typeof runSecurityAudit>> | null = null
      try {
        auditResult = await runSecurityAudit(id, appData.launchUrl ?? '')
      } catch (auditErr) {
        logger.error({ auditErr, appId: id }, '[security-audit] Pipeline failed — falling back to manual review')
      }

      // AUTO_REJECTED: transition DRAFT → SUBMITTED → REJECTED, return 422
      if (auditResult?.decision === 'AUTO_REJECTED') {
        await appsService.submit(id, creator.id)
        await appsService.adminReject(id)
        void securityLogger.threatDetected(request, id,
          auditResult.threats.map(t => ({ uri: appData.launchUrl ?? '', types: [t.type] }))
        )
        void securityLogger.adminAction(request, 'app_auto_rejected', 'App', id, {
          score:    auditResult.safetyScore,
          threats:  auditResult.threats,
        })
        return reply.status(422).send({
          success: false,
          error: {
            message: 'Submission rejected by automated security scan.',
            details: auditResult.threats.map(t => t.description),
          },
        })
      }

      // All other cases: transition to SUBMITTED first
      const submitted = await appsService.submit(id, creator.id)

      // AUTO_PUBLISHED: immediately transition SUBMITTED → PUBLISHED
      if (auditResult?.decision === 'AUTO_PUBLISHED') {
        const published = await appsService.adminApprove(id)
        void securityLogger.adminAction(request, 'app_auto_published', 'App', id, {
          score: auditResult.safetyScore,
        })
        return reply.send({ success: true, autoPublished: true, data: published })
      }

      // HELD_FOR_REVIEW (or audit pipeline failed): stay as SUBMITTED
      void securityLogger.adminAction(request, 'app_submitted', 'App', id, {
        creatorId:     creator.id,
        auditDecision: auditResult?.decision ?? 'PIPELINE_ERROR',
        score:         auditResult?.safetyScore ?? null,
      })

      return reply.send({ success: true, autoPublished: false, data: submitted })
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

      // Second gate at approval — re-audit in case URL was changed after submit
      const appData    = await appsService.get(id)
      const reaudit    = await runSecurityAudit(id, appData.launchUrl ?? '')
      if (reaudit.decision === 'AUTO_REJECTED') {
        void securityLogger.threatDetected(request, id,
          reaudit.threats.map(t => ({ uri: appData.launchUrl ?? '', types: [t.type] }))
        )
        return reply.status(422).send({
          success: false,
          error: { message: 'Approval blocked: security threats detected.', details: reaudit.threats.map(t => t.description) },
        })
      }

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
