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
import { scanAppUrls } from '../../services/threat-scan.service'
import { securityLogger } from '../../services/security-logger.service'
import { SUBMIT_RATE_LIMIT } from '../../plugins/rate-limit.plugin'

// ---------------------------------------------------------------------------
// Apps router — SECURED VERSION
//
// Changes from baseline:
//   1. POST /:id/submit  → scanAppUrls() before transition (blocks phishing)
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

      // Fetch the app to extract its URLs for threat scanning
      const appData = await appsService.get(id)

      // ── Threat scan (blocks submission if phishing/malware found) ─────────
      try {
        const scanResult = await scanAppUrls({
          launchUrl: appData.launchUrl,
        })
        if (!scanResult.clean) {
          void securityLogger.threatDetected(request, id, scanResult.threats)
        }
      } catch (scanErr) {
        // scanAppUrls throws BadRequestError when threats are found —
        // log it before re-throwing so it appears in security audit trail
        void securityLogger.threatDetected(request, id, [])
        throw scanErr
      }

      const data = await appsService.submit(id, creator.id)

      void securityLogger.adminAction(request, 'app_submitted', 'App', id, {
        creatorId: creator.id,
      })

      return reply.send({ success: true, data })
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

      // Second threat-scan gate at approval — catches URLs added after submit
      const appData = await appsService.get(id)
      try {
        await scanAppUrls({ launchUrl: appData.launchUrl })
      } catch (scanErr) {
        void securityLogger.threatDetected(request, id, [])
        throw scanErr
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
