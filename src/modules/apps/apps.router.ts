import { createHash } from 'crypto'
import type { FastifyInstance } from 'fastify'
import { UserRole } from '@prisma/client'
import { appsService } from './apps.service'
import { appsRepository } from './apps.repository'
import { launchEventsRepository } from '../launch-events/launch-events.repository'
import { scanApp } from '../../services/security-audit.service'
import {
  CreateAppBodySchema,
  ListAppsQuerySchema,
  RejectAppBodySchema,
  RenameAppBodySchema,
  UpdateAppBodySchema,
} from './apps.schema'

// ---------------------------------------------------------------------------
// Apps router
//
// Public
//   GET  /api/v1/apps           — list published apps (paginated, filterable)
//   GET  /api/v1/apps/:id       — get single app
//
// Creator  (role: CREATOR)
//   GET  /api/v1/apps/mine      — list own apps (all statuses)
//   POST /api/v1/apps           — create draft
//   PATCH /api/v1/apps/:id      — edit draft
//   DELETE /api/v1/apps/:id     — delete draft
//   POST /api/v1/apps/:id/submit — DRAFT → SUBMITTED
//
// Moderator (role: MODERATOR | ADMIN)
//   POST /api/v1/apps/:id/review  — SUBMITTED → IN_REVIEW
//   POST /api/v1/apps/:id/approve — IN_REVIEW  → APPROVED
//   POST /api/v1/apps/:id/reject  — IN_REVIEW  → REJECTED
//
// Admin (role: ADMIN)
//   GET  /api/v1/apps/admin       — list all apps (any status)
//   POST /api/v1/apps/:id/publish — APPROVED   → PUBLISHED
//
// Creator or Admin
//   POST /api/v1/apps/:id/archive — PUBLISHED  → ARCHIVED
// ---------------------------------------------------------------------------

export async function appsRouter(app: FastifyInstance) {
  // ── Static paths must come before parametric /:id ─────────────────────────

  // Creator: list own apps
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

  // Admin: list all apps with optional status filter
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

  // GET /api/v1/apps/slug/:slug — look up a published app by its slug.
  // Must be registered before /:id so Fastify's static-first routing picks it up.
  app.get('/slug/:slug', async (request, reply) => {
    const { slug } = request.params as { slug: string }
    const app = await appsRepository.findBySlug(slug)
    if (!app) {
      return reply.status(404).send({ success: false, error: { message: `App with slug '${slug}' not found` } })
    }
    return reply.send({ success: true, data: app })
  })

  app.get('/:id', async (request, reply) => {
    const { id } = request.params as { id: string }
    const data = await appsService.get(id)
    return reply.send({ success: true, data })
  })

  // ── Public: visit tracking + redirect ────────────────────────────────────
  // GET /:id/visit — records an anonymous launch event and redirects to
  // the app's launchUrl. Used by the "Visit App" button on the detail page.
  app.get('/:id/visit', async (request, reply) => {
    const { id } = request.params as { id: string }
    const app = await appsService.get(id)

    const ipHash = request.ip
      ? createHash('sha256').update(request.ip).digest('hex')
      : undefined

    // Fire-and-forget — a DB error must never break the redirect
    launchEventsRepository.create({
      appId:     id,
      ipHash,
      userAgent: request.headers['user-agent'],
    }).catch(() => {})

    const dest = app.launchUrl ?? '/'
    return reply.redirect(dest)
  })

  // ── Creator: CRUD ─────────────────────────────────────────────────────────

  app.post(
    '/',
    { preHandler: [app.requireRole([UserRole.CREATOR])] },
    async (request, reply) => {
      const creator = await appsService.resolveCreator(request.user.sub)
      const body = CreateAppBodySchema.parse(request.body)
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

  // ── Creator: rename (any status) ─────────────────────────────────────────

  app.patch(
    '/:id/rename',
    { preHandler: [app.requireRole([UserRole.CREATOR])] },
    async (request, reply) => {
      const creator = await appsService.resolveCreator(request.user.sub)
      const { id }  = request.params as { id: string }
      const body    = RenameAppBodySchema.parse(request.body)
      const data    = await appsService.rename(id, creator.id, body)
      return reply.send({ success: true, data })
    },
  )

  // ── Creator: state transitions ────────────────────────────────────────────

  app.post(
    '/:id/submit',
    { preHandler: [app.requireRole([UserRole.CREATOR])] },
    async (request, reply) => {
      const creator = await appsService.resolveCreator(request.user.sub)
      const { id }  = request.params as { id: string }

      // 1. Transition DRAFT → SUBMITTED (validates ownership + state machine)
      const submitted = await appsService.submit(id, creator.id)

      // 2. Synchronous security scan — 5 s timeout baked into the service.
      //    Fail-safe: any fetch failure or thrown error defaults to PUBLISHED.
      let malicious = false
      let threatDetails: string[] = []

      try {
        const result = await scanApp(id, submitted.launchUrl ?? '')
        if (result.malicious) {
          malicious     = true
          threatDetails = result.threats.map(t => t.description)
        }
      } catch {
        // Scan error → cannot prove malicious → publish (fail-safe)
        malicious = false
      }

      // 3a. Malicious — keep as SUBMITTED and reject with 422
      if (malicious) {
        return reply.status(422).send({
          success: false,
          error: {
            message: 'App rejected by security scan.',
            details: threatDetails,
          },
        })
      }

      // 3b. Clean (or scan failed) — auto-publish immediately
      const published = await appsService.adminApprove(id)
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
      return reply.send({ success: true, data })
    },
  )

  app.post(
    '/:id/approve',
    { preHandler: [app.requireRole([UserRole.MODERATOR, UserRole.ADMIN])] },
    async (request, reply) => {
      const { id } = request.params as { id: string }
      const data = await appsService.approve(id, request.user.sub)
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
      return reply.send({ success: true, data })
    },
  )

  // ── Admin: state transitions ──────────────────────────────────────────────

  app.post(
    '/:id/publish',
    { preHandler: [app.requireRole([UserRole.ADMIN])] },
    async (request, reply) => {
      const { id } = request.params as { id: string }
      const data = await appsService.publish(id)
      return reply.send({ success: true, data })
    },
  )

  // Creators can archive their own published app; admins can archive any app.
  app.post(
    '/:id/archive',
    { preHandler: [app.requireRole([UserRole.CREATOR, UserRole.ADMIN])] },
    async (request, reply) => {
      const { id }   = request.params as { id: string }
      const isAdmin  = request.user.role === UserRole.ADMIN
      const data     = isAdmin
        ? await appsService.archive(id)
        : await appsService.creatorArchive(id, (await appsService.resolveCreator(request.user.sub)).id)
      return reply.send({ success: true, data })
    },
  )
}
