import type { FastifyInstance } from 'fastify'
import { UserRole } from '@prisma/client'
import { promotionsService } from './promotions.service'
import {
  CreatePromotionJobBodySchema,
  ListPromotionsQuerySchema,
  RejectPromotionBodySchema,
} from './promotions.schema'

// ---------------------------------------------------------------------------
// Promotions router
//
// POST   /api/v1/promotions                  — creator/admin: request promotion
// GET    /api/v1/promotions                  — creator: own jobs | admin: all
// GET    /api/v1/promotions/:jobId           — get job + run history
// POST   /api/v1/promotions/:jobId/approve   — admin: approve & enqueue
// POST   /api/v1/promotions/:jobId/reject    — admin: reject with reason
// POST   /api/v1/promotions/:jobId/cancel    — requester/admin: cancel
// ---------------------------------------------------------------------------

export async function promotionsRouter(app: FastifyInstance) {
  // All promotion routes require at minimum an authenticated user.
  app.addHook('preHandler', app.authenticate)

  const isAdmin = (role: UserRole) =>
    role === UserRole.ADMIN

  // ── Create ────────────────────────────────────────────────────────────────

  app.post('/', async (request, reply) => {
    const body = CreatePromotionJobBodySchema.parse(request.body)
    const data = await promotionsService.createJob(
      request.user.sub,
      isAdmin(request.user.role),
      body,
    )
    return reply.status(201).send({ success: true, data })
  })

  // ── List ──────────────────────────────────────────────────────────────────

  app.get('/', async (request, reply) => {
    const query = ListPromotionsQuerySchema.parse(request.query)
    const data  = await promotionsService.list(
      request.user.sub,
      isAdmin(request.user.role),
      query,
    )
    return reply.send({ success: true, data })
  })

  // ── Get single ────────────────────────────────────────────────────────────

  app.get('/:jobId', async (request, reply) => {
    const { jobId } = request.params as { jobId: string }
    const data = await promotionsService.get(
      jobId,
      request.user.sub,
      isAdmin(request.user.role),
    )
    return reply.send({ success: true, data })
  })

  // ── Admin: approve ────────────────────────────────────────────────────────

  app.post(
    '/:jobId/approve',
    { preHandler: [app.requireRole([UserRole.ADMIN])] },
    async (request, reply) => {
      const { jobId } = request.params as { jobId: string }
      const data = await promotionsService.approve(jobId, request.user.sub)
      return reply.send({ success: true, data })
    },
  )

  // ── Admin: reject ─────────────────────────────────────────────────────────

  app.post(
    '/:jobId/reject',
    { preHandler: [app.requireRole([UserRole.ADMIN])] },
    async (request, reply) => {
      const { jobId } = request.params as { jobId: string }
      const body = RejectPromotionBodySchema.parse(request.body)
      const data = await promotionsService.reject(jobId, request.user.sub, body)
      return reply.send({ success: true, data })
    },
  )

  // ── Cancel ────────────────────────────────────────────────────────────────

  app.post('/:jobId/cancel', async (request, reply) => {
    const { jobId } = request.params as { jobId: string }
    const data = await promotionsService.cancel(
      jobId,
      request.user.sub,
      isAdmin(request.user.role),
    )
    return reply.send({ success: true, data })
  })
}
