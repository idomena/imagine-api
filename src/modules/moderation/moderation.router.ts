import type { FastifyInstance } from 'fastify'
import { UserRole } from '@prisma/client'
import { moderationService } from './moderation.service'
import { QueueQuerySchema, SubmitDecisionBodySchema } from './moderation.schema'

// ---------------------------------------------------------------------------
// Moderation router  — all routes require MODERATOR or ADMIN role.
//
// GET  /api/v1/moderation/queue              — paginated SUBMITTED apps (FIFO)
// GET  /api/v1/moderation/:appId/history     — review audit trail for one app
// POST /api/v1/moderation/:appId/claim       — SUBMITTED → IN_REVIEW (assigns reviewer)
// POST /api/v1/moderation/:appId/decision    — IN_REVIEW  → APPROVED | REJECTED
// ---------------------------------------------------------------------------

const MODERATOR_ROLES = [UserRole.MODERATOR, UserRole.ADMIN]

export async function moderationRouter(app: FastifyInstance) {
  // Every route in this plugin requires at least MODERATOR role.
  app.addHook('preHandler', app.requireRole(MODERATOR_ROLES))

  // ── Queue listing ─────────────────────────────────────────────────────────

  app.get('/queue', async (request, reply) => {
    const query = QueueQuerySchema.parse(request.query)
    const data  = await moderationService.getQueue(query)
    return reply.send({ success: true, data })
  })

  // ── Per-app review history ────────────────────────────────────────────────

  app.get('/:appId/history', async (request, reply) => {
    const { appId } = request.params as { appId: string }
    const data = await moderationService.getReviewHistory(appId)
    return reply.send({ success: true, data })
  })

  // ── Claim ─────────────────────────────────────────────────────────────────

  app.post('/:appId/claim', async (request, reply) => {
    const { appId } = request.params as { appId: string }
    // reviewerId is the User.id from the JWT, not a Creator.id
    const data = await moderationService.claim(appId, request.user.sub)
    return reply.send({ success: true, data })
  })

  // ── Decision ──────────────────────────────────────────────────────────────

  app.post('/:appId/decision', async (request, reply) => {
    const { appId } = request.params as { appId: string }
    const body = SubmitDecisionBodySchema.parse(request.body)
    const data = await moderationService.submitDecision(appId, request.user.sub, body)
    return reply.send({ success: true, data })
  })
}
