import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { reviewsRepository } from './reviews.repository'

// ---------------------------------------------------------------------------
// Reviews router
//
// GET  /api/v1/apps/:appId/reviews  — public, paginated + aggregate stats
// POST /api/v1/apps/:appId/reviews  — protected, upsert (one per user per app)
// ---------------------------------------------------------------------------

const PaginationSchema = z.object({
  page:  z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(50).default(20),
})

const CreateReviewSchema = z.object({
  rating:  z.number().int().min(1).max(5),
  comment: z.string().min(1).max(1000).trim(),
})

export async function reviewsRouter(app: FastifyInstance) {
  // ── GET /api/v1/apps/:appId/reviews ─────────────────────────────────────────
  app.get('/:appId/reviews', async (request, reply) => {
    const { appId } = request.params as { appId: string }
    const { page, limit } = PaginationSchema.parse(request.query)
    const { items, total, avgRating } = await reviewsRepository.findByApp(appId, {
      take: limit,
      skip: (page - 1) * limit,
    })
    return reply.send({
      success: true,
      data: {
        items,
        total,
        page,
        limit,
        pages: Math.ceil(total / limit),
        avgRating,
      },
    })
  })

  // ── POST /api/v1/apps/:appId/reviews ────────────────────────────────────────
  app.post('/:appId/reviews', { preHandler: [app.authenticate] }, async (request, reply) => {
    const { appId } = request.params as { appId: string }
    const body = CreateReviewSchema.parse(request.body)
    const review = await reviewsRepository.upsert(appId, request.user.sub, body)
    return reply.code(201).send({ success: true, data: review })
  })
}
