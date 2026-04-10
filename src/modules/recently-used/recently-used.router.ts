import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { recentlyUsedService } from './recently-used.service'

// ---------------------------------------------------------------------------
// Recently-used router
//
// All routes require a valid access token.
//
// GET  /api/v1/recently-used           — current user's history (newest first)
// POST /api/v1/recently-used/:appId    — record a launch (upserts the timestamp)
// ---------------------------------------------------------------------------

const PaginationQuerySchema = z.object({
  page:  z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
})

export async function recentlyUsedRouter(app: FastifyInstance) {
  app.addHook('preHandler', app.authenticate)

  app.get('/', async (request, reply) => {
    const { page, limit } = PaginationQuerySchema.parse(request.query)
    const data = await recentlyUsedService.list(request.user.sub, { page, limit })
    return reply.send({ success: true, data })
  })

  app.post('/:appId', async (request, reply) => {
    const { appId } = request.params as { appId: string }
    const data = await recentlyUsedService.record(request.user.sub, appId)
    return reply.send({ success: true, data })
  })
}
