import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { favoritesService } from './favorites.service'

// ---------------------------------------------------------------------------
// Favorites router
//
// All routes require a valid access token — only logged-in users can manage
// their favorites.
//
// GET  /api/v1/favorites          — list the current user's favorite apps
// POST /api/v1/favorites/:appId   — toggle favorite on/off (idempotent)
// ---------------------------------------------------------------------------

const PaginationQuerySchema = z.object({
  page:  z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
})

export async function favoritesRouter(app: FastifyInstance) {
  app.addHook('preHandler', app.authenticate)

  app.get('/', async (request, reply) => {
    const { page, limit } = PaginationQuerySchema.parse(request.query)
    const data = await favoritesService.list(request.user.sub, { page, limit })
    return reply.send({ success: true, data })
  })

  app.post('/:appId', async (request, reply) => {
    const { appId } = request.params as { appId: string }
    const data = await favoritesService.toggle(request.user.sub, appId)
    return reply.send({ success: true, data })
  })
}
