import type { FastifyInstance } from 'fastify'
import { UserRole } from '@prisma/client'
import { tagsService } from './tags.service'
import { CreateTagBodySchema, UpdateTagBodySchema } from './tags.schema'

// ---------------------------------------------------------------------------
// Tags router
//
// GET    /api/v1/tags        — public: list all
// GET    /api/v1/tags/:id    — public: get one
// POST   /api/v1/tags        — admin:  create
// PATCH  /api/v1/tags/:id    — admin:  update
// DELETE /api/v1/tags/:id    — admin:  delete
// ---------------------------------------------------------------------------

export async function tagsRouter(app: FastifyInstance) {
  // ── Public ───────────────────────────────────────────────────────────────
  app.get('/', async (_request, reply) => {
    const data = await tagsService.list()
    return reply.send({ success: true, data })
  })

  app.get('/:id', async (request, reply) => {
    const { id } = request.params as { id: string }
    const data = await tagsService.get(id)
    return reply.send({ success: true, data })
  })

  // ── Admin ─────────────────────────────────────────────────────────────────
  app.post(
    '/',
    { preHandler: [app.requireRole([UserRole.ADMIN])] },
    async (request, reply) => {
      const body = CreateTagBodySchema.parse(request.body)
      const data = await tagsService.create(body)
      return reply.status(201).send({ success: true, data })
    },
  )

  app.patch(
    '/:id',
    { preHandler: [app.requireRole([UserRole.ADMIN])] },
    async (request, reply) => {
      const { id } = request.params as { id: string }
      const body = UpdateTagBodySchema.parse(request.body)
      const data = await tagsService.update(id, body)
      return reply.send({ success: true, data })
    },
  )

  app.delete(
    '/:id',
    { preHandler: [app.requireRole([UserRole.ADMIN])] },
    async (request, reply) => {
      const { id } = request.params as { id: string }
      await tagsService.delete(id)
      return reply.status(204).send()
    },
  )
}
