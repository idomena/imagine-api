import type { FastifyInstance } from 'fastify'
import { UserRole } from '@prisma/client'
import { categoriesService } from './categories.service'
import { CreateCategoryBodySchema, UpdateCategoryBodySchema } from './categories.schema'

// ---------------------------------------------------------------------------
// Categories router
//
// GET    /api/v1/categories        — public: list all
// GET    /api/v1/categories/:id    — public: get one
// POST   /api/v1/categories        — admin:  create
// PATCH  /api/v1/categories/:id    — admin:  update
// DELETE /api/v1/categories/:id    — admin:  delete
// ---------------------------------------------------------------------------

export async function categoriesRouter(app: FastifyInstance) {
  // ── Public ───────────────────────────────────────────────────────────────
  app.get('/', async (_request, reply) => {
    const data = await categoriesService.list()
    return reply.send({ success: true, data })
  })

  app.get('/:id', async (request, reply) => {
    const { id } = request.params as { id: string }
    const data = await categoriesService.get(id)
    return reply.send({ success: true, data })
  })

  // ── Admin ─────────────────────────────────────────────────────────────────
  app.post(
    '/',
    { preHandler: [app.requireRole([UserRole.ADMIN])] },
    async (request, reply) => {
      const body = CreateCategoryBodySchema.parse(request.body)
      const data = await categoriesService.create(body)
      return reply.status(201).send({ success: true, data })
    },
  )

  app.patch(
    '/:id',
    { preHandler: [app.requireRole([UserRole.ADMIN])] },
    async (request, reply) => {
      const { id } = request.params as { id: string }
      const body = UpdateCategoryBodySchema.parse(request.body)
      const data = await categoriesService.update(id, body)
      return reply.send({ success: true, data })
    },
  )

  app.delete(
    '/:id',
    { preHandler: [app.requireRole([UserRole.ADMIN])] },
    async (request, reply) => {
      const { id } = request.params as { id: string }
      await categoriesService.delete(id)
      return reply.status(204).send()
    },
  )
}
