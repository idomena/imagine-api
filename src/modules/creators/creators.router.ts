import type { FastifyInstance } from 'fastify'
import { creatorsService } from './creators.service'
import { OnboardBodySchema, UpdateCreatorBodySchema } from './creators.schema'

// ---------------------------------------------------------------------------
// Creators router
//
// POST  /api/v1/creators/onboard — promote authenticated USER → CREATOR
// GET   /api/v1/creators/me      — get own creator profile
// PATCH /api/v1/creators/me      — update displayName, bio, website, avatarUrl
// ---------------------------------------------------------------------------

export async function creatorsRouter(app: FastifyInstance) {
  app.post(
    '/onboard',
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const body = OnboardBodySchema.parse(request.body)
      const data = await creatorsService.onboard(request.user.sub, body)
      return reply.status(201).send({ success: true, data })
    },
  )

  app.get(
    '/me',
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const data = await creatorsService.me(request.user.sub)
      return reply.send({ success: true, data })
    },
  )

  app.patch(
    '/me',
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const body = UpdateCreatorBodySchema.parse(request.body)
      const data = await creatorsService.update(request.user.sub, body)
      return reply.send({ success: true, data })
    },
  )
}
