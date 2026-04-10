import type { FastifyInstance } from 'fastify'
import { creatorsService } from './creators.service'
import { OnboardBodySchema } from './creators.schema'

// ---------------------------------------------------------------------------
// Creators router — transport layer only.
//
// POST /api/v1/creators/onboard — promote authenticated USER → CREATOR
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
}
