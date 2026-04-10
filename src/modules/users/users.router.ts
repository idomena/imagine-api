import type { FastifyInstance } from 'fastify'
import { usersService } from './users.service'
import { UpdateProfileBodySchema } from './users.schema'

// ---------------------------------------------------------------------------
// Users router — transport layer only.
//
// All routes require a valid access token (authenticate preHandler applied
// at the plugin scope so every route in this file is protected).
//
// GET   /api/v1/users/me   — full profile (user + creator record if any)
// PATCH /api/v1/users/me   — update mutable profile fields
// ---------------------------------------------------------------------------

export async function usersRouter(app: FastifyInstance) {
  app.addHook('preHandler', app.authenticate)

  app.get('/me', async (request, reply) => {
    const data = await usersService.getProfile(request.user.sub)
    return reply.send({ success: true, data })
  })

  app.patch('/me', async (request, reply) => {
    const body = UpdateProfileBodySchema.parse(request.body)
    const user = await usersService.updateProfile(request.user.sub, body)
    return reply.send({ success: true, data: { user } })
  })
}
