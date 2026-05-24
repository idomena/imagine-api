import type { FastifyInstance } from 'fastify'
import { UserRole } from '@prisma/client'
import { db } from '../../core/db'
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

  // Admin-only: set any user's role
  app.post(
    '/admin/set-role',
    { preHandler: [app.requireRole([UserRole.ADMIN])] },
    async (request, reply) => {
      const body = request.body as { email?: string; role?: string }
      const email = body?.email?.trim().toLowerCase()
      const role  = body?.role as UserRole | undefined

      if (!email || !role || !Object.values(UserRole).includes(role)) {
        return reply.status(400).send({ success: false, error: { message: 'email and valid role (USER | CREATOR | MODERATOR | ADMIN) are required' } })
      }

      const target = await db.user.findUnique({ where: { email } })
      if (!target) {
        return reply.status(404).send({ success: false, error: { message: `No user found with email: ${email}` } })
      }

      const updated = await db.user.update({
        where:  { email },
        data:   { role },
        select: { id: true, email: true, role: true },
      })
      return reply.send({ success: true, data: updated })
    },
  )
}
