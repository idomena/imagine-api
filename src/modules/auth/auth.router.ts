import type { FastifyInstance } from 'fastify'
import { authService } from './auth.service'
import { GoogleAuthBodySchema, LoginBodySchema, RefreshBodySchema, RegisterBodySchema } from './auth.schema'

// ---------------------------------------------------------------------------
// Auth router — transport layer only.
//
// POST /api/v1/auth/register   — create account
// POST /api/v1/auth/login      — exchange credentials for tokens
// POST /api/v1/auth/refresh    — rotate refresh token
// GET  /api/v1/auth/me         — return the authenticated user's profile
// ---------------------------------------------------------------------------

export async function authRouter(app: FastifyInstance) {
  app.post('/register', async (request, reply) => {
    const body = RegisterBodySchema.parse(request.body)
    const data = await authService.register(app, body)
    return reply.status(201).send({ success: true, data })
  })

  app.post('/login', async (request, reply) => {
    const body = LoginBodySchema.parse(request.body)
    const data = await authService.login(app, body)
    return reply.status(200).send({ success: true, data })
  })

  app.post('/refresh', async (request, reply) => {
    const body = RefreshBodySchema.parse(request.body)
    const data = await authService.refresh(app, body)
    return reply.status(200).send({ success: true, data })
  })

  app.post('/google', async (request, reply) => {
    const body = GoogleAuthBodySchema.parse(request.body)
    const data = await authService.googleAuth(app, body)
    return reply.status(200).send({ success: true, data })
  })

  app.get(
    '/me',
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const user = await authService.me(request.user.sub)
      return reply.send({ success: true, data: { user } })
    },
  )
}
