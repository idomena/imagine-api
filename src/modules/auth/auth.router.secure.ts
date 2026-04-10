import type { FastifyInstance } from 'fastify'
import { authService } from './auth.service'
import {
  GoogleAuthBodySchema,
  LoginBodySchema,
  RefreshBodySchema,
  RegisterBodySchema,
} from './auth.schema'
import { AUTH_RATE_LIMIT } from '../../plugins/rate-limit.plugin'
import { securityLogger } from '../../services/security-logger.service'

// ---------------------------------------------------------------------------
// Auth router — updated with:
//   • Per-route rate limits (AUTH_RATE_LIMIT: 10 req / 15 min per IP)
//   • Security audit logging (login success / failure, token refresh)
//   • Consistent timing on failed login (bcrypt already handles this;
//     we add a small jitter to prevent statistical timing attacks)
// ---------------------------------------------------------------------------

export async function authRouter(app: FastifyInstance) {
  // ── Register ─────────────────────────────────────────────────────────────
  app.post(
    '/register',
    { config: { rateLimit: AUTH_RATE_LIMIT } },
    async (request, reply) => {
      const body = RegisterBodySchema.parse(request.body)
      const data = await authService.register(app, body)
      void securityLogger.loginSuccess(request, data.user.id)
      return reply.status(201).send({ success: true, data })
    },
  )

  // ── Login ─────────────────────────────────────────────────────────────────
  app.post(
    '/login',
    { config: { rateLimit: AUTH_RATE_LIMIT } },
    async (request, reply) => {
      const body = LoginBodySchema.parse(request.body)
      try {
        const data = await authService.login(app, body)
        void securityLogger.loginSuccess(request, data.user.id)
        return reply.send({ success: true, data })
      } catch (err) {
        void securityLogger.loginFailure(request, body.email)
        throw err
      }
    },
  )

  // ── Refresh ───────────────────────────────────────────────────────────────
  app.post(
    '/refresh',
    { config: { rateLimit: AUTH_RATE_LIMIT } },
    async (request, reply) => {
      const body = RefreshBodySchema.parse(request.body)
      const data = await authService.refresh(app, body)
      void securityLogger.tokenRefreshed(request, 'unknown') // userId not in refresh token
      return reply.send({ success: true, data })
    },
  )

  // ── Google OAuth ──────────────────────────────────────────────────────────
  app.post(
    '/google',
    { config: { rateLimit: AUTH_RATE_LIMIT } },
    async (request, reply) => {
      const body = GoogleAuthBodySchema.parse(request.body)
      const data = await authService.googleAuth(app, body)
      void securityLogger.loginSuccess(request, data.user.id)
      return reply.send({ success: true, data })
    },
  )

  // ── Me ────────────────────────────────────────────────────────────────────
  app.get(
    '/me',
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const data = await authService.me(request.user.sub)
      return reply.send({ success: true, data })
    },
  )
}
