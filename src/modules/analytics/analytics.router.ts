import { createHash, randomUUID } from 'crypto'
import type { FastifyInstance } from 'fastify'
import { launchEventsRepository } from '../launch-events/launch-events.repository'

// ---------------------------------------------------------------------------
// Analytics router
//
// POST /api/v1/track-view — records a page view for a project.
//   Body:    { projectId: string }
//   Cookie:  vid (visitor ID) — set once and reused across sessions.
//            Stored as sessionId in LaunchEvent so per-visitor analytics
//            are possible without tracking personally identifiable data.
// ---------------------------------------------------------------------------

export async function analyticsRouter(app: FastifyInstance) {
  app.post(
    '/track-view',
    {
      schema: {
        body: {
          type: 'object',
          required: ['projectId'],
          properties: {
            projectId: { type: 'string', minLength: 1 },
          },
          additionalProperties: false,
        },
      },
    },
    async (request, reply) => {
      const { projectId } = request.body as { projectId: string }

      // Assign a persistent cookie-based visitor ID on first visit.
      // httpOnly + secure + sameSite=none so it's sent cross-origin from the frontend.
      const cookies = request.cookies as Record<string, string | undefined>
      let visitorId = cookies['vid']
      if (!visitorId) {
        visitorId = randomUUID()
        void reply.setCookie('vid', visitorId, {
          path:     '/',
          maxAge:   365 * 24 * 60 * 60, // 1 year
          httpOnly: true,
          sameSite: 'none',
          secure:   true,
        })
      }

      const ipHash = request.ip
        ? createHash('sha256').update(request.ip).digest('hex')
        : undefined

      launchEventsRepository
        .create({
          appId:     projectId,
          sessionId: visitorId,
          ipHash,
          userAgent: request.headers['user-agent'] ?? undefined,
          referrer:  (request.headers['referer'] as string | undefined) ?? undefined,
        })
        .catch(() => {})

      return reply.status(204).send()
    },
  )
}
