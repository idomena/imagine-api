import type { FastifyInstance } from 'fastify'
import { launchEventsService } from './launch-events.service'
import { RecordLaunchBodySchema } from './launch-events.schema'

// ---------------------------------------------------------------------------
// Launch events router
//
// POST /api/v1/launch-events   — record a launch (requires auth)
//
// The route requires authentication so userId is always populated from the
// JWT rather than trusted from the request body, preventing spoofing.
//
// Request metadata (IP, User-Agent) is extracted here in the transport layer
// and passed into the service as a plain object — the service stays
// framework-agnostic.
// ---------------------------------------------------------------------------

export async function launchEventsRouter(app: FastifyInstance) {
  app.addHook('preHandler', app.authenticate)

  app.post('/', async (request, reply) => {
    const body = RecordLaunchBodySchema.parse(request.body)

    const data = await launchEventsService.record(
      request.user.sub,
      body,
      {
        ip:        request.ip,
        userAgent: request.headers['user-agent'],
      },
    )

    return reply.status(201).send({ success: true, data })
  })
}
