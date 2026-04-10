import { FastifyInstance } from 'fastify'
import { db } from '../../core/db'

// ---------------------------------------------------------------------------
// Health check endpoint
//
// GET /api/v1/health
//
// Returns 200 with DB connectivity status, or 503 if the database is
// unreachable. Used by load balancers, uptime monitors, and deploy checks.
// ---------------------------------------------------------------------------

interface HealthResponse {
  status: 'ok' | 'degraded'
  timestamp: string
  version: string
  services: {
    database: 'connected' | 'disconnected'
  }
}

export async function healthRouter(app: FastifyInstance) {
  app.get<{ Reply: HealthResponse }>(
    '/health',
    {
      schema: {
        response: {
          200: {
            type: 'object',
            properties: {
              status: { type: 'string', enum: ['ok', 'degraded'] },
              timestamp: { type: 'string' },
              version: { type: 'string' },
              services: {
                type: 'object',
                properties: {
                  database: { type: 'string', enum: ['connected', 'disconnected'] },
                },
              },
            },
          },
        },
      },
    },
    async (_request, reply) => {
      let databaseStatus: 'connected' | 'disconnected' = 'disconnected'

      try {
        await db.$queryRaw`SELECT 1`
        databaseStatus = 'connected'
      } catch (err) {
        _request.log.error({ err }, 'Health check: database unreachable')
      }

      const status = databaseStatus === 'connected' ? 'ok' : 'degraded'
      const httpStatus = status === 'ok' ? 200 : 503

      return reply.status(httpStatus).send({
        status,
        timestamp: new Date().toISOString(),
        version: process.env['npm_package_version'] ?? '0.0.1',
        services: {
          database: databaseStatus,
        },
      })
    },
  )
}
