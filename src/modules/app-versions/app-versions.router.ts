import type { FastifyInstance } from 'fastify'
import { UserRole } from '@prisma/client'
import { appVersionsService } from './app-versions.service'
import { appsService } from '../apps/apps.service'
import { CreateVersionBodySchema } from './app-versions.schema'

// ---------------------------------------------------------------------------
// App versions router  (registered under /api/v1/apps)
//
// GET  /api/v1/apps/:appId/versions   — public: list all versions for an app
// POST /api/v1/apps/:appId/versions   — creator: add a new version
// ---------------------------------------------------------------------------

export async function appVersionsRouter(app: FastifyInstance) {
  app.get('/:appId/versions', async (request, reply) => {
    const { appId } = request.params as { appId: string }
    const data = await appVersionsService.list(appId)
    return reply.send({ success: true, data })
  })

  app.post(
    '/:appId/versions',
    { preHandler: [app.requireRole([UserRole.CREATOR])] },
    async (request, reply) => {
      const creator = await appsService.resolveCreator(request.user.sub)
      const { appId } = request.params as { appId: string }
      const body = CreateVersionBodySchema.parse(request.body)
      const data = await appVersionsService.create(appId, creator.id, body)
      return reply.status(201).send({ success: true, data })
    },
  )
}
