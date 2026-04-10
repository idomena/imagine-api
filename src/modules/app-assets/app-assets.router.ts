import type { FastifyInstance } from 'fastify'
import { UserRole } from '@prisma/client'
import { appAssetsService } from './app-assets.service'
import { appsService } from '../apps/apps.service'
import { RequestUploadUrlBodySchema } from './app-assets.schema'

// ---------------------------------------------------------------------------
// App assets router  (registered under /api/v1/apps)
//
// GET    /api/v1/apps/:appId/assets                  — public: list assets
// POST   /api/v1/apps/:appId/assets/upload-url       — creator: get pre-signed upload URL
// DELETE /api/v1/apps/:appId/assets/:assetId         — creator: delete asset record
// ---------------------------------------------------------------------------

export async function appAssetsRouter(app: FastifyInstance) {
  app.get('/:appId/assets', async (request, reply) => {
    const { appId } = request.params as { appId: string }
    const data = await appAssetsService.listAssets(appId)
    return reply.send({ success: true, data })
  })

  app.post(
    '/:appId/assets/upload-url',
    { preHandler: [app.requireRole([UserRole.CREATOR])] },
    async (request, reply) => {
      const creator = await appsService.resolveCreator(request.user.sub)
      const { appId } = request.params as { appId: string }
      const body = RequestUploadUrlBodySchema.parse(request.body)
      const data = await appAssetsService.getUploadUrl(appId, creator.id, body)
      return reply.send({ success: true, data })
    },
  )

  app.delete(
    '/:appId/assets/:assetId',
    { preHandler: [app.requireRole([UserRole.CREATOR])] },
    async (request, reply) => {
      const creator = await appsService.resolveCreator(request.user.sub)
      const { appId, assetId } = request.params as { appId: string; assetId: string }
      await appAssetsService.deleteAsset(assetId, appId, creator.id)
      return reply.status(204).send()
    },
  )
}
