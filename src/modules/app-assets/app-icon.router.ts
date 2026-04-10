import { randomUUID } from 'crypto'
import type { FastifyInstance } from 'fastify'
import { appsService } from '../apps/apps.service'
import { appsRepository } from '../apps/apps.repository'
import { uploadToCloudinary } from '../../core/cloudinary'

// ---------------------------------------------------------------------------
// POST /api/v1/apps/:id/icon
//
// Accepts multipart/form-data with a single image file (field: "icon").
// Streams the file to Cloudinary and updates app.iconUrl with the CDN URL.
//
// Auth: Bearer token required — must be the creator who owns the app.
// ---------------------------------------------------------------------------

const MAX_FILE_BYTES = 5 * 1024 * 1024   // 5 MB

export async function appIconRouter(app: FastifyInstance) {
  app.post<{ Params: { id: string } }>(
    '/:id/icon',
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const { id: appId } = request.params
      const userId        = request.user.sub

      const existing = await appsRepository.findById(appId)
      if (!existing) {
        return reply.status(404).send({ success: false, error: { message: 'App not found' } })
      }

      const creator = await appsRepository.findCreatorByUserId(userId)
      if (!creator || creator.id !== existing.creatorId) {
        return reply.status(403).send({ success: false, error: { message: 'Forbidden' } })
      }

      let buf: Buffer | null = null

      try {
        const parts = request.parts({ limits: { fileSize: MAX_FILE_BYTES } })
        for await (const part of parts) {
          if (part.type === 'file' && part.fieldname === 'icon') {
            buf = await part.toBuffer()
            break
          }
        }
      } catch (err) {
        return reply.status(400).send({
          success: false,
          error: { message: err instanceof Error ? err.message : 'Upload failed' },
        })
      }

      if (!buf || buf.length === 0) {
        return reply.status(400).send({ success: false, error: { message: 'No icon file provided.' } })
      }

      let result
      try {
        result = await uploadToCloudinary(buf, {
          folder:       `appmarket/icons`,
          publicId:     `icon-${appId}-${randomUUID().slice(0, 8)}`,
          resourceType: 'image',
        })
      } catch (err) {
        return reply.status(500).send({
          success: false,
          error: { message: err instanceof Error ? err.message : 'Cloudinary upload failed' },
        })
      }

      await appsService.updateIcon(appId, creator.id, result.url)

      return reply.send({ success: true, data: { iconUrl: result.url } })
    },
  )
}
