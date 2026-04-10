import { randomUUID } from 'crypto'
import type { FastifyInstance } from 'fastify'
import { appsRepository } from '../apps/apps.repository'
import { uploadToCloudinary } from '../../core/cloudinary'

// ---------------------------------------------------------------------------
// POST /api/v1/apps/:id/video
//
// Accepts multipart/form-data with a single video file (field: "video").
// Max size 100 MB. Streams to Cloudinary and updates app.videoUrl.
// ---------------------------------------------------------------------------

const MAX_VIDEO_BYTES = 100 * 1024 * 1024   // 100 MB

export async function appVideoRouter(app: FastifyInstance) {
  app.post<{ Params: { id: string } }>(
    '/:id/video',
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
        const parts = request.parts({ limits: { fileSize: MAX_VIDEO_BYTES } })
        for await (const part of parts) {
          if (part.type === 'file' && part.fieldname === 'video') {
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
        return reply.status(400).send({ success: false, error: { message: 'No video file provided.' } })
      }

      let result
      try {
        result = await uploadToCloudinary(buf, {
          folder:       `appmarket/videos`,
          publicId:     `video-${appId}-${randomUUID().slice(0, 8)}`,
          resourceType: 'video',
        })
      } catch (err) {
        return reply.status(500).send({
          success: false,
          error: { message: err instanceof Error ? err.message : 'Cloudinary upload failed' },
        })
      }

      await appsRepository.update(appId, { videoUrl: result.url })

      return reply.send({ success: true, data: { videoUrl: result.url } })
    },
  )
}
