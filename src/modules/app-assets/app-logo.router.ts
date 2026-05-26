import { randomUUID } from 'crypto'
import type { FastifyInstance } from 'fastify'
import { appsRepository } from '../apps/apps.repository'
import { uploadToCloudinary } from '../../core/cloudinary'
import { validateUpload } from '../../services/upload-validator.service'
import { UPLOAD_RATE_LIMIT } from '../../plugins/rate-limit.plugin'

// POST /api/v1/apps/:id/logo
// Multipart field name: "logo"
// Accepts PNG, JPEG, WebP up to 5 MB.
// Uploads to Cloudinary and writes the URL to App.logoUrl.

export async function appLogoRouter(app: FastifyInstance) {
  app.post<{ Params: { id: string } }>(
    '/:id/logo',
    {
      preHandler: [app.authenticate],
      config:     { rateLimit: UPLOAD_RATE_LIMIT },
    },
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
      let filename           = `logo-${randomUUID()}.png`
      let mimetype           = 'image/png'

      try {
        const parts = request.parts({ limits: { fileSize: 5 * 1024 * 1024 } })
        for await (const part of parts) {
          if (part.type === 'file' && part.fieldname === 'logo') {
            buf      = await part.toBuffer()
            filename = part.filename ?? filename
            mimetype = part.mimetype  ?? mimetype
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
        return reply.status(400).send({ success: false, error: { message: 'No logo file provided.' } })
      }

      try {
        const validated = validateUpload(filename, mimetype, buf.length, buf, 'ICON')
        filename        = validated.sanitizedFilename
      } catch (err) {
        return reply.status(400).send({
          success: false,
          error: { message: err instanceof Error ? err.message : 'Validation failed' },
        })
      }

      try {
        const result = await uploadToCloudinary(buf, {
          folder:       'appmarket/logos',
          publicId:     `${appId}-logo`,
          resourceType: 'image',
        })

        await appsRepository.update(appId, { logoUrl: result.url })

        return reply.send({ success: true, data: { logoUrl: result.url } })
      } catch (uploadErr) {
        request.log.error({ uploadErr, appId }, 'Cloudinary logo upload failed')
        return reply.status(502).send({
          success: false,
          error: { message: 'Failed to upload logo. Please try again.' },
        })
      }
    },
  )
}
