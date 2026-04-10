import { randomUUID } from 'crypto'
import type { FastifyInstance } from 'fastify'
import { appsRepository } from '../apps/apps.repository'
import { uploadToCloudinary } from '../../core/cloudinary'
import { validateUpload } from '../../services/upload-validator.service'
import { securityLogger } from '../../services/security-logger.service'
import { UPLOAD_RATE_LIMIT } from '../../plugins/rate-limit.plugin'

// ---------------------------------------------------------------------------
// Icon upload router — SECURED VERSION
//
// Security additions vs baseline:
//   1. validateUpload() — magic-byte + MIME-spoof detection + size ceiling
//   2. Upload rate limit (20 req / 10 min per user)
//   3. Security audit logging
// ---------------------------------------------------------------------------

export async function appIconRouter(app: FastifyInstance) {
  app.post<{ Params: { id: string } }>(
    '/:id/icon',
    {
      preHandler: [app.authenticate],
      config:     { rateLimit: UPLOAD_RATE_LIMIT },
    },
    async (request, reply) => {
      const { id: appId } = request.params
      const userId        = request.user.sub

      // ── Ownership check ────────────────────────────────────────────────────
      const existing = await appsRepository.findById(appId)
      if (!existing) {
        return reply.status(404).send({ success: false, error: { message: 'App not found' } })
      }
      const creator = await appsRepository.findCreatorByUserId(userId)
      if (!creator || creator.id !== existing.creatorId) {
        void securityLogger.forbiddenAccess(request, 'CREATOR')
        return reply.status(403).send({ success: false, error: { message: 'Forbidden' } })
      }

      // ── Read upload ────────────────────────────────────────────────────────
      let buf: Buffer | null      = null
      let filename = `icon-${randomUUID()}.png`
      let mimetype = 'image/png'

      try {
        const parts = request.parts({ limits: { fileSize: 5 * 1024 * 1024 } })
        for await (const part of parts) {
          if (part.type === 'file' && part.fieldname === 'icon') {
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
        return reply.status(400).send({ success: false, error: { message: 'No icon file provided.' } })
      }

      // ── Validate content ───────────────────────────────────────────────────
      try {
        const result = validateUpload(filename, mimetype, buf.length, buf, 'ICON')
        void securityLogger.uploadAccepted(request, result.sanitizedFilename, 'ICON')
        filename = result.sanitizedFilename
      } catch (validationErr) {
        const msg = validationErr instanceof Error ? validationErr.message : 'Validation failed'
        void securityLogger.uploadRejected(request, msg, filename)
        return reply.status(400).send({ success: false, error: { message: msg } })
      }

      // ── Upload to Cloudinary ───────────────────────────────────────────────
      try {
        const result = await uploadToCloudinary(buf, {
          folder:       'appmarket/icons',
          publicId:     `${appId}-icon`,
          resourceType: 'image',
        })

        await appsRepository.update(appId, { iconUrl: result.url })

        return reply.send({ success: true, data: { iconUrl: result.url } })
      } catch (uploadErr) {
        request.log.error({ uploadErr, appId }, 'Cloudinary icon upload failed')
        return reply.status(502).send({
          success: false,
          error: { message: 'Failed to upload icon. Please try again.' },
        })
      }
    },
  )
}
