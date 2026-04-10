import { randomUUID } from 'crypto'
import type { FastifyInstance } from 'fastify'
import { AssetType } from '@prisma/client'
import { appAssetsRepository } from './app-assets.repository'
import { appsRepository } from '../apps/apps.repository'
import { uploadToCloudinary } from '../../core/cloudinary'
import { validateUpload } from '../../services/upload-validator.service'
import { securityLogger } from '../../services/security-logger.service'
import { UPLOAD_RATE_LIMIT } from '../../plugins/rate-limit.plugin'

// ---------------------------------------------------------------------------
// Screenshots router — SECURED VERSION
//
// Security additions vs baseline:
//   1. validateUpload() — magic-byte check + MIME-spoof detection
//   2. Upload rate limit (20 req / 10 min per user)
//   3. Security audit logging (accept / reject outcomes)
//   4. File count ceiling enforced before reading any bytes
// ---------------------------------------------------------------------------

const MAX_FILES      = 4
const MAX_FILE_BYTES = 10 * 1024 * 1024  // 10 MB per screenshot

export async function appScreenshotsRouter(app: FastifyInstance) {
  app.post<{ Params: { id: string } }>(
    '/:id/screenshots',
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
        return reply.status(404).send({
          success: false,
          error: { message: 'App not found' },
        })
      }
      const creator = await appsRepository.findCreatorByUserId(userId)
      if (!creator || creator.id !== existing.creatorId) {
        void securityLogger.forbiddenAccess(request, 'CREATOR')
        return reply.status(403).send({ success: false, error: { message: 'Forbidden' } })
      }

      // ── Read & validate each part ──────────────────────────────────────────
      const validated: Array<{ buf: Buffer; mime: string; filename: string }> = []

      try {
        const parts = request.parts({ limits: { fileSize: MAX_FILE_BYTES } })

        for await (const part of parts) {
          if (validated.length >= MAX_FILES) break
          if (part.type !== 'file' || part.fieldname !== 'screenshots') continue

          const buf      = await part.toBuffer()
          if (buf.length === 0) continue

          const filename = part.filename ?? `screenshot-${randomUUID()}.jpg`

          try {
            const result = validateUpload(
              filename,
              part.mimetype,
              buf.length,
              buf,
              'SCREENSHOT',
            )
            validated.push({ buf, mime: result.mimeType, filename: result.sanitizedFilename })
            void securityLogger.uploadAccepted(request, result.sanitizedFilename, 'SCREENSHOT')
          } catch (validationErr) {
            const msg = validationErr instanceof Error ? validationErr.message : 'Validation failed'
            void securityLogger.uploadRejected(request, msg, filename)
            return reply.status(400).send({
              success: false,
              error: { message: msg },
            })
          }
        }
      } catch (err) {
        return reply.status(400).send({
          success: false,
          error: { message: err instanceof Error ? err.message : 'Upload failed' },
        })
      }

      if (validated.length === 0) {
        return reply.status(400).send({
          success: false,
          error: { message: 'Upload at least one screenshot.' },
        })
      }

      // ── Determine sort order ───────────────────────────────────────────────
      const existingAssets = await appAssetsRepository.findByApp(appId)
      const screenshots    = existingAssets.filter((a) => a.type === AssetType.SCREENSHOT)
      let nextSort         = screenshots.length > 0
        ? Math.max(...screenshots.map((s) => s.sortOrder ?? 0)) + 1
        : 0

      // ── Upload to Cloudinary ───────────────────────────────────────────────
      const urls: string[] = []

      for (const { buf, filename } of validated) {
        const publicId = `${appId}-${randomUUID()}`
        try {
          const result = await uploadToCloudinary(buf, {
            folder:       'appmarket/screenshots',
            publicId,
            resourceType: 'image',
          })

          await appAssetsRepository.create({
            appId,
            type:       AssetType.SCREENSHOT,
            url:        result.url,
            storageKey: result.publicId,
            sortOrder:  nextSort++,
          })

          urls.push(result.url)
        } catch (uploadErr) {
          request.log.error({ uploadErr, appId, filename }, 'Cloudinary upload failed')
          return reply.status(502).send({
            success: false,
            error: { message: 'Failed to upload file to storage. Please try again.' },
          })
        }
      }

      return reply.status(201).send({ success: true, data: { urls } })
    },
  )
}
