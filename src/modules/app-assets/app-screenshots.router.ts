import { randomUUID } from 'crypto'
import type { FastifyInstance } from 'fastify'
import { AssetType } from '@prisma/client'
import { appAssetsRepository } from './app-assets.repository'
import { appsRepository } from '../apps/apps.repository'
import { uploadToCloudinary } from '../../core/cloudinary'

// ---------------------------------------------------------------------------
// POST /api/v1/apps/:id/screenshots
//
// Accepts multipart/form-data with up to 4 image files (field: "screenshots").
// Streams each file to Cloudinary, creates AppAsset records (type: SCREENSHOT),
// and returns the Cloudinary CDN URLs.
//
// Auth: Bearer token required — must be the creator who owns the app.
// ---------------------------------------------------------------------------

const MAX_FILES      = 4
const MAX_FILE_BYTES = 15 * 1024 * 1024   // 15 MB per file

export async function appScreenshotsRouter(app: FastifyInstance) {
  app.post<{ Params: { id: string } }>(
    '/:id/screenshots',
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const { id: appId } = request.params
      const userId        = request.user.sub

      const existing = await appsRepository.findById(appId)
      if (!existing) {
        return reply.status(404).send({ success: false, code: 'NOT_FOUND', message: 'App not found' })
      }

      const creator = await appsRepository.findCreatorByUserId(userId)
      if (!creator || creator.id !== existing.creatorId) {
        return reply.status(403).send({ success: false, code: 'FORBIDDEN', message: 'Forbidden' })
      }

      const buffers: { buf: Buffer; mime: string }[] = []

      try {
        const parts = request.parts({ limits: { fileSize: MAX_FILE_BYTES } })
        for await (const part of parts) {
          if (buffers.length >= MAX_FILES) continue
          if (part.type === 'file' && part.fieldname === 'screenshots') {
            const buf = await part.toBuffer()
            if (buf.length > 0) {
              buffers.push({ buf, mime: part.mimetype || 'image/jpeg' })
            }
          }
        }
      } catch (err) {
        return reply.status(400).send({
          success: false,
          code:    'UPLOAD_ERROR',
          message: err instanceof Error ? err.message : 'Upload failed',
        })
      }

      if (buffers.length === 0) {
        return reply.status(400).send({
          success: false,
          code:    'NO_FILES',
          message: 'Upload at least one screenshot.',
        })
      }

      const existing_assets = await appAssetsRepository.findByApp(appId)
      const screenshots     = existing_assets.filter(a => a.type === AssetType.SCREENSHOT)
      let nextSort          = screenshots.length > 0
        ? Math.max(...screenshots.map(s => s.sortOrder ?? 0)) + 1
        : 0

      const urls: string[] = []

      for (const { buf, mime } of buffers) {
        let result
        try {
          result = await uploadToCloudinary(buf, {
            folder:       `appmarket/screenshots`,
            publicId:     `screenshot-${appId}-${randomUUID().slice(0, 8)}`,
            resourceType: 'image',
          })
        } catch (err) {
          return reply.status(500).send({
            success: false,
            code:    'CLOUDINARY_ERROR',
            message: err instanceof Error ? err.message : 'Cloudinary upload failed',
          })
        }

        await appAssetsRepository.create({
          appId,
          type:       AssetType.SCREENSHOT,
          url:        result.url,
          storageKey: result.publicId,
          mimeType:   mime,
          sizeBytes:  result.bytes,
          sortOrder:  nextSort++,
        })
        urls.push(result.url)
      }

      return reply.send({ success: true, data: { urls } })
    },
  )
}
