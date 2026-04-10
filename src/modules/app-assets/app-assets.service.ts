import { randomUUID } from 'crypto'
import { config } from '../../core/config'
import { appAssetsRepository } from './app-assets.repository'
import { appsRepository } from '../apps/apps.repository'
import { BadRequestError, ForbiddenError, NotFoundError } from '../../core/errors'
import type { RequestUploadUrlBody } from './app-assets.schema'

// ---------------------------------------------------------------------------
// App assets service — manages asset records and S3 pre-signed upload URLs.
//
// S3 INTEGRATION STATUS: STUB
//
// This service is designed to support direct-to-S3 uploads via pre-signed URLs.
// The full flow when @aws-sdk/client-s3 + @aws-sdk/s3-request-presigner are
// added will be:
//   1. Client calls POST /assets/upload-url
//   2. This service generates a PutObject pre-signed URL (15 min expiry)
//   3. Client uploads the file directly to S3 (never proxied through the API)
//   4. On upload completion, the client should record the asset via POST /assets
//
// To activate real presigned URLs:
//   npm install @aws-sdk/client-s3 @aws-sdk/s3-request-presigner
//   Replace the stub block below with the commented implementation.
// ---------------------------------------------------------------------------

const PRESIGNED_URL_EXPIRY_SECONDS = 900 // 15 minutes

// Asset type → folder mapping for organised S3 paths
const ASSET_FOLDER: Record<string, string> = {
  ICON:        'icons',
  SCREENSHOT:  'screenshots',
  PROMO_VIDEO: 'videos',
  BANNER:      'banners',
}

function assertS3Configured(): void {
  const required = [config.S3_BUCKET, config.S3_REGION, config.S3_ACCESS_KEY_ID, config.S3_SECRET_ACCESS_KEY]
  if (required.some((v) => !v)) {
    throw new BadRequestError(
      'Object storage is not configured. Set S3_BUCKET, S3_REGION, S3_ACCESS_KEY_ID, and S3_SECRET_ACCESS_KEY.',
    )
  }
}

export const appAssetsService = {
  async listAssets(appId: string) {
    const app = await appsRepository.findById(appId)
    if (!app) throw new NotFoundError('App', appId)
    return appAssetsRepository.findByApp(appId)
  },

  /**
   * Generate a pre-signed S3 PutObject URL for a direct browser upload.
   *
   * Returns the storageKey alongside the URL so the client can pass it back
   * when confirming the upload (via a future POST /assets endpoint).
   */
  async getUploadUrl(appId: string, creatorId: string, body: RequestUploadUrlBody) {
    assertS3Configured()

    const app = await appsRepository.findById(appId)
    if (!app) throw new NotFoundError('App', appId)
    if (app.creatorId !== creatorId) throw new ForbiddenError()

    const folder = ASSET_FOLDER[body.type] ?? 'misc'
    const ext = body.filename.includes('.') ? body.filename.split('.').pop() : ''
    const storageKey = `apps/${appId}/${folder}/${randomUUID()}${ext ? `.${ext}` : ''}`
    const endpoint = config.S3_ENDPOINT ?? `https://s3.${config.S3_REGION!}.amazonaws.com`
    const uploadUrl = `${endpoint}/${config.S3_BUCKET!}/${storageKey}`

    // ── STUB ──────────────────────────────────────────────────────────────
    // Replace the block above with the following once the SDK is installed:
    //
    // import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3'
    // import { getSignedUrl } from '@aws-sdk/s3-request-presigner'
    //
    // const s3 = new S3Client({
    //   region: config.S3_REGION!,
    //   endpoint: config.S3_ENDPOINT,
    //   credentials: {
    //     accessKeyId: config.S3_ACCESS_KEY_ID!,
    //     secretAccessKey: config.S3_SECRET_ACCESS_KEY!,
    //   },
    // })
    // const command = new PutObjectCommand({
    //   Bucket: config.S3_BUCKET!,
    //   Key: storageKey,
    //   ContentType: body.mimeType,
    //   ContentLength: body.sizeBytes,
    // })
    // const uploadUrl = await getSignedUrl(s3, command, { expiresIn: PRESIGNED_URL_EXPIRY_SECONDS })
    // ─────────────────────────────────────────────────────────────────────

    return {
      uploadUrl,
      storageKey,
      expiresIn: PRESIGNED_URL_EXPIRY_SECONDS,
    }
  },

  async deleteAsset(assetId: string, appId: string, creatorId: string) {
    const asset = await appAssetsRepository.findById(assetId)
    if (!asset || asset.appId !== appId) throw new NotFoundError('Asset', assetId)

    const app = await appsRepository.findById(appId)
    if (!app || app.creatorId !== creatorId) throw new ForbiddenError()

    await appAssetsRepository.delete(assetId)

    // TODO: delete the object from S3 using storageKey (asset.storageKey)
    // once @aws-sdk/client-s3 is integrated.
  },
}
