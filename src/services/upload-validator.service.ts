import path from 'path'
import { BadRequestError } from '../core/errors'
import { logger } from '../core/logger'

// ---------------------------------------------------------------------------
// Upload Validator
//
// Validates multipart file uploads before they reach Cloudinary or S3.
// Defends against:
//   - MIME-type spoofing (extension ≠ Content-Type)
//   - Oversized files per asset type
//   - Executable / script content disguised as images
//   - Path traversal in filenames
//   - Zip-bomb / decompression bombs (size sanity check)
// ---------------------------------------------------------------------------

// ── Allowed asset profiles ──────────────────────────────────────────────────
const ASSET_PROFILES = {
  ICON: {
    maxBytes:      5   * 1024 * 1024, //  5 MB
    allowedMimes:  ['image/png', 'image/jpeg', 'image/webp', 'image/gif'],
    allowedExts:   ['.png', '.jpg', '.jpeg', '.webp', '.gif'],
  },
  SCREENSHOT: {
    maxBytes:      10  * 1024 * 1024, // 10 MB
    allowedMimes:  ['image/png', 'image/jpeg', 'image/webp'],
    allowedExts:   ['.png', '.jpg', '.jpeg', '.webp'],
  },
  PROMO_VIDEO: {
    maxBytes:      100 * 1024 * 1024, // 100 MB
    allowedMimes:  ['video/mp4', 'video/webm', 'video/quicktime'],
    allowedExts:   ['.mp4', '.webm', '.mov'],
  },
  BANNER: {
    maxBytes:      5   * 1024 * 1024, //  5 MB
    allowedMimes:  ['image/png', 'image/jpeg', 'image/webp'],
    allowedExts:   ['.png', '.jpg', '.jpeg', '.webp'],
  },
} as const

type AssetType = keyof typeof ASSET_PROFILES

// ── Magic bytes for common image/video types ────────────────────────────────
const MAGIC: Array<{ mime: string; bytes: number[]; offset?: number }> = [
  { mime: 'image/png',        bytes: [0x89, 0x50, 0x4e, 0x47] },
  { mime: 'image/jpeg',       bytes: [0xff, 0xd8, 0xff] },
  { mime: 'image/gif',        bytes: [0x47, 0x49, 0x46, 0x38] },
  { mime: 'image/webp',       bytes: [0x57, 0x45, 0x42, 0x50], offset: 8 },
  { mime: 'video/mp4',        bytes: [0x66, 0x74, 0x79, 0x70], offset: 4 }, // ftyp box
  { mime: 'video/webm',       bytes: [0x1a, 0x45, 0xdf, 0xa3] },
]

function detectMimeFromBuffer(buf: Buffer): string | null {
  for (const { mime, bytes, offset = 0 } of MAGIC) {
    const match = bytes.every((b, i) => buf[offset + i] === b)
    if (match) return mime
  }
  return null
}

function sanitizeFilename(name: string): string {
  // Strip directory traversal, null bytes, and reserved chars
  return path
    .basename(name)
    .replace(/[^\w.\-]/g, '_')
    .replace(/\.{2,}/g, '_')
    .slice(0, 200) // max length
}

// ---------------------------------------------------------------------------
// Main validator
// ---------------------------------------------------------------------------
export interface ValidatedUpload {
  sanitizedFilename: string
  mimeType:          string
  sizeBytes:         number
}

/**
 * Validate an incoming file buffer against the expected asset type.
 * Throws `BadRequestError` for any violation so Fastify returns 400
 * before the file is forwarded to external storage.
 */
export function validateUpload(
  filename:    string,
  mimeType:    string,
  sizeBytes:   number,
  buffer:      Buffer,
  assetType:   AssetType,
): ValidatedUpload {
  const profile = ASSET_PROFILES[assetType]

  // ── 1. Filename sanitisation ─────────────────────────────────────────────
  const sanitizedFilename = sanitizeFilename(filename)
  const ext = path.extname(sanitizedFilename).toLowerCase()

  if (!(profile.allowedExts as readonly string[]).includes(ext)) {
    throw new BadRequestError(
      `File extension '${ext}' is not allowed for asset type ${assetType}. ` +
      `Allowed: ${profile.allowedExts.join(', ')}`,
    )
  }

  // ── 2. Reported MIME type check ──────────────────────────────────────────
  const normalizedMime = (mimeType.split(';')[0] ?? '').trim().toLowerCase()
  if (!(profile.allowedMimes as readonly string[]).includes(normalizedMime)) {
    throw new BadRequestError(
      `MIME type '${normalizedMime}' is not allowed for asset type ${assetType}.`,
    )
  }

  // ── 3. File size check ───────────────────────────────────────────────────
  if (sizeBytes > profile.maxBytes) {
    const limitMb = (profile.maxBytes / 1024 / 1024).toFixed(0)
    const sizeMb  = (sizeBytes        / 1024 / 1024).toFixed(2)
    throw new BadRequestError(
      `File too large: ${sizeMb} MB exceeds the ${limitMb} MB limit for ${assetType}.`,
    )
  }

  // ── 4. Magic bytes check (actual content ≠ spoofed extension) ───────────
  const detectedMime = detectMimeFromBuffer(buffer)
  if (detectedMime && detectedMime !== normalizedMime) {
    logger.warn(
      { filename: sanitizedFilename, reportedMime: normalizedMime, detectedMime },
      '[upload-validator] MIME spoofing attempt detected',
    )
    throw new BadRequestError(
      `File content does not match its declared type (detected: ${detectedMime}).`,
    )
  }

  // ── 5. Executable / script content check (belt-and-suspenders) ──────────
  // Reject files that contain common script signatures in the first 1 KB
  const head = buffer.slice(0, 1024).toString('latin1')
  const SCRIPT_PATTERNS = [
    /<script/i,
    /javascript:/i,
    /vbscript:/i,
    /on\w+\s*=/i,   // onclick=, onload=, etc.
    /<!DOCTYPE html/i,
    /<html/i,
    /MZ/,           // Windows PE executable header
    /\x7fELF/,      // Linux ELF binary
  ]
  for (const pattern of SCRIPT_PATTERNS) {
    if (pattern.test(head)) {
      logger.warn({ filename: sanitizedFilename }, '[upload-validator] Executable/script content in upload')
      throw new BadRequestError('Uploaded file contains forbidden content.')
    }
  }

  return { sanitizedFilename, mimeType: normalizedMime, sizeBytes }
}
