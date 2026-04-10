import { v2 as cloudinary } from 'cloudinary'
import { config } from './config'

cloudinary.config({
  cloud_name: config.CLOUDINARY_CLOUD_NAME,
  api_key:    config.CLOUDINARY_API_KEY,
  api_secret: config.CLOUDINARY_API_SECRET,
  secure:     true,
})

export interface CloudinaryUploadResult {
  url:        string   // Cloudinary secure_url
  publicId:   string   // public_id — used as storageKey for deletion
  bytes:      number
  width?:     number
  height?:    number
  format:     string
}

/**
 * Upload a Buffer to Cloudinary using upload_stream.
 * Returns the secure URL and public_id.
 */
export function uploadToCloudinary(
  buf: Buffer,
  opts: {
    folder:         string
    publicId?:      string
    resourceType?:  'image' | 'video' | 'raw' | 'auto'
  },
): Promise<CloudinaryUploadResult> {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      {
        folder:        opts.folder,
        public_id:     opts.publicId,
        resource_type: opts.resourceType ?? 'auto',
        overwrite:     true,
      },
      (error, result) => {
        if (error || !result) return reject(error ?? new Error('Cloudinary upload failed'))
        resolve({
          url:      result.secure_url,
          publicId: result.public_id,
          bytes:    result.bytes,
          width:    result.width,
          height:   result.height,
          format:   result.format,
        })
      },
    )
    stream.end(buf)
  })
}

export { cloudinary }
