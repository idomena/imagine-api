import { z } from 'zod'
import { AssetType } from '@prisma/client'

export const RequestUploadUrlBodySchema = z.object({
  type: z.nativeEnum(AssetType),
  filename: z
    .string()
    .min(1)
    .max(255)
    .regex(/^[\w. -]+$/, 'Filename may only contain letters, digits, spaces, hyphens, underscores, and dots'),
  mimeType: z.string().min(1).max(100),
  sizeBytes: z
    .number()
    .int()
    .positive()
    .max(50 * 1024 * 1024, 'File must be 50 MB or smaller'),
})

export type RequestUploadUrlBody = z.infer<typeof RequestUploadUrlBodySchema>
