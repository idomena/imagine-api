import { z } from 'zod'

const slugRegex = /^[a-z0-9]+(?:-[a-z0-9]+)*$/

export const CreateTagBodySchema = z.object({
  name: z.string().min(1).max(50),
  slug: z
    .string()
    .min(1)
    .max(50)
    .regex(slugRegex, 'Slug must be lowercase alphanumeric with hyphens (e.g. my-tag)'),
})

export const UpdateTagBodySchema = CreateTagBodySchema.partial()

export type CreateTagBody = z.infer<typeof CreateTagBodySchema>
export type UpdateTagBody = z.infer<typeof UpdateTagBodySchema>
