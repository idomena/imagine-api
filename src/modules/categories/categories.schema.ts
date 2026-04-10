import { z } from 'zod'

const slugRegex = /^[a-z0-9]+(?:-[a-z0-9]+)*$/

export const CreateCategoryBodySchema = z.object({
  name: z.string().min(1).max(100),
  slug: z
    .string()
    .min(1)
    .max(100)
    .regex(slugRegex, 'Slug must be lowercase alphanumeric with hyphens (e.g. my-category)'),
  description: z.string().max(500).optional(),
  iconUrl: z.string().url('Invalid icon URL').optional(),
  sortOrder: z.number().int().min(0).default(0),
  parentId: z.string().uuid('Invalid parent category ID').optional(),
})

export const UpdateCategoryBodySchema = CreateCategoryBodySchema.partial()

export type CreateCategoryBody = z.infer<typeof CreateCategoryBodySchema>
export type UpdateCategoryBody = z.infer<typeof UpdateCategoryBodySchema>
