import { z } from 'zod'

export const OnboardBodySchema = z.object({
  displayName: z
    .string()
    .min(2, 'Display name must be at least 2 characters')
    .max(100, 'Display name must be at most 100 characters'),
  bio:     z.string().max(500, 'Bio must be at most 500 characters').optional(),
  website: z.string().url('Invalid website URL').optional(),
})

export const UpdateCreatorBodySchema = z.object({
  displayName: z.string().min(2).max(100).optional(),
  bio:         z.string().max(500).nullable().optional(),
  website:     z.string().url('Invalid website URL').nullable().optional(),
  avatarUrl:   z.string().url('Invalid avatar URL').nullable().optional(),
})

export type OnboardBody        = z.infer<typeof OnboardBodySchema>
export type UpdateCreatorBody  = z.infer<typeof UpdateCreatorBodySchema>
