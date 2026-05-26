import { z } from 'zod'
import { AppStatus } from '@prisma/client'

const slugRegex = /^[a-z0-9]+(?:-[a-z0-9]+)*$/

const hexColorRegex = /^#[0-9a-fA-F]{6}$/

export const CreateAppBodySchema = z.object({
  slug: z
    .string()
    .min(1)
    .max(100)
    .regex(slugRegex, 'Slug must be lowercase alphanumeric with hyphens'),
  name:          z.string().min(1).max(100),
  tagline:       z.string().min(1).max(200),
  description:   z.string().max(5000).optional(),
  categoryId:    z.string().uuid('Invalid category ID').optional(),
  launchUrl:     z.string().url('Invalid URL').optional(),
  iconUrl:       z.string().url('Invalid icon URL').optional(),
  primaryColor:  z.string().regex(hexColorRegex, 'Must be a hex color like #14b8a6').optional(),
  videoUrl:      z.string().url('Invalid URL').optional(),
  screenshots:   z.array(z.string().url('Invalid screenshot URL')).max(8).optional(),
  agreedToTerms: z.boolean().optional(),
})

// Only mutable fields — status is never accepted from the client
export const UpdateAppBodySchema = z.object({
  name:         z.string().min(1).max(100).optional(),
  tagline:      z.string().min(1).max(200).optional(),
  description:  z.string().min(1).max(5000).optional(),
  categoryId:   z.string().uuid('Invalid category ID').nullable().optional(),
  launchUrl:    z.string().url('Invalid URL').optional(),
  primaryColor: z.string().regex(hexColorRegex, 'Must be a hex color like #14b8a6').optional(),
  videoUrl:     z.string().url('Invalid URL').optional(),
  screenshots:  z.array(z.string().url('Invalid screenshot URL')).max(8).optional(),
  tagIds:       z.array(z.string().uuid('Invalid tag ID')).max(10).optional(),
})

export const ScrapeQuerySchema = z.object({
  url: z.string().url('Invalid URL'),
})

export const RenameAppBodySchema = z.object({
  name: z.string().min(1).max(100),
})

export const RejectAppBodySchema = z.object({
  reason: z.string().min(1, 'Rejection reason is required').max(1000),
})

export const ListAppsQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  categoryId: z.string().uuid().optional(),
  status: z.nativeEnum(AppStatus).optional(), // admin-only filter
})

export type CreateAppBody  = z.infer<typeof CreateAppBodySchema>
export type UpdateAppBody  = z.infer<typeof UpdateAppBodySchema>
export type RenameAppBody  = z.infer<typeof RenameAppBodySchema>
export type RejectAppBody  = z.infer<typeof RejectAppBodySchema>
export type ListAppsQuery  = z.infer<typeof ListAppsQuerySchema>
export type ScrapeQuery    = z.infer<typeof ScrapeQuerySchema>
