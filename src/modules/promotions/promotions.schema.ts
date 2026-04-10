import { z } from 'zod'

// Known promotion channels. Extend this list as new channels are integrated.
export const PROMOTION_CHANNELS = ['openclaw', 'paperclip'] as const
export type PromotionChannel = (typeof PROMOTION_CHANNELS)[number]

export const CreatePromotionJobBodySchema = z.object({
  appId:   z.string().uuid('Invalid app ID'),
  channel: z.enum(PROMOTION_CHANNELS, {
    errorMap: () => ({
      message: `Channel must be one of: ${PROMOTION_CHANNELS.join(', ')}`,
    }),
  }),
  /** Optional channel-specific payload forwarded to the external API. */
  metadata: z.record(z.unknown()).optional(),
  /** ISO-8601 datetime — if omitted the job runs immediately after approval. */
  scheduledFor: z.string().datetime({ offset: true }).optional(),
})

export const RejectPromotionBodySchema = z.object({
  reason: z.string().min(1, 'Rejection reason is required').max(1000),
})

export const ListPromotionsQuerySchema = z.object({
  page:   z.coerce.number().int().min(1).default(1),
  limit:  z.coerce.number().int().min(1).max(100).default(20),
  appId:  z.string().uuid().optional(),
  status: z.string().optional(), // PromotionStatus string; validated in service
})

export type CreatePromotionJobBody = z.infer<typeof CreatePromotionJobBodySchema>
export type RejectPromotionBody    = z.infer<typeof RejectPromotionBodySchema>
export type ListPromotionsQuery    = z.infer<typeof ListPromotionsQuerySchema>
