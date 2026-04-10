import { z } from 'zod'

export const SubmitDecisionBodySchema = z
  .object({
    decision: z.enum(['APPROVED', 'REJECTED']),
    reason:   z.string().min(1).max(1000).optional(),
    notes:    z.string().max(2000).optional(), // internal reviewer notes, not shown to creator
  })
  .refine(
    (data) => data.decision !== 'REJECTED' || !!data.reason,
    { message: 'A rejection reason is required when rejecting an app', path: ['reason'] },
  )

export const QueueQuerySchema = z.object({
  page:  z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
})

export type SubmitDecisionBody = z.infer<typeof SubmitDecisionBodySchema>
export type QueueQuery        = z.infer<typeof QueueQuerySchema>
