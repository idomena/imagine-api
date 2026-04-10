import { z } from 'zod'

export const UpdateProfileBodySchema = z.object({
  email: z.string().email('Invalid email address').toLowerCase().optional(),
})

export type UpdateProfileBody = z.infer<typeof UpdateProfileBodySchema>
