import { z } from 'zod'

export const RecordLaunchBodySchema = z.object({
  appId: z.string().uuid('Invalid app ID'),

  // Client-generated session token — lets analytics group launches from the
  // same browser session without requiring auth.
  sessionId: z.string().max(128).optional(),

  // The referring URL, if the app was opened from a link.
  referrer: z.string().url('Invalid referrer URL').max(2048).optional(),

  // NOTE — versionNumber is accepted for documentation/intent but cannot be
  // persisted on LaunchEvent: the schema has no version column.
  // Cross-reference AppVersion records separately if needed.
  // versionNumber: z.string().optional(),
})

export type RecordLaunchBody = z.infer<typeof RecordLaunchBodySchema>
