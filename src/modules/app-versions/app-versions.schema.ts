import { z } from 'zod'

// Semver pattern: MAJOR.MINOR.PATCH (e.g. 1.0.0, 2.3.14)
const semverRegex = /^\d+\.\d+\.\d+$/

export const CreateVersionBodySchema = z.object({
  versionNumber: z
    .string()
    .regex(semverRegex, 'Version must be a valid semver string (e.g. 1.0.0)'),
  launchUrl: z.string().url('Invalid launch URL'),
  changelog: z.string().max(2000).optional(),
  // Flexible JSON config for embed options, feature flags, etc.
  config: z.record(z.unknown()).optional(),
})

export type CreateVersionBody = z.infer<typeof CreateVersionBodySchema>
