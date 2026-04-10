import { UserRole } from '@prisma/client'
import { creatorsRepository } from './creators.repository'
import { ConflictError, NotFoundError } from '../../core/errors'
import { sanitizeUser } from '../../lib/types'
import type { OnboardBody } from './creators.schema'

// ---------------------------------------------------------------------------
// Creators service — business logic for creator onboarding.
// ---------------------------------------------------------------------------

export const creatorsService = {
  async onboard(userId: string, body: OnboardBody) {
    const user = await creatorsRepository.findUserById(userId)
    if (!user) {
      throw new NotFoundError('User', userId)
    }

    if (user.role === UserRole.CREATOR) {
      throw new ConflictError('User is already a creator')
    }

    const existing = await creatorsRepository.findByUserId(userId)
    if (existing) {
      throw new ConflictError('Creator profile already exists')
    }

    const { user: updatedUser, creator } = await creatorsRepository.onboard(
      userId,
      body.displayName,
      body.bio,
      body.website,
    )

    return { user: sanitizeUser(updatedUser), creator }
  },
}
