import { UserRole } from '@prisma/client'
import { creatorsRepository } from './creators.repository'
import { ConflictError, ForbiddenError, NotFoundError } from '../../core/errors'
import { sanitizeUser } from '../../lib/types'
import type { OnboardBody, UpdateCreatorBody } from './creators.schema'

// ---------------------------------------------------------------------------
// Creators service — business logic for creator onboarding.
// ---------------------------------------------------------------------------

export const creatorsService = {
  async me(userId: string) {
    const creator = await creatorsRepository.findByUserIdWithApps(userId)
    if (!creator) throw new NotFoundError('Creator', userId)
    return creator
  },

  async update(userId: string, body: UpdateCreatorBody) {
    const creator = await creatorsRepository.findByUserId(userId)
    if (!creator) throw new ForbiddenError('No creator profile found — onboard first')
    return creatorsRepository.update(userId, body)
  },

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
