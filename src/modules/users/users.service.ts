import { usersRepository } from './users.repository'
import { ConflictError, NotFoundError } from '../../core/errors'
import { sanitizeUser } from '../../lib/types'
import type { UpdateProfileBody } from './users.schema'

// ---------------------------------------------------------------------------
// Users service — business logic for profile reads and mutations.
// ---------------------------------------------------------------------------

export const usersService = {
  async getProfile(userId: string) {
    const user = await usersRepository.findById(userId)
    if (!user) {
      throw new NotFoundError('User', userId)
    }

    const creator = await usersRepository.findCreatorByUserId(userId)
    return { user: sanitizeUser(user), creator: creator ?? null }
  },

  async updateProfile(userId: string, body: UpdateProfileBody) {
    const user = await usersRepository.findById(userId)
    if (!user) {
      throw new NotFoundError('User', userId)
    }

    // Prevent duplicate emails if the caller is changing their address.
    if (body.email && body.email !== user.email) {
      const conflict = await usersRepository.findByEmail(body.email)
      if (conflict) {
        throw new ConflictError('Email already in use')
      }
    }

    const updated = await usersRepository.update(userId, body)
    return sanitizeUser(updated)
  },
}
