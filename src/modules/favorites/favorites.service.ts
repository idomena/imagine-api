import { favoritesRepository } from './favorites.repository'
import { appsRepository } from '../apps/apps.repository'
import { NotFoundError } from '../../core/errors'

// ---------------------------------------------------------------------------
// Favorites service — toggle and list a user's favorite apps.
// ---------------------------------------------------------------------------

function withPages(result: { items: unknown[]; total: number }, page: number, limit: number) {
  return { ...result, page, limit, pages: Math.ceil(result.total / limit) }
}

export const favoritesService = {
  async list(userId: string, opts: { page: number; limit: number }) {
    const skip = (opts.page - 1) * opts.limit
    const result = await favoritesRepository.findByUser(userId, { take: opts.limit, skip })
    return withPages(result, opts.page, opts.limit)
  },

  /**
   * Idempotent toggle — adds the favorite if it doesn't exist, removes it if
   * it does. Returns the new state so the client doesn't need a follow-up GET.
   */
  async toggle(userId: string, appId: string) {
    // Guard: the app must exist before we can favorite it.
    const app = await appsRepository.findById(appId)
    if (!app) throw new NotFoundError('App', appId)

    const existing = await favoritesRepository.findOne(userId, appId)

    if (existing) {
      await favoritesRepository.remove(userId, appId)
      return { favorited: false, appId }
    }

    await favoritesRepository.add(userId, appId)
    return { favorited: true, appId }
  },
}
