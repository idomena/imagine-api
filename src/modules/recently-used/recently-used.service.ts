import { recentlyUsedRepository } from './recently-used.repository'
import { appsRepository } from '../apps/apps.repository'
import { NotFoundError } from '../../core/errors'

// ---------------------------------------------------------------------------
// Recently-used service — track and retrieve a user's launch history.
// ---------------------------------------------------------------------------

function withPages(result: { items: unknown[]; total: number }, page: number, limit: number) {
  return { ...result, page, limit, pages: Math.ceil(result.total / limit) }
}

export const recentlyUsedService = {
  async list(userId: string, opts: { page: number; limit: number }) {
    const skip = (opts.page - 1) * opts.limit
    const result = await recentlyUsedRepository.findByUser(userId, { take: opts.limit, skip })
    return withPages(result, opts.page, opts.limit)
  },

  /**
   * Record a launch for the current user.
   * Validates the app exists before writing so we don't silently create
   * history for non-existent apps.
   */
  async record(userId: string, appId: string) {
    const app = await appsRepository.findById(appId)
    if (!app) throw new NotFoundError('App', appId)
    return recentlyUsedRepository.upsert(userId, appId)
  },
}
