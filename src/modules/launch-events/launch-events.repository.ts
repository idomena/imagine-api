import { db } from '../../core/db'

// ---------------------------------------------------------------------------
// Launch events repository — append-only, never updates or deletes rows.
// ---------------------------------------------------------------------------

export const launchEventsRepository = {
  async create(data: {
    appId: string
    userId?: string
    sessionId?: string
    ipHash?: string
    userAgent?: string
    referrer?: string
  }) {
    return db.launchEvent.create({ data })
  },
}
