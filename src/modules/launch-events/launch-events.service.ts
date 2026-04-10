import { createHash } from 'crypto'
import { launchEventsRepository } from './launch-events.repository'
import { appsRepository } from '../apps/apps.repository'
import { NotFoundError } from '../../core/errors'
import type { RecordLaunchBody } from './launch-events.schema'

// ---------------------------------------------------------------------------
// Launch events service — append-only telemetry for app launches.
//
// Privacy design:
//   - IP addresses are never stored in plaintext.
//   - We store a SHA-256 hash of the IP so we can detect duplicate launches
//     from the same address for analytics without being able to reverse it.
//   - User agent strings are stored as-is (they are not PII by themselves).
// ---------------------------------------------------------------------------

/**
 * Hash an IP address with SHA-256.
 * Returns undefined if the input is empty so we never store an empty hash.
 */
function hashIp(ip: string | undefined): string | undefined {
  if (!ip) return undefined
  return createHash('sha256').update(ip).digest('hex')
}

export const launchEventsService = {
  /**
   * Record a single launch event.
   *
   * Accepts optional request metadata (IP, userAgent) extracted by the router
   * from the Fastify request object so this service stays framework-agnostic.
   */
  async record(
    userId: string,
    body: RecordLaunchBody,
    meta: { ip?: string; userAgent?: string },
  ) {
    const app = await appsRepository.findById(body.appId)
    if (!app) throw new NotFoundError('App', body.appId)

    return launchEventsRepository.create({
      appId:     body.appId,
      userId,
      sessionId: body.sessionId,
      referrer:  body.referrer,
      ipHash:    hashIp(meta.ip),
      userAgent: meta.userAgent,
    })
  },
}
