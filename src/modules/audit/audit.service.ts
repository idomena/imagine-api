import { auditRepository } from './audit.repository'
import { logger } from '../../core/logger'

// ---------------------------------------------------------------------------
// Audit service — thin wrapper around the append-only AuditLog table.
//
// All writes are fire-and-forget: an audit failure must never roll back the
// business operation that triggered it. Callers should not await the result
// of log() when it runs in a service method that has already committed its
// own writes. Use the void operator or .catch() at the call site.
//
// Convention for action strings:
//   "<domain>.<event>"  e.g. "promotion.job_created", "app.published"
//
// Convention for entityType:
//   PascalCase Prisma model name  e.g. "PromotionJob", "App", "User"
// ---------------------------------------------------------------------------

export const auditService = {
  /**
   * Write a single audit event.
   *
   * Never throws — errors are swallowed and logged so callers don't need
   * try/catch around audit calls.
   */
  async log(data: {
    action:        string
    entityType:    string
    entityId:      string
    performedById?: string
    before?:       unknown
    after?:        unknown
    metadata?:     unknown
  }): Promise<void> {
    try {
      await auditRepository.create(data)
    } catch (err) {
      // Audit failures are non-fatal. Log the error and continue.
      logger.error({ err, action: data.action, entityId: data.entityId }, 'Audit log write failed')
    }
  },

  async list(opts: {
    entityType?:    string
    entityId?:      string
    performedById?: string
    action?:        string
    page:           number
    limit:          number
  }) {
    const skip = (opts.page - 1) * opts.limit
    const result = await auditRepository.findMany({ ...opts, take: opts.limit, skip })
    return {
      ...result,
      page:  opts.page,
      limit: opts.limit,
      pages: Math.ceil(result.total / opts.limit),
    }
  },
}
