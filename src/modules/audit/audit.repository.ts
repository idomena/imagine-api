import { Prisma } from '@prisma/client'
import { db } from '../../core/db'

// ---------------------------------------------------------------------------
// Audit repository — append-only writes, paginated reads.
// Rows are never updated or deleted; the table is a permanent event log.
// ---------------------------------------------------------------------------

export const auditRepository = {
  async create(data: {
    action:        string
    entityType:    string
    entityId:      string
    performedById?: string
    before?:       unknown
    after?:        unknown
    metadata?:     unknown
  }) {
    return db.auditLog.create({
      data: {
        action:        data.action,
        entityType:    data.entityType,
        entityId:      data.entityId,
        performedById: data.performedById,
        before:        data.before  as Prisma.InputJsonValue | undefined,
        after:         data.after   as Prisma.InputJsonValue | undefined,
        metadata:      data.metadata as Prisma.InputJsonValue | undefined,
      },
    })
  },

  async findMany(opts: {
    entityType?:    string
    entityId?:      string
    performedById?: string
    action?:        string
    take:           number
    skip:           number
  }) {
    const where: Prisma.AuditLogWhereInput = {
      ...(opts.entityType    ? { entityType:    opts.entityType    } : {}),
      ...(opts.entityId      ? { entityId:      opts.entityId      } : {}),
      ...(opts.performedById ? { performedById: opts.performedById } : {}),
      ...(opts.action        ? { action:        opts.action        } : {}),
    }

    const [items, total] = await db.$transaction([
      db.auditLog.findMany({
        where,
        take:    opts.take,
        skip:    opts.skip,
        orderBy: { createdAt: 'desc' },
      }),
      db.auditLog.count({ where }),
    ])

    return { items, total }
  },
}
