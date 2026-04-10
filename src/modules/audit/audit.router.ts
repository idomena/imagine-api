import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { UserRole } from '@prisma/client'
import { auditService } from './audit.service'

// ---------------------------------------------------------------------------
// Audit router — read-only access to the audit log.
//
// GET /api/v1/audit   — admin: paginated log with optional filters
// ---------------------------------------------------------------------------

const QuerySchema = z.object({
  page:          z.coerce.number().int().min(1).default(1),
  limit:         z.coerce.number().int().min(1).max(100).default(50),
  entityType:    z.string().optional(),
  entityId:      z.string().uuid().optional(),
  performedById: z.string().uuid().optional(),
  action:        z.string().optional(),
})

export async function auditRouter(app: FastifyInstance) {
  app.addHook('preHandler', app.requireRole([UserRole.ADMIN]))

  app.get('/', async (request, reply) => {
    const query = QuerySchema.parse(request.query)
    const data  = await auditService.list(query)
    return reply.send({ success: true, data })
  })
}
