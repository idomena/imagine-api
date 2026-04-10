import { db } from '../../core/db'
import type { CreateVersionBody } from './app-versions.schema'

// ---------------------------------------------------------------------------
// App versions repository — raw DB access, no business logic.
// ---------------------------------------------------------------------------

export const appVersionsRepository = {
  async findByApp(appId: string) {
    return db.appVersion.findMany({
      where: { appId },
      orderBy: { createdAt: 'desc' },
    })
  },

  async findById(id: string) {
    return db.appVersion.findUnique({ where: { id } })
  },

  async findByVersion(appId: string, versionNumber: string) {
    return db.appVersion.findUnique({
      where: { appId_versionNumber: { appId, versionNumber } },
    })
  },

  async create(appId: string, data: CreateVersionBody) {
    return db.appVersion.create({
      data: {
        appId,
        ...data,
        config: (data.config ?? null) as never,
      },
    })
  },
}
