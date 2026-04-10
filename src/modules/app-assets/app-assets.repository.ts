import { AssetType } from '@prisma/client'
import { db } from '../../core/db'

// ---------------------------------------------------------------------------
// App assets repository — raw DB access, no business logic.
// ---------------------------------------------------------------------------

export const appAssetsRepository = {
  async findByApp(appId: string) {
    return db.appAsset.findMany({
      where: { appId },
      orderBy: [{ type: 'asc' }, { sortOrder: 'asc' }],
    })
  },

  async findById(id: string) {
    return db.appAsset.findUnique({ where: { id } })
  },

  async create(data: {
    appId: string
    type: AssetType
    url: string
    storageKey: string
    mimeType?: string
    sizeBytes?: number
    sortOrder?: number
  }) {
    return db.appAsset.create({ data })
  },

  async delete(id: string) {
    return db.appAsset.delete({ where: { id } })
  },
}
