import { AppStatus } from '@prisma/client'
import { appVersionsRepository } from './app-versions.repository'
import { appsRepository } from '../apps/apps.repository'
import { BadRequestError, ConflictError, ForbiddenError, NotFoundError } from '../../core/errors'
import type { CreateVersionBody } from './app-versions.schema'

// ---------------------------------------------------------------------------
// App versions service — business logic for versioning.
// ---------------------------------------------------------------------------

// Statuses that allow new versions to be added
const VERSIONABLE_STATUSES: AppStatus[] = [
  AppStatus.DRAFT,
  AppStatus.APPROVED,
  AppStatus.PUBLISHED,
]

export const appVersionsService = {
  async list(appId: string) {
    const app = await appsRepository.findById(appId)
    if (!app) throw new NotFoundError('App', appId)
    return appVersionsRepository.findByApp(appId)
  },

  async create(appId: string, creatorId: string, body: CreateVersionBody) {
    const app = await appsRepository.findById(appId)
    if (!app) throw new NotFoundError('App', appId)

    if (app.creatorId !== creatorId) throw new ForbiddenError()

    if (!VERSIONABLE_STATUSES.includes(app.status)) {
      throw new BadRequestError(
        `Versions can only be added to apps in: ${VERSIONABLE_STATUSES.join(', ')}`,
      )
    }

    const duplicate = await appVersionsRepository.findByVersion(appId, body.versionNumber)
    if (duplicate) {
      throw new ConflictError(`Version '${body.versionNumber}' already exists for this app`)
    }

    const version = await appVersionsRepository.create(appId, body)

    // Keep the denormalized launchUrl on the parent App in sync with the
    // latest version so list queries don't need a join.
    await appsRepository.update(appId, { launchUrl: body.launchUrl })

    return version
  },
}
