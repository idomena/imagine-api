import { tagsRepository } from './tags.repository'
import { ConflictError, NotFoundError } from '../../core/errors'
import type { CreateTagBody, UpdateTagBody } from './tags.schema'

// ---------------------------------------------------------------------------
// Tags service — business logic for tag CRUD.
// ---------------------------------------------------------------------------

export const tagsService = {
  async list() {
    return tagsRepository.findAll()
  },

  async get(id: string) {
    const tag = await tagsRepository.findById(id)
    if (!tag) throw new NotFoundError('Tag', id)
    return tag
  },

  async create(body: CreateTagBody) {
    const existing = await tagsRepository.findBySlug(body.slug)
    if (existing) throw new ConflictError(`Slug '${body.slug}' is already in use`)
    return tagsRepository.create(body)
  },

  async update(id: string, body: UpdateTagBody) {
    await tagsService.get(id) // assert exists

    if (body.slug) {
      const conflict = await tagsRepository.findBySlug(body.slug)
      if (conflict && conflict.id !== id) {
        throw new ConflictError(`Slug '${body.slug}' is already in use`)
      }
    }

    return tagsRepository.update(id, body)
  },

  async delete(id: string) {
    await tagsService.get(id) // assert exists
    await tagsRepository.delete(id)
  },
}
