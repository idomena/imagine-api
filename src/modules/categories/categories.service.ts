import { categoriesRepository } from './categories.repository'
import { ConflictError, NotFoundError } from '../../core/errors'
import type { CreateCategoryBody, UpdateCategoryBody } from './categories.schema'

// ---------------------------------------------------------------------------
// Categories service — business logic for category CRUD.
// ---------------------------------------------------------------------------

export const categoriesService = {
  async list() {
    return categoriesRepository.findAll()
  },

  async get(id: string) {
    const category = await categoriesRepository.findById(id)
    if (!category) throw new NotFoundError('Category', id)
    return category
  },

  async create(body: CreateCategoryBody) {
    const existing = await categoriesRepository.findBySlug(body.slug)
    if (existing) throw new ConflictError(`Slug '${body.slug}' is already in use`)
    return categoriesRepository.create(body)
  },

  async update(id: string, body: UpdateCategoryBody) {
    await categoriesService.get(id) // assert exists

    if (body.slug) {
      const conflict = await categoriesRepository.findBySlug(body.slug)
      if (conflict && conflict.id !== id) {
        throw new ConflictError(`Slug '${body.slug}' is already in use`)
      }
    }

    return categoriesRepository.update(id, body)
  },

  async delete(id: string) {
    await categoriesService.get(id) // assert exists
    await categoriesRepository.delete(id)
  },
}
