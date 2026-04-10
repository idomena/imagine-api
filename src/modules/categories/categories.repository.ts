import { db } from '../../core/db'
import type { CreateCategoryBody, UpdateCategoryBody } from './categories.schema'

// ---------------------------------------------------------------------------
// Categories repository — raw DB access, no business logic.
// ---------------------------------------------------------------------------

export const categoriesRepository = {
  async findAll() {
    return db.category.findMany({
      orderBy: [{ sortOrder: 'asc' }, { name: 'asc' }],
    })
  },

  async findById(id: string) {
    return db.category.findUnique({ where: { id } })
  },

  async findBySlug(slug: string) {
    return db.category.findUnique({ where: { slug } })
  },

  async create(data: CreateCategoryBody) {
    return db.category.create({ data })
  },

  async update(id: string, data: UpdateCategoryBody) {
    return db.category.update({ where: { id }, data })
  },

  async delete(id: string) {
    return db.category.delete({ where: { id } })
  },
}
