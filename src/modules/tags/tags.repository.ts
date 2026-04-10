import { db } from '../../core/db'
import type { CreateTagBody, UpdateTagBody } from './tags.schema'

// ---------------------------------------------------------------------------
// Tags repository — raw DB access, no business logic.
// ---------------------------------------------------------------------------

export const tagsRepository = {
  async findAll() {
    return db.tag.findMany({ orderBy: { name: 'asc' } })
  },

  async findById(id: string) {
    return db.tag.findUnique({ where: { id } })
  },

  async findBySlug(slug: string) {
    return db.tag.findUnique({ where: { slug } })
  },

  async create(data: CreateTagBody) {
    return db.tag.create({ data })
  },

  async update(id: string, data: UpdateTagBody) {
    return db.tag.update({ where: { id }, data })
  },

  async delete(id: string) {
    return db.tag.delete({ where: { id } })
  },
}
