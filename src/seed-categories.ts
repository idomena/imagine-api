/**
 * One-shot script: insert the 6 required categories if they don't already exist.
 * Run with: npx ts-node -r tsconfig-paths/register src/seed-categories.ts
 * Or simply execute via: npm run db:seed.
 */
import { PrismaClient } from '@prisma/client'

const db = new PrismaClient()

const CATEGORIES = [
  { name: 'Finance',      slug: 'finance'     },
  { name: 'Sports',       slug: 'sports'      },
  { name: 'Games',        slug: 'games'       },
  { name: 'Education',    slug: 'education'   },
  { name: 'Health',       slug: 'health'      },
  { name: 'Productivity', slug: 'productivity'},
]

async function main() {
  for (const [i, cat] of CATEGORIES.entries()) {
    await db.category.upsert({
      where:  { slug: cat.slug },
      update: { sortOrder: i },
      create: { ...cat, sortOrder: i },
    })
    console.log(`✓ ${cat.name}`)
  }
  console.log('Done.')
}

main()
  .catch(console.error)
  .finally(() => db.$disconnect())
