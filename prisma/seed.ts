import { PrismaClient } from '@prisma/client'

const db = new PrismaClient()

const CATEGORIES = [
  { name: 'AI Tools',   slug: 'ai-tools',   description: 'Artificial intelligence and machine learning applications', sortOrder: 0 },
  { name: 'Analytics',  slug: 'analytics',  description: 'Data analysis, dashboards, and business intelligence',      sortOrder: 1 },
  { name: 'Finance',    slug: 'finance',     description: 'Budgeting, investing, and financial management',            sortOrder: 2 },
  { name: 'Fitness',    slug: 'fitness',     description: 'Workouts, training plans, and physical wellness',           sortOrder: 3 },
  { name: 'Games',      slug: 'games',       description: 'Games and interactive entertainment',                       sortOrder: 4 },
  { name: 'Health',     slug: 'health',      description: 'Nutrition, mental wellness, and healthcare tools',          sortOrder: 5 },
  { name: 'Sports',     slug: 'sports',      description: 'Sports tracking, stats, and fan experiences',               sortOrder: 6 },
]

async function main() {
  console.log('Seeding categories…')

  for (const cat of CATEGORIES) {
    await db.category.upsert({
      where:  { slug: cat.slug },
      update: { name: cat.name, description: cat.description, sortOrder: cat.sortOrder },
      create: cat,
    })
    console.log(`  ✓ ${cat.name}`)
  }

  console.log('Done.')
}

main()
  .catch(e => { console.error(e); process.exit(1) })
  .finally(() => db.$disconnect())
