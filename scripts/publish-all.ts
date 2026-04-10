import { PrismaClient } from '@prisma/client'

const db = new PrismaClient()

async function main() {
  const r = await db.app.updateMany({
    where: { status: { not: 'PUBLISHED' } },
    data:  { status: 'PUBLISHED', publishedAt: new Date() },
  })
  console.log('Published', r.count, 'app(s)')
}

main().catch(console.error).finally(() => db.$disconnect())
