/**
 * One-time cleanup: delete duplicate MGP.AI apps, keeping the most recent.
 * Run with: cd apps/api && npx tsx scripts/cleanup-duplicates.ts
 */
import { PrismaClient } from '@prisma/client'

const db = new PrismaClient()

async function main() {
  const all = await db.app.findMany({
    where:   { name: 'MGP.AI' },
    orderBy: { createdAt: 'desc' },
    select:  { id: true, slug: true, createdAt: true },
  })

  console.log(`Found ${all.length} MGP.AI app(s)`)
  if (all.length <= 1) { console.log('Nothing to clean up.'); return }

  const toDelete = all.slice(1)  // keep [0] (newest)

  for (const app of toDelete) {
    await db.$transaction(async tx => {
      await tx.appAsset.deleteMany({ where: { appId: app.id } })
      await tx.appTag.deleteMany({ where: { appId: app.id } })
      await tx.launchEvent.deleteMany({ where: { appId: app.id } })
      await tx.favorite.deleteMany({ where: { appId: app.id } })
      await tx.recentlyUsed.deleteMany({ where: { appId: app.id } })
      await tx.moderationReview.deleteMany({ where: { appId: app.id } })
      await tx.app.delete({ where: { id: app.id } })
    })
    console.log(`  Deleted ${app.slug} (${app.id})`)
  }

  console.log(`Done. Kept: ${all[0]!.slug}`)
}

main().catch(console.error).finally(() => db.$disconnect())
