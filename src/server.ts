// Must be the first import — loads .env into process.env before any
// module reads config. In production, real env vars are used directly
// and dotenv is a safe no-op if no .env file exists.
import 'dotenv/config'

import { buildApp } from './app'
import { config } from './core/config'
import { logger } from './core/logger'
import { redisConnection } from './core/queue'
import { createNotificationWorker } from './workers/notification.worker'
import { createPromotionWorker } from './workers/promotion.worker'
import { db } from './core/db'

async function start() {
  // ── DB connectivity check ─────────────────────────────────────────────────
  const dbUrl = process.env['DATABASE_URL']
  if (!dbUrl) {
    logger.error('DATABASE_URL is not set — cannot start without a database')
    process.exit(1)
  }
  // Detect the most common Supabase misconfiguration: using the pooler endpoint
  // (*.pooler.supabase.com) without the required "postgres.PROJECT_REF" username.
  // Direct connection (db.*.supabase.co:5432) is correct for a persistent server.
  if (dbUrl.includes('pooler.supabase.com') && !dbUrl.match(/postgres\.[a-z]+/)) {
    logger.error(
      'DATABASE_URL looks like a Supabase pooler URL with wrong username format. ' +
      'Use the direct connection: postgresql://postgres:PASSWORD@db.PROJECT_REF.supabase.co:5432/postgres ' +
      'OR fix the pooler username to "postgres.PROJECT_REF".',
    )
    process.exit(1)
  }

  try {
    await db.$connect()
    logger.info('Database connected')
  } catch (err) {
    logger.error(
      { err, urlHost: new URL(dbUrl).hostname },
      'Database connection failed — verify DATABASE_URL in Railway Variables',
    )
    process.exit(1)
  }

  // ── Schema: add columns that may be missing (idempotent, one per call) ───
  for (const sql of [
    `ALTER TABLE "App"     ADD COLUMN IF NOT EXISTS "themePreference" TEXT`,
    `ALTER TABLE "App"     ADD COLUMN IF NOT EXISTS "logoUrl"         TEXT`,
    `ALTER TABLE "App"     ADD COLUMN IF NOT EXISTS "logoColor"       TEXT`,
    `ALTER TABLE "App"     ADD COLUMN IF NOT EXISTS "anonymous"       BOOLEAN NOT NULL DEFAULT false`,
    `ALTER TABLE "Creator" ADD COLUMN IF NOT EXISTS "accentColor"     TEXT`,
    `ALTER TABLE "Creator" ADD COLUMN IF NOT EXISTS "bannerUrl"       TEXT`,
  ]) {
    try {
      await db.$executeRawUnsafe(sql)
    } catch (err) {
      logger.warn({ err, sql }, 'Schema column migration failed')
    }
  }
  logger.info('Schema columns verified')

  // ── Cleanup: purge apps flagged with ADULT_CONTENT ──────────────────────
  try {
    const flagged = await db.securityAuditReport.findMany({
      where:  { threats: { string_contains: 'ADULT_CONTENT' } },
      select: { appId: true },
    })
    if (flagged.length > 0) {
      const ids = flagged.map(r => r.appId)
      const { count } = await db.app.deleteMany({ where: { id: { in: ids } } })
      logger.info({ count, ids }, '[cleanup] Purged adult-content flagged apps')
    }
  } catch (err) {
    logger.warn({ err }, '[cleanup] Adult content purge failed — non-fatal')
  }

  // ── Cleanup: delete orphan apps whose creator has no linked user ─────────
  try {
    const orphans = await db.$queryRaw<Array<{ id: string; name: string }>>`
      SELECT a.id, a.name
      FROM "App" a
      LEFT JOIN "Creator" c ON c.id = a."creatorId"
      LEFT JOIN "User" u ON u.id = c."userId"
      WHERE u.id IS NULL
    `
    if (orphans.length > 0) {
      const ids = orphans.map(a => a.id)
      await db.app.deleteMany({ where: { id: { in: ids } } })
      logger.info({ count: ids.length, names: orphans.map(a => a.name) }, '[cleanup] Deleted orphan apps')
    }
  } catch (err) {
    logger.warn({ err }, '[cleanup] Orphan app cleanup failed — non-fatal')
  }

  // ── Cleanup: remove known test/placeholder apps by slug ───────────────────
  try {
    const slugs = ['jitter', 'tradingview', 'jitter-1', 'tradingview-1']
    const apps = await db.app.findMany({
      where:  { slug: { in: slugs } },
      select: { id: true, name: true },
    })
    if (apps.length > 0) {
      const ids = apps.map(a => a.id)
      // Must remove FK-dependent rows before deleting App (RESTRICT constraints)
      await db.launchEvent.deleteMany({ where: { appId: { in: ids } } })
      await db.securityAuditReport.deleteMany({ where: { appId: { in: ids } } })
      await db.app.deleteMany({ where: { id: { in: ids } } })
      logger.info({ count: apps.length, names: apps.map(a => a.name) }, '[cleanup] Removed placeholder apps')
    }
  } catch (err) {
    logger.warn({ err }, '[cleanup] Placeholder app removal failed — non-fatal')
  }

  const app = await buildApp()

  // ── Background workers (require Redis) ───────────────────────────────────
  // Workers are skipped when REDIS_URL is not configured (e.g. Railway
  // without a Redis add-on). The HTTP server still starts normally.
  let notificationWorker: Awaited<ReturnType<typeof createNotificationWorker>> | null = null
  let promotionWorker:    Awaited<ReturnType<typeof createPromotionWorker>>    | null = null

  if (config.REDIS_URL) {
    notificationWorker = createNotificationWorker()
    promotionWorker    = createPromotionWorker()
    logger.info('Background workers started')
  } else {
    logger.warn('REDIS_URL not set — background workers disabled')
  }

  try {
    const address = await app.listen({ port: config.PORT, host: config.HOST })
    logger.info({ address, env: config.NODE_ENV }, 'Server started')
  } catch (err) {
    logger.error({ err }, 'Failed to start server')
    process.exit(1)
  }

  // ── Graceful shutdown ─────────────────────────────────────────────────────
  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Shutdown signal received')

    if (notificationWorker) await notificationWorker.close()
    if (promotionWorker)    await promotionWorker.close()
    if (config.REDIS_URL)   await redisConnection.quit()

    await app.close()
    logger.info('Server closed')

    process.exit(0)
  }

  process.on('SIGINT',  () => void shutdown('SIGINT'))
  process.on('SIGTERM', () => void shutdown('SIGTERM'))
}

void start()
