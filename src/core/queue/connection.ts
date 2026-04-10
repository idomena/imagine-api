import IORedis from 'ioredis'
import { config } from '../config'
import { logger } from '../logger'

// ---------------------------------------------------------------------------
// Shared ioredis connection for BullMQ queues and workers.
//
// maxRetriesPerRequest: null  — required by BullMQ; without it ioredis will
//   throw on the first blocked command and crash queue processors.
// enableReadyCheck: false     — avoids startup errors when Redis is briefly
//   unavailable; BullMQ manages its own readiness internally.
// lazyConnect: true           — don't connect until the first command so the
//   process can start without Redis being present (queuing degrades gracefully).
// ---------------------------------------------------------------------------

export const redisConnection = new IORedis(config.REDIS_URL ?? 'redis://localhost:6379', {
  maxRetriesPerRequest: null,
  enableReadyCheck: false,
  lazyConnect: true,
})

redisConnection.on('error', (err: Error) => {
  logger.error({ err }, 'Redis connection error')
})

redisConnection.on('connect', () => {
  logger.info('Redis connected')
})
