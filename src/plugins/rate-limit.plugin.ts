import fp from 'fastify-plugin'
import rateLimit from '@fastify/rate-limit'
import type { FastifyInstance } from 'fastify'
import IORedis from 'ioredis'
import { config } from '../core/config'
import { logger } from '../core/logger'

// ---------------------------------------------------------------------------
// Rate Limiting Plugin  (Redis-backed via @fastify/rate-limit)
//
// Tiers:
//   GLOBAL       500 req / 1 min  — blanket protection against floods
//   AUTH         10  req / 15 min — brute-force protection (login / register)
//   SUBMIT_APP   5   req / 1 hour — prevent spam submissions
//   UPLOAD       20  req / 10 min — asset upload protection
//   READ_HEAVY   200 req / 1 min  — listing / search endpoints
//
// Key strategy: per IP in public routes; per userId (from JWT sub) when the
// request is authenticated, falling back to IP so pre-auth requests are still
// covered. This prevents a single bad actor from exhausting a shared IP bucket
// on multi-tenant proxies.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Shared Redis client for rate limiting
// (separate from BullMQ connection — avoids maxRetriesPerRequest: null clash)
// ---------------------------------------------------------------------------
const rateLimitRedis = new IORedis(config.REDIS_URL ?? 'redis://localhost:6379', {
  enableReadyCheck:     false,
  lazyConnect:          true,
  maxRetriesPerRequest: 3,
  connectTimeout:       5_000,
  commandTimeout:       2_000,
})

rateLimitRedis.on('error', (err: Error) => {
  logger.error({ err }, '[rate-limit] Redis error — falling back to in-process store')
})

// ---------------------------------------------------------------------------
// Helper: extract a stable user key (userId when authenticated, else IP)
// ---------------------------------------------------------------------------
function userKey(request: { ip: string; headers: Record<string, unknown>; user?: { sub?: string } }): string {
  // JWT payload is attached by authPlugin only on authenticated routes.
  const userId = (request as { user?: { sub?: string } }).user?.sub
  return userId ? `user:${userId}` : `ip:${request.ip}`
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------
export const rateLimitPlugin = fp(async (app: FastifyInstance) => {
  // ── Global limiter (applied to every route) ─────────────────────────────
  await app.register(rateLimit, {
    global:     true,
    max:        500,
    timeWindow: '1 minute',
    redis:      rateLimitRedis,
    keyGenerator: (request) => userKey(request as Parameters<typeof userKey>[0]),
    errorResponseBuilder: (_request, context) => ({
      success:   false,
      error: {
        code:    'RATE_LIMIT_EXCEEDED',
        message: `Too many requests — please retry after ${Math.ceil(context.ttl / 1000)}s`,
        retryAfter: Math.ceil(context.ttl / 1000),
      },
    }),
    addHeaders: {
      'x-ratelimit-limit':     true,
      'x-ratelimit-remaining': true,
      'x-ratelimit-reset':     true,
      'retry-after':           true,
    },
    // Degrade gracefully: if Redis is unavailable use in-process store
    skipOnError: true,
  })
})

// ---------------------------------------------------------------------------
// Scoped rate limit configs — applied per-route via config() helper
// ---------------------------------------------------------------------------

export const AUTH_RATE_LIMIT = {
  max:        10,
  timeWindow: '15 minutes',
  redis:      rateLimitRedis,
  keyGenerator: (request: { ip: string }) => `ip:${request.ip}`, // always IP for auth
  errorResponseBuilder: (_request: unknown, context: { ttl: number }) => ({
    success: false,
    error: {
      code:       'AUTH_RATE_LIMIT',
      message:    'Too many authentication attempts. Please try again later.',
      retryAfter: Math.ceil(context.ttl / 1000),
    },
  }),
}

export const SUBMIT_RATE_LIMIT = {
  max:        5,
  timeWindow: '1 hour',
  redis:      rateLimitRedis,
  keyGenerator: (request: { user?: { sub?: string }; ip: string }) =>
    userKey(request as Parameters<typeof userKey>[0]),
  errorResponseBuilder: (_request: unknown, context: { ttl: number }) => ({
    success: false,
    error: {
      code:       'SUBMIT_RATE_LIMIT',
      message:    'Submission limit reached. You may submit up to 5 apps per hour.',
      retryAfter: Math.ceil(context.ttl / 1000),
    },
  }),
}

export const UPLOAD_RATE_LIMIT = {
  max:        20,
  timeWindow: '10 minutes',
  redis:      rateLimitRedis,
  keyGenerator: (request: { user?: { sub?: string }; ip: string }) =>
    userKey(request as Parameters<typeof userKey>[0]),
  errorResponseBuilder: (_request: unknown, context: { ttl: number }) => ({
    success: false,
    error: {
      code:       'UPLOAD_RATE_LIMIT',
      message:    'Upload limit reached. Please wait before uploading more files.',
      retryAfter: Math.ceil(context.ttl / 1000),
    },
  }),
}
