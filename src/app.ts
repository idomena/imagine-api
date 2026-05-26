import Fastify from 'fastify'
import cors from '@fastify/cors'
import fastifyCookie from '@fastify/cookie'
import formbody from '@fastify/formbody'
import fastifyStatic from '@fastify/static'
import multipart from '@fastify/multipart'
import path from 'path'
import fs from 'fs'
import { logger } from './core/logger'

// ── Security plugins ──────────────────────────────────────────────────────
import { securityHeadersPlugin }   from './plugins/security-headers.plugin'
import { rateLimitPlugin }         from './plugins/rate-limit.plugin'
import { inputSanitisationPlugin } from './plugins/input-sanitisation.plugin'

// ── Auth / error plugins ──────────────────────────────────────────────────
import { errorHandlerPlugin } from './plugins/error-handler.plugin'
import { authPlugin }         from './plugins/auth.plugin'

// ── Feature routers ───────────────────────────────────────────────────────
import { healthRouter }         from './modules/health/health.router'
import { authRouter }           from './modules/auth/auth.router.secure'
import { usersRouter }          from './modules/users/users.router'
import { creatorsRouter }       from './modules/creators/creators.router'
import { categoriesRouter }     from './modules/categories/categories.router'
import { tagsRouter }           from './modules/tags/tags.router'
import { appsRouter }           from './modules/apps/apps.router.secure'
import { appVersionsRouter }    from './modules/app-versions/app-versions.router'
import { appAssetsRouter }      from './modules/app-assets/app-assets.router'
import { favoritesRouter }      from './modules/favorites/favorites.router'
import { recentlyUsedRouter }   from './modules/recently-used/recently-used.router'
import { launchEventsRouter }   from './modules/launch-events/launch-events.router'
import { moderationRouter }     from './modules/moderation/moderation.router'
import { promotionsRouter }     from './modules/promotions/promotions.router'
import { auditRouter }          from './modules/audit/audit.router'
import { appScreenshotsRouter } from './modules/app-assets/app-screenshots.router.secure'
import { appIconRouter }        from './modules/app-assets/app-icon.router.secure'
import { appVideoRouter }       from './modules/app-assets/app-video.router'
import { reviewsRouter }        from './modules/reviews/reviews.router'
import { adminRouter }          from './modules/admin/admin.router'
import { analyticsRouter }      from './modules/analytics/analytics.router'

// ---------------------------------------------------------------------------
// Screenshots folder
//
// __dirname = apps/api/src/  →  ../screenshots = apps/api/screenshots/
// Using __dirname (not process.cwd()) so the path is correct regardless of
// which directory the process was launched from.
// ---------------------------------------------------------------------------
export const SCREENSHOTS_DIR = path.join(__dirname, '../screenshots')
fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true })

// ---------------------------------------------------------------------------
// App factory
// ---------------------------------------------------------------------------

export async function buildApp() {
  const app = Fastify({
    logger,
    ajv: {
      customOptions: {
        removeAdditional: 'all',
        coerceTypes:      false,
        allErrors:        true,
      },
    },
    // Expose real client IP when behind Railway's / Cloudflare's reverse proxy
    trustProxy: true,
  })

  // ══════════════════════════════════════════════════════════════════════════
  // SECURITY LAYER — registered first, before any routes
  // ══════════════════════════════════════════════════════════════════════════

  // 1. HTTP Security Headers (Helmet + CSP)
  await app.register(securityHeadersPlugin)

  // 2. Rate Limiting (Redis-backed global + per-route tiers)
  await app.register(rateLimitPlugin)

  // 3. Input Sanitisation (injection / prototype pollution / depth limits)
  await app.register(inputSanitisationPlugin)

  // ══════════════════════════════════════════════════════════════════════════
  // CORE MIDDLEWARE
  // ══════════════════════════════════════════════════════════════════════════

  // ── CORS ──────────────────────────────────────────────────────────────────
  // CORS_ORIGIN can be:
  //   unset / "*"  → allow any origin
  //   "https://a.com,https://b.com" → comma-separated whitelist
  // Railway *.up.railway.app, Vercel *.vercel.app, and imaginehq.services are always allowed.
  const rawOrigin = process.env.CORS_ORIGIN

  const corsOrigin =
    !rawOrigin || rawOrigin === '*'
      ? true
      : (origin: string | undefined, cb: (err: Error | null, allow: boolean) => void) => {
          const allowed = rawOrigin.split(',').map(o => o.trim())
          const alwaysAllowed = (o: string) =>
            o.endsWith('.up.railway.app') ||
            o.endsWith('.vercel.app') ||
            o === 'https://imaginehq.services' ||
            o === 'https://www.imaginehq.services' ||
            o === 'http://localhost:3001' ||
            o === 'http://localhost:3000'
          if (!origin || allowed.includes(origin) || alwaysAllowed(origin)) {
            cb(null, true)
          } else {
            cb(new Error(`CORS: origin ${origin} not allowed`), false)
          }
        }

  await app.register(cors, {
    origin:         corsOrigin,
    credentials:    true,
    methods:        ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })

  // ── Multipart (for screenshot uploads) ───────────────────────────────────
  await app.register(multipart, {
    limits: {
      files:    5,                     // up to 4 screenshots + 1 video/icon
      fileSize: 100 * 1024 * 1024,    // 100 MB ceiling (video)
      fields:   10,
    },
  })

  // ── Static screenshots ────────────────────────────────────────────────────
  // Every file saved to apps/api/screenshots/ becomes available at:
  //   GET http://localhost:3000/screenshots/<filename>.jpg
  await app.register(fastifyStatic, {
    root:          SCREENSHOTS_DIR,
    prefix:        '/screenshots/',
    decorateReply: false,
  })

  // ── Cookies (needed for admin panel session) ─────────────────────────────
  await app.register(fastifyCookie)

  // ── Form body (needed for admin login POST) ───────────────────────────────
  await app.register(formbody)

  // ── Auth / error plugins ──────────────────────────────────────────────────
  await app.register(errorHandlerPlugin)
  await app.register(authPlugin)

  // ── API routes ────────────────────────────────────────────────────────────
  await app.register(healthRouter,       { prefix: '/api/v1' })
  await app.register(authRouter,         { prefix: '/api/v1/auth' })
  await app.register(usersRouter,        { prefix: '/api/v1/users' })
  await app.register(creatorsRouter,     { prefix: '/api/v1/creators' })
  await app.register(categoriesRouter,   { prefix: '/api/v1/categories' })
  await app.register(tagsRouter,         { prefix: '/api/v1/tags' })
  await app.register(appsRouter,            { prefix: '/api/v1/apps' })
  await app.register(appVersionsRouter,     { prefix: '/api/v1/apps' })
  await app.register(appAssetsRouter,       { prefix: '/api/v1/apps' })
  await app.register(appScreenshotsRouter,  { prefix: '/api/v1/apps' })
  await app.register(appIconRouter,         { prefix: '/api/v1/apps' })
  await app.register(appVideoRouter,        { prefix: '/api/v1/apps' })
  await app.register(reviewsRouter,         { prefix: '/api/v1/apps' })
  await app.register(favoritesRouter,    { prefix: '/api/v1/favorites' })
  await app.register(recentlyUsedRouter, { prefix: '/api/v1/recently-used' })
  await app.register(launchEventsRouter, { prefix: '/api/v1/launch-events' })
  await app.register(moderationRouter,   { prefix: '/api/v1/moderation' })
  await app.register(promotionsRouter,   { prefix: '/api/v1/promotions' })
  await app.register(auditRouter,        { prefix: '/api/v1/audit' })
  await app.register(adminRouter)
  await app.register(analyticsRouter, { prefix: '/api/v1' })

  return app
}
