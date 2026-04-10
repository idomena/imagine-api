import fp from 'fastify-plugin'
import helmet from '@fastify/helmet'
import type { FastifyInstance } from 'fastify'

// ---------------------------------------------------------------------------
// Security Headers Plugin
//
// Registers @fastify/helmet with a strict Content-Security-Policy tuned for
// the Imagine API. All frame/embed vectors are blocked, HSTS is enforced,
// and dangerous browser features (XSS auditor, sniffing) are disabled.
//
// CSP directives rationale:
//   default-src 'none'     — deny everything not explicitly allowed
//   script-src  'self'     — no inline scripts, no eval
//   connect-src 'self' + Cloudinary — only our API and asset CDN
//   img-src 'self' + Cloudinary + data: — avatars, screenshots
//   frame-ancestors 'none' — clickjacking prevention
// ---------------------------------------------------------------------------

export const securityHeadersPlugin = fp(async (app: FastifyInstance) => {
  const cloudinaryHost = `https://res.cloudinary.com`
  const cloudinaryUpload = `https://api.cloudinary.com`

  await app.register(helmet, {
    // Content-Security-Policy
    contentSecurityPolicy: {
      directives: {
        defaultSrc:     ["'none'"],
        scriptSrc:      ["'self'"],
        styleSrc:       ["'self'", "'unsafe-inline'"], // allow minor inline styles
        imgSrc:         ["'self'", 'data:', cloudinaryHost],
        connectSrc:     ["'self'", cloudinaryHost, cloudinaryUpload],
        fontSrc:        ["'self'"],
        objectSrc:      ["'none'"],
        mediaSrc:       ["'self'", cloudinaryHost],
        frameSrc:       ["'none'"],
        frameAncestors: ["'none'"],
        formAction:     ["'self'"],
        baseUri:        ["'self'"],
        upgradeInsecureRequests: [],
      },
      reportOnly: false,
    },

    // Strict-Transport-Security — 1 year, include subdomains
    hsts: {
      maxAge:            31_536_000,
      includeSubDomains: true,
      preload:           true,
    },

    // Disable browser MIME-type sniffing
    noSniff: true,

    // Block the legacy XSS Auditor from reflection attacks
    xssFilter: true,

    // Prevent embedding in iframes (belt-and-suspenders alongside CSP)
    frameguard: { action: 'deny' },

    // Remove X-Powered-By
    hidePoweredBy: true,

    // Referrer policy — don't leak full URLs to third parties
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },

    // Permissions Policy — disable dangerous browser features
    permittedCrossDomainPolicies: false,
    crossOriginEmbedderPolicy: false, // must be off for Cloudinary video
  })

  // Manually set Permissions-Policy (helmet doesn't have a typed API for it)
  app.addHook('onSend', async (_request, reply) => {
    reply.header(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    )
    // Cross-Origin policies
    reply.header('Cross-Origin-Resource-Policy', 'same-site')
    reply.header('Cross-Origin-Opener-Policy',   'same-origin')
  })
})
