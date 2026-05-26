import fp from 'fastify-plugin'
import type { FastifyInstance, FastifyRequest } from 'fastify'
import { BadRequestError } from '../core/errors'
import { logger } from '../core/logger'

// ---------------------------------------------------------------------------
// Input Sanitisation Plugin
//
// Applied globally before route handlers. Defends against:
//   - SQL injection patterns in URL params / query strings
//   - XSS payloads in JSON body fields
//   - Prototype pollution  (__proto__, constructor, prototype keys)
//   - Excessively deep JSON nesting (DoS via deeply-nested objects)
//   - Abnormally long individual field values
//   - Null-byte injection
//
// Strategy: REJECT, don't silently strip. Removing characters without telling
// the client leads to confusing behaviour. Throwing 400 forces the sender to
// fix the request.
// ---------------------------------------------------------------------------

const MAX_STRING_LENGTH = 50_000      // 50 KB per field
const MAX_JSON_DEPTH    = 10          // max nesting levels
const MAX_ARRAY_LENGTH  = 1_000       // max items in any array

// ── Patterns that apply to every string value ────────────────────────────────
const UNIVERSAL_PATTERNS: RegExp[] = [
  /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|EXEC|UNION|CAST|CONVERT)\b.*\b(FROM|INTO|TABLE|WHERE|SET)\b)/i,
  /<script[\s\S]*?>[\s\S]*?<\/script>/i,
  /javascript\s*:/i,
  /vbscript\s*:/i,
  /\x00/,                          // null bytes
  /\.\.\//,                        // path traversal
]

// ── Patterns only meaningful in HTML attribute context ────────────────────────
// Skipped for URL-shaped values: Google OAuth picture URLs contain query params
// (e.g. "…=s96-c") that match the event-handler pattern but are not XSS.
const HTML_CONTEXT_PATTERNS: RegExp[] = [
  /on\w+\s*=\s*["']?[^"'>]*/i,   // event handlers: onclick=, onload=, etc.
]

function patternsFor(value: string): RegExp[] {
  return /^https?:\/\//i.test(value)
    ? UNIVERSAL_PATTERNS
    : [...UNIVERSAL_PATTERNS, ...HTML_CONTEXT_PATTERNS]
}

const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

// ---------------------------------------------------------------------------
// Recursive string scanner
// ---------------------------------------------------------------------------
function scanValue(value: unknown, depth = 0, path = 'body'): void {
  if (depth > MAX_JSON_DEPTH) {
    throw new BadRequestError(`Request body exceeds maximum nesting depth (${MAX_JSON_DEPTH} levels) at ${path}`)
  }

  if (typeof value === 'string') {
    if (value.length > MAX_STRING_LENGTH) {
      throw new BadRequestError(`Field '${path}' exceeds maximum length of ${MAX_STRING_LENGTH} characters`)
    }
    for (const pattern of patternsFor(value)) {
      if (pattern.test(value)) {
        logger.warn({ path, pattern: pattern.toString() }, '[sanitise] Injection pattern detected in request')
        throw new BadRequestError(`Field '${path}' contains forbidden content`)
      }
    }
    return
  }

  if (Array.isArray(value)) {
    if (value.length > MAX_ARRAY_LENGTH) {
      throw new BadRequestError(`Array '${path}' exceeds maximum length of ${MAX_ARRAY_LENGTH} items`)
    }
    value.forEach((item, i) => scanValue(item, depth + 1, `${path}[${i}]`))
    return
  }

  if (value !== null && typeof value === 'object') {
    for (const key of Object.keys(value as Record<string, unknown>)) {
      if (DANGEROUS_KEYS.has(key)) {
        logger.warn({ path, key }, '[sanitise] Prototype pollution attempt detected')
        throw new BadRequestError(`Key '${key}' is not allowed`)
      }
      scanValue((value as Record<string, unknown>)[key], depth + 1, `${path}.${key}`)
    }
  }
}

// ---------------------------------------------------------------------------
// URL parameter / query string scanner (lighter — no object depth needed)
// ---------------------------------------------------------------------------
function scanUrlParams(obj: Record<string, unknown>, location: 'params' | 'query'): void {
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'string') {
      for (const pattern of patternsFor(value)) {
        if (pattern.test(value)) {
          logger.warn({ key, location }, '[sanitise] Injection pattern in URL')
          throw new BadRequestError(`${location}.${key} contains forbidden content`)
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------
export const inputSanitisationPlugin = fp(async (app: FastifyInstance) => {
  app.addHook('preValidation', async (request: FastifyRequest) => {
    // Scan JSON body
    if (request.body && typeof request.body === 'object') {
      try {
        scanValue(request.body)
      } catch (err) {
        if (err instanceof BadRequestError) throw err
        throw new BadRequestError('Malformed request body')
      }
    }

    // Scan URL params
    if (request.params && typeof request.params === 'object') {
      scanUrlParams(request.params as Record<string, unknown>, 'params')
    }

    // Scan query string
    if (request.query && typeof request.query === 'object') {
      scanUrlParams(request.query as Record<string, unknown>, 'query')
    }
  })
})
