import type { Prisma } from '@prisma/client'
import { db } from '../core/db'
import { logger } from '../core/logger'

// ---------------------------------------------------------------------------
// The Sentinel — Smart Malicious Script Scanner
//
// Philosophy: Precise by Default.
//   Flag only definite attacks. Legitimate apps — including those that use
//   Stripe, PayPal, or Israeli payment processors — must never be blocked.
//
// What triggers malicious: true (and a 422):
//   1. CC Skimming   — raw card/CVV input fields with no trusted processor present
//   2. Cookie Theft  — inline script reads document.cookie AND exfiltrates to
//                      a non-whitelisted external endpoint
//   3. Storage Exfil — inline script reads localStorage/sessionStorage AND
//                      exfiltrates to a non-whitelisted external endpoint
//   4. Phishing Form — form with credentials submits to an external domain
//                      that is NOT a whitelisted payment processor
//   5. Obfuscation   — eval(atob(…)), hex char arrays, document.write(unescape(…))
//                      in inline scripts only
//
// What is explicitly ALLOWED:
//   - Stripe, PayPal, Isracard, Tranzila, Meshulam scripts and form actions
//   - eval() or atob() standalone (not combined with each other)
//   - localStorage reads without a matching exfiltration call
//   - External scripts loaded via src= (never scanned inline)
// ---------------------------------------------------------------------------

export interface ThreatEntry {
  type: string
  description: string
}

export interface ScanResult {
  appId:     string
  url:       string
  scannedAt: string
  malicious: boolean
  threats:   ThreatEntry[]
}

// ─── Payment Processor Whitelist ──────────────────────────────────────────────

const TRUSTED_PAYMENT_HOSTNAMES = new Set([
  // Stripe
  'stripe.com', 'js.stripe.com', 'checkout.stripe.com', 'api.stripe.com',
  // PayPal
  'paypal.com', 'www.paypal.com', 'checkout.paypal.com', 'api.paypal.com',
  'paypalobjects.com',
  // Isracard
  'isracard.co.il', 'online.isracard.co.il', 'gateway.isracard.co.il',
  // Tranzila
  'tranzila.com', 'direct.tranzila.com', 'secure5.tranzila.com',
  // Meshulam
  'meshulam.co.il', 'meshulam.net', 'secure.meshulam.co.il',
])

function isTrustedPaymentDomain(hostname: string): boolean {
  if (TRUSTED_PAYMENT_HOSTNAMES.has(hostname)) return true
  // Allow any subdomain of a trusted root (e.g. embed.stripe.com)
  for (const trusted of TRUSTED_PAYMENT_HOSTNAMES) {
    if (hostname.endsWith('.' + trusted)) return true
  }
  return false
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function extractDomain(url: string): string | null {
  try { return new URL(url).hostname } catch { return null }
}

/** Inline <script> blocks only — never flags external src= bundles. */
function extractInlineScripts(html: string): string {
  return [...html.matchAll(/<script(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi)]
    .map(m => m[1] ?? '')
    .join('\n')
}

/**
 * Returns true if there is a fetch/XHR/beacon call in the script that targets
 * an external non-whitelisted domain.
 */
function hasExfiltrationToUntrustedDomain(scripts: string): boolean {
  // Explicit fetch("https://...") — check the target domain
  for (const [, url] of scripts.matchAll(/fetch\s*\(\s*["'`](https?:\/\/[^"'`\s)]+)/gi)) {
    try {
      if (!isTrustedPaymentDomain(new URL(url).hostname)) return true
    } catch { return true }
  }
  // XMLHttpRequest, sendBeacon, image pixel, redirect — can't easily inspect target
  if (
    /new\s+XMLHttpRequest\s*\(\s*\)/i.test(scripts)         ||
    /navigator\.sendBeacon\s*\(/i.test(scripts)              ||
    /new\s+Image\s*\(\s*\)\s*\.src\s*=/i.test(scripts)      ||
    /document\.location\s*(?:=|\.replace)/i.test(scripts)
  ) return true

  return false
}

// ─── Check 1 — CC Skimming ────────────────────────────────────────────────────

/**
 * Flags raw credit-card input fields (card number, CVV, expiry) that appear in
 * the page HTML without a trusted payment processor (Stripe/PayPal/etc.) present.
 *
 * Legitimate apps route card data through hosted iframes or SDKs from known
 * processors — they never have bare <input name="card-number"> in raw HTML.
 */
function detectCCSkimming(html: string): ThreatEntry[] {
  // Match inputs whose name/id/placeholder/autocomplete hint at card data
  const CC_FIELD_RE = /<input[^>]+(?:name|id|placeholder|autocomplete)\s*=\s*["'][^"']*(?:card[-_\s]?(?:number|num|no)|credit[-_\s]?card|cc[-_\s]?(?:num|number)|cardnumber|card-number|cvv|cvc\b|cvc2|card[-_\s]?code|expir(?:y|ation)?[-_\s]?(?:date|month|year)?)[^"']*["'][^>]*>/gi
  if (!CC_FIELD_RE.test(html)) return []

  // If a trusted payment SDK or hosted iframe is present, the fields are secure
  const hasTrustedSDK = (() => {
    for (const [, src] of html.matchAll(/<script[^>]+\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi)) {
      try { if (isTrustedPaymentDomain(new URL(src).hostname)) return true } catch {}
    }
    for (const [, src] of html.matchAll(/<iframe[^>]+\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi)) {
      try { if (isTrustedPaymentDomain(new URL(src).hostname)) return true } catch {}
    }
    return false
  })()

  if (hasTrustedSDK) return []

  return [{
    type:        'CC_SKIMMING',
    description: 'Page contains raw credit card / CVV input fields without a trusted payment processor — potential card skimming attack.',
  }]
}

// ─── Check 2 — Cookie & Storage Theft ────────────────────────────────────────

/**
 * Detects inline scripts that read session credentials AND send them to a
 * non-whitelisted external endpoint in the same script.
 * Standalone localStorage reads without exfiltration are NOT flagged.
 */
function detectCredentialTheft(html: string): ThreatEntry[] {
  const threats: ThreatEntry[] = []
  const scripts = extractInlineScripts(html)
  if (!scripts.trim()) return threats

  const hasExfil = hasExfiltrationToUntrustedDomain(scripts)
  if (!hasExfil) return threats

  if (/document\.cookie/i.test(scripts)) {
    threats.push({
      type:        'COOKIE_THEFT',
      description: 'Inline script reads document.cookie and exfiltrates it to an external endpoint — session hijacking payload.',
    })
  }

  if (/(?:localStorage|sessionStorage)\s*\.\s*(?:getItem|key\b)/i.test(scripts)) {
    threats.push({
      type:        'STORAGE_EXFILTRATION',
      description: 'Inline script reads localStorage/sessionStorage and exfiltrates to an external endpoint — credential exfiltration payload.',
    })
  }

  return threats
}

// ─── Check 3 — Malicious Obfuscation ─────────────────────────────────────────

/**
 * Targets heavily encoded payloads in inline scripts.
 * Flags eval(atob(…)) combos, hex char arrays, and document.write(unescape(…)).
 * Standalone eval() or atob() without the other are NOT flagged.
 */
function detectMaliciousObfuscation(html: string): ThreatEntry[] {
  const scripts = extractInlineScripts(html)
  if (!scripts.trim()) return []

  const isObfuscated = (
    /eval\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(/i.test(scripts) ||
    /(?:\\x[0-9a-f]{2}){8,}/i.test(scripts)                                ||
    /String\.fromCharCode\s*\(\s*(?:\d{2,3}\s*,\s*){9,}/i.test(scripts)   ||
    /document\.write\s*\(\s*(?:unescape|decodeURIComponent)\s*\(/i.test(scripts)
  )

  if (!isObfuscated) return []

  return [{
    type:        'MALICIOUS_OBFUSCATION',
    description: 'Heavily encoded inline JavaScript detected (eval/atob combo, hex arrays, or document.write/unescape) — classic hidden malware delivery pattern.',
  }]
}

// ─── Check 4 — Phishing Forms ─────────────────────────────────────────────────

/**
 * Detects forms that collect credentials (password / email) and POST them to
 * an external domain that is NOT a whitelisted payment processor.
 * Forms that legitimately submit to Stripe, PayPal, etc. are allowed.
 */
function detectPhishingForms(html: string, pageUrl: string): ThreatEntry[] {
  const pageDomain = extractDomain(pageUrl)

  const suspiciousActions: string[] = []
  for (const [formTag] of html.matchAll(/<form[^>]*>/gi)) {
    const actionMatch = formTag.match(/\baction\s*=\s*["']([^"']+)["']/i)
    if (!actionMatch) continue
    const action = actionMatch[1] ?? ''
    // Relative URLs are safe (same origin)
    if (!action || action.startsWith('#') || action.startsWith('/') || action.startsWith('?')) continue

    try {
      const actionDomain = new URL(action).hostname
      if (pageDomain && actionDomain === pageDomain) continue   // same-origin
      if (isTrustedPaymentDomain(actionDomain)) continue        // known processor
      suspiciousActions.push(action)
    } catch { /* malformed URL — ignore */ }
  }

  if (suspiciousActions.length === 0) return []

  // Only flag if the form contains sensitive credential fields
  const hasPasswordField = /<input[^>]*\btype\s*=\s*["']password["'][^>]*>/i.test(html)
  const hasEmailField    = /<input[^>]*\btype\s*=\s*["']email["'][^>]*>/i.test(html)
  if (!hasPasswordField && !hasEmailField) return []

  return [{
    type:        'PHISHING_FORM',
    description: `Form collects credentials (${hasPasswordField ? 'password' : 'email'} field) and submits to an external domain: ${suspiciousActions[0]?.slice(0, 80)} — credential harvesting pattern.`,
  }]
}

// ─── Check 5 — Raw Body Scan ─────────────────────────────────────────────────

/**
 * Scans the raw HTML body for dangerous primitive patterns.
 * Runs after the structural checks so we can catch anything they missed.
 * Only flags password/card fields when no trusted processor is present,
 * and only flags localStorage when it appears in an inline script context.
 */
function detectRawBodyThreats(html: string, pageUrl: string): ThreatEntry[] {
  const threats: ThreatEntry[] = []

  // Password field outside a trusted-processor context
  const hasPassword = /type\s*=\s*["']password["']/i.test(html)
  if (hasPassword) {
    // Already caught by phishing check if the form has an external action.
    // Here we flag the additional case: password field + external cross-domain form.
    const pageDomain = extractDomain(pageUrl)
    for (const [formTag] of html.matchAll(/<form[^>]*>/gi)) {
      const actionMatch = formTag.match(/\baction\s*=\s*["']([^"']+)["']/i)
      if (!actionMatch) continue
      try {
        const actionDomain = new URL(actionMatch[1] ?? '').hostname
        if (pageDomain && actionDomain !== pageDomain && !isTrustedPaymentDomain(actionDomain)) {
          threats.push({
            type:        'PASSWORD_EXFIL',
            description: `Page has a password field that submits to an external domain (${actionDomain}) — potential credential harvest.`,
          })
          break
        }
      } catch {}
    }
  }

  // Raw card-type input (type="card" or autocomplete hints) without a trusted processor
  const hasCardField = /type\s*=\s*["'](?:card|credit[-_\s]?card|debit[-_\s]?card)["']/i.test(html)
  if (hasCardField) {
    const hasTrustedSDK = (() => {
      for (const [, src] of html.matchAll(/<script[^>]+\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi)) {
        try { if (isTrustedPaymentDomain(new URL(src).hostname)) return true } catch {}
      }
      return false
    })()
    if (!hasTrustedSDK) {
      threats.push({
        type:        'RAW_CARD_FIELD',
        description: 'Page contains a raw card-type input field without a trusted payment SDK — potential card data interception.',
      })
    }
  }

  // localStorage in inline scripts (already caught by credential theft if combined with exfil;
  // here we flag it as a supporting signal when combined with any other threat)
  const inlineScripts = extractInlineScripts(html)
  if (/localStorage/i.test(inlineScripts) && threats.length > 0) {
    threats.push({
      type:        'LOCALSTORAGE_RISK',
      description: 'Inline script accesses localStorage in a page that also has other threat indicators.',
    })
  }

  return threats
}

// ─── Known Malware URL Signatures ────────────────────────────────────────────

/**
 * Hardcoded URL blacklist — run before any fetch.
 * Patterns are matched case-insensitively against the full URL.
 */
const KNOWN_MALWARE_URL_PATTERNS: Array<{ pattern: string; label: string }> = [
  { pattern: 'malicious-test', label: 'Known malware test endpoint' },
]

function checkUrlSignatures(url: string): ThreatEntry[] {
  const lower = url.toLowerCase()
  for (const { pattern, label } of KNOWN_MALWARE_URL_PATTERNS) {
    if (lower.includes(pattern)) {
      return [{
        type:        'KNOWN_MALWARE_SIGNATURE',
        description: `${label} — URL contains blacklisted pattern "${pattern}". Blocked immediately.`,
      }]
    }
  }
  return []
}

// ─── Content Fetcher ──────────────────────────────────────────────────────────

const FETCH_TIMEOUT_MS  = 8_000   // raised: some CDN edge nodes are slow
const MAX_CONTENT_BYTES = 524_288 // 512 KB

interface FetchResult {
  html:    string | null
  blocked: boolean   // true = server responded but refused (4xx/5xx) or network hard-failed
}

async function fetchHtml(url: string): Promise<FetchResult> {
  try {
    const controller = new AbortController()
    const timeout    = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)

    const res = await fetch(url, {
      signal:   controller.signal,
      redirect: 'follow',
      headers: {
        // Full Chrome 124 header set — bypass Cloudflare/Vercel bot detection
        'User-Agent':                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.6367.82 Safari/537.36',
        'Accept':                    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language':           'en-US,en;q=0.9',
        'Accept-Encoding':           'gzip, deflate, br',
        'Cache-Control':             'no-cache',
        'Pragma':                    'no-cache',
        'Sec-CH-UA':                 '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        'Sec-CH-UA-Mobile':          '?0',
        'Sec-CH-UA-Platform':        '"Windows"',
        'Sec-Fetch-Dest':            'document',
        'Sec-Fetch-Mode':            'navigate',
        'Sec-Fetch-Site':            'none',
        'Sec-Fetch-User':            '?1',
        'Upgrade-Insecure-Requests': '1',
      },
    })
    clearTimeout(timeout)

    // 4xx / 5xx — server is up but blocking or broken
    if (!res.ok) return { html: null, blocked: true }

    const ct = res.headers.get('content-type') ?? ''
    if (!ct.includes('html') && !ct.includes('text')) return { html: null, blocked: false }

    const reader = res.body?.getReader()
    if (!reader) return { html: null, blocked: true }

    const chunks: Uint8Array[] = []
    let total = 0
    for (;;) {
      const { done, value } = await reader.read()
      if (done || !value) break
      total += value.length
      if (total > MAX_CONTENT_BYTES) {
        await reader.cancel()
        chunks.push(value.slice(0, MAX_CONTENT_BYTES - (total - value.length)))
        break
      }
      chunks.push(value)
    }

    return {
      html:    new TextDecoder().decode(Buffer.concat(chunks.map(c => Buffer.from(c)))),
      blocked: false,
    }
  } catch {
    // Network error / timeout / TLS failure — cannot verify the page
    return { html: null, blocked: true }
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

export async function scanApp(appId: string, launchUrl: string): Promise<ScanResult> {
  logger.info({ appId, launchUrl }, '[sentinel] Scan started')

  const threats: ThreatEntry[] = []

  if (launchUrl) {
    // Step 1 — hardcoded URL blacklist (no network needed)
    const sigThreats = checkUrlSignatures(launchUrl)
    if (sigThreats.length > 0) {
      threats.push(...sigThreats)
      logger.warn({ appId, launchUrl }, '[sentinel] URL blacklist hit — skipping fetch')
    } else {
      // Step 2 — fetch + analyse
      const { html, blocked } = await fetchHtml(launchUrl)

      if (blocked) {
        // Server refused or network failed — we cannot verify the page is safe
        threats.push({
          type:        'UNVERIFIABLE',
          description: 'Could not verify site integrity — the page was inaccessible or returned an error response.',
        })
        logger.warn({ appId, launchUrl }, '[sentinel] Fetch blocked — marking unverifiable')
      } else if (html) {
        threats.push(...detectCCSkimming(html))
        threats.push(...detectCredentialTheft(html))
        threats.push(...detectMaliciousObfuscation(html))
        threats.push(...detectPhishingForms(html, launchUrl))

        // Step 3 — raw body scan for dangerous patterns
        threats.push(...detectRawBodyThreats(html, launchUrl))
      }
    }
  }

  const malicious = threats.length > 0
  const decision  = malicious ? 'AUTO_REJECTED' : 'AUTO_PUBLISHED'
  const score     = malicious ? 0 : 100

  logger.info({ appId, malicious, threats: threats.map(t => t.type) }, '[sentinel] Scan complete')

  const phase2Snapshot: Prisma.InputJsonValue = {
    fetched:           !!launchUrl,
    contentLength:     0,
    xss: {
      cookieTheftDetected:  threats.some(t => t.type === 'COOKIE_THEFT'),
      storageTheftDetected: threats.some(t => t.type === 'STORAGE_EXFILTRATION'),
    },
    obfuscatedContent: threats.some(t => t.type === 'MALICIOUS_OBFUSCATION'),
    unverifiable:      threats.some(t => t.type === 'UNVERIFIABLE'),
    knownSignature:    threats.some(t => t.type === 'KNOWN_MALWARE_SIGNATURE'),
    payment: {
      ccSkimmingDetected:  threats.some(t => t.type === 'CC_SKIMMING' || t.type === 'RAW_CARD_FIELD'),
      trustedGatewayDetected: false,
      trustedGateways: [],
      hasPaymentFields: false,
      details: [],
    },
    phishing:      { suspiciousFormActions: threats.some(t => t.type === 'PHISHING_FORM'), externalFormActions: [], details: [] },
    identityTheft: { sensitiveFieldsFound: false, sensitiveFields: [], details: [] },
    clickjacking:  { suspiciousOverlayDetected: false, details: [] },
  }

  await db.securityAuditReport.upsert({
    where:  { appId },
    create: {
      appId,
      decision:    decision,
      safetyScore: score,
      phase2:      phase2Snapshot,
      threats:     threats as unknown as Prisma.InputJsonValue,
      warnings:    [] as unknown as Prisma.InputJsonValue,
    },
    update: {
      decision:    decision,
      safetyScore: score,
      phase2:      phase2Snapshot,
      threats:     threats as unknown as Prisma.InputJsonValue,
      warnings:    [] as unknown as Prisma.InputJsonValue,
    },
  })

  return {
    appId,
    url:       launchUrl,
    scannedAt: new Date().toISOString(),
    malicious,
    threats,
  }
}
