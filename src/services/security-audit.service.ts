import type { Prisma } from '@prisma/client'
import { db } from '../core/db'
import { logger } from '../core/logger'

// ---------------------------------------------------------------------------
// Autonomous Security Audit Pipeline — Behavioral-First Edition
//
// Philosophy: "Innocent Until Proven Guilty"
//   Every app is PUBLISHED unless a confirmed cyber threat is detected.
//   Unknown domains, new sites, and unreachable URLs are NOT a reason to hold.
//
// Phase 1 — Domain Reputation
//   Checks Google Web Risk API (MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE)
//   and the local domain blacklist (stored in AuditLog).
//   An unavailable API or an unknown domain is not penalised.
//
// Phase 2 — Deep Behavioral Analysis (The Probe)
//   Fetches the app's launchUrl and scans for active cyber attack patterns:
//   • XSS / Credential Theft: inline scripts exfiltrating cookies or storage
//   • Malicious Obfuscated JS: heavily encoded payloads (eval/atob, hex arrays)
//   • Clickjacking: invisible overlays designed to hijack clicks
//   • CC Skimming: custom credit-card form bypassing trusted gateways
//   • Identity Theft: SSN / passport / bank account harvesting fields
//   • Phishing: forms posting to unrecognised external domains
//
// Phase 3 — Autonomous Decision
//   • AUTO_REJECTED   — confirmed cyber attack detected
//   • HELD_FOR_REVIEW — high-confidence signal from Google (UNWANTED_SOFTWARE)
//   • AUTO_PUBLISHED  — no active threats found → publish immediately
//
// The full report is persisted to SecurityAuditReport BEFORE any status change.
// Auto-rejected domains are added to the local blacklist via AuditLog.
// ---------------------------------------------------------------------------

export type SecurityDecision = 'AUTO_PUBLISHED' | 'HELD_FOR_REVIEW' | 'AUTO_REJECTED'

export interface ThreatEntry {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  type: string
  description: string
}

export interface Phase1Result {
  checked: boolean
  apiAvailable: boolean
  domainReputation: 'CLEAN' | 'THREAT' | 'UNKNOWN'
  threats: Array<{ uri: string; types: string[] }>
  blacklisted: boolean
  blacklistReason?: string
}

export interface Phase2Result {
  fetched: boolean
  fetchError?: string
  contentLength: number
  payment: {
    hasPaymentFields: boolean
    trustedGatewayDetected: boolean
    trustedGateways: string[]
    untrustedCCCollection: boolean
    details: string[]
  }
  phishing: {
    suspiciousFormActions: boolean
    externalFormActions: string[]
    details: string[]
  }
  identityTheft: {
    sensitiveFieldsFound: boolean
    sensitiveFields: string[]
    details: string[]
  }
  xss: {
    cookieTheftDetected: boolean
    storageTheftDetected: boolean
    details: string[]
  }
  clickjacking: {
    suspiciousOverlayDetected: boolean
    details: string[]
  }
  obfuscatedContent: boolean
}

export interface Phase3Result {
  safetyScore: number
  decision: SecurityDecision
  criticalThreats: ThreatEntry[]
  warnings: ThreatEntry[]
  reasoning: string
}

export interface SecurityAuditResult {
  appId: string
  url: string
  auditedAt: string
  phase1: Phase1Result
  phase2: Phase2Result
  phase3: Phase3Result
  decision: SecurityDecision
  safetyScore: number
  threats: ThreatEntry[]
  warnings: ThreatEntry[]
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function extractDomain(url: string): string | null {
  try { return new URL(url).hostname } catch { return null }
}

/** Extract a named HTML attribute value from a tag string. */
function extractAttr(tag: string, attr: string): string | null {
  const m = tag.match(new RegExp(`\\b${attr}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`, 'i'))
  return m ? (m[1] ?? m[2] ?? null) : null
}

/** Extract all inline <script> blocks (excludes external src= scripts). */
function extractInlineScripts(html: string): string {
  return [...html.matchAll(/<script(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi)]
    .map(m => m[1] ?? '')
    .join('\n')
}

// ─── Domain Blacklist (stored in AuditLog) ────────────────────────────────────

async function isDomainBlacklisted(domain: string): Promise<{ blacklisted: boolean; reason?: string }> {
  const entry = await db.auditLog.findFirst({
    where: {
      action:   'security.blacklist.domain_added',
      metadata: { path: ['domain'], equals: domain },
    },
    select: { metadata: true },
  })
  if (!entry) return { blacklisted: false }
  const meta = entry.metadata as Record<string, unknown>
  return { blacklisted: true, reason: String(meta['reason'] ?? 'Prior rejection') }
}

async function addDomainToBlacklist(domain: string, appId: string, reason: string): Promise<void> {
  await db.auditLog.create({
    data: {
      action:     'security.blacklist.domain_added',
      entityType: 'Domain',
      entityId:   domain,
      metadata:   { domain, appId, reason, blacklistedAt: new Date().toISOString() },
    },
  })
  logger.warn({ domain, appId, reason }, '[security-audit] Domain added to blacklist')
}

// ─── Phase 1: Domain Reputation ───────────────────────────────────────────────

const WEB_RISK_BASE = 'https://webrisk.googleapis.com/v1'
const THREAT_TYPES  = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'] as const

async function checkWebRisk(uri: string, apiKey: string): Promise<string[] | null> {
  const params = new URLSearchParams({ uri, key: apiKey })
  for (const t of THREAT_TYPES) params.append('threatTypes', t)
  const res = await fetch(`${WEB_RISK_BASE}/uris:search?${params.toString()}`, {
    headers: { Accept: 'application/json' },
    signal:  AbortSignal.timeout(8_000),
  })
  if (!res.ok) throw new Error(`Web Risk API error ${res.status}`)
  const data = await res.json() as { threat?: { threatTypes?: string[] } }
  return data.threat?.threatTypes?.length ? data.threat.threatTypes : null
}

async function runPhase1(launchUrl: string): Promise<Phase1Result> {
  const domain = extractDomain(launchUrl)

  if (domain) {
    const bl = await isDomainBlacklisted(domain)
    if (bl.blacklisted) {
      return {
        checked: true, apiAvailable: true,
        domainReputation: 'THREAT',
        threats: [{ uri: launchUrl, types: ['BLACKLISTED'] }],
        blacklisted: true,
        blacklistReason: bl.reason,
      }
    }
  }

  const apiKey = process.env['GOOGLE_WEB_RISK_API_KEY']
  if (!apiKey) {
    logger.warn('[security-audit] GOOGLE_WEB_RISK_API_KEY not set — skipping Web Risk check')
    // Not penalised: unknown domain is not a threat signal
    return { checked: false, apiAvailable: false, domainReputation: 'UNKNOWN', threats: [], blacklisted: false }
  }

  try {
    const found = await checkWebRisk(launchUrl, apiKey)
    if (found?.length) {
      return {
        checked: true, apiAvailable: true,
        domainReputation: 'THREAT',
        threats: [{ uri: launchUrl, types: found }],
        blacklisted: false,
      }
    }
    return { checked: true, apiAvailable: true, domainReputation: 'CLEAN', threats: [], blacklisted: false }
  } catch (err) {
    logger.error({ err, uri: launchUrl }, '[security-audit] Web Risk API call failed')
    return { checked: false, apiAvailable: false, domainReputation: 'UNKNOWN', threats: [], blacklisted: false }
  }
}

// ─── Phase 2: Deep Behavioral Analysis ────────────────────────────────────────

const FETCH_TIMEOUT_MS  = 12_000
const MAX_CONTENT_BYTES = 524_288 // 512 KB

const TRUSTED_GATEWAYS: Array<{ name: string; patterns: string[] }> = [
  { name: 'Stripe',      patterns: ['js.stripe.com', 'stripe.com/v3'] },
  { name: 'PayPal',      patterns: ['paypal.com/sdk/js', 'paypalobjects.com'] },
  { name: 'Paddle',      patterns: ['cdn.paddle.com', 'paddle.com/paddle'] },
  { name: 'Square',      patterns: ['squareup.com', 'square.com/cdn'] },
  { name: 'Braintree',   patterns: ['braintreegateway.com', 'braintreepayments.com'] },
  { name: 'Adyen',       patterns: ['adyen.com/checkoutshopper'] },
  { name: 'Klarna',      patterns: ['klarna.com/v1', 'klarnaservices.com'] },
  { name: 'Razorpay',    patterns: ['razorpay.com'] },
  { name: 'Shopify Pay', patterns: ['cdn.shopify.com', 'pay.shopify.com'] },
  { name: 'Lemon Squeezy', patterns: ['lemonsqueezy.com'] },
  { name: 'Gumroad',     patterns: ['gumroad.com'] },
  { name: 'Chargebee',   patterns: ['chargebee.com'] },
]

const TRUSTED_FORM_SERVICES = [
  'typeform.com', 'forms.google.com', 'formspree.io',
  'netlify.com',  'wufoo.com',        'jotform.com',
  'tally.so',     'airtable.com',
]

// ── Check 1: Advanced CC Protection ──────────────────────────────────────────
// Only flags when a site has a CUSTOM-BUILT CC form with no trusted gateway.
// Standard landing pages, SaaS checkout pages, and gateway-hosted flows are safe.

function analyzePayment(html: string): Phase2Result['payment'] {
  const lowerHtml = html.toLowerCase()
  const details: string[] = []

  const trustedGateways: string[] = []
  for (const gw of TRUSTED_GATEWAYS) {
    if (gw.patterns.some(p => lowerHtml.includes(p))) {
      trustedGateways.push(gw.name)
    }
  }
  const trustedGatewayDetected = trustedGateways.length > 0
  if (trustedGatewayDetected) details.push(`Trusted gateway detected: ${trustedGateways.join(', ')}`)

  // HTML5 autocomplete attributes explicitly set for CC fields
  const hasCcAutocomplete = /autocomplete\s*=\s*["'](cc-number|cc-csc|cc-exp|cc-name|cc-type|cc-exp-month|cc-exp-year)["']/i.test(html)
  if (hasCcAutocomplete) details.push('CC autocomplete attributes found in form inputs')

  // Input name/id patterns specific to raw CC collection
  const CC_NAME_PATTERNS = [
    /\b(?:name|id)\s*=\s*["'][^"']*?(?:cc[-_]?number|card[-_]?number|creditcard|cardno|pan)\b/i,
    /\b(?:name|id)\s*=\s*["'][^"']*?(?:cvv|cvc2?|security[-_]?code)\b/i,
    /\b(?:name|id)\s*=\s*["'][^"']*?(?:expiry|expiration|exp[-_]?(?:month|year)|card[-_]?exp)\b/i,
  ]
  const hasNamePatterns = CC_NAME_PATTERNS.some(p => p.test(html))
  if (hasNamePatterns) details.push('Raw CC field name/id attributes found (cc-number, cvv, expiry, etc.)')

  const hasPaymentFields = hasCcAutocomplete || hasNamePatterns
  // Critical only when a custom CC form exists AND no trusted payment gateway is present
  const untrustedCCCollection = hasPaymentFields && !trustedGatewayDetected

  return { hasPaymentFields, trustedGatewayDetected, trustedGateways, untrustedCCCollection, details }
}

// ── Check 2: Phishing (external form submissions) ─────────────────────────────

function analyzePhishing(html: string, launchUrl: string): Phase2Result['phishing'] {
  const launchDomain = extractDomain(launchUrl) ?? ''
  const details: string[] = []
  const externalFormActions: string[] = []
  let suspiciousFormActions = false

  const formTagMatches = [...html.matchAll(/<form[^>]*>/gi)]
  for (const m of formTagMatches) {
    const action = extractAttr(m[0], 'action')
    if (!action || !action.includes('://')) continue
    const actionDomain = extractDomain(action)
    if (!actionDomain || actionDomain === launchDomain || actionDomain.endsWith(`.${launchDomain}`)) continue
    const isTrusted = TRUSTED_FORM_SERVICES.some(svc => actionDomain.includes(svc))
    if (!isTrusted) {
      externalFormActions.push(action)
      suspiciousFormActions = true
      details.push(`Form submits to external domain: ${action}`)
    }
  }

  return { suspiciousFormActions, externalFormActions, details }
}

// ── Check 3: Identity Theft Fields ───────────────────────────────────────────

function analyzeIdentityTheft(html: string): Phase2Result['identityTheft'] {
  const sensitiveFields: string[] = []
  const details: string[] = []

  const PATTERNS: Array<{ re: RegExp; label: string }> = [
    { re: /\b(?:name|id|placeholder)\s*=\s*["'][^"']*?(?:ssn|social.?security)\b/i,         label: 'SSN / Social Security' },
    { re: /\b(?:name|id|placeholder)\s*=\s*["'][^"']*?\bpassport\b/i,                        label: 'Passport Number' },
    { re: /\b(?:name|id|placeholder)\s*=\s*["'][^"']*?(?:national.?id|nino|nin)\b/i,         label: 'National ID / Insurance No.' },
    { re: /\b(?:name|id|placeholder)\s*=\s*["'][^"']*?(?:tax.?id|taxpayer)\b/i,              label: 'Tax ID' },
    { re: /\b(?:name|id|placeholder)\s*=\s*["'][^"']*?(?:bank.?account|routing.?number)\b/i, label: 'Bank Account / Routing No.' },
    { re: /\b(?:name|id|placeholder)\s*=\s*["'][^"']*?(?:bank.?pin|pin.?code)\b/i,           label: 'Bank PIN' },
  ]

  for (const { re, label } of PATTERNS) {
    if (re.test(html)) {
      sensitiveFields.push(label)
      details.push(`Sensitive field detected: ${label}`)
    }
  }

  return { sensitiveFieldsFound: sensitiveFields.length > 0, sensitiveFields, details }
}

// ── Check 4: XSS / Cookie & Storage Theft ────────────────────────────────────
// Detects inline scripts that read session credentials and exfiltrate them to
// external endpoints — a classic XSS cookie-stealing payload.

function detectCookieStorageTheft(html: string, launchUrl: string): Phase2Result['xss'] {
  const details: string[] = []
  const launchDomain = extractDomain(launchUrl) ?? ''
  const inlineScripts = extractInlineScripts(html)

  if (!inlineScripts.trim()) {
    return { cookieTheftDetected: false, storageTheftDetected: false, details }
  }

  // Patterns that indicate data is being sent to an external destination
  const EXFIL_PATTERNS = [
    /fetch\s*\(\s*["'`]https?:\/\/(?!(?:[\w.-]*\.)?${launchDomain})/i,
    /new\s+XMLHttpRequest\s*\(\s*\)/i,
    /navigator\.sendBeacon\s*\(/i,
    /new\s+Image\s*\(\s*\)\s*\.src\s*=/i,
    /document\.location\s*(?:=|\.replace)/i,
    /window\.location\s*(?:=|\.replace)/i,
  ]

  const hasExfilSignal = EXFIL_PATTERNS.some(p => p.test(inlineScripts))

  // Cookie theft: reading cookies AND making an outbound call
  const readsCookies  = /document\.cookie/i.test(inlineScripts)
  // Storage theft: reading local/session storage AND making an outbound call
  const readsStorage  = /(?:localStorage|sessionStorage)\s*\.\s*(?:getItem|key\b)/i.test(inlineScripts)

  const cookieTheftDetected  = hasExfilSignal && readsCookies
  const storageTheftDetected = hasExfilSignal && readsStorage

  if (cookieTheftDetected)  details.push('Inline script reads document.cookie and performs outbound network requests — potential session hijacking payload.')
  if (storageTheftDetected) details.push('Inline script reads localStorage/sessionStorage and performs outbound network requests — potential credential exfiltration.')

  return { cookieTheftDetected, storageTheftDetected, details }
}

// ── Check 5: Clickjacking (deceptive overlay detection) ───────────────────────
// Looks for invisible clickable elements overlaid to hijack user interactions.
// A legitimate app never needs opacity-zero buttons or full-page hidden iframes.

function detectClickjacking(html: string): Phase2Result['clickjacking'] {
  const details: string[] = []
  let suspiciousOverlayDetected = false

  // Invisible button / link with inline style — opacity:0 on an interactive element
  if (/(?:<button|<a\s|<input)[^>]*style\s*=\s*["'][^"']*opacity\s*:\s*0[^"']*["']/i.test(html)) {
    suspiciousOverlayDetected = true
    details.push('Invisible clickable element (opacity:0 on button/link/input) — classic clickjacking overlay pattern.')
  }

  // Full-coverage hidden iframe used as a transparent background layer
  if (/<iframe[^>]*style\s*=\s*["'][^"']*(?:opacity\s*:\s*0|display\s*:\s*none)[^"']*["']/i.test(html)) {
    suspiciousOverlayDetected = true
    details.push('Hidden iframe detected (opacity:0 or display:none) — may obscure real click targets beneath the page.')
  }

  // Extremely high z-index container with pointer-events:none (trap-layer pattern)
  if (/<(?:div|section|span)[^>]*style\s*=\s*["'][^"']*pointer-events\s*:\s*none[^"']*z-index\s*:\s*[1-9]\d{3,}[^"']*["']/i.test(html)) {
    suspiciousOverlayDetected = true
    details.push('High z-index overlay element with pointer-events:none — potential click-trap layer.')
  }

  return { suspiciousOverlayDetected, details }
}

// ── Check 6: Malicious Obfuscated JavaScript ──────────────────────────────────
// Targets heavily encoded inline payloads — the kind used to hide malware, not
// standard minified/bundled code. Only examines inline scripts (not src= files).

function detectObfuscation(html: string): boolean {
  const inlineScripts = extractInlineScripts(html)
  if (!inlineScripts.trim()) return false

  // eval() wrapping a decode function — the single most reliable obfuscation signal
  const hasEvalDecode = /eval\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(/i.test(inlineScripts)

  // Very long hex-encoded payload (8+ sequential \xNN escapes — shellcode / payload packing)
  const hasHexPayload = /(?:\\x[0-9a-f]{2}){8,}/i.test(inlineScripts)

  // Character-code array with 10+ entries (obfuscated string construction)
  const hasCharCodeArray = /String\.fromCharCode\s*\(\s*(?:\d{2,3}\s*,\s*){9,}/i.test(inlineScripts)

  // document.write() wrapping a decode function — drive-by download pattern
  const hasObfuscatedWrite = /document\.write\s*\(\s*(?:unescape|decodeURIComponent)\s*\(/i.test(inlineScripts)

  return hasEvalDecode || hasHexPayload || hasCharCodeArray || hasObfuscatedWrite
}

// ─── Content Fetcher ──────────────────────────────────────────────────────────

async function fetchContent(url: string): Promise<{ html: string } | { error: string }> {
  try {
    const controller = new AbortController()
    const timeout    = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)

    const response = await fetch(url, {
      signal:   controller.signal,
      redirect: 'follow',
      headers: {
        'User-Agent':      'Mozilla/5.0 (compatible; AppMarketSecurityBot/1.0)',
        'Accept':          'text/html,application/xhtml+xml,*/*',
        'Accept-Language': 'en-US,en;q=0.9',
      },
    })
    clearTimeout(timeout)

    if (!response.ok) return { error: `HTTP ${response.status}` }

    const ct = response.headers.get('content-type') ?? ''
    if (!ct.includes('html') && !ct.includes('text')) return { error: `Non-HTML content-type: ${ct}` }

    const reader = response.body?.getReader()
    if (!reader) return { error: 'No response body' }

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

    const html = new TextDecoder().decode(Buffer.concat(chunks.map(c => Buffer.from(c))))
    return { html }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    return { error: msg.toLowerCase().includes('abort') ? 'Request timed out' : msg }
  }
}

async function runPhase2(launchUrl: string): Promise<Phase2Result> {
  const empty: Phase2Result = {
    fetched: false, fetchError: 'No launchUrl provided', contentLength: 0,
    payment:       { hasPaymentFields: false, trustedGatewayDetected: false, trustedGateways: [], untrustedCCCollection: false, details: [] },
    phishing:      { suspiciousFormActions: false, externalFormActions: [], details: [] },
    identityTheft: { sensitiveFieldsFound: false, sensitiveFields: [], details: [] },
    xss:           { cookieTheftDetected: false, storageTheftDetected: false, details: [] },
    clickjacking:  { suspiciousOverlayDetected: false, details: [] },
    obfuscatedContent: false,
  }

  if (!launchUrl) return empty

  const result = await fetchContent(launchUrl)

  if ('error' in result) {
    // Cannot reach the site — we cannot prove it is malicious, so we do NOT penalise.
    // The app will be published; a bad actor would need the site to be reachable to cause harm.
    logger.info({ launchUrl, error: result.error }, '[security-audit] Content fetch failed — treating as non-threatening (innocent until proven guilty)')
    return { ...empty, fetchError: result.error }
  }

  const { html } = result
  return {
    fetched:           true,
    contentLength:     html.length,
    payment:           analyzePayment(html),
    phishing:          analyzePhishing(html, launchUrl),
    identityTheft:     analyzeIdentityTheft(html),
    xss:               detectCookieStorageTheft(html, launchUrl),
    clickjacking:      detectClickjacking(html),
    obfuscatedContent: detectObfuscation(html),
  }
}

// ─── Phase 3: Behavioral Decision Engine ──────────────────────────────────────
//
// Scoring model:
//   • CRITICAL threat detected → score = 0 → AUTO_REJECTED
//   • HIGH threat (Google UNWANTED_SOFTWARE) → HELD_FOR_REVIEW
//   • Everything else → AUTO_PUBLISHED (innocent until proven guilty)
//
// What is NOT a reason to hold or reject:
//   • Unknown / new domain (Web Risk API unavailable or no result)
//   • Content fetch failure (can't prove malicious)
//   • Suspicious form actions (too many false positives on legitimate SaaS apps)
//   • Basic minification / bundling

function computePhase3(phase1: Phase1Result, phase2: Phase2Result): Phase3Result {
  let score = 100
  const criticalThreats: ThreatEntry[] = []
  const warnings: ThreatEntry[] = []

  // ── Phase 1: Domain Reputation ────────────────────────────────────────────

  if (phase1.blacklisted) {
    score = 0
    criticalThreats.push({
      severity: 'CRITICAL', type: 'DOMAIN_BLACKLISTED',
      description: `Domain is on the local blacklist. Reason: ${phase1.blacklistReason ?? 'prior rejection'}`,
    })
  }

  for (const t of phase1.threats) {
    if (t.types.includes('SOCIAL_ENGINEERING')) {
      score = 0
      criticalThreats.push({ severity: 'CRITICAL', type: 'PHISHING', description: `Google Web Risk confirmed phishing / social-engineering — ${t.uri}` })
    }
    if (t.types.includes('MALWARE')) {
      score = 0
      criticalThreats.push({ severity: 'CRITICAL', type: 'MALWARE', description: `Google Web Risk confirmed malware distribution — ${t.uri}` })
    }
    if (t.types.includes('UNWANTED_SOFTWARE')) {
      // High confidence from Google but not a confirmed critical attack — hold for human review
      score -= 40
      warnings.push({ severity: 'HIGH', type: 'UNWANTED_SOFTWARE', description: `Google Web Risk flagged unwanted software / adware — ${t.uri}` })
    }
  }

  // Unknown domain or unavailable API → no penalty (new domains are not suspicious)

  // ── Phase 2: Behavioral Checks ────────────────────────────────────────────
  // Only run if we actually fetched content; an unreachable site proves nothing.

  if (phase2.fetched) {

    // XSS / Credential Theft
    if (phase2.xss.cookieTheftDetected) {
      score = 0
      criticalThreats.push({
        severity: 'CRITICAL', type: 'COOKIE_THEFT',
        description: phase2.xss.details.find(d => d.includes('cookie')) ?? 'Inline script reads and exfiltrates session cookies.',
      })
    }
    if (phase2.xss.storageTheftDetected) {
      score = 0
      criticalThreats.push({
        severity: 'CRITICAL', type: 'STORAGE_EXFILTRATION',
        description: phase2.xss.details.find(d => d.includes('storage')) ?? 'Inline script reads and exfiltrates localStorage / sessionStorage.',
      })
    }

    // Malicious Obfuscated JavaScript
    if (phase2.obfuscatedContent) {
      score = 0
      criticalThreats.push({
        severity: 'CRITICAL', type: 'MALICIOUS_OBFUSCATION',
        description: 'Heavily encoded inline JavaScript detected (eval/atob, hex arrays, or document.write/unescape) — classic hidden malware payload pattern.',
      })
    }

    // Clickjacking Overlay
    if (phase2.clickjacking.suspiciousOverlayDetected) {
      score = 0
      criticalThreats.push({
        severity: 'CRITICAL', type: 'CLICKJACKING_OVERLAY',
        description: phase2.clickjacking.details[0] ?? 'Deceptive invisible overlay element detected — designed to hijack user clicks.',
      })
    }

    // CC Skimming (custom form, no trusted gateway)
    if (phase2.payment.untrustedCCCollection) {
      score = 0
      criticalThreats.push({
        severity: 'CRITICAL', type: 'UNTRUSTED_CC_COLLECTION',
        description: 'Custom credit-card collection form detected with no trusted payment gateway (Stripe / PayPal / Paddle / etc.) — potential CC skimming.',
      })
    }

    // Identity Theft Fields
    if (phase2.identityTheft.sensitiveFieldsFound) {
      score = 0
      criticalThreats.push({
        severity: 'CRITICAL', type: 'IDENTITY_THEFT_FIELDS',
        description: `Government-issued ID or financial fields detected: ${phase2.identityTheft.sensitiveFields.join(', ')}.`,
      })
    }

    // Suspicious form actions — LOW signal only; logged but does not affect decision
    if (phase2.phishing.suspiciousFormActions) {
      warnings.push({
        severity: 'LOW', type: 'EXTERNAL_FORM_ACTION',
        description: `Form(s) post to unrecognised external domain(s): ${phase2.phishing.externalFormActions.slice(0, 3).join(', ')} — logged for reference.`,
      })
    }
  }
  // Content fetch failure → no deduction, no warning; treated as innocent

  score = Math.max(0, Math.min(100, score))

  // ── Decision ──────────────────────────────────────────────────────────────

  let decision: SecurityDecision
  let reasoning: string

  if (criticalThreats.length > 0) {
    decision  = 'AUTO_REJECTED'
    reasoning = `Rejected: ${criticalThreats.length} confirmed cyber threat(s) — ${criticalThreats.map(t => t.type).join(', ')}`
  } else if (warnings.some(w => w.severity === 'HIGH')) {
    decision  = 'HELD_FOR_REVIEW'
    reasoning = `Safety score ${score}/100 — held for review: Google Web Risk flagged high-confidence threat (UNWANTED_SOFTWARE).`
  } else {
    decision  = 'AUTO_PUBLISHED'
    reasoning = `Safety score ${score}/100 — no active cyber threats detected. Published automatically.${warnings.length > 0 ? ` (${warnings.length} low-severity note(s) logged)` : ''}`
  }

  return { safetyScore: score, decision, criticalThreats, warnings, reasoning }
}

// ─── Public API ───────────────────────────────────────────────────────────────

export async function runSecurityAudit(appId: string, launchUrl: string): Promise<SecurityAuditResult> {
  logger.info({ appId, launchUrl }, '[security-audit] Pipeline started')

  const phase1 = await runPhase1(launchUrl)
  const phase2 = await runPhase2(launchUrl)
  const phase3 = computePhase3(phase1, phase2)

  logger.info({ appId, decision: phase3.decision, score: phase3.safetyScore }, '[security-audit] Pipeline complete')

  // ── DB Integrity: persist the report FIRST, before any status transition ──
  // This guarantees the Admin Audit UI always finds the report regardless of
  // whether the subsequent status change succeeds or fails.
  await db.securityAuditReport.upsert({
    where:  { appId },
    create: {
      appId,
      decision:    phase3.decision,
      safetyScore: phase3.safetyScore,
      phase1:      phase1 as unknown as Prisma.InputJsonValue,
      phase2:      phase2 as unknown as Prisma.InputJsonValue,
      phase3:      phase3 as unknown as Prisma.InputJsonValue,
      threats:     phase3.criticalThreats as unknown as Prisma.InputJsonValue,
      warnings:    phase3.warnings        as unknown as Prisma.InputJsonValue,
    },
    update: {
      decision:    phase3.decision,
      safetyScore: phase3.safetyScore,
      phase1:      phase1 as unknown as Prisma.InputJsonValue,
      phase2:      phase2 as unknown as Prisma.InputJsonValue,
      phase3:      phase3 as unknown as Prisma.InputJsonValue,
      threats:     phase3.criticalThreats as unknown as Prisma.InputJsonValue,
      warnings:    phase3.warnings        as unknown as Prisma.InputJsonValue,
    },
  })

  // Auto-rejected → blacklist the domain to catch repeat submissions
  if (phase3.decision === 'AUTO_REJECTED' && phase3.criticalThreats.length > 0) {
    const domain = extractDomain(launchUrl)
    if (domain) {
      await addDomainToBlacklist(domain, appId, phase3.criticalThreats.map(t => t.type).join(', '))
    }
  }

  return {
    appId,
    url:         launchUrl,
    auditedAt:   new Date().toISOString(),
    phase1, phase2, phase3,
    decision:    phase3.decision,
    safetyScore: phase3.safetyScore,
    threats:     phase3.criticalThreats,
    warnings:    phase3.warnings,
  }
}
