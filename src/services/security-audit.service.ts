import type { Prisma } from '@prisma/client'
import { db } from '../core/db'
import { logger } from '../core/logger'

// ---------------------------------------------------------------------------
// Autonomous Security Audit Pipeline
//
// Phase 1 — Domain Reputation
//   Checks Google Web Risk API (MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE)
//   and the local domain blacklist (stored in AuditLog).
//
// Phase 2 — Deep Content Analysis
//   Fetches the app's launchUrl and scans the HTML for:
//   • Malicious payment collection (CC fields without trusted gateway)
//   • Phishing indicators (external form actions, identity theft fields)
//   • Obfuscated JavaScript
//
// Phase 3 — Autonomous Decision
//   Computes a 0–100 safety score and returns one of:
//   • AUTO_PUBLISHED   — score > 90, no critical threats, no warnings
//   • HELD_FOR_REVIEW  — minor warnings present; requires human eyes
//   • AUTO_REJECTED    — critical threat detected; domain blacklisted
//
// The full report is persisted to SecurityAuditReport (upserted per appId).
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

// ─── Domain Blacklist (stored in AuditLog) ────────────────────────────────────

async function isDomainBlacklisted(domain: string): Promise<{ blacklisted: boolean; reason?: string }> {
  const entry = await db.auditLog.findFirst({
    where: {
      action: 'security.blacklist.domain_added',
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

const WEB_RISK_BASE  = 'https://webrisk.googleapis.com/v1'
const THREAT_TYPES   = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'] as const

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

  // Blacklist check first — fast, no external API call
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

// ─── Phase 2: Content Analysis ────────────────────────────────────────────────

const FETCH_TIMEOUT_MS   = 12_000
const MAX_CONTENT_BYTES  = 524_288 // 512 KB

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
]

// Form services whose external action URLs are benign
const TRUSTED_FORM_SERVICES = [
  'typeform.com', 'forms.google.com', 'formspree.io',
  'netlify.com',  'wufoo.com',         'jotform.com',
]

function analyzePayment(html: string): Phase2Result['payment'] {
  const lowerHtml = html.toLowerCase()
  const details: string[] = []

  // Detect trusted payment gateway script sources
  const trustedGateways: string[] = []
  for (const gw of TRUSTED_GATEWAYS) {
    if (gw.patterns.some(p => lowerHtml.includes(p))) {
      trustedGateways.push(gw.name)
    }
  }
  const trustedGatewayDetected = trustedGateways.length > 0
  if (trustedGatewayDetected) details.push(`Trusted gateway scripts: ${trustedGateways.join(', ')}`)

  // Detect CC payment input fields via HTML5 autocomplete attributes
  const hasCcAutocomplete = /autocomplete\s*=\s*["'](cc-number|cc-csc|cc-exp|cc-name|cc-type|cc-exp-month|cc-exp-year)["']/i.test(html)
  if (hasCcAutocomplete) details.push('CC autocomplete attributes found')

  // Detect CC-related field names / ids
  const CC_NAME_PATTERNS = [
    /\b(?:name|id)\s*=\s*["'][^"']*?(?:cc[-_]?number|card[-_]?number|creditcard|cardno|pan)\b/i,
    /\b(?:name|id)\s*=\s*["'][^"']*?(?:cvv|cvc2?|security[-_]?code)\b/i,
    /\b(?:name|id)\s*=\s*["'][^"']*?(?:expiry|expiration|exp[-_]?(?:month|year)|card[-_]?exp)\b/i,
  ]
  const hasNamePatterns = CC_NAME_PATTERNS.some(p => p.test(html))
  if (hasNamePatterns) details.push('CC field name patterns found in input elements')

  const hasPaymentFields = hasCcAutocomplete || hasNamePatterns
  const untrustedCCCollection = hasPaymentFields && !trustedGatewayDetected

  return { hasPaymentFields, trustedGatewayDetected, trustedGateways, untrustedCCCollection, details }
}

function analyzePhishing(html: string, launchUrl: string): Phase2Result['phishing'] {
  const launchDomain = extractDomain(launchUrl) ?? ''
  const details: string[] = []
  const externalFormActions: string[] = []
  let suspiciousFormActions = false

  const formTagMatches = [...html.matchAll(/<form[^>]*>/gi)]
  for (const m of formTagMatches) {
    const action = extractAttr(m[0], 'action')
    if (!action) continue
    // Relative or anchor URLs are same-origin — fine
    if (!action.includes('://')) continue
    const actionDomain = extractDomain(action)
    if (!actionDomain || actionDomain === launchDomain || actionDomain.endsWith(`.${launchDomain}`)) continue
    const isTrusted = TRUSTED_FORM_SERVICES.some(svc => actionDomain.includes(svc))
    if (!isTrusted) {
      externalFormActions.push(action)
      suspiciousFormActions = true
      details.push(`Form posts to external domain: ${action}`)
    }
  }

  return { suspiciousFormActions, externalFormActions, details }
}

function analyzeIdentityTheft(html: string): Phase2Result['identityTheft'] {
  const sensitiveFields: string[] = []
  const details: string[] = []

  const PATTERNS: Array<{ re: RegExp; label: string }> = [
    { re: /\b(?:name|id|placeholder)\s*=\s*["'][^"']*?(?:ssn|social.?security)\b/i,          label: 'SSN / Social Security' },
    { re: /\b(?:name|id|placeholder)\s*=\s*["'][^"']*?\bpassport\b/i,                         label: 'Passport Number' },
    { re: /\b(?:name|id|placeholder)\s*=\s*["'][^"']*?(?:national.?id|nino|nin)\b/i,          label: 'National ID / Insurance No.' },
    { re: /\b(?:name|id|placeholder)\s*=\s*["'][^"']*?(?:tax.?id|taxpayer)\b/i,               label: 'Tax ID' },
    { re: /\b(?:name|id|placeholder)\s*=\s*["'][^"']*?(?:bank.?account|routing.?number)\b/i,  label: 'Bank Account / Routing No.' },
    { re: /\b(?:name|id|placeholder)\s*=\s*["'][^"']*?(?:bank.?pin|pin.?code)\b/i,            label: 'Bank PIN' },
  ]

  for (const { re, label } of PATTERNS) {
    if (re.test(html)) {
      sensitiveFields.push(label)
      details.push(`Sensitive field detected: ${label}`)
    }
  }

  return { sensitiveFieldsFound: sensitiveFields.length > 0, sensitiveFields, details }
}

function detectObfuscation(html: string): boolean {
  // Extract inline script content only (not src= scripts — those are legitimate bundles)
  const inlineScripts = [...html.matchAll(/<script(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi)]
    .map(m => m[1] ?? '')
    .join('\n')

  return (
    /eval\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(/i.test(inlineScripts) ||
    /\bString\.fromCharCode\s*\(\s*\d{2,3}\s*,\s*\d{2,3}\s*,/i.test(inlineScripts) ||
    /(?:\\x[0-9a-f]{2}){6,}/i.test(inlineScripts)
  )
}

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

    // Read with hard size cap
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
  if (!launchUrl) {
    return {
      fetched: false, fetchError: 'No launchUrl provided', contentLength: 0,
      payment:       { hasPaymentFields: false, trustedGatewayDetected: false, trustedGateways: [], untrustedCCCollection: false, details: [] },
      phishing:      { suspiciousFormActions: false, externalFormActions: [], details: [] },
      identityTheft: { sensitiveFieldsFound: false, sensitiveFields: [], details: [] },
      obfuscatedContent: false,
    }
  }

  const result = await fetchContent(launchUrl)

  if ('error' in result) {
    logger.warn({ launchUrl, error: result.error }, '[security-audit] Content fetch failed')
    return {
      fetched: false, fetchError: result.error, contentLength: 0,
      payment:       { hasPaymentFields: false, trustedGatewayDetected: false, trustedGateways: [], untrustedCCCollection: false, details: [] },
      phishing:      { suspiciousFormActions: false, externalFormActions: [], details: [] },
      identityTheft: { sensitiveFieldsFound: false, sensitiveFields: [], details: [] },
      obfuscatedContent: false,
    }
  }

  const { html } = result
  return {
    fetched:       true,
    contentLength: html.length,
    payment:       analyzePayment(html),
    phishing:      analyzePhishing(html, launchUrl),
    identityTheft: analyzeIdentityTheft(html),
    obfuscatedContent: detectObfuscation(html),
  }
}

// ─── Phase 3: Score & Decision ────────────────────────────────────────────────

function computePhase3(phase1: Phase1Result, phase2: Phase2Result): Phase3Result {
  let score = 100
  const criticalThreats: ThreatEntry[] = []
  const warnings: ThreatEntry[] = []

  // ── Phase 1 deductions ────────────────────────────────────────────────────

  if (phase1.blacklisted) {
    score -= 100
    criticalThreats.push({
      severity: 'CRITICAL', type: 'DOMAIN_BLACKLISTED',
      description: `Domain is on the local blacklist. Reason: ${phase1.blacklistReason ?? 'prior rejection'}`,
    })
  }

  for (const t of phase1.threats) {
    if (t.types.includes('SOCIAL_ENGINEERING')) {
      score -= 100
      criticalThreats.push({ severity: 'CRITICAL', type: 'PHISHING', description: `Google Web Risk: phishing/social-engineering — ${t.uri}` })
    }
    if (t.types.includes('MALWARE')) {
      score -= 100
      criticalThreats.push({ severity: 'CRITICAL', type: 'MALWARE', description: `Google Web Risk: malware distribution — ${t.uri}` })
    }
    if (t.types.includes('UNWANTED_SOFTWARE')) {
      score -= 60
      criticalThreats.push({ severity: 'HIGH', type: 'UNWANTED_SOFTWARE', description: `Google Web Risk: unwanted software/adware — ${t.uri}` })
    }
  }

  if (!phase1.checked && !phase1.apiAvailable) {
    warnings.push({ severity: 'LOW', type: 'DOMAIN_CHECK_UNAVAILABLE', description: 'Google Web Risk API unavailable; domain reputation unverified.' })
  }

  // ── Phase 2 deductions ────────────────────────────────────────────────────

  if (phase2.fetched) {
    if (phase2.payment.untrustedCCCollection) {
      score -= 80
      criticalThreats.push({
        severity: 'CRITICAL', type: 'UNTRUSTED_CC_COLLECTION',
        description: 'Site collects credit card data without a trusted payment gateway (Stripe / PayPal / Paddle / etc.).',
      })
    }

    if (phase2.identityTheft.sensitiveFieldsFound) {
      score -= 70
      criticalThreats.push({
        severity: 'CRITICAL', type: 'IDENTITY_THEFT_FIELDS',
        description: `Sensitive identity-theft fields detected: ${phase2.identityTheft.sensitiveFields.join(', ')}.`,
      })
    }

    if (phase2.phishing.suspiciousFormActions) {
      score -= 25
      warnings.push({
        severity: 'MEDIUM', type: 'SUSPICIOUS_FORM_ACTION',
        description: `Form(s) submit to unrecognised external domains: ${phase2.phishing.externalFormActions.slice(0, 3).join(', ')}`,
      })
    }

    if (phase2.obfuscatedContent) {
      score -= 15
      warnings.push({ severity: 'MEDIUM', type: 'OBFUSCATED_JAVASCRIPT', description: 'Obfuscated JavaScript detected (eval/atob/fromCharCode patterns).' })
    }
  } else {
    // Couldn't verify content — small deduction; hold for manual review
    score -= 10
    warnings.push({ severity: 'LOW', type: 'CONTENT_FETCH_FAILED', description: `Could not fetch page content: ${phase2.fetchError ?? 'unknown error'}` })
  }

  score = Math.max(0, Math.min(100, score))

  let decision: SecurityDecision
  let reasoning: string

  if (criticalThreats.length > 0 || score <= 20) {
    decision  = 'AUTO_REJECTED'
    reasoning = `Rejected: ${criticalThreats.length} critical threat(s) — ${criticalThreats.map(t => t.type).join(', ')}`
  } else if (score > 80 && warnings.length === 0) {
    decision  = 'AUTO_PUBLISHED'
    reasoning = `Safety score ${score}/100 with no threats or warnings — automatically published.`
  } else {
    decision  = 'HELD_FOR_REVIEW'
    reasoning = `Safety score ${score}/100 with ${warnings.length} warning(s): ${warnings.map(w => w.type).join(', ')} — held for manual review.`
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

  // Persist — upsert so re-submissions overwrite the previous report
  await db.securityAuditReport.upsert({
    where:  { appId },
    create: {
      appId,
      decision:    phase3.decision,
      safetyScore: phase3.safetyScore,
      phase1:      phase1  as unknown as Prisma.InputJsonValue,
      phase2:      phase2  as unknown as Prisma.InputJsonValue,
      phase3:      phase3  as unknown as Prisma.InputJsonValue,
      threats:     phase3.criticalThreats as unknown as Prisma.InputJsonValue,
      warnings:    phase3.warnings        as unknown as Prisma.InputJsonValue,
    },
    update: {
      decision:    phase3.decision,
      safetyScore: phase3.safetyScore,
      phase1:      phase1  as unknown as Prisma.InputJsonValue,
      phase2:      phase2  as unknown as Prisma.InputJsonValue,
      phase3:      phase3  as unknown as Prisma.InputJsonValue,
      threats:     phase3.criticalThreats as unknown as Prisma.InputJsonValue,
      warnings:    phase3.warnings        as unknown as Prisma.InputJsonValue,
    },
  })

  // Auto-rejected → blacklist the domain to catch re-submissions
  if (phase3.decision === 'AUTO_REJECTED' && phase3.criticalThreats.length > 0) {
    const domain = extractDomain(launchUrl)
    if (domain) {
      await addDomainToBlacklist(domain, appId, phase3.criticalThreats.map(t => t.type).join(', '))
    }
  }

  return {
    appId,
    url:       launchUrl,
    auditedAt: new Date().toISOString(),
    phase1, phase2, phase3,
    decision:    phase3.decision,
    safetyScore: phase3.safetyScore,
    threats:     phase3.criticalThreats,
    warnings:    phase3.warnings,
  }
}
