import type { Prisma } from '@prisma/client'
import { db } from '../core/db'
import { logger } from '../core/logger'

// ---------------------------------------------------------------------------
// The Sentinel — Malicious Script Scanner
//
// Philosophy: Pass-by-Default.
//   Apps are published immediately on submission. This scanner runs in the
//   background and only acts when it finds a *definite* malicious script.
//
// What triggers a revert to SUBMITTED:
//   1. Cookie theft  — inline script reads document.cookie and exfiltrates it
//   2. Storage theft — inline script reads localStorage/sessionStorage and
//                      exfiltrates it to an external endpoint
//   3. Malicious obfuscation — heavily encoded inline payload (eval/atob,
//                      hex char arrays, document.write/unescape)
//
// Everything else (unknown domain, fetch failure, external form actions,
// CC fields with a trusted gateway, etc.) is clean. Do not hold those apps.
//
// The scan result is persisted to SecurityAuditReport so the Admin UI
// can show the Audit button with full details.
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

// ─── Malicious Script Detectors ───────────────────────────────────────────────

/**
 * Check 1 — Cookie & Storage Theft (XSS payload pattern)
 * Detects inline scripts that read session credentials and send them off-site.
 * A legitimate app never needs to read cookies/storage AND make an outbound
 * network call in the same inline script.
 */
function detectCredentialTheft(html: string): ThreatEntry[] {
  const threats: ThreatEntry[] = []
  const scripts = extractInlineScripts(html)
  if (!scripts.trim()) return threats

  // Signals that data is being sent somewhere external
  const hasExfil = (
    /fetch\s*\(\s*["'`]https?:\/\//i.test(scripts)        ||
    /new\s+XMLHttpRequest\s*\(\s*\)/i.test(scripts)        ||
    /navigator\.sendBeacon\s*\(/i.test(scripts)            ||
    /new\s+Image\s*\(\s*\)\s*\.src\s*=/i.test(scripts)    ||
    /document\.location\s*(?:=|\.replace)/i.test(scripts)
  )

  if (hasExfil && /document\.cookie/i.test(scripts)) {
    threats.push({
      type:        'COOKIE_THEFT',
      description: 'Inline script reads document.cookie and makes an outbound network request — session hijacking payload.',
    })
  }

  if (hasExfil && /(?:localStorage|sessionStorage)\s*\.\s*(?:getItem|key\b)/i.test(scripts)) {
    threats.push({
      type:        'STORAGE_EXFILTRATION',
      description: 'Inline script reads localStorage/sessionStorage and makes an outbound network request — credential exfiltration payload.',
    })
  }

  return threats
}

/**
 * Check 2 — Malicious Obfuscation
 * Targets heavily encoded payloads in inline scripts only. Standard webpack/
 * terser bundles are loaded via src= and are never examined here.
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
    description: 'Heavily encoded inline JavaScript detected (eval/atob, hex arrays, or document.write/unescape) — classic hidden malware delivery pattern.',
  }]
}

// ─── Content Fetcher ──────────────────────────────────────────────────────────

const FETCH_TIMEOUT_MS  = 5_000
const MAX_CONTENT_BYTES = 524_288 // 512 KB

async function fetchHtml(url: string): Promise<string | null> {
  try {
    const controller = new AbortController()
    const timeout    = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)

    const res = await fetch(url, {
      signal:   controller.signal,
      redirect: 'follow',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept':     'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
      },
    })
    clearTimeout(timeout)

    if (!res.ok) return null
    const ct = res.headers.get('content-type') ?? ''
    if (!ct.includes('html') && !ct.includes('text')) return null

    const reader = res.body?.getReader()
    if (!reader) return null

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

    return new TextDecoder().decode(Buffer.concat(chunks.map(c => Buffer.from(c))))
  } catch {
    // Fetch failure → cannot prove malicious → treat as clean
    return null
  }
}

// ─── Phishing Form Detector ───────────────────────────────────────────────────

/**
 * Check 3 — Phishing Forms
 * Detects forms that collect credentials (password / email inputs) and POST
 * them to an external domain — the hallmark of a credential-harvesting page.
 */
function detectPhishingForms(html: string, pageUrl: string): ThreatEntry[] {
  const pageDomain = extractDomain(pageUrl)

  // Find all <form> tags and their action attributes
  const formMatches = [...html.matchAll(/<form[^>]*>/gi)]
  const suspiciousActions: string[] = []

  for (const [formTag] of formMatches) {
    const actionMatch = formTag.match(/\baction\s*=\s*["']([^"']+)["']/i)
    if (!actionMatch) continue
    const action = actionMatch[1] ?? ''
    if (!action || action.startsWith('#') || action.startsWith('/') || action.startsWith('?')) continue

    try {
      const actionDomain = new URL(action).hostname
      if (pageDomain && actionDomain !== pageDomain) {
        suspiciousActions.push(action)
      }
    } catch { /* relative or malformed URL */ }
  }

  if (suspiciousActions.length === 0) return []

  // Only flag if the page also has password or hidden email inputs
  const hasPasswordField = /<input[^>]*\btype\s*=\s*["']password["'][^>]*>/i.test(html)
  const hasEmailField    = /<input[^>]*\btype\s*=\s*["']email["'][^>]*>/i.test(html)

  if (!hasPasswordField && !hasEmailField) return []

  return [{
    type:        'PHISHING_FORM',
    description: `Form collects credentials (${hasPasswordField ? 'password' : 'email'} field) and submits to an external domain: ${suspiciousActions[0]?.slice(0, 80)} — credential harvesting pattern.`,
  }]
}

// ─── Public API ───────────────────────────────────────────────────────────────

export async function scanApp(appId: string, launchUrl: string): Promise<ScanResult> {
  logger.info({ appId, launchUrl }, '[sentinel] Background scan started')

  const threats: ThreatEntry[] = []

  if (launchUrl) {
    const html = await fetchHtml(launchUrl)
    // If we can't fetch the page we cannot prove it's malicious — pass it through
    if (html) {
      threats.push(...detectCredentialTheft(html))
      threats.push(...detectMaliciousObfuscation(html))
      threats.push(...detectPhishingForms(html, launchUrl))
    }
  }

  const malicious = threats.length > 0
  const decision  = malicious ? 'AUTO_REJECTED' : 'AUTO_PUBLISHED'
  const score     = malicious ? 0 : 100

  logger.info({ appId, malicious, threats: threats.map(t => t.type) }, '[sentinel] Scan complete')

  // Persist to SecurityAuditReport so the Admin Audit button always has data
  const phase2Snapshot: Prisma.InputJsonValue = {
    fetched:           !!launchUrl,
    contentLength:     0,
    xss: {
      cookieTheftDetected:  threats.some(t => t.type === 'COOKIE_THEFT'),
      storageTheftDetected: threats.some(t => t.type === 'STORAGE_EXFILTRATION'),
    },
    obfuscatedContent: threats.some(t => t.type === 'MALICIOUS_OBFUSCATION'),
    payment:       { untrustedCCCollection: false, trustedGatewayDetected: false, trustedGateways: [], hasPaymentFields: false, details: [] },
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
