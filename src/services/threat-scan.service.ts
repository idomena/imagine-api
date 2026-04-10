import { logger } from '../core/logger'
import { BadRequestError } from '../core/errors'

// ---------------------------------------------------------------------------
// Threat Detection Service
//
// Integrates with the Google Web Risk API (v1) to screen URLs submitted in
// app metadata (launchUrl, externalLinks) before they are stored or published.
//
// Threat types screened:
//   MALWARE           — drive-by malware distribution
//   SOCIAL_ENGINEERING — phishing / deceptive sites
//   UNWANTED_SOFTWARE  — adware / PUPs
//
// The check is performed at two lifecycle points:
//   1. On app SUBMIT  — blocks submission of dangerous URLs
//   2. On app APPROVE — second gate before moderation approval
//
// Flow:
//   searchUris(urls) → Google Web Risk API
//     → if any threat found → throw BadRequestError (blocks the operation)
//     → if API unavailable  → log warning, allow (fail-open to avoid blocking
//       legitimate creators when the external service has an outage)
//
// Environment variables required:
//   GOOGLE_WEB_RISK_API_KEY — from Google Cloud Console (Web Risk API enabled)
// ---------------------------------------------------------------------------

const WEB_RISK_BASE  = 'https://webrisk.googleapis.com/v1'
const THREAT_TYPES   = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'] as const
type ThreatType      = typeof THREAT_TYPES[number]

interface WebRiskThreat {
  threatTypes: ThreatType[]
  expireTime:  string
}

interface WebRiskResponse {
  threat?: WebRiskThreat
}

// ---------------------------------------------------------------------------
// Core lookup — one URI at a time (Web Risk uriSearch endpoint)
// ---------------------------------------------------------------------------
async function checkSingleUri(uri: string, apiKey: string): Promise<ThreatType[] | null> {
  const params = new URLSearchParams({ uri, key: apiKey })
  for (const t of THREAT_TYPES) params.append('threatTypes', t)

  const url      = `${WEB_RISK_BASE}/uris:search?${params.toString()}`
  const response = await fetch(url, {
    method:  'GET',
    headers: { 'Accept': 'application/json' },
    signal:  AbortSignal.timeout(8_000), // 8 s timeout
  })

  if (!response.ok) {
    const body = await response.text().catch(() => '(unreadable)')
    throw new Error(`Web Risk API error ${response.status}: ${body}`)
  }

  const data: WebRiskResponse = await response.json() as WebRiskResponse
  return data.threat?.threatTypes?.length ? data.threat.threatTypes : null
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

export interface ThreatScanResult {
  clean: boolean
  threats: Array<{ uri: string; types: ThreatType[] }>
}

/**
 * Scan one or more URLs against Google Web Risk.
 *
 * Throws `BadRequestError` when a threat is detected so the caller's
 * operation (submit / approve) is aborted automatically.
 *
 * Returns a `ThreatScanResult` so callers can log details even on success.
 */
export async function scanUrls(urls: string[]): Promise<ThreatScanResult> {
  const apiKey = process.env.GOOGLE_WEB_RISK_API_KEY

  if (!apiKey) {
    logger.warn('[threat-scan] GOOGLE_WEB_RISK_API_KEY not set — skipping URL threat scan')
    return { clean: true, threats: [] }
  }

  // Filter out empty / non-HTTP URIs upfront
  const httpUrls = urls.filter((u) => /^https?:\/\//i.test(u))
  if (!httpUrls.length) return { clean: true, threats: [] }

  const threats: Array<{ uri: string; types: ThreatType[] }> = []

  await Promise.allSettled(
    httpUrls.map(async (uri) => {
      try {
        const found = await checkSingleUri(uri, apiKey)
        if (found) {
          threats.push({ uri, types: found })
          logger.warn({ uri, types: found }, '[threat-scan] Threat detected in submitted URL')
        }
      } catch (err) {
        // API error — fail-open: log but don't block the creator
        logger.error({ err, uri }, '[threat-scan] Web Risk API call failed — skipping URI')
      }
    }),
  )

  if (threats.length > 0) {
    const summary = threats
      .map((t) => `${t.uri} [${t.types.join(', ')}]`)
      .join('; ')
    throw new BadRequestError(
      `Submission blocked: dangerous URL(s) detected — ${summary}`,
    )
  }

  return { clean: true, threats: [] }
}

/**
 * Convenience wrapper: extract all HTTP(S) URLs from an app payload and scan
 * them. Safe to call on partial updates (undefined fields are skipped).
 */
export async function scanAppUrls(app: {
  launchUrl?:    string | null
  websiteUrl?:   string | null
  supportUrl?:   string | null
  privacyUrl?:   string | null
  externalLinks?: Array<{ url: string }> | null
}): Promise<ThreatScanResult> {
  const urls: string[] = [
    app.launchUrl,
    app.websiteUrl,
    app.supportUrl,
    app.privacyUrl,
    ...(app.externalLinks?.map((l) => l.url) ?? []),
  ].filter((u): u is string => typeof u === 'string' && u.length > 0)

  return scanUrls(urls)
}
