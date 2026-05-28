// ---------------------------------------------------------------------------
// URL metadata scraper — fast, streaming, head-only.
// Reads only until </head> (or 48 KB) to avoid downloading full pages.
// Uses a full Chrome header set to bypass bot-detection on most sites.
// On blocked/403 responses, returns partial data derived from the URL
// instead of throwing — the form is pre-filled rather than left empty.
// ---------------------------------------------------------------------------

// Full Chrome 124 UA + headers — bypasses Cloudflare, Vercel, and most WAFs
const BROWSER_HEADERS: Record<string, string> = {
  'User-Agent':                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Accept':                    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
  'Accept-Language':           'en-US,en;q=0.9',
  'Cache-Control':             'max-age=0',
  'Sec-Fetch-Dest':            'document',
  'Sec-Fetch-Mode':            'navigate',
  'Sec-Fetch-Site':            'none',
  'Sec-Fetch-User':            '?1',
  'Upgrade-Insecure-Requests': '1',
}

const TIMEOUT_MS     = 5_000   // 5 s — fail fast on slow/unresponsive sites
const MAX_HEAD_BYTES = 48_000  // 48 KB — covers any <head> section

function resolveUrl(href: string, base: string): string {
  try { return new URL(href, base).href } catch { return href }
}

function extractMeta(html: string, names: string[]): string | null {
  for (const name of names) {
    const re = new RegExp(
      `<meta[^>]+(?:name|property)=["']${name}["'][^>]+content=["']([^"']{1,2000})["']` +
      `|<meta[^>]+content=["']([^"']{1,2000})["'][^>]+(?:name|property)=["']${name}["']`,
      'i',
    )
    const m   = html.match(re)
    const val = (m?.[1] || m?.[2] || '').trim()
    if (val) return val
  }
  return null
}

function extractFavicon(html: string, base: string): string {
  const patterns = [
    /<link[^>]+rel=["'][^"']*apple-touch-icon[^"']*["'][^>]+href=["']([^"']+)["']/i,
    /<link[^>]+href=["']([^"']+)["'][^>]+rel=["'][^"']*apple-touch-icon[^"']*["']/i,
    /<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]+href=["']([^"']+)["']/i,
    /<link[^>]+href=["']([^"']+)["'][^>]+rel=["'][^"']*icon[^"']*["']/i,
  ]
  for (const re of patterns) {
    const m = html.match(re)
    if (m?.[1]) return resolveUrl(m[1], base)
  }
  const { protocol, host } = new URL(base)
  return `${protocol}//${host}/favicon.ico`
}

function first(...vals: (string | null | undefined)[]): string | null {
  return vals.find(v => !!v?.trim()) ?? null
}

/** Derive a human-readable name from a hostname (e.g. "my-app.io" → "My App"). */
function nameFromHost(hostname: string): string {
  const stem = hostname.replace(/^www\./, '').split('.')[0] ?? hostname
  return stem
    .replace(/[-_]/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase())
    .slice(0, 100)
}

export interface ScrapeResult {
  name:        string
  tagline:     string
  description: string
  iconUrl:     string
  ogImage:     string | null
  partial:     boolean  // true = site blocked scraping; data is URL-derived only
}

export async function scrapeUrl(rawUrl: string): Promise<ScrapeResult> {
  const url        = rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`
  const controller = new AbortController()
  const timer      = setTimeout(() => controller.abort(), TIMEOUT_MS)

  let html     = ''
  let finalUrl = url
  let blocked  = false

  try {
    const res = await fetch(url, {
      headers:  BROWSER_HEADERS,
      signal:   controller.signal,
      redirect: 'follow',
    })

    finalUrl = res.url || url

    if (!res.ok) {
      // 403/429/5xx — site is blocking us; fall through to URL-derived fallback
      blocked = true
    } else {
      // Stream — stop after </head> or 48 KB (whichever comes first)
      const reader  = res.body?.getReader()
      const decoder = new TextDecoder()

      if (reader) {
        let bytes = 0
        while (bytes < MAX_HEAD_BYTES) {
          const { done, value } = await reader.read()
          if (done || !value) break
          html  += decoder.decode(value, { stream: true })
          bytes += value.byteLength
          if (html.includes('</head>') || html.includes('</HEAD>')) break
        }
        reader.cancel().catch(() => {})
      } else {
        html = await res.text()
      }
    }
  } catch {
    // Network error / timeout — fall through to URL-derived fallback
    blocked = true
  } finally {
    clearTimeout(timer)
  }

  // ── URL-derived fallback when site is blocked / unreachable ─────────────
  if (blocked || !html) {
    const { protocol, host } = new URL(finalUrl)
    const name = nameFromHost(host)
    return {
      name,
      tagline:     `Explore ${name}`,
      description: '',
      iconUrl:     `${protocol}//${host}/favicon.ico`,
      ogImage:     null,
      partial:     true,
    }
  }

  // ── Full extraction from HTML head ───────────────────────────────────────
  const ogTitle   = extractMeta(html, ['og:title', 'twitter:title'])
  const htmlTitle = html.match(/<title[^>]*>([^<]{1,200})<\/title>/i)?.[1]?.trim() ?? null
  const siteName  = extractMeta(html, ['og:site_name', 'application-name'])
  const ogDesc    = extractMeta(html, ['og:description', 'twitter:description'])
  const metaDesc  = extractMeta(html, ['description'])
  const ogImage   = extractMeta(html, ['og:image', 'twitter:image:src', 'twitter:image'])

  const hostname = new URL(finalUrl).hostname.replace(/^www\./, '')
  const name     = first(ogTitle, htmlTitle, siteName) ?? nameFromHost(hostname)
  const rawDesc  = first(ogDesc, metaDesc) ?? ''

  const tagline = (rawDesc.split(/\.\s/)[0] ?? rawDesc).replace(/\s+/g, ' ').trim().slice(0, 120)
    || `Explore ${name}`

  return {
    name:        name.slice(0, 100),
    tagline:     tagline.slice(0, 120),
    description: rawDesc.slice(0, 5_000),
    iconUrl:     extractFavicon(html, finalUrl),
    ogImage:     ogImage ?? null,
    partial:     false,
  }
}
