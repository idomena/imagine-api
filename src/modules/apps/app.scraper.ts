// ---------------------------------------------------------------------------
// URL metadata scraper — no external deps, uses Node's built-in fetch.
// Extracts Open Graph / meta tags to pre-populate the submit form.
// ---------------------------------------------------------------------------

const UA = 'Mozilla/5.0 (compatible; ImagineBot/1.0; +https://imaginehq.services)'

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
    const m = html.match(re)
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

export interface ScrapeResult {
  name:        string
  tagline:     string
  description: string
  iconUrl:     string
  ogImage:     string | null
}

export async function scrapeUrl(rawUrl: string): Promise<ScrapeResult> {
  const url = rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`

  const res = await fetch(url, {
    headers:  { 'User-Agent': UA },
    signal:   AbortSignal.timeout(8_000),
    redirect: 'follow',
  })

  if (!res.ok) throw new Error(`Site returned ${res.status}`)

  const html     = await res.text()
  const finalUrl = res.url || url

  const ogTitle  = extractMeta(html, ['og:title', 'twitter:title'])
  const htmlTitle = html.match(/<title[^>]*>([^<]{1,200})<\/title>/i)?.[1]?.trim() ?? null
  const siteName = extractMeta(html, ['og:site_name', 'application-name'])
  const ogDesc   = extractMeta(html, ['og:description', 'twitter:description'])
  const metaDesc = extractMeta(html, ['description'])
  const ogImage  = extractMeta(html, ['og:image', 'twitter:image:src', 'twitter:image'])

  const hostname = new URL(finalUrl).hostname.replace(/^www\./, '')
  const name     = first(ogTitle, htmlTitle, siteName) ?? hostname
  const rawDesc  = first(ogDesc, metaDesc) ?? ''

  // First sentence or 120 chars as the tagline
  const tagline = (rawDesc.split(/\.\s/)[0] ?? rawDesc).replace(/\s+/g, ' ').trim().slice(0, 120)
    || `Explore ${name}`

  return {
    name:        name.slice(0, 100),
    tagline:     tagline.slice(0, 120),
    description: rawDesc.slice(0, 5_000),
    iconUrl:     extractFavicon(html, finalUrl),
    ogImage:     ogImage ?? null,
  }
}
