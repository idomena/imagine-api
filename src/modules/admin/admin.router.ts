import crypto from 'crypto'
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import { AppStatus } from '@prisma/client'
import { db } from '../../core/db'
import { appsService } from '../apps/apps.service'
import { appsRepository } from '../apps/apps.repository'
import { logger } from '../../core/logger'

// ---------------------------------------------------------------------------
// Admin Panel
//
// Serves a self-contained HTML dashboard at /admin-dashboard.
// Authentication: cookie-based session validated against ADMIN_PANEL_SECRET.
//
// HTML routes (no /api prefix):
//   GET  /admin-dashboard          — dashboard page (or login redirect)
//   POST /admin-dashboard/auth     — login: validates secret, sets cookie
//   GET  /admin-dashboard/logout   — clears session cookie
//
// JSON API routes (used by the dashboard page via fetch()):
//   GET    /api/v1/admin/pending        — SUBMITTED apps waiting for review
//   POST   /api/v1/admin/apps/:id/approve — publish directly
//   POST   /api/v1/admin/apps/:id/reject  — reject
//   DELETE /api/v1/admin/apps/:id        — hard delete
//   GET    /api/v1/admin/security-log   — last 10 blocked security events
// ---------------------------------------------------------------------------

const COOKIE_NAME = 'admin_tok'
const COOKIE_MAX_AGE = 60 * 60 * 24 * 7 // 7 days

function getSecret(): string {
  return process.env['ADMIN_PANEL_SECRET'] ?? 'change-me-set-ADMIN_PANEL_SECRET'
}

function makeToken(secret: string): string {
  return crypto.createHmac('sha256', secret).update('admin-session').digest('hex')
}

function isAuthenticated(request: FastifyRequest): boolean {
  const secret = getSecret()
  const expected = makeToken(secret)
  const cookie = (request.cookies as Record<string, string | undefined>)[COOKIE_NAME]
  return cookie === expected
}

function requireAuth(request: FastifyRequest, reply: FastifyReply): boolean {
  if (!isAuthenticated(request)) {
    reply.redirect('/admin-dashboard')
    return false
  }
  return true
}

// ---------------------------------------------------------------------------
// Pending apps query — fetches SUBMITTED with creator + asset counts
// ---------------------------------------------------------------------------
async function getPendingApps() {
  return db.app.findMany({
    where:   { status: AppStatus.SUBMITTED },
    orderBy: { submittedAt: 'asc' },
    include: {
      creator: { select: { displayName: true, user: { select: { email: true } } } },
      _count:  { select: { assets: true, versions: true } },
    },
  })
}

// ---------------------------------------------------------------------------
// Security log query — last 10 blocked/flagged security events
// ---------------------------------------------------------------------------
async function getSecurityLog() {
  return db.auditLog.findMany({
    where:   { action: { startsWith: 'security.' } },
    orderBy: { createdAt: 'desc' },
    take:    10,
    select:  { id: true, action: true, entityType: true, entityId: true, metadata: true, createdAt: true },
  })
}

// ---------------------------------------------------------------------------
// HTML template
// ---------------------------------------------------------------------------
function loginPage(error?: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin — Login</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f0f11;color:#e2e2e5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem}
  .card{background:#1a1a1f;border:1px solid #2a2a32;border-radius:12px;padding:2rem;width:100%;max-width:380px}
  h1{font-size:1.25rem;font-weight:600;margin-bottom:.25rem}
  p{color:#888;font-size:.875rem;margin-bottom:1.5rem}
  label{display:block;font-size:.8125rem;color:#aaa;margin-bottom:.375rem}
  input[type=password]{width:100%;background:#0f0f11;border:1px solid #2a2a32;border-radius:8px;padding:.625rem .75rem;color:#e2e2e5;font-size:.9375rem;outline:none;transition:border-color .15s}
  input[type=password]:focus{border-color:#6366f1}
  button{width:100%;margin-top:1rem;background:#6366f1;color:#fff;border:none;border-radius:8px;padding:.75rem;font-size:.9375rem;font-weight:500;cursor:pointer;transition:background .15s}
  button:hover{background:#4f52d9}
  .err{margin-top:.875rem;padding:.625rem .75rem;background:#3b1212;border:1px solid #7f1d1d;border-radius:8px;font-size:.8125rem;color:#fca5a5}
</style>
</head>
<body>
<div class="card">
  <h1>Admin Panel</h1>
  <p>Enter your admin secret to continue.</p>
  <form method="POST" action="/admin-dashboard/auth">
    <label for="secret">Secret Key</label>
    <input type="password" id="secret" name="secret" placeholder="••••••••••••" autocomplete="current-password" autofocus>
    <button type="submit">Sign In</button>
    ${error ? `<div class="err">${error}</div>` : ''}
  </form>
</div>
</body>
</html>`
}

function dashboardPage(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Dashboard</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  :root{--bg:#0f0f11;--surface:#1a1a1f;--border:#2a2a32;--text:#e2e2e5;--muted:#888;--accent:#6366f1;--green:#22c55e;--red:#ef4444;--yellow:#f59e0b}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
  header{background:var(--surface);border-bottom:1px solid var(--border);padding:.875rem 1rem;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10}
  header h1{font-size:1rem;font-weight:600;letter-spacing:-.01em}
  header span{font-size:.75rem;color:var(--muted)}
  .logout{font-size:.8125rem;color:var(--muted);text-decoration:none;padding:.375rem .625rem;border:1px solid var(--border);border-radius:6px;transition:border-color .15s}
  .logout:hover{border-color:#555;color:var(--text)}
  main{max-width:780px;margin:0 auto;padding:1.25rem 1rem 3rem}
  section{margin-bottom:2rem}
  .section-head{display:flex;align-items:center;gap:.5rem;margin-bottom:.875rem}
  .section-head h2{font-size:.9375rem;font-weight:600}
  .badge{font-size:.6875rem;font-weight:600;padding:.15rem .45rem;border-radius:999px;background:#1e2030;color:var(--accent);border:1px solid #2d2f55}
  .badge.green{background:#0f2318;color:var(--green);border-color:#14532d}
  .empty{color:var(--muted);font-size:.875rem;padding:1rem 0}
  /* App cards */
  .app-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1rem;margin-bottom:.625rem;display:flex;gap:.875rem;align-items:flex-start}
  .app-card:last-child{margin-bottom:0}
  .icon{width:48px;height:48px;border-radius:10px;background:#12121a;overflow:hidden;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:1.25rem;border:1px solid var(--border)}
  .icon img{width:100%;height:100%;object-fit:cover}
  .app-info{flex:1;min-width:0}
  .app-name{font-weight:600;font-size:.9375rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .app-meta{font-size:.75rem;color:var(--muted);margin-top:.2rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .app-url{font-size:.75rem;color:var(--accent);margin-top:.25rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .actions{display:flex;gap:.5rem;flex-shrink:0;flex-direction:column;align-items:flex-end}
  @media(min-width:500px){.actions{flex-direction:row;align-items:center}}
  .btn{border:none;border-radius:7px;padding:.45rem .875rem;font-size:.8125rem;font-weight:500;cursor:pointer;transition:opacity .15s;white-space:nowrap}
  .btn:disabled{opacity:.45;cursor:default}
  .btn-approve{background:var(--green);color:#fff}
  .btn-reject{background:var(--surface);color:var(--muted);border:1px solid var(--border)}
  .btn-reject:hover:not(:disabled){border-color:#555;color:var(--text)}
  .btn-delete{background:#3b0a0a;color:var(--red);border:1px solid #7f1d1d}
  .btn-delete:hover:not(:disabled){background:#500f0f}
  .spinner{display:inline-block;width:.875rem;height:.875rem;border:2px solid #ffffff44;border-top-color:#fff;border-radius:50%;animation:spin .6s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  /* Security log */
  .log-row{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:.75rem;margin-bottom:.5rem;font-size:.8125rem}
  .log-row:last-child{margin-bottom:0}
  .log-action{font-weight:600;color:var(--yellow);word-break:break-all}
  .log-meta{color:var(--muted);margin-top:.25rem;line-height:1.5}
  .log-time{font-size:.6875rem;color:#555;margin-top:.2rem}
  /* Toast */
  #toast{position:fixed;bottom:1.25rem;right:1rem;left:1rem;max-width:360px;margin:0 auto;background:#1e2030;border:1px solid #3a3a5c;border-radius:10px;padding:.75rem 1rem;font-size:.875rem;opacity:0;transform:translateY(.5rem);transition:opacity .2s,transform .2s;pointer-events:none;z-index:999}
  #toast.show{opacity:1;transform:translateY(0)}
  #toast.err{background:#2a0f0f;border-color:#7f1d1d;color:#fca5a5}
  #toast.ok{background:#0f2318;border-color:#14532d;color:#86efac}
  .spinner-full{padding:2rem 0;text-align:center;color:var(--muted);font-size:.875rem}
</style>
</head>
<body>
<header>
  <div>
    <h1>Admin Dashboard</h1>
    <span id="last-refresh"></span>
  </div>
  <a href="/admin-dashboard/logout" class="logout">Sign out</a>
</header>
<main>
  <section id="queue-section">
    <div class="section-head">
      <h2>Review Queue</h2>
      <span class="badge" id="queue-count">…</span>
    </div>
    <div id="queue-list"><div class="spinner-full">Loading…</div></div>
  </section>

  <section id="log-section">
    <div class="section-head">
      <h2>Security Log</h2>
      <span class="badge green">last 10</span>
    </div>
    <div id="log-list"><div class="spinner-full">Loading…</div></div>
  </section>
</main>
<div id="toast"></div>

<script>
const toast = (msg, type = 'ok') => {
  const el = document.getElementById('toast')
  el.textContent = msg
  el.className = 'show ' + type
  clearTimeout(el._t)
  el._t = setTimeout(() => { el.className = '' }, 3000)
}

async function apiFetch(url, opts = {}) {
  const r = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...opts })
  const json = await r.json().catch(() => ({}))
  if (!r.ok) throw new Error(json?.error?.message ?? 'Request failed')
  return json
}

function fmtDate(iso) {
  const d = new Date(iso)
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
    + ' ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

function timeAgo(iso) {
  const secs = Math.floor((Date.now() - new Date(iso)) / 1000)
  if (secs < 60)  return secs + 's ago'
  if (secs < 3600) return Math.floor(secs/60) + 'm ago'
  if (secs < 86400) return Math.floor(secs/3600) + 'h ago'
  return Math.floor(secs/86400) + 'd ago'
}

// ── Queue ──────────────────────────────────────────────────────────────────

async function loadQueue() {
  const el = document.getElementById('queue-list')
  try {
    const { data } = await apiFetch('/api/v1/admin/pending')
    document.getElementById('queue-count').textContent = data.length
    if (!data.length) {
      el.innerHTML = '<p class="empty">No apps pending review. All clear.</p>'
      return
    }
    el.innerHTML = data.map(app => {
      const icon = app.iconUrl
        ? \`<img src="\${app.iconUrl}" alt="" loading="lazy">\`
        : '📦'
      const submittedAgo = app.submittedAt ? timeAgo(app.submittedAt) : '—'
      const creator = app.creator?.displayName ?? 'Unknown'
      const email   = app.creator?.user?.email ?? ''
      return \`
      <div class="app-card" id="card-\${app.id}">
        <div class="icon">\${icon}</div>
        <div class="app-info">
          <div class="app-name">\${esc(app.name)}</div>
          <div class="app-meta">\${esc(app.tagline)}</div>
          <div class="app-meta">\${esc(creator)}\${email ? ' · ' + esc(email) : ''} · \${submittedAgo}</div>
          \${app.launchUrl ? \`<div class="app-url">\${esc(app.launchUrl)}</div>\` : ''}
        </div>
        <div class="actions">
          <button class="btn btn-approve" onclick="approveApp('\${app.id}', this)">Approve</button>
          <button class="btn btn-delete"  onclick="deleteApp('\${app.id}', this)">Delete</button>
        </div>
      </div>\`
    }).join('')
  } catch (e) {
    el.innerHTML = '<p class="empty">Failed to load queue: ' + esc(e.message) + '</p>'
  }
}

async function approveApp(id, btn) {
  const orig = btn.textContent
  btn.disabled = true
  btn.innerHTML = '<span class="spinner"></span>'
  const card = document.getElementById('card-' + id)
  try {
    await apiFetch(\`/api/v1/admin/apps/\${id}/approve\`, { method: 'POST' })
    card.style.transition = 'opacity .3s'
    card.style.opacity = '0'
    setTimeout(() => { card.remove(); updateCount(-1) }, 300)
    toast('App approved and published.')
  } catch (e) {
    btn.disabled = false
    btn.textContent = orig
    toast(e.message, 'err')
  }
}

async function deleteApp(id, btn) {
  if (!confirm('Permanently delete this app?')) return
  const orig = btn.textContent
  btn.disabled = true
  btn.innerHTML = '<span class="spinner"></span>'
  const card = document.getElementById('card-' + id)
  try {
    await apiFetch(\`/api/v1/admin/apps/\${id}\`, { method: 'DELETE' })
    card.style.transition = 'opacity .3s'
    card.style.opacity = '0'
    setTimeout(() => { card.remove(); updateCount(-1) }, 300)
    toast('App deleted.')
  } catch (e) {
    btn.disabled = false
    btn.textContent = orig
    toast(e.message, 'err')
  }
}

function updateCount(delta) {
  const el = document.getElementById('queue-count')
  const n = (parseInt(el.textContent) || 0) + delta
  el.textContent = n
  if (n === 0) {
    document.getElementById('queue-list').innerHTML =
      '<p class="empty">No apps pending review. All clear.</p>'
  }
}

// ── Security log ───────────────────────────────────────────────────────────

async function loadSecurityLog() {
  const el = document.getElementById('log-list')
  try {
    const { data } = await apiFetch('/api/v1/admin/security-log')
    if (!data.length) {
      el.innerHTML = '<p class="empty">No security events yet.</p>'
      return
    }
    el.innerHTML = data.map(row => {
      const meta = row.metadata ? JSON.stringify(row.metadata, null, 2) : ''
      const preview = meta ? meta.slice(0, 200) + (meta.length > 200 ? '…' : '') : ''
      return \`
      <div class="log-row">
        <div class="log-action">\${esc(row.action)}</div>
        <div class="log-meta">\${esc(row.entityType)} · \${esc(row.entityId)}</div>
        \${preview ? \`<div class="log-meta" style="color:#666;font-family:monospace;font-size:.7rem;margin-top:.25rem">\${esc(preview)}</div>\` : ''}
        <div class="log-time">\${fmtDate(row.createdAt)}</div>
      </div>\`
    }).join('')
  } catch (e) {
    el.innerHTML = '<p class="empty">Failed to load log: ' + esc(e.message) + '</p>'
  }
}

function esc(str) {
  return String(str ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')
}

function refreshAll() {
  loadQueue()
  loadSecurityLog()
  document.getElementById('last-refresh').textContent =
    'Refreshed ' + new Date().toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

// Auto-refresh every 60s
refreshAll()
setInterval(refreshAll, 60_000)
</script>
</body>
</html>`
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

export async function adminRouter(app: FastifyInstance) {
  // ── Cookie middleware ──────────────────────────────────────────────────────

  // ── HTML: Dashboard ───────────────────────────────────────────────────────
  app.get('/admin-dashboard', async (request, reply) => {
    if (!isAuthenticated(request)) {
      return reply.type('text/html').send(loginPage())
    }
    return reply.type('text/html').send(dashboardPage())
  })

  // ── HTML: Login ───────────────────────────────────────────────────────────
  app.post('/admin-dashboard/auth', {
    config: { rawBody: false },
  }, async (request, reply) => {
    // multipart is registered globally; parse form body manually
    const body = request.body as Record<string, string> | undefined
    const entered = body?.['secret'] ?? ''
    const secret  = getSecret()

    if (!entered || entered !== secret) {
      logger.warn({ ip: request.ip }, '[admin] Failed login attempt')
      return reply.type('text/html').send(loginPage('Incorrect secret key.'))
    }

    const token = makeToken(secret)
    reply.setCookie(COOKIE_NAME, token, {
      httpOnly: true,
      secure:   process.env['NODE_ENV'] === 'production',
      sameSite: 'lax',
      path:     '/',
      maxAge:   COOKIE_MAX_AGE,
    })
    return reply.redirect('/admin-dashboard')
  })

  // ── HTML: Logout ──────────────────────────────────────────────────────────
  app.get('/admin-dashboard/logout', async (_request, reply) => {
    reply.clearCookie(COOKIE_NAME, { path: '/' })
    return reply.redirect('/admin-dashboard')
  })

  // ── API: Pending apps ─────────────────────────────────────────────────────
  app.get('/api/v1/admin/pending', async (request, reply) => {
    if (!requireAuth(request, reply)) return
    const apps = await getPendingApps()
    return reply.send({ success: true, data: apps })
  })

  // ── API: Approve ──────────────────────────────────────────────────────────
  app.post('/api/v1/admin/apps/:id/approve', async (request, reply) => {
    if (!requireAuth(request, reply)) return
    const { id } = request.params as { id: string }
    const app = await appsService.adminApprove(id)
    logger.info({ appId: id, ip: request.ip }, '[admin] App approved')
    return reply.send({ success: true, data: app })
  })

  // ── API: Reject ───────────────────────────────────────────────────────────
  app.post('/api/v1/admin/apps/:id/reject', async (request, reply) => {
    if (!requireAuth(request, reply)) return
    const { id } = request.params as { id: string }
    const app = await appsService.adminReject(id)
    logger.info({ appId: id, ip: request.ip }, '[admin] App rejected')
    return reply.send({ success: true, data: app })
  })

  // ── API: Delete ───────────────────────────────────────────────────────────
  app.delete('/api/v1/admin/apps/:id', async (request, reply) => {
    if (!requireAuth(request, reply)) return
    const { id } = request.params as { id: string }
    // Verify it exists before deleting
    const existing = await appsRepository.findById(id)
    if (!existing) {
      return reply.status(404).send({ success: false, error: { message: 'App not found' } })
    }
    await appsRepository.delete(id)
    logger.warn({ appId: id, ip: request.ip }, '[admin] App hard-deleted')
    return reply.status(204).send()
  })

  // ── API: Security log ─────────────────────────────────────────────────────
  app.get('/api/v1/admin/security-log', async (request, reply) => {
    if (!requireAuth(request, reply)) return
    const rows = await getSecurityLog()
    return reply.send({ success: true, data: rows })
  })
}
