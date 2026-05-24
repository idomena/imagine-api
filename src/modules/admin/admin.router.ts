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
// HTML routes:
//   GET  /admin-dashboard              — dashboard (or login page)
//   POST /admin-dashboard/auth         — validates secret, sets cookie
//   GET  /admin-dashboard/logout       — clears cookie, redirects to login
//   GET  /admin-dashboard/bundle.js    — dashboard JS (served separately so
//                                        CSP script-src 'self' allows it)
//
// JSON API routes (called by the dashboard JS via fetch):
//   GET    /api/v1/admin/pending            — SUBMITTED apps
//   POST   /api/v1/admin/apps/:id/approve   — SUBMITTED → PUBLISHED
//   POST   /api/v1/admin/apps/:id/reject    — SUBMITTED → REJECTED
//   DELETE /api/v1/admin/apps/:id           — hard delete
//   GET    /api/v1/admin/security-log       — last 10 blocked security events
// ---------------------------------------------------------------------------

const COOKIE_NAME    = 'admin_tok'
const COOKIE_MAX_AGE = 60 * 60 * 24 * 7  // 7 days

function getSecret(): string {
  return process.env['ADMIN_PANEL_SECRET'] ?? 'change-me-set-ADMIN_PANEL_SECRET'
}

function makeToken(secret: string): string {
  return crypto.createHmac('sha256', secret).update('admin-session').digest('hex')
}

function isAuthenticated(request: FastifyRequest): boolean {
  const expected = makeToken(getSecret())
  const cookie   = (request.cookies as Record<string, string | undefined>)[COOKIE_NAME]
  return cookie === expected
}

// ---------------------------------------------------------------------------
// DB helpers
// ---------------------------------------------------------------------------

async function getPendingApps() {
  return db.app.findMany({
    where:   { status: AppStatus.SUBMITTED },
    orderBy: { submittedAt: 'asc' },
    include: {
      creator: {
        select: {
          displayName: true,
          user: { select: { email: true } },
        },
      },
      securityAuditReport: { select: { decision: true } },
    },
  })
}

async function getSecurityLog() {
  return db.auditLog.findMany({
    where:   { action: { startsWith: 'security.' } },
    orderBy: { createdAt: 'desc' },
    take:    10,
    select:  {
      id:         true,
      action:     true,
      entityType: true,
      entityId:   true,
      metadata:   true,
      createdAt:  true,
    },
  })
}

// ---------------------------------------------------------------------------
// HTML pages
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
  .btn-delete{background:#3b0a0a;color:var(--red);border:1px solid #7f1d1d}
  .btn-delete:hover:not(:disabled){background:#500f0f}
  .spinner{display:inline-block;width:.875rem;height:.875rem;border:2px solid #ffffff44;border-top-color:#fff;border-radius:50%;animation:spin .6s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  .log-row{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:.75rem;margin-bottom:.5rem;font-size:.8125rem}
  .log-row:last-child{margin-bottom:0}
  .log-action{font-weight:600;color:var(--yellow);word-break:break-all}
  .log-meta{color:var(--muted);margin-top:.25rem;line-height:1.5}
  .log-time{font-size:.6875rem;color:#555;margin-top:.2rem}
  #toast{position:fixed;bottom:1.25rem;right:1rem;left:1rem;max-width:360px;margin:0 auto;background:#1e2030;border:1px solid #3a3a5c;border-radius:10px;padding:.75rem 1rem;font-size:.875rem;opacity:0;transform:translateY(.5rem);transition:opacity .2s,transform .2s;pointer-events:none;z-index:999}
  #toast.show{opacity:1;transform:translateY(0)}
  #toast.err{background:#2a0f0f;border-color:#7f1d1d;color:#fca5a5}
  #toast.ok{background:#0f2318;border-color:#14532d;color:#86efac}
  .spinner-full{padding:2rem 0;text-align:center;color:var(--muted);font-size:.875rem}
  .btn-audit{background:#1e2030;color:var(--accent);border:1px solid #2d2f55}
  .btn-audit:hover:not(:disabled){background:#252742}
  .modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.8);z-index:100;display:flex;align-items:center;justify-content:center;padding:1rem}
  .modal{background:var(--surface);border:1px solid var(--border);border-radius:12px;width:100%;max-width:620px;max-height:90vh;overflow-y:auto;padding:1.5rem}
  .modal-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.25rem}
  .modal-title{font-size:1rem;font-weight:600}
  .modal-close{background:none;border:none;color:var(--muted);cursor:pointer;font-size:1.5rem;line-height:1;padding:0 .25rem}
  .modal-close:hover{color:var(--text)}
  .decision-badge{display:inline-flex;align-items:center;padding:.3rem .75rem;border-radius:999px;font-size:.8125rem;font-weight:600}
  .decision-auto-published{background:#0f2318;color:var(--green);border:1px solid #14532d}
  .decision-held{background:#1c1206;color:var(--yellow);border:1px solid #78350f}
  .decision-rejected{background:#2a0f0f;color:var(--red);border:1px solid #7f1d1d}
  .score-bar{height:6px;border-radius:3px;background:#2a2a32;margin:.6rem 0 .25rem}
  .score-fill{height:100%;border-radius:3px}
  .score-high{background:var(--green)}.score-mid{background:var(--yellow)}.score-low{background:var(--red)}
  .audit-section{margin-top:1rem;border-top:1px solid var(--border);padding-top:1rem}
  .audit-section h3{font-size:.75rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin-bottom:.625rem}
  .threat-item{padding:.4rem 0;border-bottom:1px solid #1e1e25;font-size:.8rem;line-height:1.5}
  .threat-item:last-child{border-bottom:none}
  .sev-CRITICAL{color:var(--red);font-weight:700}.sev-HIGH{color:#f97316;font-weight:600}.sev-MEDIUM{color:var(--yellow);font-weight:600}.sev-LOW{color:#60a5fa}
  .check-row{display:flex;align-items:center;gap:.375rem;font-size:.8rem;color:var(--muted);padding:.2rem 0}
  .chk-ok{color:var(--green)}.chk-fail{color:var(--red)}
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
<script src="/admin-dashboard/bundle.js"></script>
</body>
</html>`
}

// ---------------------------------------------------------------------------
// Dashboard JavaScript — served as a same-origin file so CSP script-src
// 'self' allows it (inline <script> blocks would be rejected by the policy).
// ---------------------------------------------------------------------------
const BUNDLE_JS = `
'use strict';

const toast = (msg, type) => {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'show ' + (type || 'ok');
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.className = ''; }, 3000);
};

async function apiFetch(url, opts) {
  opts = opts || {};
  const r = await fetch(url, Object.assign({ headers: { 'Content-Type': 'application/json' } }, opts));
  if (r.status === 401) {
    window.location.href = '/admin-dashboard';
    return;
  }
  const json = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((json && json.error && json.error.message) || 'Request failed');
  return json;
}

function fmtDate(iso) {
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
    + ' ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

function timeAgo(iso) {
  const secs = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (secs < 60)    return secs + 's ago';
  if (secs < 3600)  return Math.floor(secs / 60) + 'm ago';
  if (secs < 86400) return Math.floor(secs / 3600) + 'h ago';
  return Math.floor(secs / 86400) + 'd ago';
}

function esc(str) {
  return String(str == null ? '' : str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function updateCount(delta) {
  const el = document.getElementById('queue-count');
  const n = (parseInt(el.textContent, 10) || 0) + delta;
  el.textContent = n;
  if (n <= 0) {
    document.getElementById('queue-list').innerHTML =
      '<p class="empty">No apps pending review. All clear.</p>';
  }
}

async function loadQueue() {
  const el = document.getElementById('queue-list');
  try {
    const res = await apiFetch('/api/v1/admin/pending');
    if (!res) return; // redirected to login
    const data = res.data || [];
    document.getElementById('queue-count').textContent = data.length;
    if (!data.length) {
      el.innerHTML = '<p class="empty">No apps pending review. All clear.</p>';
      return;
    }
    el.innerHTML = data.map(function(app) {
      const icon = app.iconUrl
        ? '<img src="' + esc(app.iconUrl) + '" alt="" loading="lazy">'
        : '📦';
      const submittedAgo = app.submittedAt ? timeAgo(app.submittedAt) : '-';
      const creator  = (app.creator && app.creator.displayName) || 'Unknown';
      const email    = (app.creator && app.creator.user && app.creator.user.email) || '';
      const launchRow = app.launchUrl
        ? '<div class="app-url">' + esc(app.launchUrl) + '</div>'
        : '';
      const isSecurityFlag = app.securityAuditReport && app.securityAuditReport.decision === 'AUTO_REJECTED';
      const secBadge = isSecurityFlag
        ? '<span style="display:inline-block;background:#2a0f0f;color:#ef4444;border:1px solid #7f1d1d;border-radius:999px;font-size:.625rem;font-weight:700;padding:.1rem .45rem;margin-left:.4rem;vertical-align:middle;letter-spacing:.02em">⚠ SECURITY FLAG</span>'
        : '';
      return '<div class="app-card" id="card-' + esc(app.id) + '"' + (isSecurityFlag ? ' style="border-color:#7f1d1d"' : '') + '>'
        + '<div class="icon">' + icon + '</div>'
        + '<div class="app-info">'
        + '<div class="app-name">' + esc(app.name) + secBadge + '</div>'
        + '<div class="app-meta">' + esc(app.tagline) + '</div>'
        + '<div class="app-meta">' + esc(creator) + (email ? ' &middot; ' + esc(email) : '') + ' &middot; ' + esc(submittedAgo) + '</div>'
        + launchRow
        + '</div>'
        + '<div class="actions">'
        + '<button class="btn btn-audit"   data-id="' + esc(app.id) + '">Audit</button>'
        + '<button class="btn btn-approve" data-id="' + esc(app.id) + '">Approve</button>'
        + '<button class="btn btn-delete"  data-id="' + esc(app.id) + '">Delete</button>'
        + '</div>'
        + '</div>';
    }).join('');
  } catch(e) {
    el.innerHTML = '<p class="empty">Failed to load queue: ' + esc(e.message) + '</p>';
  }
}

async function approveApp(btn) {
  var id = btn.dataset.id;
  console.log('Click detected for app:', id);
  var orig = btn.textContent;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>';
  try {
    await apiFetch('/api/v1/admin/apps/' + id + '/approve', { method: 'POST' });
    toast('App approved and published.');
    setTimeout(function() { loadQueue(); }, 300);
  } catch(e) {
    btn.disabled = false;
    btn.textContent = orig;
    toast(e.message, 'err');
  }
}

async function deleteApp(btn) {
  var id = btn.dataset.id;
  console.log('Click detected for app:', id);
  if (!confirm('Permanently delete this app?')) return;
  var orig = btn.textContent;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>';
  try {
    await apiFetch('/api/v1/admin/apps/' + id, { method: 'DELETE' });
    toast('App deleted.');
    setTimeout(function() { loadQueue(); }, 300);
  } catch(e) {
    btn.disabled = false;
    btn.textContent = orig;
    toast(e.message, 'err');
  }
}

async function loadSecurityLog() {
  const el = document.getElementById('log-list');
  try {
    const res = await apiFetch('/api/v1/admin/security-log');
    if (!res) return;
    const data = res.data || [];
    if (!data.length) {
      el.innerHTML = '<p class="empty">No security events yet.</p>';
      return;
    }
    el.innerHTML = data.map(function(row) {
      var meta = row.metadata ? JSON.stringify(row.metadata) : '';
      var preview = meta.length > 180 ? meta.slice(0, 180) + '...' : meta;
      return '<div class="log-row">'
        + '<div class="log-action">' + esc(row.action) + '</div>'
        + '<div class="log-meta">' + esc(row.entityType) + ' &middot; ' + esc(row.entityId) + '</div>'
        + (preview ? '<div class="log-meta" style="color:#555;font-family:monospace;font-size:.7rem;margin-top:.2rem">' + esc(preview) + '</div>' : '')
        + '<div class="log-time">' + fmtDate(row.createdAt) + '</div>'
        + '</div>';
    }).join('');
  } catch(e) {
    el.innerHTML = '<p class="empty">Failed to load log: ' + esc(e.message) + '</p>';
  }
}

function refreshAll() {
  loadQueue();
  loadSecurityLog();
  const ts = new Date().toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  document.getElementById('last-refresh').textContent = 'Refreshed ' + ts;
}

function showAuditModal(report) {
  var existing = document.getElementById('audit-modal-overlay');
  if (existing) existing.remove();
  if (!report) { toast('No audit report available for this app.', 'err'); return; }

  var decision = report.decision || 'UNKNOWN';
  var decCls   = decision === 'AUTO_PUBLISHED' ? 'decision-auto-published'
               : decision === 'AUTO_REJECTED'  ? 'decision-rejected'
               : 'decision-held';
  var decLbl   = decision === 'AUTO_PUBLISHED' ? 'Auto-Published'
               : decision === 'AUTO_REJECTED'  ? 'Auto-Rejected'
               : 'Held for Review';

  var score     = typeof report.safetyScore === 'number' ? report.safetyScore : 0;
  var scoreCls  = score > 90 ? 'score-high' : score > 50 ? 'score-mid' : 'score-low';
  var threats   = Array.isArray(report.threats)  ? report.threats  : [];
  var warnings  = Array.isArray(report.warnings) ? report.warnings : [];
  var phase1    = report.phase1 || {};
  var phase2    = report.phase2 || {};
  var phase3    = report.phase3 || {};
  var pay       = phase2.payment       || {};
  var phi       = phase2.phishing      || {};
  var idt       = phase2.identityTheft || {};

  function threatRows(items) {
    if (!items.length) return '<div class="check-row" style="color:#555">None detected.</div>';
    return items.map(function(t) {
      return '<div class="threat-item"><span class="sev-' + esc(t.severity || 'LOW') + '">[' + esc(t.severity) + '] ' + esc(t.type) + '</span> — ' + esc(t.description || '') + '</div>';
    }).join('');
  }

  function chk(ok, label) {
    return '<div class="check-row"><span class="' + (ok ? 'chk-ok' : 'chk-fail') + '">' + (ok ? '✓' : '✗') + '</span> ' + esc(label) + '</div>';
  }

  var auditedAt = report.updatedAt || report.createdAt;
  var auditedStr = auditedAt ? new Date(auditedAt).toLocaleString() : '—';

  var html = '<div class="modal-overlay" id="audit-modal-overlay">'
    + '<div class="modal">'
    + '<div class="modal-header"><span class="modal-title">Security Audit Report</span>'
    + '<button class="modal-close" id="close-audit-modal">&times;</button></div>'

    + '<div style="display:flex;align-items:center;gap:.75rem;flex-wrap:wrap">'
    + '<span class="decision-badge ' + decCls + '">' + decLbl + '</span>'
    + '<span style="color:var(--muted);font-size:.875rem">Safety Score: <strong style="color:var(--text)">' + score + ' / 100</strong></span>'
    + '</div>'
    + '<div class="score-bar"><div class="score-fill ' + scoreCls + '" style="width:' + score + '%"></div></div>'
    + '<p style="font-size:.8rem;color:var(--muted);margin-top:.375rem">' + esc(phase3.reasoning || 'No reasoning recorded.') + '</p>'

    + '<div class="audit-section"><h3>Critical Threats (' + threats.length + ')</h3>' + threatRows(threats) + '</div>'
    + '<div class="audit-section"><h3>Warnings (' + warnings.length + ')</h3>' + threatRows(warnings) + '</div>'

    + '<div class="audit-section"><h3>Phase 1 — Domain Reputation</h3>'
    + chk(phase1.apiAvailable !== false, 'Google Web Risk API reachable')
    + chk(phase1.domainReputation !== 'THREAT', 'Domain not flagged by Web Risk')
    + chk(!phase1.blacklisted, 'Domain not in local blacklist')
    + '</div>'

    + '<div class="audit-section"><h3>Phase 2 — Content Analysis</h3>'
    + chk(phase2.fetched !== false, phase2.fetched !== false ? 'Page fetched (' + (phase2.contentLength || 0).toLocaleString() + ' bytes)' : 'Page fetch failed: ' + (phase2.fetchError || 'unknown'))
    + chk(!pay.untrustedCCCollection, pay.untrustedCCCollection ? 'UNTRUSTED credit card collection detected' : 'No untrusted CC collection')
    + (pay.trustedGatewayDetected ? chk(true, 'Trusted gateway: ' + (pay.trustedGateways || []).join(', ')) : '')
    + chk(!phi.suspiciousFormActions, phi.suspiciousFormActions ? 'Suspicious external form actions' : 'No suspicious form actions')
    + chk(!idt.sensitiveFieldsFound, idt.sensitiveFieldsFound ? 'Identity theft fields: ' + (idt.sensitiveFields || []).join(', ') : 'No identity theft fields detected')
    + chk(!phase2.obfuscatedContent, phase2.obfuscatedContent ? 'Malicious obfuscated JavaScript detected' : 'No malicious obfuscation')
    + chk(!(phase2.xss && (phase2.xss.cookieTheftDetected || phase2.xss.storageTheftDetected)), (phase2.xss && phase2.xss.cookieTheftDetected) ? 'Cookie/session theft script detected' : (phase2.xss && phase2.xss.storageTheftDetected) ? 'Storage exfiltration script detected' : 'No XSS credential theft detected')
    + chk(!(phase2.clickjacking && phase2.clickjacking.suspiciousOverlayDetected), (phase2.clickjacking && phase2.clickjacking.suspiciousOverlayDetected) ? 'Clickjacking overlay detected' : 'No clickjacking overlay detected')
    + '</div>'

    + '<div style="margin-top:1rem;font-size:.75rem;color:#555">Last audited: ' + esc(auditedStr) + '</div>'
    + '</div></div>';

  document.body.insertAdjacentHTML('beforeend', html);

  document.getElementById('audit-modal-overlay').addEventListener('click', function(e) {
    if (e.target === this) this.remove();
  });
  document.getElementById('close-audit-modal').addEventListener('click', function() {
    var overlay = document.getElementById('audit-modal-overlay');
    if (overlay) overlay.remove();
  });
}

async function viewAuditReport(btn) {
  var id   = btn.dataset.id;
  var orig = btn.textContent;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>';
  try {
    var res = await apiFetch('/api/v1/admin/apps/' + id + '/audit-report');
    if (!res) return;
    showAuditModal(res.data);
  } catch(e) {
    toast(e.message || 'Failed to load audit report', 'err');
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
}

// Event delegation for queue buttons — avoids inline onclick which CSP blocks
document.getElementById('queue-list').addEventListener('click', function(e) {
  var btn = e.target.closest('button');
  if (!btn) return;
  if (btn.classList.contains('btn-audit'))   viewAuditReport(btn);
  if (btn.classList.contains('btn-approve')) approveApp(btn);
  if (btn.classList.contains('btn-delete'))  deleteApp(btn);
});

refreshAll();
setInterval(refreshAll, 60000);
`

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------
export async function adminRouter(app: FastifyInstance) {

  // ── HTML: Dashboard or Login ──────────────────────────────────────────────
  app.get('/admin-dashboard', async (request, reply) => {
    if (!isAuthenticated(request)) {
      return reply.type('text/html').send(loginPage())
    }
    return reply.type('text/html').send(dashboardPage())
  })

  // ── JS bundle — served as same-origin file to satisfy CSP script-src 'self'
  app.get('/admin-dashboard/bundle.js', async (_request, reply) => {
    return reply
      .type('application/javascript')
      .header('Cache-Control', 'no-store')
      .send(BUNDLE_JS)
  })

  // ── HTML: Login POST ──────────────────────────────────────────────────────
  app.post('/admin-dashboard/auth', async (request, reply) => {
    const body    = request.body as Record<string, string> | undefined
    const entered = body?.['secret'] ?? ''
    const secret  = getSecret()

    if (!entered || entered !== secret) {
      logger.warn({ ip: request.ip }, '[admin] Failed login attempt')
      return reply.type('text/html').send(loginPage('Incorrect secret key.'))
    }

    reply.setCookie(COOKIE_NAME, makeToken(secret), {
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

  // ─────────────────────────────────────────────────────────────────────────
  // JSON API helpers
  // All API routes return 401 JSON (not a redirect) so that fetch() in the
  // dashboard JS can detect unauthenticated responses cleanly.
  // ─────────────────────────────────────────────────────────────────────────

  function apiAuth(request: FastifyRequest, reply: FastifyReply): boolean {
    if (!isAuthenticated(request)) {
      void reply.status(401).send({ success: false, error: { message: 'Unauthorized' } })
      return false
    }
    return true
  }

  // ── API: Pending apps ─────────────────────────────────────────────────────
  app.get('/api/v1/admin/pending', async (request, reply) => {
    if (!apiAuth(request, reply)) return
    const apps = await getPendingApps()
    return reply.send({ success: true, data: apps })
  })

  // ── API: Approve ──────────────────────────────────────────────────────────
  app.post('/api/v1/admin/apps/:id/approve', async (request, reply) => {
    if (!apiAuth(request, reply)) return
    const { id } = request.params as { id: string }
    const result = await appsService.adminApprove(id)
    logger.info({ appId: id, ip: request.ip }, '[admin] App approved')
    return reply.send({ success: true, data: result })
  })

  // ── API: Reject ───────────────────────────────────────────────────────────
  app.post('/api/v1/admin/apps/:id/reject', async (request, reply) => {
    if (!apiAuth(request, reply)) return
    const { id } = request.params as { id: string }
    const result = await appsService.adminReject(id)
    logger.info({ appId: id, ip: request.ip }, '[admin] App rejected')
    return reply.send({ success: true, data: result })
  })

  // ── API: Delete ───────────────────────────────────────────────────────────
  app.delete('/api/v1/admin/apps/:id', async (request, reply) => {
    if (!apiAuth(request, reply)) return
    const { id } = request.params as { id: string }
    const existing = await appsRepository.findById(id)
    if (!existing) {
      return reply.status(404).send({ success: false, error: { message: 'App not found' } })
    }
    await appsRepository.delete(id)
    logger.warn({ appId: id, ip: request.ip }, '[admin] App hard-deleted')
    return reply.status(204).send()
  })

  // ── API: Security Audit Report ───────────────────────────────────────────
  app.get('/api/v1/admin/apps/:id/audit-report', async (request, reply) => {
    if (!apiAuth(request, reply)) return
    const { id } = request.params as { id: string }
    const report = await db.securityAuditReport.findUnique({ where: { appId: id } })
    if (!report) {
      return reply.status(404).send({
        success: false,
        error: { message: 'No audit report found. This app may have been submitted before the auto-approve pipeline was enabled.' },
      })
    }
    return reply.send({ success: true, data: report })
  })

  // ── API: Security log ─────────────────────────────────────────────────────
  app.get('/api/v1/admin/security-log', async (request, reply) => {
    if (!apiAuth(request, reply)) return
    const rows = await getSecurityLog()
    return reply.send({ success: true, data: rows })
  })

  // ── TEMPORARY: Delete all apps ────────────────────────────────────────────
  app.delete('/api/v1/admin/nuke-apps', async (request, reply) => {
    const token = (request.headers['x-nuke-token'] as string | undefined) ?? ''
    if (token !== 'imagine-nuke-2026') {
      return reply.status(401).send({ success: false, error: { message: 'Forbidden' } })
    }
    const { count } = await db.app.deleteMany({})
    logger.warn({ count, ip: request.ip }, '[admin] All apps nuked')
    return reply.send({ success: true, data: { deleted: count } })
  })
}
