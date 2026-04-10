import type { FastifyRequest } from 'fastify'
import { logger } from '../core/logger'
import { auditService } from '../modules/audit/audit.service'

// ---------------------------------------------------------------------------
// Security Audit Logger
//
// Centralises all security-relevant event logging. Writes to two sinks:
//   1. Structured JSON log (pino) — goes to Railway log drain / SIEM
//   2. Audit table (Prisma)       — queryable by admins via /api/v1/audit
//
// Event taxonomy:
//   security.auth.*        — login, logout, token refresh, failures
//   security.ratelimit.*   — rate limit hits
//   security.upload.*      — file validation outcomes
//   security.threat.*      — Web Risk findings
//   security.access.*      — forbidden / unauthorised access attempts
//   security.admin.*       — privileged admin actions
// ---------------------------------------------------------------------------

export interface SecurityEventContext {
  userId?:    string
  ip?:        string
  userAgent?: string
  path?:      string
  method?:    string
}

function extractContext(request: FastifyRequest): SecurityEventContext {
  return {
    userId:    (request as { user?: { sub?: string } }).user?.sub,
    ip:        request.ip,
    userAgent: request.headers['user-agent'],
    path:      request.url,
    method:    request.method,
  }
}

// ---------------------------------------------------------------------------
// Core logging function
// ---------------------------------------------------------------------------
async function logSecurityEvent(
  action:     string,
  entityType: string,
  entityId:   string,
  metadata:   Record<string, unknown>,
  ctx?:       SecurityEventContext,
): Promise<void> {
  const fullMeta = { ...ctx, ...metadata }

  // Always write to structured log immediately (synchronous path)
  logger.warn({ action, entityType, entityId, ...fullMeta }, `[security] ${action}`)

  // Best-effort write to audit DB (non-blocking)
  void auditService.log({
    action,
    entityType,
    entityId,
    performedById: ctx?.userId,
    metadata:      fullMeta,
  })
}

// ---------------------------------------------------------------------------
// Auth events
// ---------------------------------------------------------------------------

export const securityLogger = {
  // Successful login
  async loginSuccess(request: FastifyRequest, userId: string) {
    await logSecurityEvent(
      'security.auth.login_success',
      'User', userId,
      { outcome: 'success' },
      extractContext(request),
    )
  },

  // Failed login attempt (wrong credentials / unknown email)
  async loginFailure(request: FastifyRequest, email: string) {
    await logSecurityEvent(
      'security.auth.login_failure',
      'User', 'unknown',
      { email, outcome: 'failure' },
      extractContext(request),
    )
  },

  // Token refresh (rotation)
  async tokenRefreshed(request: FastifyRequest, userId: string) {
    await logSecurityEvent(
      'security.auth.token_refreshed',
      'User', userId,
      {},
      extractContext(request),
    )
  },

  // Repeated failed logins from the same IP → potential brute force
  async bruteForceDetected(request: FastifyRequest, attemptCount: number) {
    await logSecurityEvent(
      'security.auth.brute_force_detected',
      'IP', request.ip,
      { attemptCount, severity: 'HIGH' },
      extractContext(request),
    )
  },

  // ---------------------------------------------------------------------------
  // Rate limit events
  // ---------------------------------------------------------------------------

  async rateLimitHit(request: FastifyRequest, limitType: string) {
    await logSecurityEvent(
      'security.ratelimit.exceeded',
      'Request', `${request.method}:${request.url}`,
      { limitType },
      extractContext(request),
    )
  },

  // ---------------------------------------------------------------------------
  // Upload / file events
  // ---------------------------------------------------------------------------

  async uploadRejected(request: FastifyRequest, reason: string, filename: string) {
    await logSecurityEvent(
      'security.upload.rejected',
      'Upload', filename,
      { reason, severity: 'MEDIUM' },
      extractContext(request),
    )
  },

  async uploadAccepted(request: FastifyRequest, filename: string, assetType: string) {
    await logSecurityEvent(
      'security.upload.accepted',
      'Upload', filename,
      { assetType },
      extractContext(request),
    )
  },

  // ---------------------------------------------------------------------------
  // Threat detection events
  // ---------------------------------------------------------------------------

  async threatDetected(
    request:    FastifyRequest,
    appId:      string,
    threats:    Array<{ uri: string; types: string[] }>,
  ) {
    await logSecurityEvent(
      'security.threat.url_blocked',
      'App', appId,
      { threats, severity: 'CRITICAL' },
      extractContext(request),
    )
  },

  // ---------------------------------------------------------------------------
  // Access control events
  // ---------------------------------------------------------------------------

  async unauthorizedAccess(request: FastifyRequest) {
    await logSecurityEvent(
      'security.access.unauthorized',
      'Request', `${request.method}:${request.url}`,
      { severity: 'MEDIUM' },
      extractContext(request),
    )
  },

  async forbiddenAccess(request: FastifyRequest, requiredRole: string) {
    await logSecurityEvent(
      'security.access.forbidden',
      'Request', `${request.method}:${request.url}`,
      { requiredRole, severity: 'MEDIUM' },
      extractContext(request),
    )
  },

  // ---------------------------------------------------------------------------
  // Admin / privileged actions
  // ---------------------------------------------------------------------------

  async adminAction(
    request: FastifyRequest,
    action:  string,
    entityType: string,
    entityId:   string,
    details?:   Record<string, unknown>,
  ) {
    await logSecurityEvent(
      `security.admin.${action}`,
      entityType, entityId,
      { ...details, severity: 'INFO' },
      extractContext(request),
    )
  },

  // ---------------------------------------------------------------------------
  // Suspicious activity (catch-all)
  // ---------------------------------------------------------------------------

  async suspiciousActivity(
    request:     FastifyRequest,
    description: string,
    details?:    Record<string, unknown>,
  ) {
    await logSecurityEvent(
      'security.suspicious_activity',
      'Request', `${request.method}:${request.url}`,
      { description, ...details, severity: 'HIGH' },
      extractContext(request),
    )
  },
}
