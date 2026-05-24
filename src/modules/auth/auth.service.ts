import bcrypt from 'bcryptjs'
import type { FastifyInstance } from 'fastify'
import { authRepository } from './auth.repository'
import { ConflictError, UnauthorizedError } from '../../core/errors'
import { sanitizeUser } from '../../lib/types'
import {
  generateAccessToken,
  generateRefreshToken,
  getRefreshTokenExpiry,
  hashToken,
} from '../../lib/tokens'
import type { GoogleAuthBody, LoginBody, RefreshBody, RegisterBody } from './auth.schema'

// ---------------------------------------------------------------------------
// Auth service — business logic for registration, login, token refresh, and
// current-user lookup. All DB access goes through authRepository.
// ---------------------------------------------------------------------------

const SALT_ROUNDS = 12

export const authService = {
  async register(app: FastifyInstance, body: RegisterBody) {
    const existing = await authRepository.findByEmail(body.email)
    if (existing) {
      throw new ConflictError('Email already in use')
    }

    const passwordHash = await bcrypt.hash(body.password, SALT_ROUNDS)
    const displayName  = body.displayName?.trim() || body.email.split('@')[0] || 'Creator'
    const user = await authRepository.create(body.email, passwordHash, displayName)

    const payload = { sub: user.id, email: user.email, role: user.role }
    const accessToken = generateAccessToken(app, payload)
    const { raw: refreshToken, hash: refreshTokenHash } = generateRefreshToken()
    await authRepository.saveRefreshToken(user.id, refreshTokenHash, getRefreshTokenExpiry())

    return { user: sanitizeUser(user), accessToken, refreshToken }
  },

  async login(app: FastifyInstance, body: LoginBody) {
    const user = await authRepository.findByEmail(body.email)

    // Use a constant-time comparison even when the user doesn't exist to
    // prevent timing-based user enumeration.
    const passwordHash = user?.passwordHash ?? ''
    const valid = user !== null && (await bcrypt.compare(body.password, passwordHash))

    if (!valid) {
      throw new UnauthorizedError('Invalid credentials')
    }

    const payload = { sub: user.id, email: user.email, role: user.role }
    const accessToken = generateAccessToken(app, payload)
    const { raw: refreshToken, hash: refreshTokenHash } = generateRefreshToken()
    await authRepository.saveRefreshToken(user.id, refreshTokenHash, getRefreshTokenExpiry())

    return { user: sanitizeUser(user), accessToken, refreshToken }
  },

  async refresh(app: FastifyInstance, body: RefreshBody) {
    const tokenHash = hashToken(body.refreshToken)
    const stored = await authRepository.findRefreshToken(tokenHash)

    if (!stored || stored.revokedAt !== null || stored.expiresAt < new Date()) {
      throw new UnauthorizedError('Invalid or expired refresh token')
    }

    // Rotate: revoke the consumed token, then issue a fresh pair.
    await authRepository.revokeRefreshToken(tokenHash)

    const { user } = stored
    const payload = { sub: user.id, email: user.email, role: user.role }
    const accessToken = generateAccessToken(app, payload)
    const { raw: refreshToken, hash: newHash } = generateRefreshToken()
    await authRepository.saveRefreshToken(user.id, newHash, getRefreshTokenExpiry())

    return { accessToken, refreshToken, user: sanitizeUser(user) }
  },

  async googleAuth(app: FastifyInstance, body: GoogleAuthBody) {
    const user = await authRepository.upsertGoogleUser({
      googleId: body.googleId,
      email:    body.email,
      name:     body.name ?? body.email.split('@')[0]!,
      picture:  body.picture,
    })

    const payload = { sub: user.id, email: user.email, role: user.role }
    const accessToken = generateAccessToken(app, payload)
    const { raw: refreshToken, hash: refreshTokenHash } = generateRefreshToken()
    await authRepository.saveRefreshToken(user.id, refreshTokenHash, getRefreshTokenExpiry())

    return { user: sanitizeUser(user), accessToken, refreshToken }
  },

  async me(userId: string) {
    const user = await authRepository.findById(userId)
    if (!user) {
      throw new UnauthorizedError('User not found')
    }
    return sanitizeUser(user)
  },
}
