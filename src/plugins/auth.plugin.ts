import fp from 'fastify-plugin'
import fastifyJwt from '@fastify/jwt'
import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import { config } from '../core/config'
import { ForbiddenError, UnauthorizedError } from '../core/errors'
import { UserRole } from '@prisma/client'

// ---------------------------------------------------------------------------
// JWT payload shape — stored in the access token and available via
// request.user after authenticate() runs.
// ---------------------------------------------------------------------------

export interface JwtPayload {
  /** User's database UUID */
  sub: string
  email: string
  role: UserRole
}

// ---------------------------------------------------------------------------
// Fastify type augmentation
//
// Declares the shape of request.user and the helper decorators so TypeScript
// knows about them without casting throughout the codebase.
// ---------------------------------------------------------------------------

declare module '@fastify/jwt' {
  interface FastifyJWT {
    payload: JwtPayload
    user: JwtPayload
  }
}

declare module 'fastify' {
  interface FastifyInstance {
    /** Validates the Bearer token. Throws UnauthorizedError if invalid. */
    authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>
    /** Returns a preHandler that enforces one of the given roles. */
    requireRole: (roles: UserRole[]) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>
  }
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export const authPlugin = fp(async (app: FastifyInstance) => {
  // Register @fastify/jwt — makes app.jwt and request.jwtVerify() available
  await app.register(fastifyJwt, {
    secret: config.JWT_SECRET,
    sign: {
      expiresIn: config.JWT_ACCESS_EXPIRY,
    },
  })

  // Decorator: verify access token and populate request.user
  app.decorate(
    'authenticate',
    async (request: FastifyRequest, _reply: FastifyReply): Promise<void> => {
      try {
        await request.jwtVerify()
      } catch {
        throw new UnauthorizedError('Invalid or expired token')
      }
    },
  )

  // Decorator: verify token AND assert the user has one of the required roles
  app.decorate(
    'requireRole',
    (roles: UserRole[]) =>
      async (request: FastifyRequest, _reply: FastifyReply): Promise<void> => {
        try {
          await request.jwtVerify()
        } catch {
          throw new UnauthorizedError('Invalid or expired token')
        }
        if (!roles.includes(request.user.role)) {
          throw new ForbiddenError()
        }
      },
  )
})
