import fp from 'fastify-plugin'
import { FastifyInstance } from 'fastify'
import { ZodError } from 'zod'
import { AppError } from '../core/errors'
import { config } from '../core/config'

// ---------------------------------------------------------------------------
// Global error handler
//
// Translates AppError, ZodError, and unexpected errors into a consistent
// JSON response shape: { success: false, error: { code, message, details? } }
//
// Wrapped in fastify-plugin so the handler is registered on the root scope
// and applies to all routes regardless of where they are registered.
// ---------------------------------------------------------------------------

export const errorHandlerPlugin = fp(async (app: FastifyInstance) => {
  app.setErrorHandler((error, request, reply) => {
    // Zod validation errors (thrown manually in controllers/services)
    if (error instanceof ZodError) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: error.flatten().fieldErrors,
        },
      })
    }

    // Domain errors from services and repositories
    if (error instanceof AppError) {
      return reply.status(error.statusCode).send({
        success: false,
        error: {
          code: error.code,
          message: error.message,
          ...(error.details !== undefined ? { details: error.details } : {}),
        },
      })
    }

    // Fastify built-in schema validation errors
    if ('validation' in error && error.validation) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Request validation failed',
          details: error.validation,
        },
      })
    }

    // Unhandled / unexpected errors
    request.log.error({ err: error }, 'Unhandled server error')

    return reply.status(500).send({
      success: false,
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        message:
          config.NODE_ENV === 'production'
            ? 'An unexpected error occurred'
            : (error.message ?? 'Internal server error'),
      },
    })
  })
})
