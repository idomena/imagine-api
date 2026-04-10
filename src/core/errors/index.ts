// ---------------------------------------------------------------------------
// Domain error types
//
// All errors thrown inside services / repositories must be one of these.
// The error handler plugin translates them into the correct HTTP response.
// ---------------------------------------------------------------------------

export class AppError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly statusCode: number,
    public readonly details?: unknown,
  ) {
    super(message)
    this.name = 'AppError'
    // Restore prototype chain (required when extending built-in Error in TS)
    Object.setPrototypeOf(this, new.target.prototype)
  }
}

export class NotFoundError extends AppError {
  constructor(resource: string, id?: string) {
    super(
      'NOT_FOUND',
      id ? `${resource} '${id}' not found` : `${resource} not found`,
      404,
    )
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = 'Unauthorized') {
    super('UNAUTHORIZED', message, 401)
  }
}

export class ForbiddenError extends AppError {
  constructor(message = 'Insufficient permissions') {
    super('FORBIDDEN', message, 403)
  }
}

export class ConflictError extends AppError {
  constructor(message: string) {
    super('CONFLICT', message, 409)
  }
}

export class ValidationError extends AppError {
  constructor(details: unknown) {
    super('VALIDATION_ERROR', 'Validation failed', 400, details)
  }
}

export class BadRequestError extends AppError {
  constructor(message: string) {
    super('BAD_REQUEST', message, 400)
  }
}

export class UnprocessableError extends AppError {
  constructor(message: string, details?: unknown) {
    super('UNPROCESSABLE', message, 422, details)
  }
}
