import pino from 'pino'
import { config } from '../config'

// ---------------------------------------------------------------------------
// Structured logger (pino)
//
// Used directly in server bootstrap, workers, and any non-HTTP context.
// Fastify receives this same instance via `loggerInstance` so all output
// is unified under one logger.
// ---------------------------------------------------------------------------

const isDev = config.NODE_ENV !== 'production'

export const logger = pino({
  level: isDev ? 'debug' : 'info',
  ...(isDev
    ? {
        transport: {
          target: 'pino-pretty',
          options: {
            colorize: true,
            translateTime: 'HH:MM:ss',
            ignore: 'pid,hostname',
          },
        },
      }
    : {
        // Production: structured JSON, no transport overhead
        formatters: {
          level: (label: string) => ({ level: label }),
        },
        timestamp: pino.stdTimeFunctions.isoTime,
      }),
})
