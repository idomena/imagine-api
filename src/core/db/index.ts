import { PrismaClient, Prisma } from '@prisma/client'

declare global {
  // eslint-disable-next-line no-var
  var __prisma: PrismaClient | undefined
}

function makePrisma(): PrismaClient {
  const base = new PrismaClient({
    log:
      process.env['NODE_ENV'] === 'development'
        ? [{ emit: 'event', level: 'query' }, 'warn', 'error']
        : ['error'],
  })

  // Railway's PostgreSQL proxy drops idle TCP connections after a few minutes.
  // When Prisma tries to reuse a dead connection it throws P1017 "Server has
  // closed the connection". We intercept every query, and on P1017 we
  // disconnect/reconnect once before retrying — transparent to all callers.
  return base.$extends({
    query: {
      $allModels: {
        async $allOperations({ args, query }) {
          try {
            return await query(args)
          } catch (err) {
            if (
              err instanceof Prisma.PrismaClientKnownRequestError &&
              err.code === 'P1017'
            ) {
              await base.$disconnect().catch(() => {})
              await base.$connect()
              return await query(args)
            }
            throw err
          }
        },
      },
    },
  }) as unknown as PrismaClient
}

export const db: PrismaClient =
  globalThis.__prisma ?? makePrisma()

if (process.env['NODE_ENV'] !== 'production') {
  globalThis.__prisma = db
}
