import { Elysia } from 'elysia';
import { openapi } from '@elysia/openapi';
import { authRoutes } from './routes/auth';
import { protectedRoutes } from './routes/protected';
import { publicRoutes } from './routes/public';
import { prisma } from './db/prisma';

/**
 * Server API principale.
 * Usa Elysia 1.4+ con Zod Standard Schema per la validazione.
 * Documentazione: mount openapi({ name, version }) con i rotte installati.
 */
export const app = new Elysia()
  .use(publicRoutes)
  .use(authRoutes)
  .use(protectedRoutes)
  .onError(({ code, error }) => {
    if (code === 'NOT_FOUND') {
      return { success: false, message: 'Rotta non trovata' };
    }
      return { success: false, message: (error as Error).message || 'Errore interno del server' };
  })
  .get('/health', () => ({ status: 'ok', timestamp: new Date().toISOString() }))
  .use(
    openapi({
      docsPath: '/docs',
      documentation: {
        info: {
          title: 'Bun Monorepo API',
          version: '1.0.0',
          description: 'API server per il monorepo Bun + Elysia + React',
        },
      },
    })
  )
  .listen(3000);

console.log(`🏍️  Elysia is running at ${app.server?.url}`);
