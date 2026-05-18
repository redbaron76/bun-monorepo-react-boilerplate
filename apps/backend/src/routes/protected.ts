import { Elysia } from 'elysia';
import { prisma } from '../db/prisma';
import { authJwtPlugin } from './auth';

/**
 * Rotte protette — /api/protected/*
 * Usa il JWT plugin condiviso da auth.ts per verificare i token.
 * L'estrazione del Bearer token avviene nell'handler.
 */
export const protectedRoutes = new Elysia({ prefix: '/api/protected' })
  .use(authJwtPlugin)
  .get(
    '/dashboard',
    async ({ request, jwt: jwtHelper }) => {
      const authHeader = request.headers.get('authorization');
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return { success: false, error: 'Token di autenticazione richiesto' };
      }

      const token = authHeader.slice(7);
      const user = await jwtHelper.verify(token);
      if (!user) {
        return { success: false, error: 'Token non valido o scaduto' };
      }

      const dbUser = await prisma.user.findUnique({
        where: { id: user.sub },
        select: { id: true, email: true, name: true, createdAt: true },
      });

      if (!dbUser) {
        return { success: false, error: 'Utente non trovato' };
      }

      return {
        success: true,
        message: 'Benvenuto nella tua area riservata!',
        user: {
          id: dbUser.id,
          email: dbUser.email,
          name: dbUser.name,
        },
      };
    }
  );
