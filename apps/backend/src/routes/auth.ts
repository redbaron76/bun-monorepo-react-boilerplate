import { Elysia } from 'elysia';
import { jwt } from '@elysiajs/jwt';
import { prisma } from '../db/prisma';
import { registerSchema, loginSchema, refreshTokenSchema, JWT_EXPIRY } from '@mono/shared';

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-change-in-production-2024';

/**
 * Plugin JWT condiviso — istanziato una volta, riutilizzato in auth e protected.
 * Usato da: authRoutes, protectedRoutes
 * Dove: apps/backend/src/routes/auth.ts
 * Esempio: export const authJwtPlugin = jwt(...)
 */
export const authJwtPlugin = jwt({
  name: 'jwt',
  secret: JWT_SECRET,
  exp: JWT_EXPIRY,
});

/**
 * Hash della password dell'utente con PBKDF2.
 * Usato da: authRoutes.register
 * Dove: apps/backend/src/routes/auth.ts
 * Esempio: const hash = await hashPassword('user-password');
 */
async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  const hashHex = Array.from(new Uint8Array(derivedBits))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  const saltB64 = btoa(
    Array.from(salt)
      .map((b) => String.fromCharCode(b))
      .join('')
  );
  return `${saltB64}:${hashHex}`;
}

/**
 * Verifica una password contro un hash stored PBKDF2.
 * Usato da: authRoutes.login
 * Dove: apps/backend/src/routes/auth.ts
 * Esempio: const valid = await verifyPassword('input', storedHash);
 */
async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const idx = stored.indexOf(':');
  if (idx === -1) return false;
  const salt = Uint8Array.from(atob(stored.slice(0, idx)), (c) => c.charCodeAt(0));
  const expectedHashHex = stored.slice(idx + 1);

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  const hashHex = Array.from(new Uint8Array(derivedBits))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return hashHex === expectedHashHex;
}

/**
 * Rotte di autenticazione — /api/auth/*
 * Montano il plugin JWT condiviso per sign/verify.
 * Validazione: Zod schema diretto dal package @mono/shared (Standard Schema Elysia).
 */
export const authRoutes = new Elysia({ prefix: '/api/auth' })
  .use(authJwtPlugin)

  .post('/register', async ({ set, body }) => {
    const { email, password } = body;

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      set.status = 409;
      return { success: false, message: 'Email già registrata' };
    }

    const passwordHash = await hashPassword(password);

    await prisma.user.create({
      data: {
        email,
        password: passwordHash,
        refreshToken: crypto.getRandomValues(new Uint8Array(32)).toString('hex'),
      },
    });

    return { success: true, message: 'Registrazione completata' };
  }, {
    body: registerSchema,
  })

  .post('/login', async ({ set, body, jwt }) => {
    const { email, password } = body;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      set.status = 401;
      return { success: false, message: 'Credenziali non valide' };
    }

    const valid = await verifyPassword(password, user.password);
    if (!valid) {
      set.status = 401;
      return { success: false, message: 'Credenziali non valide' };
    }

    const accessToken = await jwt.sign({
      sub: user.id,
      email: user.email,
      type: 'access',
    });

    const refreshToken = await jwt.sign({
      sub: user.id,
      email: user.email,
      type: 'refresh',
    });

    await prisma.user.update({
      where: { id: user.id },
      data: { refreshToken },
    });

    return {
      success: true,
      data: {
        accessToken,
        refreshToken,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
        },
      },
    };
  }, {
    body: loginSchema,
  })

  .post('/refresh', async ({ set, body, jwt: jwtSign }) => {
    const { refreshToken: rt } = body;
    if (!rt) {
      set.status = 400;
      return { success: false, message: 'Refresh token richiesto' };
    }

    const decoded = await jwtSign.verify(rt);
    if (!decoded || decoded.type !== 'refresh') {
      set.status = 401;
      return { success: false, message: 'Refresh token non valido' };
    }

    const dbUser = await prisma.user.findUnique({ where: { id: decoded.sub } });
    if (!dbUser || dbUser.refreshToken !== rt) {
      set.status = 401;
      return { success: false, message: 'Refresh token non valido' };
    }

    const accessToken = await jwtSign.sign({
      sub: dbUser.id,
      email: dbUser.email,
      type: 'access',
    });

    const newRefreshToken = await jwtSign.sign({
      sub: dbUser.id,
      email: dbUser.email,
      type: 'refresh',
    });

    await prisma.user.update({
      where: { id: dbUser.id },
      data: { refreshToken: newRefreshToken },
    });

    return {
      success: true,
      data: {
        accessToken,
        refreshToken: newRefreshToken,
      },
    };
  }, {
    body: refreshTokenSchema,
  });
