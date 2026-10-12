import { createHmac, randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const backendDirectory = dirname(fileURLToPath(import.meta.url));
const databasePath = resolve(process.env.DATABASE_PATH || join(backendDirectory, 'data', 'noir.sqlite'));
const dataDirectory = dirname(databasePath);
const port = Number(process.env.PORT || 4000);
const currencies = new Set(['USD', 'EUR', 'GBP', 'NGN']);
const tokenLifetimeMs = 7 * 24 * 60 * 60 * 1000;

mkdirSync(dataDirectory, { recursive: true });

function loadTokenSecret() {
  if (process.env.TOKEN_SECRET) {
    const secret = Buffer.from(process.env.TOKEN_SECRET);
    if (secret.length < 32) throw new Error('TOKEN_SECRET must be at least 32 bytes.');
    return secret;
  }

  const secretPath = join(dataDirectory, 'token.secret');
  try {
    return Buffer.from(readFileSync(secretPath, 'utf8').trim(), 'hex');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const value = randomBytes(32).toString('hex');
  try {
    writeFileSync(secretPath, value, { flag: 'wx' });
    return Buffer.from(value, 'hex');
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    return Buffer.from(readFileSync(secretPath, 'utf8').trim(), 'hex');
  }
}

const tokenSecret = loadTokenSecret();
const database = new DatabaseSync(databasePath);
database.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('fan', 'creator')),
    currency TEXT NOT NULL CHECK (currency IN ('USD', 'EUR', 'GBP', 'NGN')),
    age_confirmed_at TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
`);

const findUserByEmail = database.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE');
const findUserById = database.prepare('SELECT * FROM users WHERE id = ?');
const findDuplicate = database.prepare('SELECT email, username FROM users WHERE email = ? COLLATE NOCASE OR username = ? COLLATE NOCASE');
const updateUserCurrency = database.prepare('UPDATE users SET currency = ? WHERE id = ?');
const insertUser = database.prepare(`
  INSERT INTO users (id, email, username, display_name, password_hash, role, currency, age_confirmed_at, created_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

function httpError(status, message) {
  return Object.assign(new Error(message), { status });
}

function sendJson(response, status, value) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  response.end(JSON.stringify(value));
}

async function readJson(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 32 * 1024) throw httpError(413, 'Request body is too large.');
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw httpError(400, 'Request body must be valid JSON.');
  }
}

function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 64);
  return `${salt.toString('hex')}:${hash.toString('hex')}`;
}

function verifyPassword(password, storedHash) {
  const [saltHex, hashHex, extra] = storedHash.split(':');
  if (!saltHex || !hashHex || extra !== undefined) return false;
  const salt = Buffer.from(saltHex, 'hex');
  const expected = Buffer.from(hashHex, 'hex');
  if (salt.length !== 16 || expected.length !== 64) return false;
  return timingSafeEqual(scryptSync(password, salt, expected.length), expected);
}

function makeToken(userId) {
  const payload = Buffer.from(JSON.stringify({ sub: userId, exp: Date.now() + tokenLifetimeMs })).toString('base64url');
  const signature = createHmac('sha256', tokenSecret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function tokenUserId(request) {
  const authorization = request.headers.authorization || '';
  const [scheme, token] = authorization.split(' ');
  if (scheme !== 'Bearer' || !token) throw httpError(401, 'Please sign in to continue.');

  const [payload, signature, extra] = token.split('.');
  if (!payload || !signature || extra !== undefined) throw httpError(401, 'Your sign-in session is invalid.');
  const expected = createHmac('sha256', tokenSecret).update(payload).digest();
  const actual = Buffer.from(signature, 'base64url');
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    throw httpError(401, 'Your sign-in session is invalid.');
  }

  try {
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (typeof claims.sub !== 'string' || claims.exp <= Date.now()) throw new Error();
    return claims.sub;
  } catch {
    throw httpError(401, 'Your sign-in session has expired. Please sign in again.');
  }
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    username: user.username,
    display_name: user.display_name,
    role: user.role,
    currency: user.currency,
    kyc_status: null,
  };
}

function authResponse(user) {
  return { token: makeToken(user.id), user: publicUser(user) };
}

function allowLocalOrigin(request, response) {
  const origin = request.headers.origin;
  if (origin === 'null' || /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(origin || '')) {
    response.setHeader('Access-Control-Allow-Origin', origin);
    response.setHeader('Vary', 'Origin');
  }
  response.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, OPTIONS');
  response.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

const server = createServer(async (request, response) => {
  allowLocalOrigin(request, response);
  if (request.method === 'OPTIONS') {
    response.writeHead(204);
    return response.end();
  }

  const path = new URL(request.url, 'http://localhost').pathname;
  try {
    if (request.method === 'GET' && path === '/health') {
      return sendJson(response, 200, { ok: true });
    }

    if (request.method === 'GET' && path === '/categories') {
      return sendJson(response, 200, []);
    }

    if (request.method === 'GET' && path === '/videos') {
      return sendJson(response, 200, { videos: [] });
    }

    if (request.method === 'POST' && path === '/auth/register') {
      const body = await readJson(request);
      const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
      const username = typeof body.username === 'string' ? body.username.trim() : '';
      const password = typeof body.password === 'string' ? body.password : '';
      const currency = typeof body.currency === 'string' ? body.currency : 'USD';
      const displayName = typeof body.cname === 'string' && body.cname.trim() ? body.cname.trim() : username;

      if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        throw httpError(400, 'Enter a valid email address.');
      }
      if (!/^[a-zA-Z0-9_.-]{3,24}$/.test(username)) {
        throw httpError(400, 'Username must be 3-24 characters using letters, numbers, dots, underscores, or hyphens.');
      }
      if (password.length < 8 || password.length > 256) {
        throw httpError(400, 'Password must be between 8 and 256 characters.');
      }
      if (body.ageConfirmed !== true) throw httpError(400, 'Confirm that you are 18 or older to create an account.');
      if (!currencies.has(currency)) throw httpError(400, 'Choose a supported currency.');
      if (displayName.length > 40) throw httpError(400, 'Creator name must be 40 characters or fewer.');
      if (findDuplicate.get(email, username)) throw httpError(409, 'That email or username is already registered.');

      const now = new Date().toISOString();
      const userId = randomUUID();
      const role = body.as === 'creator' ? 'creator' : 'fan';
      try {
        insertUser.run(userId, email, username, displayName, hashPassword(password), role, currency, now, now);
      } catch (error) {
        if (String(error.message).includes('UNIQUE constraint failed')) {
          throw httpError(409, 'That email or username is already registered.');
        }
        throw error;
      }
      return sendJson(response, 201, authResponse(findUserById.get(userId)));
    }

    if (request.method === 'POST' && path === '/auth/login') {
      const body = await readJson(request);
      const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
      const password = typeof body.password === 'string' ? body.password : '';
      const user = findUserByEmail.get(email);
      if (!user || !verifyPassword(password, user.password_hash)) {
        throw httpError(401, 'Email or password is incorrect.');
      }
      return sendJson(response, 200, authResponse(user));
    }

    if (request.method === 'GET' && path === '/auth/me') {
      const user = findUserById.get(tokenUserId(request));
      if (!user) throw httpError(401, 'Your account no longer exists.');
      return sendJson(response, 200, publicUser(user));
    }

    if (request.method === 'PATCH' && path === '/auth/me') {
      const userId = tokenUserId(request);
      const body = await readJson(request);
      if (typeof body.currency !== 'string' || !currencies.has(body.currency)) {
        throw httpError(400, 'Choose a supported currency.');
      }
      updateUserCurrency.run(body.currency, userId);
      const user = findUserById.get(userId);
      if (!user) throw httpError(401, 'Your account no longer exists.');
      return sendJson(response, 200, publicUser(user));
    }

    return sendJson(response, 404, { error: 'Route not found.' });
  } catch (error) {
    if (response.headersSent) return response.destroy();
    return sendJson(response, error.status || 500, { error: error.status ? error.message : 'Server error.' });
  }
});

server.listen(port, '127.0.0.1', () => {
  console.log(`Noir API listening at http://127.0.0.1:${server.address().port}`);
});