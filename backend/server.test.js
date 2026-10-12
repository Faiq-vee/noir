import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, before, test } from 'node:test';

const serverPath = fileURLToPath(new URL('./server.js', import.meta.url));
let child;
let baseUrl;
let temporaryDirectory;

before(async () => {
  temporaryDirectory = mkdtempSync(join(tmpdir(), 'noir-auth-'));
  child = spawn(process.execPath, [serverPath], {
    env: {
      ...process.env,
      DATABASE_PATH: join(temporaryDirectory, 'test.sqlite'),
      PORT: '0',
      TOKEN_SECRET: 'test-only-secret-with-at-least-32-bytes',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  baseUrl = await new Promise((resolve, reject) => {
    let output = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', chunk => {
      output += chunk;
      const match = output.match(/Noir API listening at http:\/\/127\.0\.0\.1:(\d+)/);
      if (match) resolve(`http://127.0.0.1:${match[1]}`);
    });
    child.once('error', reject);
    child.once('exit', code => reject(new Error(`Backend exited before listening (${code}).`)));
  });
});

after(async () => {
  if (child && child.exitCode === null) {
    const exited = once(child, 'exit');
    child.kill();
    await exited;
  }
  if (temporaryDirectory) rmSync(temporaryDirectory, { recursive: true, force: true });
});

test('signup stores an account that can sign in and access its profile', async () => {
  const signup = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'Noir.User@example.com',
      username: 'noir_user',
      password: 'CorrectHorse9!',
      currency: 'NGN',
      ageConfirmed: true,
    }),
  });
  assert.equal(signup.status, 201);
  const created = await signup.json();
  assert.equal(created.user.email, 'noir.user@example.com');
  assert.equal(created.user.username, 'noir_user');
  assert.equal(created.user.role, 'fan');
  assert.equal(created.user.currency, 'NGN');
  assert.equal('password_hash' in created.user, false);

  const duplicate = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'noir.user@example.com',
      username: 'another_user',
      password: 'CorrectHorse9!',
      currency: 'USD',
      ageConfirmed: true,
    }),
  });
  assert.equal(duplicate.status, 409);

  const login = await fetch(`${baseUrl}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'NOIR.USER@example.com', password: 'CorrectHorse9!' }),
  });
  assert.equal(login.status, 200);
  const session = await login.json();

  const profile = await fetch(`${baseUrl}/auth/me`, {
    headers: { Authorization: `Bearer ${session.token}` },
  });
  assert.equal(profile.status, 200);
  assert.equal((await profile.json()).currency, 'NGN');

  const currencyUpdate = await fetch(`${baseUrl}/auth/me`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${session.token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ currency: 'EUR' }),
  });
  assert.equal(currencyUpdate.status, 200);
  assert.equal((await currencyUpdate.json()).currency, 'EUR');

  const relogin = await fetch(`${baseUrl}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'noir.user@example.com', password: 'CorrectHorse9!' }),
  });
  assert.equal((await relogin.json()).user.currency, 'EUR');

  const badLogin = await fetch(`${baseUrl}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'noir.user@example.com', password: 'wrong-password' }),
  });
  assert.equal(badLogin.status, 401);
});

test('signup requires age confirmation', async () => {
  const response = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'underage-check@example.com',
      username: 'agecheck',
      password: 'CorrectHorse9!',
      currency: 'USD',
      ageConfirmed: false,
    }),
  });
  assert.equal(response.status, 400);
});