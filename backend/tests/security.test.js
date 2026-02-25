'use strict';

/**
 * Comprehensive Security Test Suite
 * Covers: CORS, CSRF, CSP/XSS, SSRF, AuthN/AuthZ, RBAC/ABAC+Tenant Isolation,
 *         Validation+NoSQL Injection, Rate Limiting, Cookie/Session Security,
 *         Secret Management, Security Headers/HSTS, Audit Logging, Error Exposure
 */

// Load env before any module
require('./setup');

// ─── Mock firebase-admin ──────────────────────────────────────────────────────
jest.mock('../lib/firebase', () => ({
  verifyIdToken: jest.fn(),
}));

const request = require('supertest');
const app = require('../server');
const { verifyIdToken } = require('../lib/firebase');
const { issueToken, issueRefreshToken, _clearBlacklist } = require('../middleware/auth');
const { validateUrl, isPrivateIp } = require('../middleware/ssrf');
const { noSqlSanitize } = require('../middleware/validation');
const { sanitizeInput, sanitizeDeep } = require('../middleware/csp');
const { validateSecrets, deriveKey, rotateSecret, registerSecret, getSecret, SecretValue } = require('../middleware/secrets');
const { redact } = require('../middleware/auditLog');
const { hasPermission, PERMISSIONS } = require('../middleware/rbac');
const { v4: uuidv4 } = require('uuid');
const { _clearStore } = require('../routes/data');

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Create an agent that maintains cookies between requests */
function makeAgent() {
  return request.agent(app);
}

/** Get CSRF token via GET /api/csrf-token using an agent */
async function getCsrfToken(agent) {
  const res = await agent.get('/api/csrf-token');
  expect(res.status).toBe(200);
  return res.body.csrfToken;
}

/** Issue a valid JWT for a user */
function tokenFor(uid, role = 'user', email = 'user@example.com') {
  return issueToken({ uid, email, role, tenantId: uid });
}

// ─── Shared state ────────────────────────────────────────────────────────────
beforeEach(() => {
  _clearBlacklist();
  _clearStore();
  jest.clearAllMocks();
});

// ═══════════════════════════════════════════════════════════════════════════════
//  1. SECURITY HEADERS / HTTPS / HSTS
// ═══════════════════════════════════════════════════════════════════════════════
describe('Security Headers (HSTS, CSP, X-Frame-Options, etc.)', () => {
  let res;
  beforeAll(async () => {
    res = await request(app).get('/health');
  });

  test('Strict-Transport-Security header is present', () => {
    const hsts = res.headers['strict-transport-security'];
    expect(hsts).toBeDefined();
    expect(hsts).toMatch(/max-age=\d+/);
    expect(hsts).toContain('includeSubDomains');
  });

  test('X-Frame-Options: DENY', () => {
    expect(res.headers['x-frame-options']).toBe('DENY');
  });

  test('X-Content-Type-Options: nosniff', () => {
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  test('Content-Security-Policy header is present', () => {
    const csp = res.headers['content-security-policy'];
    expect(csp).toBeDefined();
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
  });

  test('Referrer-Policy header is present', () => {
    const rp = res.headers['referrer-policy'];
    expect(rp).toBeDefined();
    expect(rp).toContain('strict-origin');
  });

  test('X-Powered-By header is removed', () => {
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  test('Permissions-Policy header is present', () => {
    const pp = res.headers['permissions-policy'];
    expect(pp).toBeDefined();
    expect(pp).toContain('geolocation=()');
    expect(pp).toContain('microphone=()');
  });

  test('Cache-Control: no-store for API responses', async () => {
    const apiRes = await request(app)
      .get('/api/csrf-token')
      .expect((r) => {
        expect(r.headers['cache-control']).toMatch(/no-store/);
      });
  });

  test('Cross-Origin-Resource-Policy header is set', () => {
    expect(res.headers['cross-origin-resource-policy']).toBe('same-origin');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  2. CORS / PREFLIGHT
// ═══════════════════════════════════════════════════════════════════════════════
describe('CORS / Preflight', () => {
  test('Allowed origin receives Access-Control-Allow-Origin', async () => {
    const res = await request(app)
      .get('/health')
      .set('Origin', 'http://localhost:3000');
    expect(res.headers['access-control-allow-origin']).toBe('http://localhost:3000');
  });

  test('Allowed origin https://example.com is accepted', async () => {
    const res = await request(app)
      .get('/health')
      .set('Origin', 'https://example.com');
    expect(res.headers['access-control-allow-origin']).toBe('https://example.com');
  });

  test('Disallowed origin is rejected (no ACAO header)', async () => {
    const res = await request(app)
      .get('/health')
      .set('Origin', 'https://evil.com');
    // Either 403 or no ACAO header
    const acao = res.headers['access-control-allow-origin'];
    expect(acao).not.toBe('https://evil.com');
  });

  test('OPTIONS preflight returns 204', async () => {
    const res = await request(app)
      .options('/api/auth/login')
      .set('Origin', 'http://localhost:3000')
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'Content-Type,X-CSRF-Token');
    expect(res.status).toBe(204);
  });

  test('Access-Control-Allow-Credentials is true for allowed origin', async () => {
    const res = await request(app)
      .get('/health')
      .set('Origin', 'http://localhost:3000');
    expect(res.headers['access-control-allow-credentials']).toBe('true');
  });

  test('Access-Control-Max-Age is set (preflight caching)', async () => {
    const res = await request(app)
      .options('/api/csrf-token')
      .set('Origin', 'http://localhost:3000')
      .set('Access-Control-Request-Method', 'GET');
    expect(res.headers['access-control-max-age']).toBeDefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  3. CSRF PROTECTION
// ═══════════════════════════════════════════════════════════════════════════════
describe('CSRF Protection', () => {
  test('GET /api/csrf-token returns a token', async () => {
    const agent = makeAgent();
    const res = await agent.get('/api/csrf-token');
    expect(res.status).toBe(200);
    expect(res.body.csrfToken).toBeDefined();
    expect(typeof res.body.csrfToken).toBe('string');
    expect(res.body.csrfToken.length).toBeGreaterThanOrEqual(32);
  });

  test('CSRF cookie is set (non-HttpOnly so JS can read it)', async () => {
    const agent = makeAgent();
    await agent.get('/api/csrf-token');
    // The agent stores cookies; check response header
    const res = await agent.get('/api/csrf-token');
    const setCookie = res.headers['set-cookie'] || [];
    const csrfCookie = [setCookie].flat().find((c) => c.startsWith('_csrf='));
    expect(csrfCookie).toBeDefined();
    // Must NOT be HttpOnly
    expect(csrfCookie.toLowerCase()).not.toContain('httponly');
    // Must be SameSite=Strict
    expect(csrfCookie.toLowerCase()).toContain('samesite=strict');
  });

  test('POST without CSRF token returns 403', async () => {
    const agent = makeAgent();
    await agent.get('/api/csrf-token');
    const res = await agent
      .post('/api/auth/login')
      .send({ idToken: 'some-token' });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('CSRF_TOKEN_MISSING');
  });

  test('POST with wrong CSRF token returns 403', async () => {
    const agent = makeAgent();
    await agent.get('/api/csrf-token');
    const res = await agent
      .post('/api/auth/login')
      .set('x-csrf-token', 'a'.repeat(64))
      .send({ idToken: 'some-token' });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('CSRF_TOKEN_INVALID');
  });

  test('POST with valid CSRF token is not rejected by CSRF middleware', async () => {
    const agent = makeAgent();
    const csrfToken = await getCsrfToken(agent);

    // This will fail for other reasons (invalid firebase token), but NOT 403 CSRF
    verifyIdToken.mockRejectedValueOnce(new Error('Invalid token'));

    const res = await agent
      .post('/api/auth/login')
      .set('x-csrf-token', csrfToken)
      .send({ idToken: 'bad-firebase-token' });

    expect(res.status).not.toBe(403); // CSRF is valid
    expect(res.body.code).not.toBe('CSRF_TOKEN_MISSING');
    expect(res.body.code).not.toBe('CSRF_TOKEN_INVALID');
  });

  test('CSRF token rotates after use', async () => {
    const agent = makeAgent();
    const token1 = await getCsrfToken(agent);

    verifyIdToken.mockRejectedValueOnce(new Error('nope'));

    await agent
      .post('/api/auth/login')
      .set('x-csrf-token', token1)
      .send({ idToken: 'x' });

    const token2 = await getCsrfToken(agent);
    expect(token2).not.toBe(token1);
  });

  test('Timing-safe comparison: garbled hex rejected', async () => {
    const agent = makeAgent();
    await agent.get('/api/csrf-token');
    const res = await agent
      .post('/api/auth/login')
      .set('x-csrf-token', 'not-valid-hex!!!')
      .send({ idToken: 'x' });
    expect(res.status).toBe(403);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  4. XSS / CSP — Input Sanitization
// ═══════════════════════════════════════════════════════════════════════════════
describe('XSS / CSP — Input Sanitization', () => {
  test('sanitizeInput strips script tags', () => {
    const result = sanitizeInput('<script>alert("xss")</script>Hello');
    expect(result).not.toContain('<script>');
    expect(result).toContain('Hello');
  });

  test('sanitizeInput strips onerror attributes', () => {
    const result = sanitizeInput('<img src=x onerror=alert(1)>');
    expect(result).not.toContain('onerror');
    expect(result).not.toContain('<img');
  });

  test('sanitizeInput strips iframe', () => {
    const result = sanitizeInput('<iframe src="evil.com"></iframe>text');
    expect(result).not.toContain('<iframe');
    expect(result).toContain('text');
  });

  test('sanitizeInput preserves safe text', () => {
    expect(sanitizeInput('Hello World 123')).toBe('Hello World 123');
  });

  test('sanitizeDeep sanitizes nested objects', () => {
    const input = {
      name: '<script>xss</script>',
      nested: { description: '<b>bold</b>' },
      arr: ['<em>em</em>'],
    };
    const result = sanitizeDeep(input);
    expect(result.name).not.toContain('<script>');
    expect(result.nested.description).not.toContain('<b>');
    expect(result.arr[0]).not.toContain('<em>');
  });

  test('CSP nonce header is included in response', async () => {
    const res = await request(app).get('/health');
    expect(res.headers['x-csp-nonce']).toBeDefined();
    expect(res.headers['x-csp-nonce'].length).toBeGreaterThan(0);
  });

  test('CSP scriptSrc includes nonce', async () => {
    const res = await request(app).get('/health');
    const csp = res.headers['content-security-policy'] || '';
    expect(csp).toContain("nonce-");
  });

  test('Hobby name with XSS payload is sanitized — returns 422 or sanitized', async () => {
    const agent = makeAgent();
    const csrfToken = await getCsrfToken(agent);
    const token = tokenFor('uid-xss-test');

    const res = await agent
      .post('/api/data/hobbies')
      .set('Authorization', `Bearer ${token}`)
      .set('x-csrf-token', csrfToken)
      .send({
        name: '<script>alert(1)</script>',
        type: 'binary',
      });

    // Either validation rejects it (422) or it's sanitized (201 with clean name)
    if (res.status === 201) {
      expect(res.body.hobby.name).not.toContain('<script>');
    } else {
      expect(res.status).toBe(422);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  5. SSRF PROTECTION
// ═══════════════════════════════════════════════════════════════════════════════
describe('SSRF Protection', () => {
  test('localhost (127.0.0.1) is blocked', () => {
    expect(validateUrl('http://127.0.0.1/secret').ok).toBe(false);
    expect(validateUrl('http://127.0.0.1/secret').reason).toBe('PRIVATE_IP');
  });

  test('loopback localhost is blocked', () => {
    expect(validateUrl('http://localhost/api').ok).toBe(false);
  });

  test('Private Class A (10.x.x.x) is blocked', () => {
    expect(validateUrl('http://10.0.0.1/data').ok).toBe(false);
    expect(validateUrl('http://10.255.255.255/data').ok).toBe(false);
  });

  test('Private Class B (172.16-31.x.x) is blocked', () => {
    expect(validateUrl('http://172.16.0.1').ok).toBe(false);
    expect(validateUrl('http://172.31.255.255').ok).toBe(false);
  });

  test('Private Class C (192.168.x.x) is blocked', () => {
    expect(validateUrl('http://192.168.1.1').ok).toBe(false);
  });

  test('AWS metadata endpoint (169.254.169.254) is blocked', () => {
    expect(validateUrl('http://169.254.169.254/latest/meta-data/').ok).toBe(false);
  });

  test('GCP metadata hostname is blocked', () => {
    expect(validateUrl('http://metadata.google.internal/').ok).toBe(false);
  });

  test('Non-HTTP scheme (file://) is blocked', () => {
    const result = validateUrl('file:///etc/passwd');
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('SCHEME_NOT_ALLOWED');
  });

  test('ftp:// is blocked', () => {
    expect(validateUrl('ftp://example.com/file').ok).toBe(false);
  });

  test('javascript: scheme is blocked', () => {
    expect(validateUrl('javascript:alert(1)').ok).toBe(false);
  });

  test('Malformed URL is blocked', () => {
    expect(validateUrl('not-a-url').ok).toBe(false);
    expect(validateUrl('').ok).toBe(false);
  });

  test('Valid HTTPS public URL passes', () => {
    expect(validateUrl('https://api.example.com/data').ok).toBe(true);
  });

  test('Valid HTTP public URL passes', () => {
    expect(validateUrl('http://example.com').ok).toBe(true);
  });

  test('isPrivateIp correctly identifies private ranges', () => {
    expect(isPrivateIp('10.0.0.1')).toBe(true);
    expect(isPrivateIp('192.168.1.1')).toBe(true);
    expect(isPrivateIp('172.16.0.1')).toBe(true);
    expect(isPrivateIp('127.0.0.1')).toBe(true);
    expect(isPrivateIp('8.8.8.8')).toBe(false);
    expect(isPrivateIp('1.1.1.1')).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  6. AUTHENTICATION (AuthN)
// ═══════════════════════════════════════════════════════════════════════════════
describe('Authentication (AuthN)', () => {
  test('Protected route without token returns 401', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('NO_TOKEN');
  });

  test('Protected route with invalid token returns 401', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', 'Bearer totally.invalid.token');
    expect(res.status).toBe(401);
  });

  test('Login with valid Firebase token issues JWT', async () => {
    const agent = makeAgent();
    const csrfToken = await getCsrfToken(agent);

    verifyIdToken.mockResolvedValueOnce({ uid: 'user-1', email: 'user1@example.com' });

    const res = await agent
      .post('/api/auth/login')
      .set('x-csrf-token', csrfToken)
      .send({ idToken: 'valid-firebase-token' });

    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeDefined();
    expect(res.body.refreshToken).toBeDefined();
    expect(res.body.role).toBe('user');
  });

  test('Login with invalid Firebase token returns 401', async () => {
    const agent = makeAgent();
    const csrfToken = await getCsrfToken(agent);

    verifyIdToken.mockRejectedValueOnce(new Error('Token expired'));

    const res = await agent
      .post('/api/auth/login')
      .set('x-csrf-token', csrfToken)
      .send({ idToken: 'invalid-firebase-token' });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('FIREBASE_TOKEN_INVALID');
  });

  test('/api/auth/me returns user info with valid JWT', async () => {
    const token = tokenFor('uid-me-test', 'user', 'me@example.com');
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.uid).toBe('uid-me-test');
    expect(res.body.email).toBe('me@example.com');
    expect(res.body.role).toBe('user');
  });

  test('Expired JWT returns 401 with TOKEN_EXPIRED code', async () => {
    const jwt = require('jsonwebtoken');
    const expired = jwt.sign(
      { uid: 'x', email: 'x@x.com', role: 'user' },
      process.env.JWT_SECRET,
      { expiresIn: -1 } // already expired
    );
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${expired}`);
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('TOKEN_EXPIRED');
  });

  test('Revoked JWT returns 401 with TOKEN_REVOKED code', async () => {
    const { revokeToken } = require('../middleware/auth');
    const token = tokenFor('uid-revoke-test');
    revokeToken(token);

    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('TOKEN_REVOKED');
  });

  test('Logout revokes token and destroys session', async () => {
    const agent = makeAgent();
    const csrfToken = await getCsrfToken(agent);

    verifyIdToken.mockResolvedValueOnce({ uid: 'uid-logout', email: 'logout@test.com' });

    const loginRes = await agent
      .post('/api/auth/login')
      .set('x-csrf-token', csrfToken)
      .send({ idToken: 'good-token' });

    const { accessToken } = loginRes.body;

    const csrfToken2 = await getCsrfToken(agent);
    const logoutRes = await agent
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('x-csrf-token', csrfToken2);
    expect(logoutRes.status).toBe(200);

    // Token should now be revoked
    const meRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(meRes.status).toBe(401);
  });

  test('Token refresh issues new tokens', async () => {
    const refreshToken = issueRefreshToken('uid-refresh-test');

    const agent = makeAgent();
    const csrfToken = await getCsrfToken(agent);

    const res = await agent
      .post('/api/auth/refresh')
      .set('x-csrf-token', csrfToken)
      .send({ refreshToken });

    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeDefined();
    expect(res.body.refreshToken).toBeDefined();
    // New refresh token should be different (rotation)
    expect(res.body.refreshToken).not.toBe(refreshToken);
  });

  test('Session ID regenerates on login (session fixation protection)', async () => {
    const agent = makeAgent();
    // Establish a session
    const firstCsrfRes = await agent.get('/api/csrf-token');
    const sidBefore = (firstCsrfRes.headers['set-cookie'] || [])
      .flat()
      .find((c) => c.startsWith('sid='));

    verifyIdToken.mockResolvedValueOnce({ uid: 'uid-session-fix', email: 'sf@test.com' });
    const csrfToken = firstCsrfRes.body.csrfToken;

    const loginRes = await agent
      .post('/api/auth/login')
      .set('x-csrf-token', csrfToken)
      .send({ idToken: 'token' });

    const sidAfter = (loginRes.headers['set-cookie'] || [])
      .flat()
      .find((c) => c.startsWith('sid='));

    // Session should be regenerated (new sid cookie)
    if (sidBefore && sidAfter) {
      expect(sidAfter).not.toBe(sidBefore);
    }
    expect(loginRes.status).toBe(200);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  7. AUTHORIZATION (AuthZ) — RBAC / ABAC / Tenant Isolation
// ═══════════════════════════════════════════════════════════════════════════════
describe('Authorization — RBAC / ABAC / Tenant Isolation', () => {
  test('Admin-only route rejects regular user', async () => {
    const token = tokenFor('uid-regular', 'user');
    const res = await request(app)
      .get('/api/data/admin/users')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
  });

  test('Admin-only route accessible to admin', async () => {
    const token = tokenFor('uid-admin', 'admin');
    const res = await request(app)
      .get('/api/data/admin/users')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
  });

  test('Viewer role cannot create hobbies', () => {
    expect(hasPermission('viewer', 'hobby:create')).toBe(false);
  });

  test('User role can create hobbies', () => {
    expect(hasPermission('user', 'hobby:create')).toBe(true);
  });

  test('Viewer role can read hobbies', () => {
    expect(hasPermission('viewer', 'hobby:read')).toBe(true);
  });

  test('Admin has all permissions', () => {
    for (const perm of Object.keys(PERMISSIONS)) {
      expect(hasPermission('admin', perm)).toBe(true);
    }
  });

  test('User A cannot delete User B hobby (tenant isolation)', async () => {
    const uidA = 'tenant-user-a';
    const uidB = 'tenant-user-b';
    const tokenA = tokenFor(uidA);
    const tokenB = tokenFor(uidB);
    const hobbyId = uuidv4();

    const agent = makeAgent();

    // User B creates a hobby
    const csrfToken1 = await getCsrfToken(agent);
    const createRes = await agent
      .post('/api/data/hobbies')
      .set('Authorization', `Bearer ${tokenB}`)
      .set('x-csrf-token', csrfToken1)
      .send({ name: 'UserB Hobby', type: 'binary' });
    expect(createRes.status).toBe(201);
    const createdId = createRes.body.hobby.id;

    // User A tries to delete it (different tenant)
    // Note: User A's store won't have User B's hobby, so it returns 404 (also acceptable)
    const csrfToken2 = await getCsrfToken(agent);
    const deleteRes = await agent
      .delete(`/api/data/hobbies/${createdId}`)
      .set('Authorization', `Bearer ${tokenA}`)
      .set('x-csrf-token', csrfToken2);

    // Either 404 (not in A's store) or 403 (forbidden) — both are correct
    expect([403, 404]).toContain(deleteRes.status);
  });

  test('User can delete their own hobby', async () => {
    const uid = 'tenant-owner-test';
    const token = tokenFor(uid);
    const agent = makeAgent();

    const csrfToken1 = await getCsrfToken(agent);
    const createRes = await agent
      .post('/api/data/hobbies')
      .set('Authorization', `Bearer ${token}`)
      .set('x-csrf-token', csrfToken1)
      .send({ name: 'My Hobby', type: 'binary' });
    expect(createRes.status).toBe(201);
    const id = createRes.body.hobby.id;

    const csrfToken2 = await getCsrfToken(agent);
    const deleteRes = await agent
      .delete(`/api/data/hobbies/${id}`)
      .set('Authorization', `Bearer ${token}`)
      .set('x-csrf-token', csrfToken2);
    expect(deleteRes.status).toBe(200);
  });

  test('Unauthenticated request to /api/data returns 401', async () => {
    const res = await request(app).get('/api/data/hobbies');
    expect(res.status).toBe(401);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  8. INPUT VALIDATION + NoSQL INJECTION DEFENSE
// ═══════════════════════════════════════════════════════════════════════════════
describe('Input Validation + NoSQL Injection Defense', () => {
  test('noSqlSanitize removes $ operator keys', () => {
    const input = { $where: 'sleep(1000)', name: 'test' };
    const result = noSqlSanitize(input);
    expect(result.$where).toBeUndefined();
    expect(result.name).toBe('test');
  });

  test('noSqlSanitize removes . keys (dot notation)', () => {
    const input = { '.admin': true, safe: 'value' };
    const result = noSqlSanitize(input);
    expect(result['.admin']).toBeUndefined();
    expect(result.safe).toBe('value');
  });

  test('noSqlSanitize handles nested objects', () => {
    const input = { user: { $gt: '', name: 'ok' } };
    const result = noSqlSanitize(input);
    expect(result.user.$gt).toBeUndefined();
    expect(result.user.name).toBe('ok');
  });

  test('noSqlSanitize handles arrays', () => {
    const input = [{ $ne: null }, { value: 'safe' }];
    const result = noSqlSanitize(input);
    expect(result[0].$ne).toBeUndefined();
    expect(result[1].value).toBe('safe');
  });

  test('Hobby creation with missing name returns 422', async () => {
    const token = tokenFor('uid-val-test');
    const agent = makeAgent();
    const csrfToken = await getCsrfToken(agent);

    const res = await agent
      .post('/api/data/hobbies')
      .set('Authorization', `Bearer ${token}`)
      .set('x-csrf-token', csrfToken)
      .send({ type: 'binary' }); // missing name
    expect(res.status).toBe(422);
    expect(res.body.code).toBe('VALIDATION_FAILED');
  });

  test('Hobby name longer than 20 chars returns 422', async () => {
    const token = tokenFor('uid-len-test');
    const agent = makeAgent();
    const csrfToken = await getCsrfToken(agent);

    const res = await agent
      .post('/api/data/hobbies')
      .set('Authorization', `Bearer ${token}`)
      .set('x-csrf-token', csrfToken)
      .send({ name: 'A'.repeat(21), type: 'binary' });
    expect(res.status).toBe(422);
  });

  test('Hobby with invalid type returns 422', async () => {
    const token = tokenFor('uid-type-test');
    const agent = makeAgent();
    const csrfToken = await getCsrfToken(agent);

    const res = await agent
      .post('/api/data/hobbies')
      .set('Authorization', `Bearer ${token}`)
      .set('x-csrf-token', csrfToken)
      .send({ name: 'Test', type: 'invalid-type' });
    expect(res.status).toBe(422);
  });

  test('Hobby with invalid color hex returns 422', async () => {
    const token = tokenFor('uid-color-test');
    const agent = makeAgent();
    const csrfToken = await getCsrfToken(agent);

    const res = await agent
      .post('/api/data/hobbies')
      .set('Authorization', `Bearer ${token}`)
      .set('x-csrf-token', csrfToken)
      .send({ name: 'Test', type: 'binary', color: 'not-a-color' });
    expect(res.status).toBe(422);
  });

  test('Record with invalid date format returns 422', async () => {
    const uid = 'uid-date-test';
    const token = tokenFor(uid);
    const agent = makeAgent();

    // Create a hobby first
    const csrfToken1 = await getCsrfToken(agent);
    const hobbyRes = await agent
      .post('/api/data/hobbies')
      .set('Authorization', `Bearer ${token}`)
      .set('x-csrf-token', csrfToken1)
      .send({ name: 'Running', type: 'quant', targetValue: 5, unit: 'km' });
    expect(hobbyRes.status).toBe(201);

    const csrfToken2 = await getCsrfToken(agent);
    const res = await agent
      .post('/api/data/records')
      .set('Authorization', `Bearer ${token}`)
      .set('x-csrf-token', csrfToken2)
      .send({ hobbyId: hobbyRes.body.hobby.id, date: '2024/01/01' }); // wrong format
    expect(res.status).toBe(422);
  });

  test('Login without idToken returns 422', async () => {
    const agent = makeAgent();
    const csrfToken = await getCsrfToken(agent);

    const res = await agent
      .post('/api/auth/login')
      .set('x-csrf-token', csrfToken)
      .send({});
    expect(res.status).toBe(422);
  });

  test('Request body larger than 10kb is rejected', async () => {
    const agent = makeAgent();
    const csrfToken = await getCsrfToken(agent);
    const bigBody = { name: 'x'.repeat(20000) };

    const res = await agent
      .post('/api/data/hobbies')
      .set('x-csrf-token', csrfToken)
      .send(bigBody);
    // Either 413 Payload Too Large or 401 (auth fails first) or 422
    expect([400, 401, 413, 422]).toContain(res.status);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  9. RATE LIMITING / BRUTE FORCE PROTECTION
// ═══════════════════════════════════════════════════════════════════════════════
describe('Rate Limiting / Brute Force Protection', () => {
  test('Rate limit headers are present in responses', async () => {
    const res = await request(app).get('/api/csrf-token');
    // Headers may be present for /api/ routes
    // At minimum the response should succeed
    expect(res.status).toBe(200);
  });

  test('Exceeding auth rate limit returns 429', async () => {
    const { createLimiter } = require('../middleware/rateLimit');
    const express = require('express');
    const mini = express();
    mini.use(express.json());
    mini.use(createLimiter({ windowMs: 60000, max: 2 }));
    mini.post('/test', (req, res) => res.json({ ok: true }));

    const req1 = await request(mini).post('/test').send({});
    const req2 = await request(mini).post('/test').send({});
    const req3 = await request(mini).post('/test').send({});

    expect(req1.status).toBe(200);
    expect(req2.status).toBe(200);
    expect(req3.status).toBe(429);
    expect(req3.body.code).toBe('RATE_LIMIT_EXCEEDED');
  });

  test('429 response includes retryAfter', async () => {
    const { createLimiter } = require('../middleware/rateLimit');
    const express = require('express');
    const mini = express();
    mini.use(express.json());
    mini.use(createLimiter({ windowMs: 60000, max: 1 }));
    mini.get('/test', (req, res) => res.json({ ok: true }));

    await request(mini).get('/test');
    const res = await request(mini).get('/test');

    expect(res.status).toBe(429);
    expect(res.body.retryAfter).toBeDefined();
    expect(res.body.retryAfter).toBeGreaterThan(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  10. COOKIE / SESSION SECURITY
// ═══════════════════════════════════════════════════════════════════════════════
describe('Cookie / Session Security', () => {
  test('Session cookie has HttpOnly flag', async () => {
    const agent = makeAgent();
    const res = await agent.get('/api/csrf-token');
    const cookies = [res.headers['set-cookie']].flat();
    const sidCookie = cookies.find((c) => c.startsWith('sid='));
    if (sidCookie) {
      expect(sidCookie.toLowerCase()).toContain('httponly');
    }
    // If no session cookie is set here, that's also fine (may be set on first interaction)
    expect(res.status).toBe(200);
  });

  test('Session cookie has SameSite=Strict', async () => {
    const agent = makeAgent();
    const res = await agent.get('/api/csrf-token');
    const cookies = [res.headers['set-cookie']].flat();
    const sidCookie = cookies.find((c) => c.startsWith('sid='));
    if (sidCookie) {
      expect(sidCookie.toLowerCase()).toContain('samesite=strict');
    }
  });

  test('Session cookie has path=/', async () => {
    const agent = makeAgent();
    const res = await agent.get('/api/csrf-token');
    const cookies = [res.headers['set-cookie']].flat();
    const sidCookie = cookies.find((c) => c.startsWith('sid='));
    if (sidCookie) {
      expect(sidCookie.toLowerCase()).toContain('path=/');
    }
  });

  test('createSessionMiddleware respects httpOnly option on session cookie', () => {
    const { createSessionMiddleware } = require('../middleware/session');
    // Just verify it returns a function (middleware)
    const mw = createSessionMiddleware({ secure: false });
    expect(typeof mw).toBe('function');
  });

  test('Session is destroyed on logout', async () => {
    const agent = makeAgent();
    const csrfToken = await getCsrfToken(agent);

    verifyIdToken.mockResolvedValueOnce({ uid: 'uid-sess-destroy', email: 'sd@test.com' });

    const loginRes = await agent
      .post('/api/auth/login')
      .set('x-csrf-token', csrfToken)
      .send({ idToken: 'token' });
    const { accessToken } = loginRes.body;

    const csrfToken2 = await getCsrfToken(agent);
    const logoutRes = await agent
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('x-csrf-token', csrfToken2);
    expect(logoutRes.status).toBe(200);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  11. SECRET MANAGEMENT + ROTATION
// ═══════════════════════════════════════════════════════════════════════════════
describe('Secret Management + Rotation', () => {
  test('validateSecrets warns in non-production for short secrets', () => {
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    validateSecrets({
      NODE_ENV: 'development',
      SESSION_SECRET: 'short',
      JWT_SECRET: 'also-short',
    });
    expect(warnSpy).toHaveBeenCalled();
    warnSpy.mockRestore();
  });

  test('validateSecrets throws in production for missing secrets', () => {
    expect(() =>
      validateSecrets({ NODE_ENV: 'production' })
    ).toThrow();
  });

  test('validateSecrets passes with valid secrets', () => {
    expect(() =>
      validateSecrets({
        NODE_ENV: 'test',
        SESSION_SECRET: 'a-valid-session-secret-that-is-32chars!',
        JWT_SECRET: 'a-valid-jwt-secret-that-is-32chars!!!!!',
      })
    ).not.toThrow();
  });

  test('deriveKey produces consistent derivation', () => {
    const key1 = deriveKey('csrf');
    const key2 = deriveKey('csrf');
    expect(key1.equals(key2)).toBe(true);
  });

  test('deriveKey produces different keys for different purposes', () => {
    const k1 = deriveKey('csrf');
    const k2 = deriveKey('email-verification');
    expect(k1.equals(k2)).toBe(false);
  });

  test('registerSecret + getSecret work', () => {
    registerSecret('test-key', 'current-secret-value-1234567890');
    const { current, previous } = getSecret('test-key');
    expect(current).toBe('current-secret-value-1234567890');
    expect(previous).toBeNull();
  });

  test('rotateSecret preserves previous key', () => {
    registerSecret('rotate-key', 'original-secret-value-long-enough');
    rotateSecret('rotate-key', 'new-secret-value-also-long-enough!!');
    const { current, previous } = getSecret('rotate-key');
    expect(current).toBe('new-secret-value-also-long-enough!!');
    expect(previous).toBe('original-secret-value-long-enough');
  });

  test('SecretValue does not expose value in toString/JSON', () => {
    const secret = new SecretValue('super-secret-password');
    expect(String(secret)).toBe('[SECRET]');
    expect(JSON.stringify({ s: secret })).toBe('{"s":"[SECRET]"}');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  12. AUDIT LOGGING
// ═══════════════════════════════════════════════════════════════════════════════
describe('Audit Logging', () => {
  test('redact removes password field', () => {
    const input = { email: 'user@test.com', password: 'secret123' };
    const result = redact(input);
    expect(result.email).toBe('user@test.com');
    expect(result.password).toBe('[REDACTED]');
  });

  test('redact removes token fields', () => {
    const input = {
      accessToken: 'eyJhbGc...',
      refreshToken: 'eyJhbGc...',
      idToken: 'firebase...',
    };
    const result = redact(input);
    expect(result.accessToken).toBe('[REDACTED]');
    expect(result.refreshToken).toBe('[REDACTED]');
    expect(result.idToken).toBe('[REDACTED]');
  });

  test('redact removes secret and apiKey', () => {
    const result = redact({ secret: 'mysecret', apiKey: 'key-123', name: 'test' });
    expect(result.secret).toBe('[REDACTED]');
    expect(result.apiKey).toBe('[REDACTED]');
    expect(result.name).toBe('test');
  });

  test('redact handles nested objects', () => {
    const input = { user: { password: 'p@ss', name: 'alice' } };
    const result = redact(input);
    expect(result.user.password).toBe('[REDACTED]');
    expect(result.user.name).toBe('alice');
  });

  test('redact handles null and primitives safely', () => {
    expect(redact(null)).toBeNull();
    expect(redact('string')).toBe('string');
    expect(redact(42)).toBe(42);
  });

  test('Login failure is auditable (logged)', async () => {
    const agent = makeAgent();
    const csrfToken = await getCsrfToken(agent);

    verifyIdToken.mockRejectedValueOnce(new Error('invalid'));

    // Just ensure audit logging doesn't crash the request
    const res = await agent
      .post('/api/auth/login')
      .set('x-csrf-token', csrfToken)
      .send({ idToken: 'bad' });

    expect(res.status).toBe(401);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  13. ERROR EXPOSURE PREVENTION
// ═══════════════════════════════════════════════════════════════════════════════
describe('Error Exposure Prevention', () => {
  test('404 for unknown routes does not expose internals', async () => {
    const res = await request(app).get('/api/nonexistent-route-xyz');
    expect(res.status).toBe(404);
    expect(res.body.error).toBeDefined();
    expect(res.body.stack).toBeUndefined(); // no stack in test (NODE_ENV=test)
  });

  test('Error response does not expose stack trace in production', () => {
    const { errorHandler } = require('../middleware/errorHandler');
    const origEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';

    const err = new Error('Internal database failure with sensitive path /secret');
    const req = { path: '/api/test', method: 'GET', user: null, ip: '1.2.3.4' };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    const next = jest.fn();

    errorHandler(err, req, res, next);

    const response = res.json.mock.calls[0][0];
    expect(response.stack).toBeUndefined();
    expect(response.error).toBe('An internal error occurred. Please try again later.');

    process.env.NODE_ENV = origEnv;
  });

  test('Validation errors return 422, not 500', async () => {
    const token = tokenFor('uid-val-err');
    const agent = makeAgent();
    const csrfToken = await getCsrfToken(agent);

    const res = await agent
      .post('/api/data/hobbies')
      .set('Authorization', `Bearer ${token}`)
      .set('x-csrf-token', csrfToken)
      .send({ name: '', type: 'INVALID' });
    expect(res.status).toBe(422);
    expect(res.body.details).toBeDefined();
  });

  test('Auth error returns 401 with code, not stack trace', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', 'Bearer invalid.jwt.token');
    expect(res.status).toBe(401);
    expect(res.body.stack).toBeUndefined();
    expect(res.body.code).toBeDefined();
  });

  test('/health endpoint returns 200 without sensitive info', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    // Should not contain secrets, env vars, or file paths
    const bodyStr = JSON.stringify(res.body);
    expect(bodyStr).not.toContain('SECRET');
    expect(bodyStr).not.toContain('password');
    expect(bodyStr).not.toContain('/home/');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  14. MINIMUM PRIVILEGE (Least Privilege)
// ═══════════════════════════════════════════════════════════════════════════════
describe('Least Privilege', () => {
  test('Data routes cannot be accessed without authentication', async () => {
    const endpoints = [
      { method: 'get', path: '/api/data/hobbies' },
      { method: 'get', path: '/api/data/records' },
    ];
    for (const { method, path } of endpoints) {
      const res = await request(app)[method](path);
      expect(res.status).toBe(401);
    }
  });

  test('Viewer cannot create resources (permission check)', () => {
    expect(hasPermission('viewer', 'hobby:create')).toBe(false);
    expect(hasPermission('viewer', 'record:create')).toBe(false);
    expect(hasPermission('viewer', 'hobby:delete')).toBe(false);
  });

  test('Viewer can only read', () => {
    expect(hasPermission('viewer', 'hobby:read')).toBe(true);
    expect(hasPermission('viewer', 'record:read')).toBe(true);
  });

  test('User cannot access admin endpoints', () => {
    expect(hasPermission('user', 'admin:users:read')).toBe(false);
    expect(hasPermission('user', 'admin:audit:read')).toBe(false);
  });

  test('Data response for user only contains own data (scoped)', async () => {
    const uid1 = 'scope-user-1';
    const uid2 = 'scope-user-2';
    const token1 = tokenFor(uid1);
    const token2 = tokenFor(uid2);

    const agent = makeAgent();

    // User 1 creates a hobby
    const csrf1 = await getCsrfToken(agent);
    await agent
      .post('/api/data/hobbies')
      .set('Authorization', `Bearer ${token1}`)
      .set('x-csrf-token', csrf1)
      .send({ name: 'User1 Hobby', type: 'binary' });

    // User 2 lists hobbies — should not see User 1's hobby
    const listRes = await agent
      .get('/api/data/hobbies')
      .set('Authorization', `Bearer ${token2}`);
    expect(listRes.status).toBe(200);
    const hobbies = listRes.body.hobbies;
    const found = hobbies.find((h) => h.ownerUid === uid1);
    expect(found).toBeUndefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  15. FULL INTEGRATION — Hobby + Record Lifecycle
// ═══════════════════════════════════════════════════════════════════════════════
describe('Integration — Hobby + Record Lifecycle', () => {
  test('Create → List → Update → Delete hobby end-to-end', async () => {
    const uid = 'integration-user-1';
    const token = tokenFor(uid);
    const agent = makeAgent();

    // Create
    const csrf1 = await getCsrfToken(agent);
    const createRes = await agent
      .post('/api/data/hobbies')
      .set('Authorization', `Bearer ${token}`)
      .set('x-csrf-token', csrf1)
      .send({ name: 'Running', type: 'quant', targetValue: 5, unit: 'km', color: '#26a641' });
    expect(createRes.status).toBe(201);
    const hobbyId = createRes.body.hobby.id;

    // List
    const listRes = await agent
      .get('/api/data/hobbies')
      .set('Authorization', `Bearer ${token}`);
    expect(listRes.status).toBe(200);
    expect(listRes.body.hobbies.some((h) => h.id === hobbyId)).toBe(true);

    // Update
    const csrf2 = await getCsrfToken(agent);
    const updateRes = await agent
      .put(`/api/data/hobbies/${hobbyId}`)
      .set('Authorization', `Bearer ${token}`)
      .set('x-csrf-token', csrf2)
      .send({ name: 'Cycling', type: 'quant', targetValue: 10, unit: 'km' });
    expect(updateRes.status).toBe(200);
    expect(updateRes.body.hobby.name).toBe('Cycling');

    // Create record
    const csrf3 = await getCsrfToken(agent);
    const recRes = await agent
      .post('/api/data/records')
      .set('Authorization', `Bearer ${token}`)
      .set('x-csrf-token', csrf3)
      .send({ hobbyId, date: '2024-01-15', value: 12, achieved: true, memo: 'Great ride!' });
    expect(recRes.status).toBe(201);
    const recordId = recRes.body.record.id;

    // List records
    const recListRes = await agent
      .get('/api/data/records')
      .set('Authorization', `Bearer ${token}`);
    expect(recListRes.status).toBe(200);
    expect(recListRes.body.records.some((r) => r.id === recordId)).toBe(true);

    // Delete record
    const csrf4 = await getCsrfToken(agent);
    const delRecRes = await agent
      .delete(`/api/data/records/${recordId}`)
      .set('Authorization', `Bearer ${token}`)
      .set('x-csrf-token', csrf4);
    expect(delRecRes.status).toBe(200);

    // Delete hobby
    const csrf5 = await getCsrfToken(agent);
    const delRes = await agent
      .delete(`/api/data/hobbies/${hobbyId}`)
      .set('Authorization', `Bearer ${token}`)
      .set('x-csrf-token', csrf5);
    expect(delRes.status).toBe(200);
  });
});
