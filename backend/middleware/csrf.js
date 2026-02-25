'use strict';

const crypto = require('crypto');

const CSRF_HEADER = 'x-csrf-token';
const CSRF_COOKIE = '_csrf';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Generate a cryptographically secure CSRF token.
 */
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * CSRF Token Seeding Middleware
 * Ensures every session has a CSRF token.
 * Must run after session middleware.
 */
function csrfSeedMiddleware(req, res, next) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = generateToken();
  }

  // Set as a readable (non-HttpOnly) cookie so frontend JS can retrieve it
  res.cookie(CSRF_COOKIE, req.session.csrfToken, {
    httpOnly: false,        // must be readable by JS
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: 24 * 60 * 60 * 1000, // 1 day
  });

  next();
}

/**
 * CSRF Validation Middleware
 * Rejects state-changing requests (POST/PUT/PATCH/DELETE) without a valid token.
 * Uses constant-time comparison to prevent timing attacks.
 */
function csrfValidateMiddleware(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();

  const sessionToken = req.session && req.session.csrfToken;
  const requestToken =
    req.headers[CSRF_HEADER] ||
    (req.body && req.body._csrf);

  if (!sessionToken || !requestToken) {
    return res.status(403).json({
      error: 'Forbidden',
      code: 'CSRF_TOKEN_MISSING',
    });
  }

  let sessionBuf, requestBuf;
  try {
    sessionBuf = Buffer.from(sessionToken, 'hex');
    requestBuf = Buffer.from(requestToken, 'hex');
  } catch {
    return res.status(403).json({ error: 'Forbidden', code: 'CSRF_TOKEN_INVALID' });
  }

  if (
    sessionBuf.length !== requestBuf.length ||
    !crypto.timingSafeEqual(sessionBuf, requestBuf)
  ) {
    return res.status(403).json({
      error: 'Forbidden',
      code: 'CSRF_TOKEN_INVALID',
    });
  }

  // Rotate token after successful use
  req.session.csrfToken = generateToken();

  next();
}

/**
 * GET /api/csrf-token endpoint handler.
 * Returns the current session's CSRF token in JSON.
 */
function csrfTokenHandler(req, res) {
  return res.json({ csrfToken: req.session.csrfToken });
}

module.exports = {
  csrfSeedMiddleware,
  csrfValidateMiddleware,
  csrfTokenHandler,
  generateToken,
  CSRF_HEADER,
  CSRF_COOKIE,
};
