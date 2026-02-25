'use strict';

const jwt = require('jsonwebtoken');
const { audit } = require('./auditLog');

/**
 * Authentication & Authorization Middleware
 *
 * Flow:
 *  1. Client authenticates with Firebase → receives Firebase ID token.
 *  2. Client POSTs token to POST /api/auth/login.
 *  3. Backend verifies Firebase token via firebase-admin.
 *  4. Backend issues a short-lived JWT (15 min) + refresh token (7 days).
 *  5. All subsequent requests include `Authorization: Bearer <jwt>`.
 *  6. authMiddleware verifies the JWT on every protected route.
 */

const JWT_SECRET = () => process.env.JWT_SECRET || 'dev-jwt-secret-change-me-please!!';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '15m';
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '7d';

// In-memory token blacklist (revoked tokens).
// In production, use Redis with TTL matching token expiry.
const _blacklist = new Set();

class AuthError extends Error {
  constructor(message, code, status = 401) {
    super(message);
    this.name = 'AuthError';
    this.code = code;
    this.status = status;
  }
}

/**
 * Issue a signed JWT for a user.
 */
function issueToken(payload, options = {}) {
  const { uid, email, role = 'user', tenantId } = payload;
  return jwt.sign(
    { uid, email, role, tenantId },
    JWT_SECRET(),
    { expiresIn: options.expiresIn || JWT_EXPIRES_IN, algorithm: 'HS256' }
  );
}

/**
 * Issue a refresh token (longer-lived).
 * Includes a unique jti (JWT ID) so two tokens issued in the same second differ.
 */
function issueRefreshToken(uid) {
  const { v4: uuidv4 } = require('uuid');
  return jwt.sign(
    { uid, type: 'refresh', jti: uuidv4() },
    JWT_SECRET(),
    { expiresIn: JWT_REFRESH_EXPIRES_IN, algorithm: 'HS256' }
  );
}

/**
 * Verify a JWT synchronously. Throws AuthError on failure.
 */
function verifyToken(token) {
  if (_blacklist.has(token)) {
    throw new AuthError('Token has been revoked', 'TOKEN_REVOKED');
  }
  try {
    return jwt.verify(token, JWT_SECRET(), { algorithms: ['HS256'] });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      throw new AuthError('Token expired', 'TOKEN_EXPIRED');
    }
    throw new AuthError('Invalid token', 'TOKEN_INVALID');
  }
}

/**
 * Revoke a token (add to blacklist).
 * In production, store in Redis with TTL = token expiry.
 */
function revokeToken(token) {
  _blacklist.add(token);
}

/**
 * Extract bearer token from Authorization header.
 */
function extractBearer(req) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return null;
  return auth.slice(7).trim() || null;
}

/**
 * Authentication middleware — attaches req.user on success.
 */
function authMiddleware(req, res, next) {
  const token = extractBearer(req);
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized', code: 'NO_TOKEN' });
  }

  try {
    const decoded = verifyToken(token);
    req.user = {
      uid: decoded.uid,
      email: decoded.email,
      role: decoded.role || 'user',
      tenantId: decoded.tenantId || decoded.uid,
    };
    req._rawToken = token; // needed for logout
    next();
  } catch (err) {
    audit('AUTH_VERIFY_FAILED', {
      ip: req.ip,
      code: err.code,
      path: req.path,
    });
    return res.status(err.status || 401).json({
      error: 'Unauthorized',
      code: err.code || 'AUTH_FAILED',
    });
  }
}

/**
 * Optional auth — same as authMiddleware but doesn't block if no token.
 * Useful for endpoints that behave differently for authed vs anonymous users.
 */
function optionalAuth(req, res, next) {
  const token = extractBearer(req);
  if (!token) return next();

  try {
    const decoded = verifyToken(token);
    req.user = {
      uid: decoded.uid,
      email: decoded.email,
      role: decoded.role || 'user',
      tenantId: decoded.tenantId || decoded.uid,
    };
    req._rawToken = token;
  } catch {
    // ignore invalid token for optional auth
  }
  next();
}

/** Clear the blacklist (for test isolation). */
function _clearBlacklist() {
  _blacklist.clear();
}

module.exports = {
  authMiddleware,
  optionalAuth,
  issueToken,
  issueRefreshToken,
  verifyToken,
  revokeToken,
  extractBearer,
  AuthError,
  _clearBlacklist,
};
