'use strict';

require('express-async-errors');
const { Router } = require('express');
const {
  issueToken,
  issueRefreshToken,
  verifyToken,
  revokeToken,
  extractBearer,
  authMiddleware,
  AuthError,
} = require('../middleware/auth');
const { validateLogin } = require('../middleware/validation');
const { audit } = require('../middleware/auditLog');

const router = Router();

/**
 * POST /api/auth/login
 * Verify a Firebase ID token, issue our own JWT + refresh token.
 *
 * Body: { idToken: string }
 */
router.post('/login', validateLogin, async (req, res) => {
  const { idToken } = req.body;
  const ip = req.ip;

  let firebaseUser;
  try {
    // Verify with Firebase Admin (mocked in tests)
    const firebase = require('../lib/firebase');
    firebaseUser = await firebase.verifyIdToken(idToken);
  } catch (err) {
    audit('AUTH_LOGIN_FAILED', { ip, reason: 'FIREBASE_VERIFY_FAILED' });
    return res.status(401).json({
      error: 'Invalid credentials',
      code: 'FIREBASE_TOKEN_INVALID',
    });
  }

  const { uid, email } = firebaseUser;

  // Determine role (simplistic: check env-listed admin UIDs)
  const adminUids = (process.env.ADMIN_UIDS || '').split(',').map((s) => s.trim());
  const role = adminUids.includes(uid) ? 'admin' : 'user';

  const accessToken = issueToken({ uid, email, role, tenantId: uid });
  const refreshToken = issueRefreshToken(uid);

  // Rotate session ID on login to prevent session fixation
  await new Promise((resolve, reject) => {
    req.session.regenerate((err) => (err ? reject(err) : resolve()));
  });

  req.session.uid = uid;
  req.session.role = role;

  audit('AUTH_LOGIN_SUCCESS', { uid, email, ip, role });

  return res.json({
    accessToken,
    refreshToken,
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
    role,
  });
});

/**
 * POST /api/auth/refresh
 * Exchange a refresh token for a new access token.
 *
 * Body: { refreshToken: string }
 */
router.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ error: 'refreshToken is required', code: 'MISSING_REFRESH_TOKEN' });
  }

  let decoded;
  try {
    decoded = verifyToken(refreshToken);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid refresh token', code: err.code || 'TOKEN_INVALID' });
  }

  if (decoded.type !== 'refresh') {
    return res.status(401).json({ error: 'Invalid token type', code: 'WRONG_TOKEN_TYPE' });
  }

  // Rotate: revoke old refresh token, issue new pair
  revokeToken(refreshToken);

  const adminUids = (process.env.ADMIN_UIDS || '').split(',').map((s) => s.trim());
  const role = adminUids.includes(decoded.uid) ? 'admin' : 'user';

  const newAccessToken = issueToken({
    uid: decoded.uid,
    email: decoded.email || '',
    role,
    tenantId: decoded.uid,
  });
  const newRefreshToken = issueRefreshToken(decoded.uid);

  audit('AUTH_TOKEN_REFRESHED', { uid: decoded.uid, ip: req.ip });

  return res.json({
    accessToken: newAccessToken,
    refreshToken: newRefreshToken,
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
  });
});

/**
 * POST /api/auth/logout
 * Revoke the current access token and destroy the session.
 */
router.post('/logout', authMiddleware, async (req, res) => {
  const token = req._rawToken;
  if (token) revokeToken(token);

  await new Promise((resolve) => req.session.destroy(resolve));
  res.clearCookie('sid');

  audit('AUTH_LOGOUT', { uid: req.user.uid, ip: req.ip });

  return res.json({ message: 'Logged out successfully' });
});

/**
 * GET /api/auth/me
 * Return current user info (requires valid JWT).
 */
router.get('/me', authMiddleware, (req, res) => {
  return res.json({
    uid: req.user.uid,
    email: req.user.email,
    role: req.user.role,
  });
});

module.exports = router;
