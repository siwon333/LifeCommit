'use strict';

require('express-async-errors');

// Load .env early (no-op if file doesn't exist)
require('dotenv').config();

const express = require('express');
const cookieParser = require('cookie-parser');
const hpp = require('hpp');

const { securityHeaders, customSecurityHeaders } = require('./middleware/headers');
const { cspNonceMiddleware } = require('./middleware/csp');
const { corsMiddleware } = require('./middleware/cors');
const { sessionMiddleware } = require('./middleware/session');
const { csrfSeedMiddleware, csrfValidateMiddleware, csrfTokenHandler } = require('./middleware/csrf');
const { generalLimiter, authLimiter } = require('./middleware/rateLimit');
const { auditMiddleware } = require('./middleware/auditLog');
const { noSqlSanitizeMiddleware } = require('./middleware/validation');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');
const { validateSecrets } = require('./middleware/secrets');

const authRoutes = require('./routes/auth');
const dataRoutes = require('./routes/data');

// ─── Startup checks ───────────────────────────────────────────────────────────
validateSecrets();

// ─── App ──────────────────────────────────────────────────────────────────────
const app = express();

// Trust first proxy (required for accurate req.ip behind nginx/load balancer)
app.set('trust proxy', 1);

// ── 1. CSP nonce generation (must run before helmet) ──────────────────────────
app.use(cspNonceMiddleware);

// ── 2. Security headers (helmet + custom) ────────────────────────────────────
app.use(securityHeaders);
app.use(customSecurityHeaders);

// ── 3. CORS ───────────────────────────────────────────────────────────────────
app.use(corsMiddleware);

// ── 4. Body parsers (size-limited) ───────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(cookieParser(process.env.COOKIE_SECRET || 'dev-cookie-secret'));

// ── 5. HTTP Parameter Pollution prevention ────────────────────────────────────
app.use(hpp());

// ── 6. NoSQL injection sanitization ──────────────────────────────────────────
app.use(noSqlSanitizeMiddleware);

// ── 7. Session ────────────────────────────────────────────────────────────────
app.use(sessionMiddleware);

// ── 8. CSRF (seed on every request, validate on state-changing) ───────────────
app.use(csrfSeedMiddleware);
app.use(csrfValidateMiddleware);

// ── 9. Audit logging ──────────────────────────────────────────────────────────
app.use(auditMiddleware);

// ─── Routes ───────────────────────────────────────────────────────────────────

// Health check (no auth, no rate limit)
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// CSRF token endpoint (GET — safe method, no CSRF validation)
app.get('/api/csrf-token', csrfTokenHandler);

// Auth routes (with tighter rate limiting)
app.use('/api/auth', authLimiter, authRoutes);

// Data routes (with general rate limiting)
app.use('/api/data', generalLimiter, dataRoutes);

// ─── Error handling ───────────────────────────────────────────────────────────
app.use(notFoundHandler);
app.use(errorHandler);

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT, 10) || 3000;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[LifeCommit] Server listening on port ${PORT} (${process.env.NODE_ENV || 'development'})`);
  });
}

module.exports = app;
