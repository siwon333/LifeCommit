'use strict';

const cors = require('cors');

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

/**
 * CORS Middleware
 * - Strict origin whitelist
 * - Credentials support
 * - Preflight caching (OPTIONS → 204, max-age=86400)
 */
const corsOptions = {
  origin(origin, callback) {
    // Requests with no Origin (same-origin, curl, server-to-server) are allowed
    if (!origin) return callback(null, true);

    if (ALLOWED_ORIGINS.includes(origin) || ALLOWED_ORIGINS.includes('*')) {
      return callback(null, true);
    }

    const err = new Error('CORS_ORIGIN_NOT_ALLOWED');
    err.status = 403;
    return callback(err);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-CSRF-Token',
    'X-Requested-With',
  ],
  exposedHeaders: ['X-CSRF-Token', 'X-RateLimit-Limit', 'X-RateLimit-Remaining'],
  maxAge: 86400, // 24-hour preflight cache
  optionsSuccessStatus: 204,
};

const corsMiddleware = cors(corsOptions);

module.exports = { corsMiddleware, corsOptions, ALLOWED_ORIGINS };
