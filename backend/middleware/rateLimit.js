'use strict';

const rateLimit = require('express-rate-limit');

/**
 * Rate Limiting & Brute-Force Protection
 *
 * Three tiers:
 *  1. generalLimiter   — broad API protection (100 req/min)
 *  2. authLimiter      — login/register (10 req/15min per IP)
 *  3. strictLimiter    — password-reset / sensitive ops (5 req/hour)
 */

const WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 60_000; // 1 min
const MAX_GENERAL = parseInt(process.env.RATE_LIMIT_MAX, 10) || 100;
const MAX_AUTH = parseInt(process.env.AUTH_RATE_LIMIT_MAX, 10) || 10;

/** Standard headers: RateLimit-* (draft-7) */
const STANDARD_HEADERS = 'draft-7';
const LEGACY_HEADERS = false;

const defaultOptions = {
  standardHeaders: STANDARD_HEADERS,
  legacyHeaders: LEGACY_HEADERS,
  skipSuccessfulRequests: false,
  handler(req, res) {
    res.status(429).json({
      error: 'Too Many Requests',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: Math.ceil(this.windowMs / 1000),
    });
  },
  // Key by IP; in prod, ensure trust proxy is set correctly
  keyGenerator: (req) => req.ip || req.socket.remoteAddress || 'unknown',
};

/** General API rate limiter */
const generalLimiter = rateLimit({
  ...defaultOptions,
  windowMs: WINDOW_MS,
  max: MAX_GENERAL,
  message: undefined, // use custom handler
});

/** Auth endpoint rate limiter (tighter window) */
const authLimiter = rateLimit({
  ...defaultOptions,
  windowMs: 15 * 60_000, // 15 minutes
  max: MAX_AUTH,
  skipSuccessfulRequests: true, // don't count successful logins
});

/** Strict limiter for password reset / admin ops */
const strictLimiter = rateLimit({
  ...defaultOptions,
  windowMs: 60 * 60_000, // 1 hour
  max: 5,
  skipSuccessfulRequests: false,
});

/**
 * Create a fresh limiter with custom options.
 * Useful in tests to get a limiter with a separate in-memory store.
 */
function createLimiter(opts = {}) {
  return rateLimit({ ...defaultOptions, ...opts });
}

module.exports = {
  generalLimiter,
  authLimiter,
  strictLimiter,
  createLimiter,
};
