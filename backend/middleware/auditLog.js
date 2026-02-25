'use strict';

const winston = require('winston');
const path = require('path');

/**
 * Audit Logging
 *
 * Logs security-relevant events in structured JSON.
 * Rules:
 *  - Never log passwords, tokens, or raw secrets.
 *  - Include: timestamp, event type, user ID (if known), IP, method, path, outcome.
 *  - Stored in logs/audit.log (rotating in production).
 */

const LOG_DIR = path.resolve(__dirname, '..', 'logs');
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const IS_TEST = process.env.NODE_ENV === 'test';

// Sensitive field names (all lowercase — compared with k.toLowerCase())
const SENSITIVE_FIELDS = new Set([
  'password', 'passwordhash', 'token', 'accesstoken', 'refreshtoken',
  'idtoken', 'secret', 'apikey', 'authorization', 'cookie', 'x-csrf-token',
  '_csrf', 'creditcard', 'ssn',
]);

/**
 * Redact sensitive fields from an object before logging.
 */
function redact(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const result = {};
  for (const [k, v] of Object.entries(obj)) {
    if (SENSITIVE_FIELDS.has(k.toLowerCase())) {
      result[k] = '[REDACTED]';
    } else if (v && typeof v === 'object') {
      result[k] = redact(v);
    } else {
      result[k] = v;
    }
  }
  return result;
}

/** Build winston transports based on environment */
function buildTransports() {
  if (IS_TEST) {
    // In tests: use silent transport to avoid polluting output
    return [new winston.transports.Console({ silent: true })];
  }

  const transports = [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
  ];

  if (process.env.AUDIT_LOG_FILE) {
    transports.push(
      new winston.transports.File({
        filename: process.env.AUDIT_LOG_FILE,
        maxsize: 10 * 1024 * 1024, // 10 MB
        maxFiles: 5,
        tailable: true,
      })
    );
  }

  return transports;
}

const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: false }), // never log stack in audit
    winston.format.json()
  ),
  transports: buildTransports(),
  exitOnError: false,
});

/**
 * Log an audit event.
 * @param {string} event - e.g. 'AUTH_LOGIN_SUCCESS'
 * @param {object} context
 */
function audit(event, context = {}) {
  const safe = redact(context);
  logger.info({ event, ...safe });
}

/**
 * Express middleware: logs every request's outcome.
 * Captures IP, method, path, status, user.
 */
function auditMiddleware(req, res, next) {
  res.on('finish', () => {
    // Only log API routes and auth events
    if (!req.path.startsWith('/api/') && req.path !== '/health') return;

    audit('HTTP_REQUEST', {
      method: req.method,
      path: req.path,
      status: res.statusCode,
      ip: req.ip || req.socket.remoteAddress,
      uid: req.user ? req.user.uid : undefined,
      userAgent: req.headers['user-agent'],
    });
  });
  next();
}

module.exports = { audit, auditMiddleware, redact, logger };
