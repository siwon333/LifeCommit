'use strict';

const { audit } = require('./auditLog');

/**
 * Centralized Error Handler
 *
 * Rules:
 *  - Never expose stack traces in production.
 *  - Map operational errors to safe client messages.
 *  - Log full details server-side for debugging.
 *  - Return consistent JSON error shape: { error, code }.
 */

// Read at call time so tests can change NODE_ENV
const isProduction = () => process.env.NODE_ENV === 'production';

// Map error names/codes to HTTP status codes
const STATUS_MAP = {
  ValidationError: 422,
  CastError: 400,
  AuthError: 401,
  ForbiddenError: 403,
  NotFoundError: 404,
  SecretsError: 500,
  CORS_ORIGIN_NOT_ALLOWED: 403,
};

// Safe messages for unexpected errors (never expose internals)
const GENERIC_500 = 'An internal error occurred. Please try again later.';

/**
 * 404 handler — attach before errorHandler.
 */
function notFoundHandler(req, res) {
  res.status(404).json({
    error: 'Not Found',
    code: 'NOT_FOUND',
    path: req.path,
  });
}

/**
 * Global error handler middleware.
 * Must have 4 parameters for Express to recognise it as an error handler.
 */
// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  // Determine status
  const status =
    err.status ||
    err.statusCode ||
    STATUS_MAP[err.name] ||
    STATUS_MAP[err.code] ||
    500;

  // Always log server-side
  audit('SERVER_ERROR', {
    status,
    message: err.message,
    code: err.code,
    name: err.name,
    path: req && req.path,
    method: req && req.method,
    uid: req && req.user && req.user.uid,
    // Stack only in non-production
    stack: isProduction() ? undefined : err.stack,
  });

  // CORS error from cors middleware
  if (err.message === 'CORS_ORIGIN_NOT_ALLOWED') {
    return res.status(403).json({
      error: 'Forbidden',
      code: 'CORS_BLOCKED',
    });
  }

  // Build safe response
  const isOperational = status < 500 || !!err.code;
  const message = isOperational ? err.message : GENERIC_500;

  const body = {
    error: message,
    code: err.code || 'INTERNAL_ERROR',
  };

  // In development, include stack trace for debugging
  if (!isProduction() && err.stack) {
    body.stack = err.stack;
  }

  // Validation detail (express-validator)
  if (err.details) {
    body.details = err.details;
  }

  return res.status(status).json(body);
}

module.exports = { errorHandler, notFoundHandler };
