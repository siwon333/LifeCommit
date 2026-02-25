'use strict';

const crypto = require('crypto');

/**
 * CSP Nonce Middleware
 * Generates a per-request cryptographic nonce and exposes it to:
 *  1. res.locals.cspNonce — used by helmet's scriptSrc directive
 *  2. X-CSP-Nonce response header — readable by frontend for dynamic script injection
 *
 * This middleware must run BEFORE helmet/securityHeaders so the nonce
 * is available when helmet builds the CSP header.
 */
function cspNonceMiddleware(req, res, next) {
  res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
  // Expose to frontend (not sensitive — nonce is per-request and single-use)
  res.setHeader('X-CSP-Nonce', res.locals.cspNonce);
  next();
}

/**
 * Input sanitization helper — strips dangerous HTML to mitigate XSS.
 * Used in routes before persisting user content.
 */
let _sanitizeHtml;
function getSanitizer() {
  if (!_sanitizeHtml) {
    _sanitizeHtml = require('sanitize-html'); // lazy-load
  }
  return _sanitizeHtml;
}

const SANITIZE_OPTS = {
  allowedTags: [],          // strip ALL HTML tags
  allowedAttributes: {},
  disallowedTagsMode: 'discard',
};

/**
 * Sanitize a string value to prevent XSS.
 * @param {string} input
 * @returns {string}
 */
function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  return getSanitizer()(input, SANITIZE_OPTS).trim();
}

/**
 * Recursively sanitize all string fields of an object.
 * @param {unknown} data
 * @returns {unknown}
 */
function sanitizeDeep(data) {
  if (typeof data === 'string') return sanitizeInput(data);
  if (Array.isArray(data)) return data.map(sanitizeDeep);
  if (data !== null && typeof data === 'object') {
    const result = {};
    for (const [k, v] of Object.entries(data)) {
      result[k] = sanitizeDeep(v);
    }
    return result;
  }
  return data;
}

module.exports = { cspNonceMiddleware, sanitizeInput, sanitizeDeep };
