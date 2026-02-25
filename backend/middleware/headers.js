'use strict';

const helmet = require('helmet');

/**
 * Security Headers Middleware
 * Implements HTTPS/HSTS, CSP frame-ancestors, X-Frame-Options,
 * X-Content-Type-Options, Referrer-Policy, Permissions-Policy, etc.
 */
const securityHeaders = helmet({
  // Strict-Transport-Security: max-age=1yr + includeSubDomains + preload
  strictTransportSecurity: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },

  // X-Frame-Options: DENY
  frameguard: { action: 'deny' },

  // X-Content-Type-Options: nosniff
  noSniff: true,

  // X-XSS-Protection (legacy IE)
  xssFilter: true,

  // Referrer-Policy
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },

  // X-DNS-Prefetch-Control
  dnsPrefetchControl: { allow: false },

  // X-Permitted-Cross-Domain-Policies
  permittedCrossDomainPolicies: false,

  // X-Download-Options (IE)
  ieNoOpen: true,

  // Remove X-Powered-By
  hidePoweredBy: true,

  // Content-Security-Policy — base policy (CSP nonce layer is in csp.js)
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        // nonce is injected by csp.js middleware
        (req, res) => `'nonce-${res.locals.cspNonce}'`,
      ],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: [
        "'self'",
        'https://firestore.googleapis.com',
        'https://identitytoolkit.googleapis.com',
        'https://securetoken.googleapis.com',
      ],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      objectSrc: ["'none'"],
      mediaSrc: ["'none'"],
      frameSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null,
    },
  },

  // Cross-Origin-Embedder-Policy
  crossOriginEmbedderPolicy: false, // set to true for full isolation if needed
});

/**
 * Custom security headers not covered by helmet
 */
function customSecurityHeaders(req, res, next) {
  // Permissions-Policy (formerly Feature-Policy)
  res.setHeader(
    'Permissions-Policy',
    'geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()'
  );

  // Cache-Control for API responses
  if (req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
  }

  // Cross-Origin-Resource-Policy
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');

  next();
}

module.exports = { securityHeaders, customSecurityHeaders };
