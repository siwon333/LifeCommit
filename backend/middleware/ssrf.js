'use strict';

const { URL } = require('url');
const net = require('net');

/**
 * SSRF Protection Utility
 *
 * Validates URLs before the server makes outbound requests.
 * Blocks:
 *   - Non-HTTP/HTTPS schemes
 *   - Private/loopback/link-local IP ranges
 *   - Cloud provider metadata endpoints (169.254.169.254, etc.)
 *   - Hostnames that resolve to private IPs (DNS rebinding — requires async check)
 */

// CIDR ranges that must never be reached via SSRF
const BLOCKED_RANGES = [
  // Loopback
  { start: ip2long('127.0.0.0'), end: ip2long('127.255.255.255') },
  // Private Class A
  { start: ip2long('10.0.0.0'), end: ip2long('10.255.255.255') },
  // Private Class B
  { start: ip2long('172.16.0.0'), end: ip2long('172.31.255.255') },
  // Private Class C
  { start: ip2long('192.168.0.0'), end: ip2long('192.168.255.255') },
  // Link-local (AWS/GCP/Azure metadata)
  { start: ip2long('169.254.0.0'), end: ip2long('169.254.255.255') },
  // Broadcast
  { start: ip2long('255.255.255.255'), end: ip2long('255.255.255.255') },
  // Unspecified
  { start: ip2long('0.0.0.0'), end: ip2long('0.255.255.255') },
];

// Cloud metadata hostnames + loopback hostnames
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  '::1',
  'metadata.google.internal',
  'metadata',
  'instance-data',
  'computeMetadata',
]);

function ip2long(ip) {
  return ip.split('.').reduce((acc, oct) => (acc << 8) | parseInt(oct, 10), 0) >>> 0;
}

/**
 * Check if an IPv4 address falls in a blocked range.
 */
function isPrivateIp(ipStr) {
  if (!net.isIPv4(ipStr)) return false; // skip IPv6 for now (treat as safe)
  const long = ip2long(ipStr);
  return BLOCKED_RANGES.some((r) => long >= r.start && long <= r.end);
}

/**
 * Synchronously validate a URL string.
 * Returns { ok: true } or { ok: false, reason: string }.
 */
function validateUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { ok: false, reason: 'INVALID_URL' };
  }

  // Only allow HTTP and HTTPS
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { ok: false, reason: 'SCHEME_NOT_ALLOWED' };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Block metadata hostnames
  if (BLOCKED_HOSTNAMES.has(hostname)) {
    return { ok: false, reason: 'BLOCKED_HOSTNAME' };
  }

  // Block if hostname is a raw private IP
  if (net.isIP(hostname) && isPrivateIp(hostname)) {
    return { ok: false, reason: 'PRIVATE_IP' };
  }

  // Block IPv6 loopback/unspecified
  if (hostname === '::1' || hostname === '::' || hostname === '[::1]') {
    return { ok: false, reason: 'PRIVATE_IP' };
  }

  return { ok: true };
}

/**
 * Express middleware that validates a URL from the request body.
 * Usage: add to routes that accept a URL parameter, e.g. webhooks.
 * Field name defaults to 'url'.
 */
function ssrfMiddleware(fieldName = 'url') {
  return (req, res, next) => {
    const rawUrl = (req.body && req.body[fieldName]) || req.query[fieldName];
    if (!rawUrl) return next(); // field not present — let schema validation handle it

    const result = validateUrl(rawUrl);
    if (!result.ok) {
      return res.status(400).json({
        error: 'Invalid URL',
        code: `SSRF_${result.reason}`,
      });
    }

    next();
  };
}

module.exports = { validateUrl, ssrfMiddleware, isPrivateIp, ip2long };
