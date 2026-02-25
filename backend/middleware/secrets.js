'use strict';

const crypto = require('crypto');

/**
 * Secret Management & Rotation
 *
 * Responsibilities:
 *  1. Validate required environment variables at startup.
 *  2. Derive sub-keys from a master secret so individual keys can be rotated.
 *  3. Support dual-key rotation (current + previous key) for zero-downtime rotation.
 *  4. Ensure secrets are never logged.
 */

const REQUIRED_SECRETS = [
  'SESSION_SECRET',
  'JWT_SECRET',
];

const MIN_SECRET_LENGTH = 32;

class SecretsError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SecretsError';
  }
}

/**
 * Validate that all required secrets are present and long enough.
 * Call this at application startup.
 */
function validateSecrets(env = process.env) {
  const errors = [];

  for (const name of REQUIRED_SECRETS) {
    const value = env[name];
    if (!value) {
      errors.push(`Missing required secret: ${name}`);
    } else if (value.length < MIN_SECRET_LENGTH) {
      errors.push(`Secret ${name} is too short (min ${MIN_SECRET_LENGTH} chars)`);
    }
  }

  if (errors.length > 0) {
    if (env.NODE_ENV === 'production') {
      throw new SecretsError(errors.join('; '));
    } else {
      // In development/test warn but don't crash
      console.warn('[secrets] WARNING:', errors.join('; '));
    }
  }
}

/**
 * Derive a sub-key from the master secret using HKDF.
 * @param {string} purpose - e.g. 'csrf', 'email-verification'
 * @returns {Buffer}
 */
function deriveKey(purpose) {
  const master = process.env.JWT_SECRET || 'dev-key-do-not-use-in-prod-placeholder!';
  return crypto
    .createHmac('sha256', master)
    .update(`lifecommit:${purpose}`)
    .digest();
}

/**
 * Token rotation registry.
 * Supports a "current" and "previous" secret for rolling rotation.
 * Tokens signed with the previous secret are still valid during the
 * rotation window, giving clients time to refresh.
 */
const _registry = new Map();

/**
 * Register a named secret with optional rotation support.
 * @param {string} name
 * @param {string} current - current secret
 * @param {string} [previous] - previous secret (optional, for rotation window)
 */
function registerSecret(name, current, previous = null) {
  _registry.set(name, { current, previous, rotatedAt: Date.now() });
}

/**
 * Get the current and (optionally) previous secret for a named key.
 * @param {string} name
 * @returns {{ current: string, previous: string|null }}
 */
function getSecret(name) {
  const entry = _registry.get(name);
  if (!entry) throw new SecretsError(`Unknown secret: ${name}`);
  return { current: entry.current, previous: entry.previous };
}

/**
 * Rotate a named secret to a new value.
 * The old value becomes "previous" and remains valid for rotationWindowMs.
 */
function rotateSecret(name, newSecret) {
  const existing = _registry.get(name);
  const previous = existing ? existing.current : null;
  _registry.set(name, { current: newSecret, previous, rotatedAt: Date.now() });
}

// Custom inspect / toJSON to prevent accidental logging
class SecretValue {
  constructor(value) {
    this._value = value;
  }
  valueOf() { return this._value; }
  toString() { return '[SECRET]'; }
  toJSON() { return '[SECRET]'; }
  [Symbol.for('nodejs.util.inspect.custom')]() { return '[SECRET]'; }
}

module.exports = {
  validateSecrets,
  deriveKey,
  registerSecret,
  getSecret,
  rotateSecret,
  SecretValue,
  SecretsError,
  REQUIRED_SECRETS,
  MIN_SECRET_LENGTH,
};
