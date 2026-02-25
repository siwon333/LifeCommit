'use strict';

/**
 * Jest global test setup
 */

// Set test environment variables before any module loads
process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-session-secret-that-is-at-least-32-chars!';
process.env.JWT_SECRET = 'test-jwt-secret-that-is-at-least-32-chars-long!!';
process.env.COOKIE_SECRET = 'test-cookie-secret-that-is-32chars!!';
process.env.JWT_EXPIRES_IN = '15m';
process.env.JWT_REFRESH_EXPIRES_IN = '7d';
process.env.ALLOWED_ORIGINS = 'http://localhost:3000,https://example.com';
process.env.FIREBASE_PROJECT_ID = 'test-project';
process.env.RATE_LIMIT_WINDOW_MS = '60000';
process.env.RATE_LIMIT_MAX = '1000';   // High limit to avoid rate-limiting in tests
process.env.AUTH_RATE_LIMIT_MAX = '50';
