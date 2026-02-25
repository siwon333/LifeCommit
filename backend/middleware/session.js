'use strict';

const session = require('express-session');

/**
 * Session Middleware
 * Cookie flags: HttpOnly, Secure (prod), SameSite=strict
 * Session ID rotation happens on login (see auth route).
 * Memory store used in development/test; swap for Redis/DB in production.
 */

const SESSION_MAX_AGE = 24 * 60 * 60 * 1000; // 24 hours

function createSessionMiddleware(opts = {}) {
  const isProd = (opts.nodeEnv || process.env.NODE_ENV) === 'production';

  return session({
    name: 'sid',
    secret: opts.secret || process.env.SESSION_SECRET || 'dev-session-secret-change-me!',
    resave: false,
    saveUninitialized: false,
    store: opts.store || undefined, // undefined → default MemoryStore (dev/test)
    cookie: {
      httpOnly: true,
      secure: opts.secure !== undefined ? opts.secure : isProd,
      sameSite: 'strict',
      maxAge: SESSION_MAX_AGE,
      path: '/',
    },
    rolling: true, // reset maxAge on each request
  });
}

const sessionMiddleware = createSessionMiddleware();

module.exports = { sessionMiddleware, createSessionMiddleware, SESSION_MAX_AGE };
