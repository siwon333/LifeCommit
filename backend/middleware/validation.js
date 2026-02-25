'use strict';

const { body, param, query, validationResult } = require('express-validator');
const validator = require('validator');
const { sanitizeInput } = require('./csp');

/**
 * Input Validation + SQL/NoSQL Injection Defense
 *
 * Strategy:
 *  1. express-validator chains declare expected shape/type/length.
 *  2. sanitizeInput() strips HTML on all string fields (XSS).
 *  3. noSqlSanitize() removes MongoDB operator keys ($, .) from objects.
 *  4. handleValidationErrors() converts failures to 422 response.
 */

// ─── NoSQL Injection Prevention ───────────────────────────────────────────────

const NOSQL_OPERATORS = /^\$|^\./;

/**
 * Remove keys that look like NoSQL operators from an object (recursive).
 * Protects against MongoDB $where, $gt injection etc.
 */
function noSqlSanitize(obj) {
  if (Array.isArray(obj)) return obj.map(noSqlSanitize);
  if (obj !== null && typeof obj === 'object') {
    const result = {};
    for (const [k, v] of Object.entries(obj)) {
      if (NOSQL_OPERATORS.test(k)) continue; // drop operator keys
      result[k] = noSqlSanitize(v);
    }
    return result;
  }
  if (typeof obj === 'string') return sanitizeInput(obj);
  return obj;
}

/**
 * Express middleware: sanitize req.body, req.query, req.params against NoSQL injection.
 */
function noSqlSanitizeMiddleware(req, res, next) {
  if (req.body) req.body = noSqlSanitize(req.body);
  if (req.query) req.query = noSqlSanitize(req.query);
  // params are read-only in express but we can sanitize for reporting
  next();
}

// ─── Validation Error Handler ─────────────────────────────────────────────────

/**
 * Middleware: convert express-validator errors to a 422 response.
 */
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      error: 'Validation Error',
      code: 'VALIDATION_FAILED',
      details: errors.array().map((e) => ({
        field: e.path,
        message: e.msg,
      })),
    });
  }
  next();
}

// ─── Validation Chain Helpers ─────────────────────────────────────────────────

/** Common sanitizer: trim + strip HTML */
const sanitizeStr = (field) =>
  body(field)
    .trim()
    .customSanitizer((v) => (typeof v === 'string' ? sanitizeInput(v) : v));

// ─── Auth Validation Chains ───────────────────────────────────────────────────

const validateLogin = [
  body('idToken')
    .notEmpty().withMessage('idToken is required')
    .isString().withMessage('idToken must be a string')
    .isLength({ max: 4096 }).withMessage('idToken too long'),
  handleValidationErrors,
];

const validateRegister = [
  body('email')
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Invalid email format')
    .normalizeEmail()
    .isLength({ max: 254 }),
  body('password')
    .notEmpty().withMessage('Password is required')
    .isLength({ min: 8, max: 128 }).withMessage('Password must be 8–128 characters')
    .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
    .matches(/[a-z]/).withMessage('Password must contain a lowercase letter')
    .matches(/[0-9]/).withMessage('Password must contain a digit'),
  handleValidationErrors,
];

// ─── Hobby Validation Chains ──────────────────────────────────────────────────

const HOBBY_TYPES = ['quant', 'binary'];
const HOBBY_UNITS = ['분', '개', '회', '페이지', 'km', '잔', ''];

const validateCreateHobby = [
  sanitizeStr('name')
    .notEmpty().withMessage('Hobby name is required')
    .isLength({ min: 1, max: 20 }).withMessage('Hobby name must be 1–20 characters'),
  body('type')
    .notEmpty().withMessage('Type is required')
    .isIn(HOBBY_TYPES).withMessage(`Type must be one of: ${HOBBY_TYPES.join(', ')}`),
  body('icon')
    .optional()
    .isString()
    .isLength({ max: 10 }).withMessage('Icon too long'),
  body('color')
    .optional()
    .matches(/^#[0-9a-fA-F]{6}$/).withMessage('Color must be a valid hex color'),
  body('targetValue')
    .optional()
    .isFloat({ min: 0, max: 100000 }).withMessage('targetValue must be 0–100000'),
  body('unit')
    .optional()
    .isIn(HOBBY_UNITS).withMessage(`Unit must be one of: ${HOBBY_UNITS.join(', ')}`),
  sanitizeStr('description').optional().isLength({ max: 200 }),
  handleValidationErrors,
];

const validateUpdateHobby = [
  param('id').isUUID(4).withMessage('Invalid hobby ID'),
  ...validateCreateHobby.slice(0, -1), // reuse but re-add error handler
  handleValidationErrors,
];

// ─── Record Validation Chains ─────────────────────────────────────────────────

const validateCreateRecord = [
  body('hobbyId')
    .notEmpty().withMessage('hobbyId is required')
    .isUUID(4).withMessage('Invalid hobbyId'),
  body('date')
    .notEmpty().withMessage('date is required')
    .matches(/^\d{4}-\d{2}-\d{2}$/).withMessage('date must be YYYY-MM-DD')
    .custom((v) => {
      const d = new Date(v);
      if (isNaN(d.getTime())) throw new Error('Invalid date');
      return true;
    }),
  body('value')
    .optional()
    .isFloat({ min: 0, max: 100000 }).withMessage('value must be 0–100000'),
  body('achieved')
    .optional()
    .isBoolean().withMessage('achieved must be boolean'),
  sanitizeStr('memo').optional().isLength({ max: 500 }),
  handleValidationErrors,
];

const validateIdParam = [
  param('id').isUUID(4).withMessage('Invalid ID'),
  handleValidationErrors,
];

module.exports = {
  noSqlSanitize,
  noSqlSanitizeMiddleware,
  handleValidationErrors,
  validateLogin,
  validateRegister,
  validateCreateHobby,
  validateUpdateHobby,
  validateCreateRecord,
  validateIdParam,
};
