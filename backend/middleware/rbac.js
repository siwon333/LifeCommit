'use strict';

/**
 * RBAC / ABAC + Tenant Isolation
 *
 * Roles:
 *   admin  — full access to all tenants
 *   user   — access only to own tenant (UID-scoped)
 *   viewer — read-only access to own tenant
 *
 * Tenant Isolation:
 *   Every data resource is tagged with a tenantId = ownerUid.
 *   Users can only access resources where tenantId === req.user.uid
 *   unless they are admin.
 *
 * ABAC extensions:
 *   requireOwner(getResourceOwnerId) — checks resource owner dynamically.
 */

const ROLE_HIERARCHY = {
  admin: 3,
  user: 2,
  viewer: 1,
};

const PERMISSIONS = {
  // hobby operations
  'hobby:read':   ['admin', 'user', 'viewer'],
  'hobby:create': ['admin', 'user'],
  'hobby:update': ['admin', 'user'],
  'hobby:delete': ['admin', 'user'],
  // record operations
  'record:read':   ['admin', 'user', 'viewer'],
  'record:create': ['admin', 'user'],
  'record:update': ['admin', 'user'],
  'record:delete': ['admin', 'user'],
  // admin operations
  'admin:users:read': ['admin'],
  'admin:audit:read': ['admin'],
  'admin:any':        ['admin'],
};

class ForbiddenError extends Error {
  constructor(message, code = 'FORBIDDEN') {
    super(message);
    this.name = 'ForbiddenError';
    this.code = code;
    this.status = 403;
  }
}

/**
 * Check if a role has a given permission.
 */
function hasPermission(role, permission) {
  const allowed = PERMISSIONS[permission];
  if (!allowed) return false;
  return allowed.includes(role);
}

/**
 * Middleware: require the user to have a specific permission.
 * Must run after authMiddleware.
 */
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized', code: 'NO_USER' });
    }
    if (!hasPermission(req.user.role, permission)) {
      return res.status(403).json({
        error: 'Forbidden',
        code: 'INSUFFICIENT_PERMISSION',
        required: permission,
      });
    }
    next();
  };
}

/**
 * Middleware: require minimum role level.
 */
function requireRole(minRole) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized', code: 'NO_USER' });
    }
    const userLevel = ROLE_HIERARCHY[req.user.role] || 0;
    const requiredLevel = ROLE_HIERARCHY[minRole] || 0;
    if (userLevel < requiredLevel) {
      return res.status(403).json({
        error: 'Forbidden',
        code: 'INSUFFICIENT_ROLE',
        required: minRole,
        current: req.user.role,
      });
    }
    next();
  };
}

/**
 * Middleware: enforce tenant isolation.
 * Admin users bypass this check.
 * For all others, tenantId param must match req.user.uid.
 *
 * @param {Function} getTenantId - async fn(req) → tenantId string
 */
function requireTenantAccess(getTenantId) {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized', code: 'NO_USER' });
    }

    // Admins bypass tenant isolation
    if (req.user.role === 'admin') return next();

    try {
      const tenantId = await getTenantId(req);
      if (!tenantId) {
        return res.status(404).json({ error: 'Resource not found', code: 'NOT_FOUND' });
      }
      if (tenantId !== req.user.uid) {
        return res.status(403).json({
          error: 'Forbidden',
          code: 'TENANT_MISMATCH',
        });
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

/**
 * ABAC: check resource ownership dynamically.
 * @param {Function} getOwnerId - async fn(req) → ownerId string (or null if not found)
 */
function requireOwner(getOwnerId) {
  return requireTenantAccess(getOwnerId);
}

/**
 * Scope a Firestore/DB query to the current user's tenant.
 * Returns the uid to scope by (or null for admins who can see all).
 */
function getTenantScope(req) {
  if (!req.user) return null;
  if (req.user.role === 'admin') return null; // admin sees all
  return req.user.uid;
}

module.exports = {
  hasPermission,
  requirePermission,
  requireRole,
  requireTenantAccess,
  requireOwner,
  getTenantScope,
  ForbiddenError,
  PERMISSIONS,
  ROLE_HIERARCHY,
};
