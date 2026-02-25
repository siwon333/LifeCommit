'use strict';

require('express-async-errors');
const { Router } = require('express');
const { v4: uuidv4 } = require('uuid');

const { authMiddleware } = require('../middleware/auth');
const {
  requirePermission,
  requireRole,
  getTenantScope,
} = require('../middleware/rbac');
const {
  validateCreateHobby,
  validateUpdateHobby,
  validateCreateRecord,
  validateIdParam,
} = require('../middleware/validation');
const { audit } = require('../middleware/auditLog');

const router = Router();

// All data routes require authentication (least privilege: auth first)
router.use(authMiddleware);

// ─── In-memory data store (replace with Firestore in production) ──────────────

const _hobbies = new Map(); // uid → Hobby[]
const _records = new Map(); // uid → Record[]

function getHobbies(uid) { return _hobbies.get(uid) || []; }
function getRecords(uid) { return _records.get(uid) || []; }
function setHobbies(uid, arr) { _hobbies.set(uid, arr); }
function setRecords(uid, arr) { _records.set(uid, arr); }

// ─── Hobbies ──────────────────────────────────────────────────────────────────

/**
 * GET /api/data/hobbies
 * List hobbies for the authenticated user.
 */
router.get('/hobbies', requirePermission('hobby:read'), (req, res) => {
  const scope = getTenantScope(req);
  // Admin without scope sees all users' hobbies (just aggregate for demo)
  const hobbies = scope
    ? getHobbies(scope)
    : Array.from(_hobbies.values()).flat();
  return res.json({ hobbies });
});

/**
 * POST /api/data/hobbies
 * Create a new hobby.
 */
router.post(
  '/hobbies',
  requirePermission('hobby:create'),
  validateCreateHobby,
  (req, res) => {
    const uid = req.user.uid;
    const { name, type, icon, color, targetValue, unit, description } = req.body;

    const hobby = {
      id: uuidv4(),
      name,
      type,
      icon: icon || '⭐',
      color: color || '#26a641',
      targetValue: type === 'quant' ? Number(targetValue) : undefined,
      unit: type === 'quant' ? unit : undefined,
      description: type === 'binary' ? description : undefined,
      isActive: true,
      createdAt: new Date().toISOString(),
      ownerUid: uid,
    };

    const hobbies = getHobbies(uid);
    hobbies.push(hobby);
    setHobbies(uid, hobbies);

    audit('HOBBY_CREATED', { uid, hobbyId: hobby.id });

    return res.status(201).json({ hobby });
  }
);

/**
 * PUT /api/data/hobbies/:id
 * Update a hobby (owner or admin only).
 */
router.put(
  '/hobbies/:id',
  requirePermission('hobby:update'),
  validateUpdateHobby,
  (req, res) => {
    const uid = req.user.uid;
    const { id } = req.params;
    const hobbies = getHobbies(uid);
    const idx = hobbies.findIndex((h) => h.id === id);

    if (idx === -1) {
      return res.status(404).json({ error: 'Hobby not found', code: 'NOT_FOUND' });
    }

    // Tenant isolation: only owner or admin can update
    if (hobbies[idx].ownerUid !== uid && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden', code: 'TENANT_MISMATCH' });
    }

    const { name, type, icon, color, targetValue, unit, description, isActive } = req.body;
    hobbies[idx] = {
      ...hobbies[idx],
      name: name !== undefined ? name : hobbies[idx].name,
      type: type !== undefined ? type : hobbies[idx].type,
      icon: icon !== undefined ? icon : hobbies[idx].icon,
      color: color !== undefined ? color : hobbies[idx].color,
      targetValue: targetValue !== undefined ? Number(targetValue) : hobbies[idx].targetValue,
      unit: unit !== undefined ? unit : hobbies[idx].unit,
      description: description !== undefined ? description : hobbies[idx].description,
      isActive: isActive !== undefined ? isActive : hobbies[idx].isActive,
      updatedAt: new Date().toISOString(),
    };
    setHobbies(uid, hobbies);

    audit('HOBBY_UPDATED', { uid, hobbyId: id });

    return res.json({ hobby: hobbies[idx] });
  }
);

/**
 * DELETE /api/data/hobbies/:id
 */
router.delete(
  '/hobbies/:id',
  requirePermission('hobby:delete'),
  validateIdParam,
  (req, res) => {
    const uid = req.user.uid;
    const { id } = req.params;
    const hobbies = getHobbies(uid);
    const idx = hobbies.findIndex((h) => h.id === id);

    if (idx === -1) {
      return res.status(404).json({ error: 'Hobby not found', code: 'NOT_FOUND' });
    }

    if (hobbies[idx].ownerUid !== uid && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden', code: 'TENANT_MISMATCH' });
    }

    hobbies.splice(idx, 1);
    setHobbies(uid, hobbies);

    audit('HOBBY_DELETED', { uid, hobbyId: id });

    return res.json({ message: 'Deleted' });
  }
);

// ─── Records ──────────────────────────────────────────────────────────────────

/**
 * GET /api/data/records
 */
router.get('/records', requirePermission('record:read'), (req, res) => {
  const scope = getTenantScope(req);
  const records = scope
    ? getRecords(scope)
    : Array.from(_records.values()).flat();
  return res.json({ records });
});

/**
 * POST /api/data/records
 */
router.post(
  '/records',
  requirePermission('record:create'),
  validateCreateRecord,
  (req, res) => {
    const uid = req.user.uid;
    const { hobbyId, date, value, achieved, memo } = req.body;

    // Verify hobby belongs to user
    const hobbies = getHobbies(uid);
    const hobby = hobbies.find((h) => h.id === hobbyId);
    if (!hobby) {
      return res.status(404).json({ error: 'Hobby not found', code: 'HOBBY_NOT_FOUND' });
    }

    const record = {
      id: uuidv4(),
      hobbyId,
      date,
      value: value !== undefined ? Number(value) : undefined,
      achieved: achieved !== undefined ? Boolean(achieved) : false,
      memo: memo || '',
      createdAt: new Date().toISOString(),
      ownerUid: uid,
    };

    const records = getRecords(uid);
    records.push(record);
    setRecords(uid, records);

    audit('RECORD_CREATED', { uid, recordId: record.id, hobbyId });

    return res.status(201).json({ record });
  }
);

/**
 * DELETE /api/data/records/:id
 */
router.delete(
  '/records/:id',
  requirePermission('record:delete'),
  validateIdParam,
  (req, res) => {
    const uid = req.user.uid;
    const { id } = req.params;
    const records = getRecords(uid);
    const idx = records.findIndex((r) => r.id === id);

    if (idx === -1) {
      return res.status(404).json({ error: 'Record not found', code: 'NOT_FOUND' });
    }

    if (records[idx].ownerUid !== uid && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden', code: 'TENANT_MISMATCH' });
    }

    records.splice(idx, 1);
    setRecords(uid, records);

    audit('RECORD_DELETED', { uid, recordId: id });

    return res.json({ message: 'Deleted' });
  }
);

// ─── Admin Routes ─────────────────────────────────────────────────────────────

/**
 * GET /api/data/admin/users
 * Admin only: list all user IDs that have data.
 */
router.get('/admin/users', requireRole('admin'), (req, res) => {
  const uids = Array.from(new Set([
    ..._hobbies.keys(),
    ..._records.keys(),
  ]));
  return res.json({ users: uids });
});

// ─── Test helpers (only in test env) ─────────────────────────────────────────

function _clearStore() {
  _hobbies.clear();
  _records.clear();
}

module.exports = router;
module.exports._clearStore = _clearStore;
