'use strict';

/**
 * Firebase Admin wrapper — injectable for testing.
 * In production, verifies real Firebase ID tokens.
 * In test environments, this module is mocked via jest.mock().
 */

let admin = null;

function getAdmin() {
  if (admin) return admin;

  try {
    // eslint-disable-next-line global-require
    admin = require('firebase-admin');

    if (!admin.apps.length) {
      const projectId = process.env.FIREBASE_PROJECT_ID;
      const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
      const privateKeyB64 = process.env.FIREBASE_PRIVATE_KEY_BASE64;

      if (projectId && clientEmail && privateKeyB64) {
        const privateKey = Buffer.from(privateKeyB64, 'base64').toString('utf8');
        admin.initializeApp({
          credential: admin.credential.cert({ projectId, clientEmail, privateKey }),
        });
      } else {
        // Fallback: use application default credentials (e.g., Cloud Run)
        admin.initializeApp();
      }
    }
  } catch (err) {
    throw new Error(`Firebase Admin init failed: ${err.message}`);
  }

  return admin;
}

/**
 * Verify a Firebase ID token.
 * @param {string} idToken
 * @returns {Promise<{uid: string, email: string}>}
 */
async function verifyIdToken(idToken) {
  const a = getAdmin();
  const decoded = await a.auth().verifyIdToken(idToken);
  return { uid: decoded.uid, email: decoded.email || '' };
}

module.exports = { verifyIdToken };
