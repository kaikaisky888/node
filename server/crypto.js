/**
 * Cryptographic utilities
 * - ECC P-256 (prime256v1) ECDSA signature verification
 * - CSPRNG token generation
 * - SHA-256 hashing
 */

import crypto from 'node:crypto';

/**
 * Convert raw ECDSA signature (r || s) to DER format
 * Web Crypto API returns raw signatures (64 bytes for P-256: 32 bytes r + 32 bytes s)
 * Node.js crypto.verify expects DER-encoded signatures
 */
function rawSigToDer(rawSig) {
  const len = rawSig.length;
  const halfLen = len / 2;
  let r = rawSig.subarray(0, halfLen);
  let s = rawSig.subarray(halfLen);

  // Remove leading zeros but keep at least one byte
  let rStart = 0;
  while (rStart < r.length - 1 && r[rStart] === 0) rStart++;
  r = r.subarray(rStart);

  let sStart = 0;
  while (sStart < s.length - 1 && s[sStart] === 0) sStart++;
  s = s.subarray(sStart);

  // If high bit is set, prepend a 0x00 byte (positive integer in DER)
  const rPad = r[0] & 0x80 ? 1 : 0;
  const sPad = s[0] & 0x80 ? 1 : 0;

  const rLen = r.length + rPad;
  const sLen = s.length + sPad;
  const totalLen = rLen + sLen + 4; // 4 = two 0x02 type bytes + two length bytes

  const der = Buffer.alloc(totalLen + 2); // +2 for 0x30 and total length
  let offset = 0;
  der[offset++] = 0x30; // SEQUENCE
  der[offset++] = totalLen;
  der[offset++] = 0x02; // INTEGER
  der[offset++] = rLen;
  if (rPad) der[offset++] = 0;
  r.copy(der, offset);
  offset += r.length;
  der[offset++] = 0x02; // INTEGER
  der[offset++] = sLen;
  if (sPad) der[offset++] = 0;
  s.copy(der, offset);

  return der;
}

/**
 * Verify ECDSA P-256 signature
 * @param {string} pubKeyHex - Raw public key as hex (65 bytes uncompressed: 04 + x + y)
 * @param {string} message - The signed message
 * @param {string} signatureB64 - Base64url-encoded raw signature (from Web Crypto API)
 * @returns {boolean}
 */
export function verifyECDSASignature(pubKeyHex, message, signatureB64) {
  try {
    // Convert raw public key hex to SPKI DER format
    const rawKey = Buffer.from(pubKeyHex, 'hex');
    if (rawKey.length !== 65 || rawKey[0] !== 0x04) {
      console.log('[Crypto] Invalid public key: length=' + rawKey.length + ', first=' + (rawKey[0]?.toString(16) || 'none'));
      return false;
    }

    // Build SPKI header for P-256
    const SPKI_HEADER = Buffer.from(
      '3059301306072a8648ce3d020106082a8648ce3d030107034200',
      'hex'
    );
    const spkiDer = Buffer.concat([SPKI_HEADER, rawKey]);

    const publicKey = crypto.createPublicKey({
      key: spkiDer,
      format: 'der',
      type: 'spki',
    });

    // Decode base64url signature
    const sigBase64 = signatureB64.replace(/-/g, '+').replace(/_/g, '/');
    const sigBuffer = Buffer.from(sigBase64, 'base64');
    console.log('[Crypto] Signature length:', sigBuffer.length, 'hex:', sigBuffer.toString('hex').substring(0, 40) + '...');

    // Web Crypto API returns raw signatures (r || s), convert to DER
    let derSig;
    if (sigBuffer.length === 64) {
      // Raw P-256 signature (32 bytes r + 32 bytes s)
      derSig = rawSigToDer(sigBuffer);
      console.log('[Crypto] Converted raw sig to DER, length:', derSig.length);
    } else if (sigBuffer.length > 64 && sigBuffer[0] === 0x30) {
      // Already DER format
      derSig = sigBuffer;
      console.log('[Crypto] Signature already in DER format');
    } else {
      console.log('[Crypto] Unexpected signature format, length:', sigBuffer.length);
      return false;
    }

    const verifier = crypto.createVerify('SHA256');
    verifier.update(message);
    verifier.end();

    const result = verifier.verify(publicKey, derSig);
    console.log('[Crypto] Verification result:', result);
    return result;
  } catch (e) {
    console.log('[Crypto] Verification error:', e.message);
    return false;
  }
}

/**
 * Generate a one-time token
 * Format: CSPRNG 32 bytes + timestamp + pubKeyHash
 */
export function generateToken(pubKeyHex) {
  const randomBytes = crypto.randomBytes(32);
  const timestamp = Date.now().toString(36);
  const pubKeyHash = crypto
    .createHash('sha256')
    .update(pubKeyHex)
    .digest('hex')
    .slice(0, 16);

  return (
    randomBytes.toString('hex') + '.' + timestamp + '.' + pubKeyHash
  );
}

/**
 * Generate a session ID
 */
export function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * SHA-256 hash
 */
export function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Hash a public key for storage/comparison
 */
export function hashPublicKey(pubKeyHex) {
  return sha256(pubKeyHex);
}
