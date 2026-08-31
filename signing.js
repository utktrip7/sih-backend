const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// 1. Load Keys (Environment variables first, fallback to local files)
let privateKey, publicKey;

try {
    if (process.env.SIGNING_PRIVATE_KEY && process.env.SIGNING_PUBLIC_KEY) {
        privateKey = process.env.SIGNING_PRIVATE_KEY;
        publicKey = process.env.SIGNING_PUBLIC_KEY;
    } else {
        privateKey = fs.readFileSync(path.join(__dirname, 'keys', 'private.pem'), 'utf8');
        publicKey = fs.readFileSync(path.join(__dirname, 'keys', 'public.pem'), 'utf8');
    }
} catch (err) {
    console.error("⚠️ CRITICAL: Could not load Ed25519 keys. Did you run 'node keys/generate-keys.js'?");
}

/**
 * Signs a payload string using the institution's private key.
 * Returns a hex-encoded signature.
 */
function signPayload(payload) {
    if (!privateKey) throw new Error("Private key is missing!");
    const signatureBuffer = crypto.sign(null, Buffer.from(payload, 'utf8'), privateKey);
    return signatureBuffer.toString('hex');
}

/**
 * Verifies a payload against a hex signature using the public key.
 * Never throws; returns false if malformed or tampered.
 */
function verifyPayload(payload, signatureHex) {
    if (!publicKey || !signatureHex) return false;
    try {
        const signatureBuffer = Buffer.from(signatureHex, 'hex');
        return crypto.verify(null, Buffer.from(payload, 'utf8'), publicKey, signatureBuffer);
    } catch (err) {
        return false;
    }
}

/**
 * Returns the public key to share with third-party verifiers.
 */
function getPublicKeyPem() {
    return publicKey;
}

module.exports = { signPayload, verifyPayload, getPublicKeyPem };