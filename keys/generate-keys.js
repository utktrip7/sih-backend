const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const keysDir = path.join(__dirname);

// Generate Ed25519 keypair using Node's native crypto
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// Save to local files
fs.writeFileSync(path.join(keysDir, 'public.pem'), publicKey);
fs.writeFileSync(path.join(keysDir, 'private.pem'), privateKey);

console.log("Keys generated successfully in the /keys directory.");
console.log("CRITICAL: Add keys/private.pem to your .gitignore right now!");