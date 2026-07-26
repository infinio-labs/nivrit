// Packaged-install regression: run AFTER `bun install` of the SDK tarball plus
// the matching @nivrit/helper-* tarball, from a temp project, with
// NIVRIT_CRYPTO_HELPER unset and no cargo build present. Proves the
// optionalDependency helper resolves and crypto works.
const assert = require('assert');
const { HelperCrypto } = require('@nivrit/sdk');

const c = new HelperCrypto();
assert(c.helperPath.includes('@nivrit/helper-'), `not bundled: ${c.helperPath}`);
assert.strictEqual(c.hybridSuiteId(), 'hybrid_x25519_ml_kem_768_aes256gcm_v1');

const kp = c.generateKeypair('pw');
const priv = c.decryptPrivateKey(kp.encrypted_private_key, kp.private_key_nonce, 'pw');
const pk = Buffer.alloc(32).toString('base64');
const enc = c.encapsulateProjectKey(pk, kp.public_key);
const blob = Buffer.from(JSON.stringify(enc)).toString('base64');
assert.strictEqual(c.decapsulateProjectKey(blob, priv), pk, 'roundtrip mismatch');

console.log(`NODE PACKAGED ROUNDTRIP OK (bundled: ${c.helperPath})`);
