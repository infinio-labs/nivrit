// Smallest check on helper resolution. Run: node test/find_helper.js
const assert = require('assert');

process.env.NIVRIT_CRYPTO_HELPER = '/tmp/fake-helper';
const { HelperCrypto } = require('../src/crypto');
assert.strictEqual(new HelperCrypto().helperPath, '/tmp/fake-helper');

console.log('ok');
