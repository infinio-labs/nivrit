const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

function findHelper() {
  if (process.env.NIVRIT_CRYPTO_HELPER) return process.env.NIVRIT_CRYPTO_HELPER;
  const exe = process.platform === 'win32' ? 'nivrit-crypto-helper.exe' : 'nivrit-crypto-helper';
  // Bundled platform package, installed via optionalDependencies (the package
  // manager picks the one matching os+cpu). See scripts/build-platform-packages.sh.
  try {
    return require.resolve(`@nivrit/helper-${process.platform}-${process.arch}/bin/${exe}`);
  } catch (_) { /* not installed for this platform — fall through */ }
  // Dev fallback: monorepo cargo build output.
  for (const sub of ['release', 'debug']) {
    const c = path.join(__dirname, '..', '..', '..', 'target', sub, exe);
    if (fs.existsSync(c)) return c;
  }
  throw new Error(
    'nivrit-crypto-helper not found. Reinstall @nivrit/sdk on a supported platform, ' +
    'set NIVRIT_CRYPTO_HELPER, or run `cargo build --release -p nivrit-crypto-helper`.'
  );
}

class HelperCrypto {
  constructor(helperPath) {
    this.helperPath = helperPath || findHelper();
  }

  call(req) {
    const result = spawnSync(this.helperPath, [], {
      input: JSON.stringify(req),
      encoding: 'utf-8',
      timeout: 30000,
    });
    if (result.error) throw new Error(`crypto helper failed: ${result.error.message}`);
    if (result.status !== 0) throw new Error(`crypto helper exited ${result.status}: ${result.stderr}`);
    let resp;
    try {
      resp = JSON.parse(result.stdout.trim());
    } catch (e) {
      throw new Error(`crypto helper returned invalid JSON: ${result.stdout}`);
    }
    if (!resp.ok) throw new Error(resp.error || 'crypto helper error');
    return resp.result;
  }

  hybridSuiteId() {
    return this.call({ op: 'hybrid_suite_id' });
  }

  generateKeypair(password) {
    return this.call({ op: 'generate_keypair', password });
  }

  decryptPrivateKey(encryptedPrivateKey, nonce, password) {
    return this.call({
      op: 'decrypt_private_key',
      encrypted_private_key: encryptedPrivateKey,
      nonce,
      password,
    }).private_key;
  }

  decapsulateProjectKey(encryptedProjectKey, privateKey) {
    return this.call({
      op: 'decapsulate_project_key',
      encrypted_project_key: encryptedProjectKey,
      private_key: privateKey,
    }).project_key;
  }

  encryptValue(plaintext, key) {
    return this.call({ op: 'encrypt_value', plaintext, key });
  }

  decryptValue(ciphertext, nonce, key) {
    return this.call({ op: 'decrypt_value', ciphertext, nonce, key }).plaintext;
  }

  encapsulateProjectKey(projectKey, recipientPublicKey) {
    return this.call({
      op: 'encapsulate_project_key',
      project_key: projectKey,
      recipient_public_key: recipientPublicKey,
    });
  }
}

module.exports = { HelperCrypto };
