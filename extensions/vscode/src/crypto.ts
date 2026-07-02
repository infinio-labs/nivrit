import * as path from 'path';

let wasmModule: {
  init_panic_hook: () => void;
  decrypt_private_key: (encrypted_private_key_b64: string, nonce_b64: string, password: string) => any;
  decapsulate_project_key: (encapsulated: any, private_key_b64: string) => any;
  decrypt_value: (ciphertext_b64: string, nonce_b64: string, key_b64: string) => any;
  hybrid_suite_id: () => string;
} | null = null;

export function initCrypto(extensionPath: string): void {
  if (wasmModule) return;
  const wasmPath = path.join(extensionPath, 'wasm', 'pkg', 'nivrit_web_crypto.js');
  const mod = require(wasmPath);
  mod.init_panic_hook();
  wasmModule = mod;
}

function getWasm() {
  if (!wasmModule) throw new Error('crypto not initialized; call initCrypto() first');
  return wasmModule;
}

export interface EncapsulatedProjectKey {
  suite: string;
  encapsulated_key: string;
  ml_kem_ciphertext: string;
  nonce: string;
  ciphertext: string;
}

export function decryptPrivateKey(
  encryptedPrivateKey: string,
  nonce: string,
  password: string
): string {
  const result = getWasm().decrypt_private_key(encryptedPrivateKey, nonce, password);
  return result.private_key as string;
}

export function decapsulateProjectKey(
  encapsulated: EncapsulatedProjectKey,
  privateKeyBase64: string
): string {
  const result = getWasm().decapsulate_project_key(encapsulated, privateKeyBase64);
  return result.project_key as string;
}

export function decryptValue(ciphertextBase64: string, nonceBase64: string, keyBase64: string): string {
  const result = getWasm().decrypt_value(ciphertextBase64, nonceBase64, keyBase64);
  return result.plaintext as string;
}

export function hybridSuiteId(): string {
  return getWasm().hybrid_suite_id();
}
