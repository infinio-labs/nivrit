import type {
  derive_auth_hash as DeriveAuthHashFn,
  derive_recovery_auth_hash as DeriveRecoveryAuthHashFn,
  generate_registration_material as GenerateRegistrationMaterialFn,
  reset_password_material as ResetPasswordMaterialFn,
  decrypt_private_key as DecryptPrivateKeyFn,
  decrypt_value as DecryptValueFn,
  decapsulate_project_key as DecapsulateProjectKeyFn,
  encapsulate_project_key as EncapsulateProjectKeyFn,
  encrypt_value as EncryptValueFn,
  generate_user_keypair as GenerateUserKeypairFn,
  hybrid_suite_id as HybridSuiteIdFn,
  init_panic_hook as InitPanicHookFn,
} from './wasm/pkg/nivrit_web_crypto';

let wasmModule: {
  init_panic_hook: typeof InitPanicHookFn;
  generate_user_keypair: typeof GenerateUserKeypairFn;
  generate_registration_material: typeof GenerateRegistrationMaterialFn;
  derive_auth_hash: typeof DeriveAuthHashFn;
  derive_recovery_auth_hash: typeof DeriveRecoveryAuthHashFn;
  reset_password_material: typeof ResetPasswordMaterialFn;
  decrypt_private_key: typeof DecryptPrivateKeyFn;
  encapsulate_project_key: typeof EncapsulateProjectKeyFn;
  decapsulate_project_key: typeof DecapsulateProjectKeyFn;
  encrypt_value: typeof EncryptValueFn;
  decrypt_value: typeof DecryptValueFn;
  hybrid_suite_id: typeof HybridSuiteIdFn;
} | null = null;

export async function initCrypto(): Promise<void> {
  if (wasmModule) return;
  // Use the wasm-pack "bundler" target for Vite/browser so that
  // vite-plugin-wasm can transform and emit the .wasm asset. Bun tests use
  // the "node" target, which is ignored by Vite via the @vite-ignore comment.
  const mod =
    typeof process !== 'undefined' && process.env?.NODE_ENV === 'test'
      ? await import(/* @vite-ignore */ './wasm/pkg-node/nivrit_web_crypto.js')
      : await import('./wasm/pkg/nivrit_web_crypto.js');
  mod.init_panic_hook();
  wasmModule = mod;
}

function getWasm() {
  if (!wasmModule) throw new Error('crypto not initialized; call initCrypto() first');
  return wasmModule;
}

export interface GeneratedKeypair {
  public_key: string;
  encrypted_private_key: string;
  private_key_nonce: string;
  private_key_algorithm: string;
}

export async function generateUserKeypair(password: string): Promise<GeneratedKeypair> {
  const wasm = getWasm();
  const result = wasm.generate_user_keypair(password);
  return result as unknown as GeneratedKeypair;
}

export async function decryptPrivateKey(
  encryptedPrivateKey: string,
  nonce: string,
  password: string
): Promise<string> {
  const wasm = getWasm();
  const result = wasm.decrypt_private_key(encryptedPrivateKey, nonce, password);
  return (result as unknown as { private_key: string }).private_key;
}

export interface EncapsulatedProjectKey {
  suite: string;
  encapsulated_key: string;
  ml_kem_ciphertext: string;
  nonce: string;
  ciphertext: string;
}

export async function encapsulateProjectKey(
  projectKeyBase64: string,
  recipientPublicKeyBase64: string
): Promise<EncapsulatedProjectKey> {
  const wasm = getWasm();
  const result = wasm.encapsulate_project_key(projectKeyBase64, recipientPublicKeyBase64);
  return result as unknown as EncapsulatedProjectKey;
}

export async function decapsulateProjectKey(
  encapsulated: EncapsulatedProjectKey,
  privateKeyBase64: string
): Promise<string> {
  const wasm = getWasm();
  const result = wasm.decapsulate_project_key(encapsulated as unknown as object, privateKeyBase64);
  return (result as unknown as { project_key: string }).project_key;
}

export interface EncryptedValue {
  ciphertext: string;
  nonce: string;
}

export async function encryptValue(plaintext: string, keyBase64: string): Promise<EncryptedValue> {
  const wasm = getWasm();
  const result = wasm.encrypt_value(plaintext, keyBase64);
  return result as unknown as EncryptedValue;
}

export async function decryptValue(
  ciphertextBase64: string,
  nonceBase64: string,
  keyBase64: string
): Promise<string> {
  const wasm = getWasm();
  const result = wasm.decrypt_value(ciphertextBase64, nonceBase64, keyBase64);
  return (result as unknown as { plaintext: string }).plaintext;
}

export function hybridSuiteId(): string {
  return getWasm().hybrid_suite_id();
}

/**
 * Everything registration needs, computed in WASM.
 *
 * The master password and the plaintext private key never cross back into
 * JavaScript, so they cannot be read by injected script or sent to the server.
 * `recovery_code` is the one value that must be shown to the user, once.
 */
export interface RegistrationMaterial {
  public_key: string;
  encrypted_private_key: string;
  private_key_nonce: string;
  private_key_algorithm: string;
  auth_hash: string;
  recovery_code: string;
  recovery_auth_hash: string;
  encrypted_private_key_recovery: string;
  private_key_recovery_nonce: string;
  private_key_recovery_algorithm: string;
}

export async function generateRegistrationMaterial(
  password: string,
  email: string
): Promise<RegistrationMaterial> {
  const wasm = getWasm();
  return wasm.generate_registration_material(password, email) as unknown as RegistrationMaterial;
}

/** The opaque credential the server accepts in place of the password. */
export async function deriveAuthHash(password: string, email: string): Promise<string> {
  return getWasm().derive_auth_hash(password, email);
}

/** The opaque credential proving possession of a recovery code. */
export async function deriveRecoveryAuthHash(
  recoveryCode: string,
  email: string
): Promise<string> {
  return getWasm().derive_recovery_auth_hash(recoveryCode, email);
}

export interface ResetMaterial {
  auth_hash: string;
  encrypted_private_key: string;
  private_key_nonce: string;
  private_key_algorithm: string;
}

/**
 * Unwrap the private key with the recovery code and re-wrap it under a new
 * password. Runs entirely in WASM: neither password nor the recovery code is
 * exposed to JavaScript or transmitted.
 */
export async function resetPasswordMaterial(
  encryptedPrivateKeyRecovery: string,
  privateKeyRecoveryNonce: string,
  recoveryCode: string,
  email: string,
  newPassword: string
): Promise<ResetMaterial> {
  const wasm = getWasm();
  return wasm.reset_password_material(
    encryptedPrivateKeyRecovery,
    privateKeyRecoveryNonce,
    recoveryCode,
    email,
    newPassword
  ) as unknown as ResetMaterial;
}
