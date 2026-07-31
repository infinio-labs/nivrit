/* tslint:disable */
/* eslint-disable */

/**
 * Assess a master password against Nivrit's policy.
 *
 * Shares one implementation with the CLI (`nivrit_crypto::password_policy`) so
 * that a password accepted when registering in the browser is also accepted
 * when changing it from the command line. The server cannot perform this check
 * at all — it only ever sees a derived hash.
 */
export function assess_password(password: string, email?: string | null): any;

/**
 * Decapsulate a project key using the recipient's plaintext hybrid private key.
 */
export function decapsulate_project_key(encapsulated: any, private_key_b64: string): any;

/**
 * Decrypt a private key that was produced by `generate_user_keypair`.
 */
export function decrypt_private_key(encrypted_private_key_b64: string, nonce_b64: string, password: string): any;

/**
 * Decrypt a base64 ciphertext under a 32-byte AES-256-GCM key and nonce.
 */
export function decrypt_value(ciphertext_b64: string, nonce_b64: string, key_b64: string): any;

/**
 * Derive the opaque credential the server accepts in place of the password.
 */
export function derive_auth_hash(password: string, email: string): string;

/**
 * Derive the opaque credential that proves possession of a recovery code.
 */
export function derive_recovery_auth_hash(recovery_code: string, email: string): string;

/**
 * Encapsulate a 32-byte project key to a recipient's hybrid public key.
 */
export function encapsulate_project_key(project_key_b64: string, recipient_public_key_b64: string): any;

/**
 * Encrypt a UTF-8 string under a 32-byte AES-256-GCM key.
 */
export function encrypt_value(plaintext: string, key_b64: string): any;

/**
 * Generate a hybrid keypair and every derived value registration needs.
 *
 * Replaces the old flow where the server decrypted the user's private key in
 * order to build the recovery blob. All of that now happens here, on the
 * client, so the server never holds the plaintext private key or the password.
 */
export function generate_registration_material(password: string, email: string): any;

/**
 * Generate a hybrid `X25519 + ML-KEM-768` keypair and encrypt the private key
 * to `password` using Argon2id + AES-256-GCM.
 */
export function generate_user_keypair(password: string): any;

/**
 * Return the suite identifier used for hybrid project-key encapsulation.
 */
export function hybrid_suite_id(): string;

/**
 * Install a panic hook that forwards Rust panics to `console.error`.
 */
export function init_panic_hook(): void;

/**
 * Recover the private key from a recovery blob, re-wrap it under a new
 * password, *and* mint a fresh recovery code to replace the one just used.
 *
 * A reset is often needed because the old recovery code may itself be
 * compromised - that is frequently the reason a reset is happening at all -
 * so leaving it valid afterward would defeat the point. This mirrors what
 * `generate_registration_material` does at signup and what `rotate_key` does
 * on key rotation: the recovery code, the old private key, and both passwords
 * stay on the client; the server receives only opaque credentials and
 * ciphertext.
 */
export function reset_password_material(encrypted_private_key_recovery_b64: string, private_key_recovery_nonce_b64: string, recovery_code: string, email: string, new_password: string): any;
