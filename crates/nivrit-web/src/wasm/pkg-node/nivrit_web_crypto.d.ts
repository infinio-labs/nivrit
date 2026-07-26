/* tslint:disable */
/* eslint-disable */

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
 * Encapsulate a 32-byte project key to a recipient's hybrid public key.
 */
export function encapsulate_project_key(project_key_b64: string, recipient_public_key_b64: string): any;

/**
 * Encrypt a UTF-8 string under a 32-byte AES-256-GCM key.
 */
export function encrypt_value(plaintext: string, key_b64: string): any;

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
