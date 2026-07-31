/**
 * Master-password policy.
 *
 * A thin wrapper over `nivrit_crypto::password_policy`, reached through the WASM
 * module. The rules deliberately do not live here: the CLI enforces the same
 * ones, and a second implementation in TypeScript would drift, so a password
 * accepted when registering in the browser could be rejected when changing it
 * from the command line.
 *
 * Enforcement has to happen client-side at all because, under split derivation
 * (see docs/adr/0002), the server receives a fixed-width `auth_hash` and cannot
 * tell a long passphrase from a short one. These checks are therefore the only
 * enforcement that exists — and they are advisory against a determined user,
 * who can call the API directly with a hash derived from anything.
 */
import { assessPasswordWasm } from './crypto';

export interface PasswordAssessment {
  /** False when the password must be rejected outright. */
  acceptable: boolean;
  /** Shown beneath the field whenever there is something to say. */
  message?: string;
  /** Coarse strength, for the meter. */
  strength: 'weak' | 'fair' | 'strong';
}

/**
 * Assess a candidate master password.
 *
 * Synchronous, so it can drive a live strength meter during render. Safe because
 * the app does not render any password field until `initCrypto()` has resolved.
 */
export function assessPassword(password: string, email?: string): PasswordAssessment {
  return assessPasswordWasm(password, email);
}

/** Throwing form, for paths that must not proceed on a weak password. */
export function assertAcceptablePassword(password: string, email?: string): void {
  const assessment = assessPassword(password, email);
  if (!assessment.acceptable) {
    throw new Error(assessment.message ?? 'Choose a stronger master password.');
  }
}
