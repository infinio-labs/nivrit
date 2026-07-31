// Runs the Argon2id-backed WASM calls off the main thread, so the browser
// tab doesn't freeze mid-keystroke during login/register/reset. Only loaded
// in real browsers - see shouldUseWorker() in crypto.ts.
import * as wasmMod from './wasm/pkg/nivrit_web_crypto.js';

wasmMod.init_panic_hook();

const HEAVY_FNS = {
  generate_user_keypair: wasmMod.generate_user_keypair,
  generate_registration_material: wasmMod.generate_registration_material,
  derive_auth_hash: wasmMod.derive_auth_hash,
  derive_recovery_auth_hash: wasmMod.derive_recovery_auth_hash,
  reset_password_material: wasmMod.reset_password_material,
  decrypt_private_key: wasmMod.decrypt_private_key,
};

export type HeavyFnName = keyof typeof HEAVY_FNS;

interface WorkerRequest {
  id: number;
  fn: HeavyFnName;
  args: unknown[];
}

interface WorkerResponse {
  id: number;
  result?: unknown;
  error?: string;
}

const ctx = self as unknown as {
  postMessage: (msg: WorkerResponse) => void;
  onmessage: ((ev: MessageEvent<WorkerRequest>) => void) | null;
};

ctx.onmessage = (ev) => {
  const { id, fn, args } = ev.data;
  try {
    const result = (HEAVY_FNS[fn] as (...a: unknown[]) => unknown)(...args);
    ctx.postMessage({ id, result });
  } catch (err) {
    ctx.postMessage({ id, error: err instanceof Error ? err.message : String(err) });
  }
};
