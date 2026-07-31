/* @ts-self-types="./nivrit_web_crypto.d.ts" */
import * as wasm from "./nivrit_web_crypto_bg.wasm";
import { __wbg_set_wasm } from "./nivrit_web_crypto_bg.js";

__wbg_set_wasm(wasm);

export {
    assess_password, decapsulate_project_key, decrypt_private_key, decrypt_value, derive_auth_hash, derive_recovery_auth_hash, encapsulate_project_key, encrypt_value, generate_registration_material, generate_user_keypair, hybrid_suite_id, init_panic_hook, reset_password_material
} from "./nivrit_web_crypto_bg.js";
