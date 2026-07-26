/* @ts-self-types="./nivrit_web_crypto.d.ts" */
import * as wasm from "./nivrit_web_crypto_bg.wasm";
import { __wbg_set_wasm } from "./nivrit_web_crypto_bg.js";

__wbg_set_wasm(wasm);
wasm.__wbindgen_start();
export {
    decapsulate_project_key, decrypt_private_key, decrypt_value, encapsulate_project_key, encrypt_value, generate_user_keypair, hybrid_suite_id, init_panic_hook
} from "./nivrit_web_crypto_bg.js";
