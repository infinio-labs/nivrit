"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.initCrypto = initCrypto;
exports.decryptPrivateKey = decryptPrivateKey;
exports.decapsulateProjectKey = decapsulateProjectKey;
exports.decryptValue = decryptValue;
exports.hybridSuiteId = hybridSuiteId;
const path = __importStar(require("path"));
let wasmModule = null;
function initCrypto(extensionPath) {
    if (wasmModule)
        return;
    const wasmPath = path.join(extensionPath, 'wasm', 'pkg', 'nivrit_web_crypto.js');
    const mod = require(wasmPath);
    mod.init_panic_hook();
    wasmModule = mod;
}
function getWasm() {
    if (!wasmModule)
        throw new Error('crypto not initialized; call initCrypto() first');
    return wasmModule;
}
function decryptPrivateKey(encryptedPrivateKey, nonce, password) {
    const result = getWasm().decrypt_private_key(encryptedPrivateKey, nonce, password);
    return result.private_key;
}
function decapsulateProjectKey(encapsulated, privateKeyBase64) {
    const result = getWasm().decapsulate_project_key(encapsulated, privateKeyBase64);
    return result.project_key;
}
function decryptValue(ciphertextBase64, nonceBase64, keyBase64) {
    const result = getWasm().decrypt_value(ciphertextBase64, nonceBase64, keyBase64);
    return result.plaintext;
}
function hybridSuiteId() {
    return getWasm().hybrid_suite_id();
}
//# sourceMappingURL=crypto.js.map