# Packaged-install regression: run AFTER `pip install` of the platform wheel,
# from a dir outside the repo, with NIVRIT_CRYPTO_HELPER unset and no cargo
# build present. Proves the wheel's bundled helper resolves and crypto works.
import base64
import json

from nivrit.crypto import HelperCrypto

c = HelperCrypto()
assert "/nivrit/bin/" in c.helper_path, f"not using bundled binary: {c.helper_path}"
assert c.hybrid_suite_id() == "hybrid_x25519_ml_kem_768_aes256gcm_v1"

kp = c.generate_keypair("pw")
priv = c.decrypt_private_key(kp["encrypted_private_key"], kp["private_key_nonce"], "pw")
pk = base64.b64encode(bytes(32)).decode()
enc = c.encapsulate_project_key(pk, kp["public_key"])
blob = base64.b64encode(json.dumps(enc).encode()).decode()
assert c.decapsulate_project_key(blob, priv) == pk, "roundtrip mismatch"

print(f"PYTHON PACKAGED ROUNDTRIP OK (bundled: {c.helper_path})")
