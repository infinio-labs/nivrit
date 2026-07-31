import json
import os
import subprocess
from pathlib import Path
from typing import Any


class HelperCrypto:
    def __init__(self, helper_path: str | None = None):
        self.helper_path = helper_path or self._find_helper()

    def _find_helper(self) -> str:
        exe = "nivrit-crypto-helper.exe" if os.name == "nt" else "nivrit-crypto-helper"
        if env := os.environ.get("NIVRIT_CRYPTO_HELPER"):
            return env
        # Bundled in the platform wheel (nivrit/bin/), see build-wheels.sh.
        bundled = Path(__file__).resolve().parent / "bin" / exe
        if bundled.exists():
            return str(bundled)
        # Dev fallback: monorepo cargo build output.
        here = Path(__file__).resolve()
        for sub in ("release", "debug"):
            c = here.parents[3] / "target" / sub / exe
            if c.exists():
                return str(c)
        raise FileNotFoundError(
            "nivrit-crypto-helper not found. Install the platform wheel, set "
            "NIVRIT_CRYPTO_HELPER, or run `cargo build --locked --release -p nivrit-crypto-helper`."
        )

    def _call(self, req: dict[str, Any]) -> Any:
        proc = subprocess.run(
            [self.helper_path],
            input=json.dumps(req).encode(),
            capture_output=True,
            timeout=30,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"crypto helper exited {proc.returncode}: {proc.stderr.decode()}"
            )
        resp = json.loads(proc.stdout.decode().strip())
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error", "crypto helper error"))
        return resp["result"]

    def hybrid_suite_id(self) -> str:
        return self._call({"op": "hybrid_suite_id"})

    def generate_keypair(self, password: str) -> dict[str, str]:
        return self._call({"op": "generate_keypair", "password": password})

    def generate_registration_material(self, password: str, email: str) -> dict[str, str]:
        """Everything registration needs, computed locally: keypair, recovery
        material, and the auth_hash the server accepts in place of the password."""
        return self._call(
            {"op": "generate_registration_material", "password": password, "email": email}
        )

    def derive_auth_hash(self, password: str, email: str) -> str:
        """The opaque credential the server accepts in place of the password."""
        return self._call(
            {"op": "derive_auth_hash", "password": password, "email": email}
        )["auth_hash"]

    def decrypt_private_key(
        self, encrypted_private_key: str, nonce: str, password: str
    ) -> str:
        return self._call(
            {
                "op": "decrypt_private_key",
                "encrypted_private_key": encrypted_private_key,
                "nonce": nonce,
                "password": password,
            }
        )["private_key"]

    def decapsulate_project_key(
        self, encrypted_project_key: str, private_key: str
    ) -> str:
        return self._call(
            {
                "op": "decapsulate_project_key",
                "encrypted_project_key": encrypted_project_key,
                "private_key": private_key,
            }
        )["project_key"]

    def encrypt_value(self, plaintext: str, key: str) -> dict[str, str]:
        return self._call(
            {"op": "encrypt_value", "plaintext": plaintext, "key": key}
        )

    def decrypt_value(self, ciphertext: str, nonce: str, key: str) -> str:
        return self._call(
            {"op": "decrypt_value", "ciphertext": ciphertext, "nonce": nonce, "key": key}
        )["plaintext"]

    def encapsulate_project_key(
        self, project_key: str, recipient_public_key: str
    ) -> dict[str, str]:
        return self._call(
            {
                "op": "encapsulate_project_key",
                "project_key": project_key,
                "recipient_public_key": recipient_public_key,
            }
        )
