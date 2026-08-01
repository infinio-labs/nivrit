import base64
import json
import secrets
from typing import Any

from .client import NivritClient
from .crypto import HelperCrypto


class NivritSession:
    def __init__(self, base_url: str, token: str, crypto: HelperCrypto):
        self.base_url = base_url
        self.token = token
        self.crypto = crypto
        self.client = NivritClient(base_url, token)
        self.user: dict[str, Any] | None = None
        self.private_key: str | None = None
        # project_id -> {version: decapsulated key}. A project that's never
        # been rotated has exactly one entry (ADR 0008).
        self._project_keys: dict[str, dict[int, str]] = {}

    @classmethod
    async def from_pat(
        cls, base_url: str, pat: str, password: str, crypto: HelperCrypto
    ) -> "NivritSession":
        session = cls(base_url, pat, crypto)
        await session.authenticate(password)
        return session

    async def authenticate(self, password: str) -> None:
        self.user = self.client.get_me()
        self.private_key = self.crypto.decrypt_private_key(
            self.user["encrypted_private_key"],
            self.user["private_key_nonce"],
            password,
        )

    def list_orgs(self) -> list[dict[str, Any]]:
        return self.client.list_orgs()

    def list_projects(self, org_id: str) -> list[dict[str, Any]]:
        projects = self.client.list_org_projects(org_id)
        memberships = {m["project_id"]: m for m in self.client.list_my_projects()}
        return [{**p, "membership": memberships.get(p["id"])} for p in projects]

    def load_project_keys(self, project_id: str) -> dict[int, str]:
        """Every project-key version this account has been granted,
        decapsulated and cached, oldest first (ADR 0008). Idempotent per
        project per process -- call again after a rotation you triggered
        yourself to pick up the new version without a fresh login."""
        entries = self.client.list_key_versions(project_id)
        versions: dict[int, str] = {}
        for entry in entries:
            if not entry.get("encrypted_project_key"):
                continue
            key = self.crypto.decapsulate_project_key(
                entry["encrypted_project_key"], self.private_key
            )
            versions[entry["version"]] = key
        self._project_keys[project_id] = versions
        return versions

    def get_project_key(self, project_id: str, version: int | None = None) -> str:
        """The key for a specific project-key version, loading the cache
        first if needed. Omit `version` for the current (highest) one."""
        versions = self._project_keys.get(project_id)
        if not versions:
            versions = self.load_project_keys(project_id)
        resolved_version = version if version is not None else max(versions.keys())
        key = versions.get(resolved_version)
        if not key:
            raise ValueError(
                f"no cached key for project {project_id} version {resolved_version}; "
                "call load_project_keys() again to pick up any versions granted since"
            )
        return key

    def current_project_key_version(self, project_id: str) -> int:
        """The version new secret writes should use -- for building a
        create_secret/set_secret request's `project_key_version` field."""
        versions = self._project_keys.get(project_id)
        if not versions:
            versions = self.load_project_keys(project_id)
        return max(versions.keys())

    def list_secrets(self, project_id: str, environment_id: str) -> list[dict[str, Any]]:
        secrets_list = self.client.list_secrets(project_id, environment_id)
        return [
            {
                **s,
                "value": self.crypto.decrypt_value(
                    s["encrypted_value"],
                    s["nonce"],
                    self.get_project_key(project_id, s.get("project_key_version") or 1),
                ),
            }
            for s in secrets_list
        ]

    def get_secret(self, project_id: str, environment_id: str, key: str) -> dict[str, Any]:
        secret = self.client.get_secret(project_id, environment_id, key)
        project_key = self.get_project_key(
            project_id, secret.get("project_key_version") or 1
        )
        return {
            **secret,
            "value": self.crypto.decrypt_value(
                secret["encrypted_value"], secret["nonce"], project_key
            ),
        }

    def invite_member(self, project_id: str, email: str, role: str) -> dict[str, Any]:
        """Invite a user to a project by email, encapsulating the project's
        current key version to their public key. Grants whichever version is
        current, not a hardcoded version 1, so an invite after a rotation
        doesn't hand out a superseded key (ADR 0008)."""
        project_key = self.get_project_key(project_id)
        recipient = self.client.get_public_key(email, project_id)
        encapsulated = self.crypto.encapsulate_project_key(
            project_key, recipient["public_key"]
        )
        return self.client.invite_member(
            project_id,
            {
                "email": email,
                "role": role,
                "encrypted_project_key": encapsulated,
            },
        )

    def rotate_project_key(self, project_id: str) -> dict[str, Any]:
        """Mint a new project-key version and grant it to exactly the
        project's current members (ADR 0008). No existing secret is touched.
        A removed member simply never receives this grant, so they're locked
        out of everything created from this point forward."""
        # Proves we hold a valid key for this project before bothering to
        # mint the next version; the actual replacement key is generated
        # fresh below.
        self.get_project_key(project_id)

        members = self.client.list_members(project_id)
        new_key = base64.b64encode(secrets.token_bytes(32)).decode()

        grants = []
        for member in members:
            encapsulated = self.crypto.encapsulate_project_key(
                new_key, member["public_key"]
            )
            grants.append(
                {
                    "user_id": member["user_id"],
                    "encrypted_project_key": base64.b64encode(
                        json.dumps(encapsulated).encode()
                    ).decode(),
                    "project_key_nonce": "",
                    "project_key_algorithm": encapsulated["suite"],
                }
            )

        result = self.client.rotate_key(project_id, {"grants": grants})

        versions = self._project_keys.setdefault(project_id, {})
        versions[result["version"]] = new_key

        return {"version": result["version"], "granted_to": len(grants)}
