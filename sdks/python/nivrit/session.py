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
        self._project_keys: dict[str, str] = {}

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

    def get_project_key(self, membership: dict[str, Any]) -> str:
        if membership is None:
            raise ValueError("No membership for project")
        pid = membership["project_id"]
        if pid in self._project_keys:
            return self._project_keys[pid]
        key = self.crypto.decapsulate_project_key(
            membership["encrypted_project_key"], self.private_key
        )
        self._project_keys[pid] = key
        return key

    def list_secrets(self, project_id: str, environment_id: str) -> list[dict[str, Any]]:
        secrets = self.client.list_secrets(project_id, environment_id)
        membership = next(
            (m for m in self.client.list_my_projects() if m["project_id"] == project_id),
            None,
        )
        project_key = self.get_project_key(membership)
        return [
            {
                **s,
                "value": self.crypto.decrypt_value(
                    s["encrypted_value"], s["nonce"], project_key
                ),
            }
            for s in secrets
        ]

    def get_secret(self, project_id: str, environment_id: str, key: str) -> dict[str, Any]:
        secret = self.client.get_secret(project_id, environment_id, key)
        membership = next(
            (m for m in self.client.list_my_projects() if m["project_id"] == project_id),
            None,
        )
        project_key = self.get_project_key(membership)
        return {
            **secret,
            "value": self.crypto.decrypt_value(
                secret["encrypted_value"], secret["nonce"], project_key
            ),
        }
