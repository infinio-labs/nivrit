import json
import urllib.request
from typing import Any


class NivritClient:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.token = token

    def _request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> Any:
        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode()
            return json.loads(text) if text else None

    def get_me(self) -> dict[str, Any]:
        return self._request("GET", "/users/me")

    def list_orgs(self) -> list[dict[str, Any]]:
        return self._request("GET", "/users/me/orgs")

    def list_my_projects(self) -> list[dict[str, Any]]:
        return self._request("GET", "/users/me/projects")

    def list_org_projects(self, org_id: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/orgs/{org_id}/projects")

    def list_environments(self, project_id: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/projects/{project_id}/environments")

    def list_secrets(self, project_id: str, environment_id: str) -> list[dict[str, Any]]:
        return self._request(
            "GET",
            f"/projects/{project_id}/secrets?environment_id={environment_id}",
        )

    def get_secret(self, project_id: str, environment_id: str, key: str) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/projects/{project_id}/secrets/{key}?environment_id={environment_id}",
        )

    def list_secret_versions(
        self, project_id: str, environment_id: str, key: str
    ) -> list[dict[str, Any]]:
        return self._request(
            "GET",
            f"/projects/{project_id}/secrets/{key}/versions?environment_id={environment_id}",
        )

    def restore_secret(
        self, project_id: str, environment_id: str, key: str, version: int
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/projects/{project_id}/secrets/{key}/restore",
            {"environment_id": environment_id, "version": version},
        )

    def list_folders(self, project_id: str, environment_id: str) -> list[dict[str, Any]]:
        return self._request(
            "GET", f"/projects/{project_id}/folders?environment_id={environment_id}"
        )

    def create_folder(
        self, project_id: str, environment_id: str, name: str, path: str
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/projects/{project_id}/folders",
            {"environment_id": environment_id, "name": name, "path": path},
        )

    def delete_folder(self, project_id: str, folder_id: str) -> dict[str, Any]:
        return self._request("DELETE", f"/projects/{project_id}/folders/{folder_id}")

    def list_imports(self, project_id: str, environment_id: str) -> list[dict[str, Any]]:
        return self._request(
            "GET", f"/projects/{project_id}/imports?environment_id={environment_id}"
        )

    def create_import(
        self,
        project_id: str,
        environment_id: str,
        source_environment_id: str,
        position: int = 0,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/projects/{project_id}/imports",
            {
                "environment_id": environment_id,
                "source_environment_id": source_environment_id,
                "position": position,
            },
        )

    def delete_import(self, project_id: str, import_id: str) -> dict[str, Any]:
        return self._request("DELETE", f"/projects/{project_id}/imports/{import_id}")

    def list_tags(self, project_id: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/projects/{project_id}/tags")

    def create_tag(
        self, project_id: str, name: str, color: str = "#888888"
    ) -> dict[str, Any]:
        return self._request(
            "POST", f"/projects/{project_id}/tags", {"name": name, "color": color}
        )

    def delete_tag(self, project_id: str, tag_id: str) -> dict[str, Any]:
        return self._request("DELETE", f"/projects/{project_id}/tags/{tag_id}")

    def list_secret_tags(
        self, project_id: str, environment_id: str, key: str
    ) -> list[dict[str, Any]]:
        return self._request(
            "GET",
            f"/projects/{project_id}/secrets/{key}/tags?environment_id={environment_id}",
        )

    def tag_secret(
        self, project_id: str, environment_id: str, key: str, tag_id: str
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/projects/{project_id}/secrets/{key}/tags",
            {"environment_id": environment_id, "tag_id": tag_id},
        )

    def untag_secret(
        self, project_id: str, environment_id: str, key: str, tag_id: str
    ) -> dict[str, Any]:
        return self._request(
            "DELETE",
            f"/projects/{project_id}/secrets/{key}/tags/{tag_id}?environment_id={environment_id}",
        )

    def create_org(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/orgs", body)

    def create_project(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/projects", body)

    def create_environment(self, project_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", f"/projects/{project_id}/environments", body)

    def create_secret(self, project_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", f"/projects/{project_id}/secrets", body)

    def create_pat(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/auth/pat", body)
