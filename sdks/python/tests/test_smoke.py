import asyncio
import base64
import json
import os
import secrets
import time
import urllib.request

from nivrit import HelperCrypto, NivritClient, NivritSession

API_URL = os.environ.get("NIVRIT_API_URL", "http://localhost:4000")
EMAIL = f"sdk-python-{int(time.time() * 1000)}@example.com"
PASSWORD = "Correct-Horse-Battery-Staple!"


def api_request(method: str, path: str, body: dict | None = None, token: str | None = None):
    url = f"{API_URL}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as resp:
        text = resp.read().decode()
        return json.loads(text) if text else None


async def main():
    crypto = HelperCrypto()
    material = crypto.generate_registration_material(PASSWORD, EMAIL)

    reg = api_request(
        "POST",
        "/auth/register",
        {
            "email": EMAIL,
            "auth_hash": material["auth_hash"],
            "name": "Python SDK Test",
            "public_key": material["public_key"],
            "encrypted_private_key": material["encrypted_private_key"],
            "private_key_nonce": material["private_key_nonce"],
            "private_key_algorithm": material["private_key_algorithm"],
            "recovery_auth_hash": material["recovery_auth_hash"],
            "encrypted_private_key_recovery": material["encrypted_private_key_recovery"],
            "private_key_recovery_nonce": material["private_key_recovery_nonce"],
            "private_key_recovery_algorithm": material["private_key_recovery_algorithm"],
        },
    )
    print("registered", reg["user"]["email"])

    pat = api_request("POST", "/auth/pat", {"name": "python-sdk-test"}, reg["token"])
    print("created PAT")

    session = await NivritSession.from_pat(API_URL, pat["token"], PASSWORD, crypto)
    print("session user", session.user["email"])

    org = session.client.create_org(
        {"name": "Python SDK Org", "slug": f"python-sdk-org-{int(time.time())}"}
    )
    print("created org", org["name"])

    project_key = base64.b64encode(secrets.token_bytes(32)).decode()
    encapsulated = crypto.encapsulate_project_key(project_key, session.user["public_key"])
    encrypted_project_key = base64.b64encode(
        json.dumps(encapsulated).encode()
    ).decode()
    project = session.client.create_project(
        {
            "org_id": org["id"],
            "name": "Python SDK Project",
            "slug": f"python-sdk-project-{int(time.time())}",
            "encrypted_project_key": encrypted_project_key,
            "project_key_nonce": base64.b64encode(secrets.token_bytes(12)).decode(),
            "project_key_algorithm": "hybrid_x25519_ml_kem_768_aes256gcm_v1",
        }
    )
    print("created project", project["name"])

    env = session.client.create_environment(project["id"], {"name": "Dev", "slug": "dev"})
    print("created environment", env["name"])

    encrypted = crypto.encrypt_value("hello-python-sdk", project_key)
    session.client.create_secret(
        project["id"],
        {
            "environment_id": env["id"],
            "key": "GREETING",
            "encrypted_value": encrypted["ciphertext"],
            "nonce": encrypted["nonce"],
            "algorithm": "aes256gcm-v1",
        },
    )
    print("created secret")

    secrets_list = session.list_secrets(project["id"], env["id"])
    assert len(secrets_list) == 1
    assert secrets_list[0]["value"] == "hello-python-sdk"
    print("decrypted secret matches expected value")

    api_request("DELETE", f"/auth/pats/{pat['id']}", token=reg["token"])
    print("revoked PAT")
    print("Python SDK smoke test passed.")


if __name__ == "__main__":
    asyncio.run(main())
