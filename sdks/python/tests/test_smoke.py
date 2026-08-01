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
EMAIL_B = f"sdk-python-b-{int(time.time() * 1000)}@example.com"
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

    # --- versioned project-key rotation (ADR 0008) ---------------------------
    material_b = crypto.generate_registration_material(PASSWORD, EMAIL_B)
    reg_b = api_request(
        "POST",
        "/auth/register",
        {
            "email": EMAIL_B,
            "auth_hash": material_b["auth_hash"],
            "name": "Python SDK Test B",
            "public_key": material_b["public_key"],
            "encrypted_private_key": material_b["encrypted_private_key"],
            "private_key_nonce": material_b["private_key_nonce"],
            "private_key_algorithm": material_b["private_key_algorithm"],
            "recovery_auth_hash": material_b["recovery_auth_hash"],
            "encrypted_private_key_recovery": material_b["encrypted_private_key_recovery"],
            "private_key_recovery_nonce": material_b["private_key_recovery_nonce"],
            "private_key_recovery_algorithm": material_b["private_key_recovery_algorithm"],
        },
    )
    print("registered second user", reg_b["user"]["email"])

    # Invited before the rotation: starts out holding only version 1.
    session.invite_member(project["id"], EMAIL_B, "member")
    print("invited second user to project")

    pat_b = api_request("POST", "/auth/pat", {"name": "python-sdk-test-b"}, reg_b["token"])
    session_b = await NivritSession.from_pat(API_URL, pat_b["token"], PASSWORD, crypto)
    pre_rotation = session_b.get_secret(project["id"], env["id"], "GREETING")
    assert pre_rotation["value"] == "hello-python-sdk"
    print("second user decrypted pre-rotation secret")

    rotated = session.rotate_project_key(project["id"])
    assert rotated["version"] == 2
    assert rotated["granted_to"] == 2
    print(f"rotated project key to version {rotated['version']} (granted to {rotated['granted_to']} members)")

    current_version = session.current_project_key_version(project["id"])
    current_key = session.get_project_key(project["id"])
    encrypted_post_rotation = crypto.encrypt_value("hello-after-rotation", current_key)
    session.client.create_secret(
        project["id"],
        {
            "environment_id": env["id"],
            "key": "POST_ROTATION",
            "encrypted_value": encrypted_post_rotation["ciphertext"],
            "nonce": encrypted_post_rotation["nonce"],
            "algorithm": "aes256gcm-v1",
            "project_key_version": current_version,
        },
    )
    print("created post-rotation secret under version", current_version)

    # Second user was a current member at rotation time, so they automatically
    # received the new version -- confirm without a fresh login, proving
    # rotate_project_key's cache update on the rotating side and the grant on
    # the receiving side both worked.
    session_b.load_project_keys(project["id"])
    post_rotation_for_b = session_b.get_secret(project["id"], env["id"], "POST_ROTATION")
    assert post_rotation_for_b["value"] == "hello-after-rotation"
    pre_rotation_again_for_b = session_b.get_secret(project["id"], env["id"], "GREETING")
    assert pre_rotation_again_for_b["value"] == "hello-python-sdk"
    print("second user decrypted both pre- and post-rotation secrets after rotation")

    api_request("DELETE", f"/auth/pats/{pat_b['id']}", token=reg_b["token"])
    api_request("DELETE", f"/auth/pats/{pat['id']}", token=reg["token"])
    print("revoked PATs")
    print("Python SDK smoke test passed.")


if __name__ == "__main__":
    asyncio.run(main())
