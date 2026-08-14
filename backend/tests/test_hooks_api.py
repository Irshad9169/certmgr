"""Hooks API: encrypted SSH credential storage — must never be echoed back,
and PATCH must follow Jenkins-credential-style masking semantics (omit =
leave untouched, empty string = clear, non-empty = replace)."""

from __future__ import annotations

from app.core.security import decrypt_secret
from app.models.certificate import Hook

_FAKE_PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "ZmFrZS1rZXktbWF0ZXJpYWwtZm9yLXRlc3Rpbmctb25seQ==\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)
_OTHER_FAKE_PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "ZGlmZmVyZW50LWtleS1tYXRlcmlhbC1oZXJl\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)


def _script(tmp_path):
    p = tmp_path / "hook.sh"
    p.write_text("#!/bin/sh\necho x\n")
    p.chmod(0o755)
    return str(p)


def test_create_hook_with_ssh_key_never_echoes_it(client, admin_headers, tmp_path, db):
    resp = client.post(
        "/api/v1/hooks",
        json={
            "name": "auth-hook", "hook_type": "auth", "script_path": _script(tmp_path),
            "ssh_private_key": _FAKE_PEM, "ssh_target_host": "lets-encrypt01.example.com",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["has_ssh_key"] is True
    assert body["ssh_target_host"] == "lets-encrypt01.example.com"
    assert "ssh_private_key" not in body
    assert "ssh_private_key_encrypted" not in body

    row = db.query(Hook).filter(Hook.id == body["id"]).first()
    assert row.ssh_private_key_encrypted is not None
    assert row.ssh_private_key_encrypted != _FAKE_PEM  # stored encrypted, not plaintext
    assert decrypt_secret(row.ssh_private_key_encrypted) == _FAKE_PEM


def test_create_hook_rejects_invalid_pem(client, admin_headers, tmp_path):
    resp = client.post(
        "/api/v1/hooks",
        json={
            "name": "bad-hook", "hook_type": "auth", "script_path": _script(tmp_path),
            "ssh_private_key": "not a key", "ssh_target_host": "host.example.com",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 422


def test_patch_without_key_field_leaves_existing_key_untouched(client, admin_headers, tmp_path, db):
    created = client.post(
        "/api/v1/hooks",
        json={
            "name": "keep-key", "hook_type": "auth", "script_path": _script(tmp_path),
            "ssh_private_key": _FAKE_PEM, "ssh_target_host": "host.example.com",
        },
        headers=admin_headers,
    ).json()

    resp = client.patch(
        f"/api/v1/hooks/{created['id']}",
        json={"description": "updated description"},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["has_ssh_key"] is True

    row = db.query(Hook).filter(Hook.id == created["id"]).first()
    assert decrypt_secret(row.ssh_private_key_encrypted) == _FAKE_PEM


def test_patch_empty_string_clears_key(client, admin_headers, tmp_path, db):
    created = client.post(
        "/api/v1/hooks",
        json={
            "name": "clear-key", "hook_type": "auth", "script_path": _script(tmp_path),
            "ssh_private_key": _FAKE_PEM, "ssh_target_host": "host.example.com",
        },
        headers=admin_headers,
    ).json()

    resp = client.patch(
        f"/api/v1/hooks/{created['id']}",
        json={"ssh_private_key": ""},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["has_ssh_key"] is False

    row = db.query(Hook).filter(Hook.id == created["id"]).first()
    assert row.ssh_private_key_encrypted is None


def test_patch_new_key_replaces_existing(client, admin_headers, tmp_path, db):
    created = client.post(
        "/api/v1/hooks",
        json={
            "name": "replace-key", "hook_type": "auth", "script_path": _script(tmp_path),
            "ssh_private_key": _FAKE_PEM, "ssh_target_host": "host.example.com",
        },
        headers=admin_headers,
    ).json()

    resp = client.patch(
        f"/api/v1/hooks/{created['id']}",
        json={"ssh_private_key": _OTHER_FAKE_PEM},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["has_ssh_key"] is True

    row = db.query(Hook).filter(Hook.id == created["id"]).first()
    assert decrypt_secret(row.ssh_private_key_encrypted) == _OTHER_FAKE_PEM


def test_hook_list_never_includes_key(client, admin_headers, tmp_path):
    client.post(
        "/api/v1/hooks",
        json={
            "name": "list-hook", "hook_type": "auth", "script_path": _script(tmp_path),
            "ssh_private_key": _FAKE_PEM, "ssh_target_host": "host.example.com",
        },
        headers=admin_headers,
    )
    resp = client.get("/api/v1/hooks", headers=admin_headers)
    assert resp.status_code == 200
    for hook in resp.json():
        assert "ssh_private_key" not in hook
        assert "ssh_private_key_encrypted" not in hook
