"""Unit tests for F-10: Local passphrase gate (salted KDF), destructive action gating, and SECURITY.md."""

from pathlib import Path
import pytest

from src.reporting.json_export import export_investigation_json, restore_investigation_from_json
from src.security.passphrase_gate import (
    PassphraseGate,
    is_passphrase_configured,
    set_passphrase,
    verify_passphrase,
)
from src.storage.repository import InvestigationRepository


def test_reproduce_passphrase_gate_kdf_and_storage(tmp_path):
    """Passphrase gate must use a salted KDF (PBKDF2-HMAC-SHA256) and reject incorrect passwords."""
    auth_file = tmp_path / ".chronica_auth.json"
    assert not is_passphrase_configured(auth_file)

    # Set passphrase
    set_passphrase("InvestigatorSecret123!", auth_file)
    assert is_passphrase_configured(auth_file)

    # Verify correct passphrase
    assert verify_passphrase("InvestigatorSecret123!", auth_file) is True

    # Reject incorrect passphrase
    assert verify_passphrase("WrongPassword!", auth_file) is False
    assert verify_passphrase("", auth_file) is False


def test_reproduce_destructive_actions_gated_by_passphrase(tmp_path):
    """Destructive actions (delete, restore, export) must require valid passphrase when gate is configured."""
    auth_file = tmp_path / ".chronica_auth.json"
    set_passphrase("StrongAnalystPass123!", auth_file)

    repo = InvestigationRepository(data_root=tmp_path / "cases", auth_file=auth_file)
    meta = repo.create_investigation("case_destruct_01", "Destructive Test Case")

    # 1. Delete without passphrase must raise PermissionError
    with pytest.raises(PermissionError, match="passphrase"):
        repo.delete_investigation("case_destruct_01", passphrase=None)

    with pytest.raises(PermissionError, match="passphrase"):
        repo.delete_investigation("case_destruct_01", passphrase="WrongPass")

    # 2. Export without passphrase must raise PermissionError
    manifest = repo.get_manifest("case_destruct_01")
    with pytest.raises(PermissionError, match="passphrase"):
        export_investigation_json(
            meta, manifest, [], [], None,
            auth_file=auth_file,
            passphrase=None,
        )

    # 3. Restore without passphrase must raise PermissionError
    backup_data = {
        "format": "chronica_investigation_backup",
        "version": "1.0.0",
        "investigation_id": "case_destruct_01",
        "metadata": meta.to_dict(),
        "manifest": manifest.to_dict(),
        "events": [],
    }
    with pytest.raises(PermissionError, match="passphrase"):
        restore_investigation_from_json(
            backup_data, repo,
            auth_file=auth_file,
            passphrase="WrongPassword",
        )

    # 4. Valid passphrase authorizes all actions
    # Export succeeds
    json_export = export_investigation_json(
        meta, manifest, [], [], None,
        auth_file=auth_file,
        passphrase="StrongAnalystPass123!",
    )
    assert "case_destruct_01" in json_export

    # Delete succeeds
    repo.delete_investigation("case_destruct_01", passphrase="StrongAnalystPass123!")
    assert repo.get_investigation("case_destruct_01") is None


def test_reproduce_security_md_documentation_exists():
    """SECURITY.md must exist in repository root documenting the threat model and controls."""
    sec_path = Path(__file__).resolve().parent.parent.parent / "SECURITY.md"
    assert sec_path.exists(), "SECURITY.md must exist in root"
    content = sec_path.read_text(encoding="utf-8")
    assert "Threat Model" in content
    assert "127.0.0.1" in content
    assert "Passphrase" in content or "Passphrase Gate" in content
    assert "STRIDE" in content


def test_adversarial_passphrase_input_validation_and_clear(tmp_path):
    """Adversarial check: rejection of empty passphrases and secure clearing."""
    auth_file = tmp_path / "custom_auth.json"

    # Reject empty or whitespace-only passphrases
    with pytest.raises(ValueError, match="empty"):
        set_passphrase("", auth_file)
    with pytest.raises(ValueError, match="empty"):
        set_passphrase("   ", auth_file)

    # Configure and verify object-oriented PassphraseGate
    gate = PassphraseGate(auth_file)
    assert not gate.is_configured()
    gate.set("ForensicAccess2026!")
    assert gate.is_configured()
    assert gate.verify("ForensicAccess2026!") is True

    # Clearing requires the current password
    assert gate.clear("WrongCurrentPass") is False
    assert gate.is_configured()

    # Clear with correct password
    assert gate.clear("ForensicAccess2026!") is True
    assert not gate.is_configured()

    # When unconfigured, destructive actions are permitted without passphrase (optional gate)
    assert gate.check_authorized("delete_investigation") is True


def test_adversarial_corrupted_auth_file_fails_closed(tmp_path):
    """Adversarial check: corrupted or unparseable auth configuration fails closed safely."""
    auth_file = tmp_path / "corrupt_auth.json"
    auth_file.write_text("{bad_json: True", encoding="utf-8")

    assert not is_passphrase_configured(auth_file)
    assert verify_passphrase("AnyPassword", auth_file) is False

    # Truncated payload missing fields
    auth_file.write_text('{"algorithm": "pbkdf2_hmac_sha256"}', encoding="utf-8")
    assert not is_passphrase_configured(auth_file)
    assert verify_passphrase("AnyPassword", auth_file) is False
