"""Local passphrase gate with salted Key Derivation Function (PBKDF2-HMAC-SHA256).

Provides an optional security gate protecting destructive actions
(investigation deletion, case restoration, and data export) on analyst workstations.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
from typing import Optional

DEFAULT_AUTH_FILE = Path(os.environ.get("CHRONICA_AUTH_FILE", Path.home() / ".chronica" / "auth.json"))
KDF_ALGORITHM = "pbkdf2_hmac_sha256"
KDF_ITERATIONS = 100_000
SALT_BYTES = 16


def _resolve_auth_file(storage_path: Optional[Path] = None) -> Path:
    if storage_path is not None:
        return Path(storage_path)
    return DEFAULT_AUTH_FILE


def is_passphrase_configured(storage_path: Optional[Path] = None) -> bool:
    """Return True if a local passphrase gate has been configured and stored."""
    p = _resolve_auth_file(storage_path)
    if not p.is_file():
        return False
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        return bool(data.get("hash") and data.get("salt"))
    except Exception:
        return False


def set_passphrase(passphrase: str, storage_path: Optional[Path] = None) -> None:
    """Derive a salted PBKDF2 hash from passphrase and persist to auth configuration."""
    if not passphrase or not passphrase.strip():
        raise ValueError("Passphrase cannot be empty or whitespace only.")
    p = _resolve_auth_file(storage_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    salt = secrets.token_bytes(SALT_BYTES)
    derived = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, KDF_ITERATIONS)

    payload = {
        "algorithm": KDF_ALGORITHM,
        "iterations": KDF_ITERATIONS,
        "salt": salt.hex(),
        "hash": derived.hex(),
    }
    with open(p, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    # Restrict permissions where supported
    try:
        p.chmod(0o600)
    except Exception:
        pass


def verify_passphrase(passphrase: str, storage_path: Optional[Path] = None) -> bool:
    """Verify candidate passphrase against stored salted PBKDF2 hash using constant-time comparison."""
    if not passphrase:
        return False
    p = _resolve_auth_file(storage_path)
    if not p.is_file():
        return False

    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        stored_hash = bytes.fromhex(data["hash"])
        stored_salt = bytes.fromhex(data["salt"])
        iterations = int(data.get("iterations", KDF_ITERATIONS))

        computed = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), stored_salt, iterations)
        return hmac.compare_digest(stored_hash, computed)
    except Exception:
        return False


def clear_passphrase(current_passphrase: str, storage_path: Optional[Path] = None) -> bool:
    """Remove stored passphrase gate after verifying the current passphrase."""
    if not verify_passphrase(current_passphrase, storage_path):
        return False
    p = _resolve_auth_file(storage_path)
    if p.is_file():
        try:
            p.unlink()
            return True
        except Exception:
            return False
    return True


def check_destructive_action_authorized(
    action_name: str,
    passphrase: Optional[str] = None,
    storage_path: Optional[Path] = None,
) -> bool:
    """Check authorization for a destructive action.

    If no passphrase gate is configured, all actions are authorized (optional gate).
    If configured, a valid matching passphrase must be supplied, otherwise raises PermissionError.
    """
    if not is_passphrase_configured(storage_path):
        return True

    if passphrase and verify_passphrase(passphrase, storage_path):
        return True

    raise PermissionError(
        f"Destructive action '{action_name}' is protected by a local passphrase gate. "
        "A valid authorization passphrase must be provided."
    )


class PassphraseGate:
    """Object-oriented wrapper around the local passphrase gate."""

    def __init__(self, storage_path: Optional[Path] = None) -> None:
        self.storage_path = _resolve_auth_file(storage_path)

    def is_configured(self) -> bool:
        return is_passphrase_configured(self.storage_path)

    def set(self, passphrase: str) -> None:
        set_passphrase(passphrase, self.storage_path)

    def verify(self, passphrase: str) -> bool:
        return verify_passphrase(passphrase, self.storage_path)

    def clear(self, current_passphrase: str) -> bool:
        return clear_passphrase(current_passphrase, self.storage_path)

    def check_authorized(self, action_name: str, passphrase: Optional[str] = None) -> bool:
        return check_destructive_action_authorized(action_name, passphrase, self.storage_path)
