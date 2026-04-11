"""AutoNetGuard centralized configuration.

Configuration is loaded from an external ``config.ini`` file located in the
same directory as this module (or the running executable).  A
``config.ini.example`` template is shipped alongside the application so users
know which keys are available.

Priority (highest → lowest):
  1. ``config.ini`` next to the executable / script
  2. Built-in defaults below (no credentials – will raise if missing)

Credential encryption
---------------------
Sensitive values (``user_account`` and ``user_password``) are encrypted at
rest using **Fernet** symmetric encryption (from the ``cryptography`` library).
A per-machine AES key is derived via PBKDF2-HMAC-SHA256 from a stable,
machine-specific identifier (Windows MachineGuid when available, otherwise
hostname + network-interface MAC).

On the **first run** after the user fills in their plaintext credentials the
application automatically rewrites ``config.ini`` with the encrypted values.
Subsequent runs decrypt transparently.  If the ``config.ini`` is copied to a
different machine the user will receive a clear error and must re-enter their
plaintext credentials.
"""

from __future__ import annotations

import base64
import configparser
import os
import platform
import sys
import uuid as _uuid_module
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ---------------------------------------------------------------------------
# Locate config.ini
# ---------------------------------------------------------------------------

def _config_dir() -> Path:
    """Return the directory that should contain config.ini.

    When running as a PyInstaller one-file bundle ``sys.executable`` points to
    the EXE; otherwise fall back to the directory of this source file.
    """
    if getattr(sys, "frozen", False):
        # Running inside a PyInstaller bundle
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


_CONFIG_PATH = _config_dir() / "config.ini"

# ---------------------------------------------------------------------------
# Machine-bound encryption
# ---------------------------------------------------------------------------

# Prefix that marks an encrypted value in config.ini
_ENC_PREFIX = "ENC:"

# Fixed application salt for PBKDF2 (not secret – for domain separation only)
_KDF_SALT = b"AutoNetGuard-config-v1"
_KDF_ITERATIONS = 200_000

# Fields in [credentials] that are encrypted at rest
_ENCRYPTED_FIELDS = ("user_account", "user_password")


def _get_machine_id() -> str:
    """Return a stable, machine-specific identifier string.

    On Windows the registry ``MachineGuid`` is preferred because it persists
    across network-card replacements.  A hostname + MAC address combination
    is used as a cross-platform fallback.
    """
    if sys.platform == "win32":
        try:
            import winreg  # noqa: PLC0415  (Windows-only import)
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
            ) as key:
                guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                return str(guid)
        except OSError:
            pass
    return platform.node() + str(_uuid_module.getnode())


def _derive_fernet_key(machine_id: str) -> bytes:
    """Derive a 256-bit Fernet key from *machine_id* using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_KDF_SALT,
        iterations=_KDF_ITERATIONS,
    )
    raw = kdf.derive(machine_id.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


# Computed once at import time; all encrypt/decrypt operations use this object.
_FERNET: Fernet = Fernet(_derive_fernet_key(_get_machine_id()))


def _encrypt_value(plaintext: str) -> str:
    """Return an ``ENC:``-prefixed Fernet-encrypted representation of *plaintext*."""
    token = _FERNET.encrypt(plaintext.encode("utf-8"))
    return _ENC_PREFIX + token.decode("ascii")


def _decrypt_value(ciphertext: str) -> str:
    """Decrypt an ``ENC:``-prefixed value and return the original plaintext.

    Raises ``InvalidToken`` (from ``cryptography``) if the token is invalid or
    was encrypted with a different machine key.
    """
    token = ciphertext[len(_ENC_PREFIX):].encode("ascii")
    return _FERNET.decrypt(token).decode("utf-8")


def _is_encrypted(value: str) -> bool:
    """Return ``True`` when *value* carries the ``ENC:`` encryption prefix."""
    return value.startswith(_ENC_PREFIX)


def _maybe_encrypt_credentials(parser: configparser.ConfigParser,
                                config_path: Path) -> None:
    """Encrypt any plaintext credential fields and rewrite *config_path*.

    This function is a no-op when all credential fields are already encrypted
    or when *config_path* does not exist.
    """
    if not config_path.exists():
        return
    if not parser.has_section("credentials"):
        return

    changed = False
    for field in _ENCRYPTED_FIELDS:
        value = parser.get("credentials", field, fallback=None)
        if value and value.strip() and not _is_encrypted(value):
            parser.set("credentials", field, _encrypt_value(value))
            changed = True

    if changed:
        with config_path.open("w", encoding="utf-8") as fh:
            parser.write(fh)


# ---------------------------------------------------------------------------
# Load config.ini and auto-encrypt credentials on first run
# ---------------------------------------------------------------------------

_parser = configparser.ConfigParser()
_parser.read(_CONFIG_PATH, encoding="utf-8")

# Encrypt plaintext credentials and persist the change immediately.
_maybe_encrypt_credentials(_parser, _CONFIG_PATH)


def _get(section: str, key: str, fallback: str | None = None) -> str:
    """Read a value from config.ini, with an optional fallback.

    Encrypted values (``ENC:`` prefix) are decrypted transparently.

    Raises ``KeyError`` when the key is absent and no fallback is provided,
    so that missing *required* settings (credentials) are caught early.
    """
    value = _parser.get(section, key, fallback=fallback)
    if value is None:
        raise KeyError(
            f"Required config key [{section}] {key} is missing from {_CONFIG_PATH}. "
            f"Copy config.ini.example to config.ini and fill in your credentials."
        )
    if _is_encrypted(value):
        try:
            return _decrypt_value(value)
        except InvalidToken as exc:
            raise KeyError(
                f"Failed to decrypt [{section}] {key} in {_CONFIG_PATH}. "
                "The config.ini was likely created on a different machine. "
                "Please re-enter your plaintext credentials in config.ini and "
                "restart the application."
            ) from exc
    return value


# ---------------------------------------------------------------------------
# [credentials]
# ---------------------------------------------------------------------------

USER_ACCOUNT: str = _get("credentials", "user_account")
USER_PASSWORD: str = _get("credentials", "user_password")

# ---------------------------------------------------------------------------
# [network]
# ---------------------------------------------------------------------------

GATEWAY_IP: str = _get("network", "gateway_ip", fallback="10.10.10.2")
GATEWAY_HOST: str = f"http://{GATEWAY_IP}"
LOGIN_URL: str = _get("network", "login_url", fallback=f"http://{GATEWAY_IP}:801/eportal/portal/login")
REFERER: str = _get("network", "referer", fallback=f"http://{GATEWAY_IP}/")

WLAN_AC_IP: str = _get("network", "wlan_ac_ip", fallback="10.0.253.2")
WLAN_AC_NAME: str = _get("network", "wlan_ac_name", fallback="WS6812")

# ---------------------------------------------------------------------------
# [connectivity]
# ---------------------------------------------------------------------------

CONNECTIVITY_URL: str = _get("connectivity", "check_url", fallback="http://www.google.cn/generate_204")

# ---------------------------------------------------------------------------
# [timing]
# ---------------------------------------------------------------------------

REQUEST_TIMEOUT_SECONDS: int = int(_get("timing", "request_timeout_seconds", fallback="8"))
CHECK_INTERVAL_SECONDS: int = int(_get("timing", "check_interval_seconds", fallback="30"))
LOGIN_RETRY_COUNT: int = int(_get("timing", "login_retry_count", fallback="3"))
BACKOFF_BASE_SECONDS: int = int(_get("timing", "backoff_base_seconds", fallback="1"))

# ---------------------------------------------------------------------------
# [logging]
# ---------------------------------------------------------------------------

LOG_FILE: str = _get("logging", "log_file", fallback="service.log")
