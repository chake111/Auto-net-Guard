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

    Handles both the legacy ``[credentials]`` section and any
    ``[profile:<name>]`` sections that contain ``user_account`` /
    ``user_password`` in plaintext.

    This function is a no-op when all credential fields are already encrypted
    or when *config_path* does not exist.
    """
    if not config_path.exists():
        return

    changed = False

    # Legacy [credentials] section
    if parser.has_section("credentials"):
        for field in _ENCRYPTED_FIELDS:
            value = parser.get("credentials", field, fallback=None)
            if value and value.strip() and not _is_encrypted(value):
                parser.set("credentials", field, _encrypt_value(value))
                changed = True

    # Each [profile:<name>] section
    for section in parser.sections():
        if section.lower().startswith("profile:"):
            for field in _ENCRYPTED_FIELDS:
                value = parser.get(section, field, fallback=None)
                if value and value.strip() and not _is_encrypted(value):
                    parser.set(section, field, _encrypt_value(value))
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


def _parse_bool(value: str) -> bool:
    """Parse a config string as a boolean value.

    Returns ``False`` only for the canonical false-y strings; everything else
    is treated as ``True`` to match common INI-file conventions.
    """
    return value.lower() not in ("false", "0", "no", "off")


# ---------------------------------------------------------------------------
# Multi-profile helpers
# ---------------------------------------------------------------------------

def _get_profile_or_fallback(
    key: str,
    legacy_section: str,
    fallback: str | None = None,
) -> str:
    """Return *key* from the active profile section, falling back to *legacy_section*.

    Resolution order:
    1. ``[profile:<active_profile>]`` section (if an active profile is set and
       the section contains *key*).
    2. *legacy_section* (e.g. ``"credentials"`` or ``"network"``), read via
       the usual :func:`_get` helper.
    3. *fallback* value (passed through to :func:`_get`).

    Encrypted values (``ENC:`` prefix) are decrypted transparently at every
    step.
    """
    profile = _parser.get("global", "active_profile", fallback="").strip()
    if profile:
        profile_section = f"profile:{profile}"
        if _parser.has_section(profile_section):
            raw = _parser.get(profile_section, key, fallback=None)
            if raw is not None:
                if _is_encrypted(raw):
                    try:
                        return _decrypt_value(raw)
                    except Exception as exc:
                        raise KeyError(
                            f"Failed to decrypt [{profile_section}] {key} in "
                            f"{_CONFIG_PATH}. The config.ini was likely created "
                            "on a different machine. Please re-enter your "
                            "plaintext credentials and restart the application."
                        ) from exc
                return raw
    return _get(legacy_section, key, fallback=fallback)


def list_profiles() -> list[str]:
    """Return a sorted list of all configured profile names.

    Scans ``_parser`` for sections whose name starts with ``profile:`` and
    returns the suffix (the profile name) for each one.  Returns an empty
    list when no profiles are configured.
    """
    return sorted(
        section[len("profile:"):]
        for section in _parser.sections()
        if section.lower().startswith("profile:")
    )


def get_active_profile() -> str:
    """Return the name of the currently active profile, or ``''`` if none."""
    return _parser.get("global", "active_profile", fallback="").strip()


def switch_profile(name: str) -> None:
    """Persist *name* as the active profile in ``config.ini`` and reload globals.

    Steps:
    1. Read the current ``config.ini``.
    2. Set ``[global] active_profile = <name>``.
    3. Write the updated file.
    4. Call :func:`reload_config` so that all module-level constants reflect
       the new profile immediately.

    This function is intended to be called from the system-tray profile-switch
    menu.  After it returns the caller should set ``state.config_changed`` and
    ``state.wakeup_event`` so that the guardian thread applies the new
    configuration and reconnects immediately.
    """
    parser = configparser.ConfigParser()
    parser.read(_CONFIG_PATH, encoding="utf-8")

    if not parser.has_section("global"):
        parser.add_section("global")
    parser.set("global", "active_profile", name)

    with _CONFIG_PATH.open("w", encoding="utf-8") as fh:
        parser.write(fh)

    reload_config()


# ---------------------------------------------------------------------------
# [credentials]  /  active profile credentials
# ---------------------------------------------------------------------------

USER_ACCOUNT: str = _get_profile_or_fallback("user_account", "credentials")
USER_PASSWORD: str = _get_profile_or_fallback("user_password", "credentials")

# ---------------------------------------------------------------------------
# [network]  /  active profile network settings
# ---------------------------------------------------------------------------

GATEWAY_IP: str = _get_profile_or_fallback("gateway_ip", "network", fallback="10.10.10.2")
GATEWAY_HOST: str = f"http://{GATEWAY_IP}"
LOGIN_URL: str = _get_profile_or_fallback(
    "login_url", "network", fallback=f"http://{GATEWAY_IP}:801/eportal/portal/login"
)
REFERER: str = _get_profile_or_fallback("referer", "network", fallback=f"http://{GATEWAY_IP}/")

WLAN_AC_IP: str = _get_profile_or_fallback("wlan_ac_ip", "network", fallback="10.0.253.2")
WLAN_AC_NAME: str = _get_profile_or_fallback("wlan_ac_name", "network", fallback="WS6812")

# ---------------------------------------------------------------------------
# [global]  – active profile name
# ---------------------------------------------------------------------------

ACTIVE_PROFILE: str = get_active_profile()

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

# ---------------------------------------------------------------------------
# [ui]
# ---------------------------------------------------------------------------

ENABLE_NOTIFICATIONS: bool = _parse_bool(_get("ui", "enable_notifications", fallback="true"))

# ---------------------------------------------------------------------------
# [auth]
# ---------------------------------------------------------------------------

AUTH_TYPE: str = _get("auth", "auth_type", fallback="drcom")

# HTTP method used by GenericPostAuthenticator ("GET" or "POST").
AUTH_METHOD: str = _get("auth", "auth_method", fallback="POST")

# Comma-separated substrings that indicate a successful login response.
# Used by GenericPostAuthenticator; DrcomAuthenticator has its own built-in
# markers and ignores this setting.
AUTH_SUCCESS_MARKERS: str = _get(
    "auth",
    "auth_success_markers",
    fallback="success,登录成功",
)

# ---------------------------------------------------------------------------
# [srun]  (used by SrunAuthenticator)
# ---------------------------------------------------------------------------

# AC-ID value shown on the Srun portal login page (varies per deployment).
SRUN_ACID: str = _get("srun", "acid", fallback="1")

# ---------------------------------------------------------------------------
# [auth_params]  (used by GenericPostAuthenticator)
# ---------------------------------------------------------------------------

def _load_auth_params(parser: configparser.ConfigParser) -> dict[str, str]:
    """Return the ``[auth_params]`` section as a plain ``dict[str, str]``.

    Values that carry the ``ENC:`` prefix are decrypted transparently.
    Returns an empty dict when the section is absent.
    """
    if not parser.has_section("auth_params"):
        return {}
    result: dict[str, str] = {}
    for key, value in parser.items("auth_params"):
        if _is_encrypted(value):
            try:
                value = _decrypt_value(value)
            except Exception:  # pylint: disable=broad-except
                pass
        result[key] = value
    return result


AUTH_PARAMS: dict[str, str] = _load_auth_params(_parser)

# ---------------------------------------------------------------------------
# Runtime config update helpers (used by the GUI settings window)
# ---------------------------------------------------------------------------


def save_config(
    user_account: str,
    user_password: str,
    gateway_ip: str,
    login_url: str,
    check_interval_seconds: int,
    enable_notifications: bool = True,
) -> None:
    """将新配置写入 config.ini 并同步更新模块全局变量（热加载）。

    当存在活跃 Profile 时，凭据和网关设置写入对应的 ``[profile:<name>]`` 节；
    否则写入传统的 ``[credentials]`` / ``[network]`` 节。

    凭据以明文形式写入文件，随后由 ``_maybe_encrypt_credentials`` 加密并回写，
    确保与已有的加密逻辑完全兼容。

    守护进程通过 ``import config as _cfg`` 读取配置，因此下一次循环迭代
    时即可自动感知新值，无需重启守护线程。
    """
    global _parser  # noqa: PLW0603
    global USER_ACCOUNT, USER_PASSWORD, GATEWAY_IP, GATEWAY_HOST  # noqa: PLW0603
    global LOGIN_URL, REFERER, CHECK_INTERVAL_SECONDS, ENABLE_NOTIFICATIONS  # noqa: PLW0603

    # 读取现有配置文件，保留本次未修改的字段
    parser = configparser.ConfigParser()
    parser.read(_CONFIG_PATH, encoding="utf-8")

    def _ensure(section: str) -> None:
        if not parser.has_section(section):
            parser.add_section(section)

    # 凭据和网络设置：优先写入活跃 Profile，否则写入传统节
    active_profile = parser.get("global", "active_profile", fallback="").strip()
    if active_profile:
        profile_section = f"profile:{active_profile}"
        _ensure(profile_section)
        # 存明文；_maybe_encrypt_credentials 随后将其加密并回写
        parser.set(profile_section, "user_account", user_account)
        parser.set(profile_section, "user_password", user_password)
        parser.set(profile_section, "gateway_ip", gateway_ip)
        parser.set(profile_section, "login_url", login_url)
        parser.set(profile_section, "referer", f"http://{gateway_ip}/")
    else:
        _ensure("credentials")
        # 存明文；_maybe_encrypt_credentials 随后将其加密并回写
        parser.set("credentials", "user_account", user_account)
        parser.set("credentials", "user_password", user_password)

        _ensure("network")
        parser.set("network", "gateway_ip", gateway_ip)
        parser.set("network", "login_url", login_url)
        parser.set("network", "referer", f"http://{gateway_ip}/")

    _ensure("timing")
    parser.set("timing", "check_interval_seconds", str(check_interval_seconds))

    _ensure("ui")
    parser.set("ui", "enable_notifications", "true" if enable_notifications else "false")

    with _CONFIG_PATH.open("w", encoding="utf-8") as fh:
        parser.write(fh)

    # 加密明文凭据并回写文件
    _maybe_encrypt_credentials(parser, _CONFIG_PATH)

    # 更新模块全局 parser（_get 依赖它）及所有常量
    _parser = parser
    USER_ACCOUNT = user_account
    USER_PASSWORD = user_password
    GATEWAY_IP = gateway_ip
    GATEWAY_HOST = f"http://{gateway_ip}"
    LOGIN_URL = login_url
    REFERER = f"http://{gateway_ip}/"
    CHECK_INTERVAL_SECONDS = check_interval_seconds
    ENABLE_NOTIFICATIONS = enable_notifications


def reload_config() -> None:
    """从 config.ini 重新加载全部配置项并更新模块全局变量。

    当 ``[global] active_profile`` 指向某个 Profile 时，凭据和网络设置从对应的
    ``[profile:<name>]`` 节读取；否则从传统 ``[credentials]`` / ``[network]`` 节读取。

    可在守护进程重启前调用，确保新线程拿到最新值。
    """
    global _parser  # noqa: PLW0603
    global ACTIVE_PROFILE  # noqa: PLW0603
    global USER_ACCOUNT, USER_PASSWORD, GATEWAY_IP, GATEWAY_HOST  # noqa: PLW0603
    global LOGIN_URL, REFERER, WLAN_AC_IP, WLAN_AC_NAME  # noqa: PLW0603
    global CONNECTIVITY_URL, REQUEST_TIMEOUT_SECONDS, CHECK_INTERVAL_SECONDS  # noqa: PLW0603
    global LOGIN_RETRY_COUNT, BACKOFF_BASE_SECONDS, LOG_FILE  # noqa: PLW0603
    global AUTH_TYPE, AUTH_METHOD, AUTH_SUCCESS_MARKERS, AUTH_PARAMS, SRUN_ACID  # noqa: PLW0603
    global ENABLE_NOTIFICATIONS  # noqa: PLW0603

    _parser = configparser.ConfigParser()
    _parser.read(_CONFIG_PATH, encoding="utf-8")
    _maybe_encrypt_credentials(_parser, _CONFIG_PATH)

    ACTIVE_PROFILE = get_active_profile()

    USER_ACCOUNT = _get_profile_or_fallback("user_account", "credentials")
    USER_PASSWORD = _get_profile_or_fallback("user_password", "credentials")
    GATEWAY_IP = _get_profile_or_fallback("gateway_ip", "network", fallback=GATEWAY_IP)
    GATEWAY_HOST = f"http://{GATEWAY_IP}"
    LOGIN_URL = _get_profile_or_fallback("login_url", "network", fallback=LOGIN_URL)
    REFERER = _get_profile_or_fallback("referer", "network", fallback=REFERER)
    WLAN_AC_IP = _get_profile_or_fallback("wlan_ac_ip", "network", fallback=WLAN_AC_IP)
    WLAN_AC_NAME = _get_profile_or_fallback("wlan_ac_name", "network", fallback=WLAN_AC_NAME)
    CONNECTIVITY_URL = _get("connectivity", "check_url", fallback=CONNECTIVITY_URL)
    REQUEST_TIMEOUT_SECONDS = int(
        _get("timing", "request_timeout_seconds", fallback=str(REQUEST_TIMEOUT_SECONDS))
    )
    CHECK_INTERVAL_SECONDS = int(
        _get("timing", "check_interval_seconds", fallback=str(CHECK_INTERVAL_SECONDS))
    )
    LOGIN_RETRY_COUNT = int(
        _get("timing", "login_retry_count", fallback=str(LOGIN_RETRY_COUNT))
    )
    BACKOFF_BASE_SECONDS = int(
        _get("timing", "backoff_base_seconds", fallback=str(BACKOFF_BASE_SECONDS))
    )
    LOG_FILE = _get("logging", "log_file", fallback=LOG_FILE)
    AUTH_TYPE = _get("auth", "auth_type", fallback=AUTH_TYPE)
    AUTH_METHOD = _get("auth", "auth_method", fallback=AUTH_METHOD)
    AUTH_SUCCESS_MARKERS = _get(
        "auth", "auth_success_markers", fallback=AUTH_SUCCESS_MARKERS
    )
    AUTH_PARAMS = _load_auth_params(_parser)
    SRUN_ACID = _get("srun", "acid", fallback=SRUN_ACID)
    ENABLE_NOTIFICATIONS = _parse_bool(_get("ui", "enable_notifications", fallback="true"))
