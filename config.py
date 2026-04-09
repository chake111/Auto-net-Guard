"""AutoNetGuard centralized configuration.

Configuration is loaded from an external ``config.ini`` file located in the
same directory as this module (or the running executable).  A
``config.ini.example`` template is shipped alongside the application so users
know which keys are available.

Priority (highest → lowest):
  1. ``config.ini`` next to the executable / script
  2. Built-in defaults below (no credentials – will raise if missing)
"""

from __future__ import annotations

import configparser
import os
import sys
from pathlib import Path


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

_parser = configparser.ConfigParser()
_parser.read(_CONFIG_PATH, encoding="utf-8")


def _get(section: str, key: str, fallback: str | None = None) -> str:
    """Read a value from config.ini, with an optional fallback.

    Raises ``KeyError`` when the key is absent and no fallback is provided,
    so that missing *required* settings (credentials) are caught early.
    """
    value = _parser.get(section, key, fallback=fallback)
    if value is None:
        raise KeyError(
            f"Required config key [{section}] {key} is missing from {_CONFIG_PATH}. "
            f"Copy config.ini.example to config.ini and fill in your credentials."
        )
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
