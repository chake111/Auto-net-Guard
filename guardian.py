"""AutoNetGuard: keep campus network online by auto re-authentication.

Entry points
------------
* Run directly (``python guardian.py`` or the compiled EXE):
    Starts the system-tray icon on the main thread and the guardian loop on
    a background daemon thread.

* Import as a library:
    Call ``guardian_target(state, stop_event)`` directly.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
import os
import signal
import socket
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

import requests

try:
    from config import BACKOFF_BASE_SECONDS
    from config import CHECK_INTERVAL_SECONDS
    from config import CONNECTIVITY_URL
    from config import GATEWAY_IP
    from config import LOG_FILE
    from config import LOGIN_RETRY_COUNT
    from config import LOGIN_URL
    from config import REFERER
    from config import REQUEST_TIMEOUT_SECONDS
    from config import USER_ACCOUNT
    from config import USER_PASSWORD
    from config import WLAN_AC_IP
    from config import WLAN_AC_NAME
except KeyError as _cfg_err:
    print(
        f"\n[AutoNetGuard] 配置错误: {_cfg_err}\n"
        "请将 config.ini.example 复制为 config.ini 并填写你的账号和密码。\n"
        "  copy config.ini.example config.ini\n"
        "  notepad config.ini\n",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

from tray import AppState, NetStatus, run_tray


LOGGER = logging.getLogger("autonetguard")

# ---------------------------------------------------------------------------
# Runtime directory & PID file
# ---------------------------------------------------------------------------

def _runtime_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


PID_FILE = _runtime_dir() / "guardian.pid"


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging() -> None:
    """Configure rotating file logging."""
    LOGGER.setLevel(logging.INFO)
    if LOGGER.handlers:
        return

    log_path = _runtime_dir() / LOG_FILE
    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=2 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(formatter)
    LOGGER.addHandler(file_handler)


# ---------------------------------------------------------------------------
# Single-instance lock
# ---------------------------------------------------------------------------

def _is_process_running(pid: int) -> bool:
    if psutil is not None:
        return psutil.pid_exists(pid)
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def acquire_instance_lock() -> None:
    if PID_FILE.exists():
        try:
            existing_pid = int(PID_FILE.read_text(encoding="utf-8").strip())
        except (ValueError, OSError):
            existing_pid = 0

        if existing_pid > 0 and _is_process_running(existing_pid):
            print(
                f"[AutoNetGuard] 已有实例正在运行 (PID {existing_pid})，本次启动已中止。\n"
                f"如需强制重启，请先终止该进程或删除 {PID_FILE}",
                file=sys.stderr,
            )
            sys.exit(1)

        LOGGER.warning("Removing stale PID file (pid=%s).", existing_pid)

    PID_FILE.write_text(str(os.getpid()), encoding="utf-8")


def release_instance_lock() -> None:
    try:
        PID_FILE.unlink(missing_ok=True)
    except OSError as exc:
        LOGGER.warning("Failed to remove PID file: %s", exc)


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _normalize_mac(mac: str) -> str:
    cleaned = mac.replace("-", "").replace(":", "").strip().lower()
    if len(cleaned) == 12 and cleaned != "000000000000":
        return cleaned
    return ""


def get_active_ip() -> str:
    """Discover the active local IPv4 used to reach the gateway."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((GATEWAY_IP, 53))
        return sock.getsockname()[0]


def get_active_mac() -> str:
    """Fetch the MAC for the network interface carrying the active local IP."""
    active_ip = get_active_ip()

    if psutil is not None:
        af_link = getattr(psutil, "AF_LINK", None)
        for _, addresses in psutil.net_if_addrs().items():
            has_active_ip = any(
                addr.family == socket.AF_INET and addr.address == active_ip
                for addr in addresses
            )
            if not has_active_ip:
                continue
            for addr in addresses:
                if af_link is not None and addr.family == af_link:
                    mac = _normalize_mac(addr.address)
                    if mac:
                        return mac

    fallback = _normalize_mac(f"{uuid.getnode():012x}")
    if fallback:
        return fallback
    raise RuntimeError("Unable to determine active interface MAC address.")


def _build_login_params(ip: str, mac: str) -> dict[str, str]:
    return {
        "callback": "dr1003",
        "login_method": "1",
        "user_account": USER_ACCOUNT,
        "user_password": USER_PASSWORD,
        "wlan_user_ip": ip,
        "wlan_user_ipv6": "",
        "wlan_user_mac": mac,
        "wlan_vlan_id": "0",
        "wlan_ac_ip": WLAN_AC_IP,
        "wlan_ac_name": WLAN_AC_NAME,
        "authex_enable": "",
        "jsVersion": "4.2.2",
        "terminal_type": "1",
        "lang": "zh-cn",
        "v": str(int(time.time()) % 10000),
    }


def check_connectivity(session: requests.Session) -> bool:
    try:
        response = session.get(
            CONNECTIVITY_URL,
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
        return response.status_code == 204
    except requests.RequestException as exc:
        LOGGER.warning("Connectivity check failed: %s", exc)
        return False


def _do_login(session: requests.Session, ip: str, mac: str) -> bool:
    params = _build_login_params(ip=ip, mac=mac)
    response = session.get(
        LOGIN_URL,
        params=params,
        headers={"Referer": REFERER},
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()

    text = response.text.lower()
    success_markers = [
        "success",
        "portal_success",
        '"result":"1"',
        '"result":1',
        "登录成功",
    ]
    return any(marker in text for marker in success_markers)


def login_with_retry(session: requests.Session) -> bool:
    for attempt in range(1, LOGIN_RETRY_COUNT + 1):
        try:
            ip = get_active_ip()
            mac = get_active_mac()
            LOGGER.info(
                "Login attempt %s/%s | ip=%s | mac=%s",
                attempt,
                LOGIN_RETRY_COUNT,
                ip,
                mac,
            )
            if _do_login(session=session, ip=ip, mac=mac):
                LOGGER.info("Login success on attempt %s.", attempt)
                return True
            LOGGER.warning("Login rejected on attempt %s.", attempt)
        except Exception as exc:  # pylint: disable=broad-except
            LOGGER.error("Login error on attempt %s: %s", attempt, exc)

        if attempt < LOGIN_RETRY_COUNT:
            delay = BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
            LOGGER.info("Retrying in %s seconds.", delay)
            time.sleep(delay)

    return False


# ---------------------------------------------------------------------------
# Guardian target (runs on background thread)
# ---------------------------------------------------------------------------

def guardian_target(state: AppState, stop_event: threading.Event) -> None:
    """Network-monitoring loop.  Designed to run on a daemon thread.

    Parameters
    ----------
    state:
        Shared ``AppState`` instance; updated to reflect current network status.
    stop_event:
        Set by the tray (or signal handler) to request a clean shutdown.
    """
    setup_logging()
    LOGGER.info("AutoNetGuard guardian started (pid=%s, tid=%s).",
                os.getpid(), threading.get_ident())

    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AutoNetGuard/1.0",
            "Accept": "*/*",
        }
    )

    previous_ip = ""

    while not stop_event.is_set():
        try:
            current_ip = get_active_ip()
            if current_ip != previous_ip:
                LOGGER.info(
                    "IP changed: %s -> %s", previous_ip or "<none>", current_ip
                )
                previous_ip = current_ip

            if check_connectivity(session):
                LOGGER.info("Connectivity healthy.")
                state.status = NetStatus.ONLINE
            else:
                LOGGER.warning("Disconnected detected, triggering login.")
                state.status = NetStatus.LOGGING_IN
                state.increment_disconnect()

                if login_with_retry(session):
                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    state.last_login_time = now
                    if check_connectivity(session):
                        LOGGER.info("Connectivity restored.")
                        state.status = NetStatus.ONLINE
                    else:
                        LOGGER.warning(
                            "Login succeeded but connectivity is still unavailable."
                        )
                        state.status = NetStatus.OFFLINE
                else:
                    LOGGER.error("All login retries failed.")
                    state.status = NetStatus.OFFLINE

        except Exception as exc:  # pylint: disable=broad-except
            LOGGER.exception("Unhandled guardian error: %s", exc)
            state.status = NetStatus.UNKNOWN

        stop_event.wait(timeout=CHECK_INTERVAL_SECONDS)

    LOGGER.info("Guardian thread stopped.")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    setup_logging()
    acquire_instance_lock()

    def _handle_shutdown(signum: int, _frame: object) -> None:
        sig_name = (
            signal.Signals(signum).name
            if hasattr(signal, "Signals")
            else str(signum)
        )
        LOGGER.info("Received signal %s – shutting down.", sig_name)
        # stop_event is owned by run_tray; we can only ask the tray to quit
        # by raising SystemExit which pystray will catch on the main thread.
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _handle_shutdown)

    try:
        run_tray(guardian_target=guardian_target)
    except (KeyboardInterrupt, SystemExit):
        LOGGER.info("AutoNetGuard exiting.")
    finally:
        release_instance_lock()
        LOGGER.info("AutoNetGuard stopped.")


if __name__ == "__main__":
    main()
