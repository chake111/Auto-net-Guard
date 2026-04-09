"""AutoNetGuard – Windows startup (registry) helper.

Provides two public functions:
  enable_autostart()   – write the EXE path to HKCU Run key
  disable_autostart()  – remove the entry from HKCU Run key
  is_autostart_enabled() – check whether the entry exists and matches
"""

from __future__ import annotations

import sys
from pathlib import Path

# winreg is Windows-only; guard for dev/test on other platforms
try:
    import winreg
    _WINREG_AVAILABLE = True
except ImportError:  # pragma: no cover
    _WINREG_AVAILABLE = False

APP_NAME = "AutoNetGuard"
_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def _exe_path() -> str:
    """Return the absolute path of the running executable."""
    if getattr(sys, "frozen", False):
        # PyInstaller bundle
        return str(Path(sys.executable).resolve())
    # Running as a plain Python script – point to the script itself
    return str(Path(__file__).resolve().parent / "guardian.py")


def enable_autostart() -> bool:
    """Register AutoNetGuard to start with Windows (current user).

    Returns True on success, False if winreg is unavailable.
    """
    if not _WINREG_AVAILABLE:
        return False
    exe = _exe_path()
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_SET_VALUE
    ) as key:
        winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, exe)
    return True


def disable_autostart() -> bool:
    """Remove AutoNetGuard from Windows startup (current user).

    Returns True on success, False if the entry did not exist or winreg
    is unavailable.
    """
    if not _WINREG_AVAILABLE:
        return False
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.DeleteValue(key, APP_NAME)
        return True
    except FileNotFoundError:
        return False


def is_autostart_enabled() -> bool:
    """Return True if the registry entry exists and points to the current EXE."""
    if not _WINREG_AVAILABLE:
        return False
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_READ
        ) as key:
            value, _ = winreg.QueryValueEx(key, APP_NAME)
            return value == _exe_path()
    except FileNotFoundError:
        return False
