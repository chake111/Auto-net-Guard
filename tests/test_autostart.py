"""Unit tests for autostart.py – platform-specific startup registration."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

import autostart
from autostart import (
    APP_NAME,
    _exe_path,
    _launch_command,
    _linux_desktop_content,
    _linux_desktop_path,
    _linux_disable,
    _linux_enable,
    _linux_is_enabled,
    _macos_disable,
    _macos_enable,
    _macos_is_enabled,
    _macos_plist_content,
    _macos_plist_path,
    disable_autostart,
    enable_autostart,
    is_autostart_enabled,
)


# ---------------------------------------------------------------------------
# _exe_path / _launch_command
# ---------------------------------------------------------------------------

class TestExePath:
    def test_returns_string(self):
        assert isinstance(_exe_path(), str)

    def test_returns_absolute_path(self):
        assert Path(_exe_path()).is_absolute()

    def test_frozen_returns_executable_path(self):
        fake_exe = "/tmp/AutoNetGuard"
        with (
            patch.object(sys, "frozen", True, create=True),
            patch.object(sys, "executable", fake_exe),
        ):
            result = _exe_path()
        assert result == str(Path(fake_exe).resolve())

    def test_script_mode_points_to_guardian_py(self):
        # When not frozen, the path should contain "guardian.py"
        with patch.object(sys, "frozen", False, create=True):
            result = _exe_path()
        assert "guardian.py" in result


class TestLaunchCommand:
    def test_frozen_returns_exe_path_only(self):
        fake_exe = "/tmp/AutoNetGuard"
        with (
            patch.object(sys, "frozen", True, create=True),
            patch.object(sys, "executable", fake_exe),
        ):
            result = _launch_command()
        assert result == str(Path(fake_exe).resolve())

    def test_script_mode_includes_python_interpreter(self):
        with patch.object(sys, "frozen", False, create=True):
            result = _launch_command()
        assert sys.executable in result

    def test_script_mode_includes_guardian_script(self):
        with patch.object(sys, "frozen", False, create=True):
            result = _launch_command()
        assert "guardian.py" in result


# ---------------------------------------------------------------------------
# Linux autostart
# ---------------------------------------------------------------------------

class TestLinuxDesktopPath:
    def test_uses_xdg_config_home_when_set(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        path = _linux_desktop_path()
        assert str(tmp_path) in str(path)

    def test_filename_uses_app_name(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        path = _linux_desktop_path()
        assert path.name == f"{APP_NAME}.desktop"

    def test_falls_back_to_home_config_when_xdg_unset(self, monkeypatch):
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        path = _linux_desktop_path()
        assert ".config" in str(path)


class TestLinuxDesktopContent:
    def test_desktop_entry_section_present(self):
        assert "[Desktop Entry]" in _linux_desktop_content()

    def test_type_is_application(self):
        assert "Type=Application" in _linux_desktop_content()

    def test_app_name_present(self):
        assert APP_NAME in _linux_desktop_content()

    def test_exec_key_present(self):
        assert "Exec=" in _linux_desktop_content()

    def test_autostart_enabled_flag(self):
        assert "X-GNOME-Autostart-enabled=true" in _linux_desktop_content()


class TestLinuxEnable:
    def test_creates_desktop_file_and_returns_true(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        result = _linux_enable()
        assert result is True
        assert _linux_desktop_path().exists()

    def test_creates_parent_directories(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        _linux_enable()
        assert _linux_desktop_path().parent.is_dir()

    def test_desktop_file_content_is_valid(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        _linux_enable()
        content = _linux_desktop_path().read_text(encoding="utf-8")
        assert "[Desktop Entry]" in content
        assert "Exec=" in content


class TestLinuxDisable:
    def test_removes_existing_desktop_file_and_returns_true(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        desktop = _linux_desktop_path()
        desktop.parent.mkdir(parents=True, exist_ok=True)
        desktop.write_text("placeholder", encoding="utf-8")
        assert _linux_disable() is True
        assert not desktop.exists()

    def test_returns_false_when_no_file_exists(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        assert _linux_disable() is False


class TestLinuxIsEnabled:
    def test_returns_false_when_no_desktop_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        assert _linux_is_enabled() is False

    def test_returns_true_when_desktop_file_exists(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        desktop = _linux_desktop_path()
        desktop.parent.mkdir(parents=True, exist_ok=True)
        desktop.write_text("placeholder", encoding="utf-8")
        assert _linux_is_enabled() is True


# ---------------------------------------------------------------------------
# macOS autostart
# ---------------------------------------------------------------------------

class TestMacosPlistContent:
    def test_com_autonetguard_label_present(self):
        assert "com.autonetguard" in _macos_plist_content()

    def test_run_at_load_present(self):
        assert "RunAtLoad" in _macos_plist_content()

    def test_keep_alive_is_false(self):
        content = _macos_plist_content()
        # KeepAlive should be false (i.e. <false/>)
        assert "KeepAlive" in content
        assert "<false/>" in content

    def test_exe_path_embedded(self):
        exe = _exe_path()
        assert exe in _macos_plist_content()

    def test_valid_plist_structure(self):
        content = _macos_plist_content()
        assert '<?xml version="1.0"' in content
        assert "<plist" in content
        assert "<dict>" in content


class TestMacosEnable:
    def test_creates_plist_file_and_returns_true(self, tmp_path):
        plist_file = tmp_path / "com.autonetguard.plist"
        with patch("autostart._macos_plist_path", return_value=plist_file):
            result = _macos_enable()
        assert result is True
        assert plist_file.exists()

    def test_plist_content_is_valid(self, tmp_path):
        plist_file = tmp_path / "com.autonetguard.plist"
        with patch("autostart._macos_plist_path", return_value=plist_file):
            _macos_enable()
        content = plist_file.read_text(encoding="utf-8")
        assert "com.autonetguard" in content


class TestMacosDisable:
    def test_removes_existing_plist_and_returns_true(self, tmp_path):
        plist_file = tmp_path / "com.autonetguard.plist"
        plist_file.write_text("placeholder", encoding="utf-8")
        with patch("autostart._macos_plist_path", return_value=plist_file):
            result = _macos_disable()
        assert result is True
        assert not plist_file.exists()

    def test_returns_false_when_plist_absent(self, tmp_path):
        plist_file = tmp_path / "nonexistent.plist"
        with patch("autostart._macos_plist_path", return_value=plist_file):
            result = _macos_disable()
        assert result is False


class TestMacosIsEnabled:
    def test_returns_false_when_no_plist(self, tmp_path):
        plist_file = tmp_path / "nonexistent.plist"
        with patch("autostart._macos_plist_path", return_value=plist_file):
            assert _macos_is_enabled() is False

    def test_returns_true_when_plist_contains_exe_path(self, tmp_path):
        exe = _exe_path()
        plist_file = tmp_path / "com.autonetguard.plist"
        plist_file.write_text(f"<string>{exe}</string>", encoding="utf-8")
        with patch("autostart._macos_plist_path", return_value=plist_file):
            assert _macos_is_enabled() is True

    def test_returns_false_when_plist_has_different_exe(self, tmp_path):
        plist_file = tmp_path / "com.autonetguard.plist"
        plist_file.write_text("<string>/other/path/app</string>", encoding="utf-8")
        with patch("autostart._macos_plist_path", return_value=plist_file):
            assert _macos_is_enabled() is False


# ---------------------------------------------------------------------------
# Public API – platform dispatch
# ---------------------------------------------------------------------------

class TestPublicApiDispatch:
    def test_enable_autostart_dispatches_to_linux(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        with patch("autostart._linux_enable", return_value=True) as mock:
            result = enable_autostart()
        mock.assert_called_once()
        assert result is True

    def test_enable_autostart_dispatches_to_macos(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        with patch("autostart._macos_enable", return_value=True) as mock:
            result = enable_autostart()
        mock.assert_called_once()
        assert result is True

    def test_disable_autostart_dispatches_to_linux(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        with patch("autostart._linux_disable", return_value=True) as mock:
            result = disable_autostart()
        mock.assert_called_once()
        assert result is True

    def test_disable_autostart_dispatches_to_macos(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        with patch("autostart._macos_disable", return_value=True) as mock:
            result = disable_autostart()
        mock.assert_called_once()
        assert result is True

    def test_is_autostart_enabled_dispatches_to_linux(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        with patch("autostart._linux_is_enabled", return_value=True) as mock:
            result = is_autostart_enabled()
        mock.assert_called_once()
        assert result is True

    def test_is_autostart_enabled_dispatches_to_macos(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        with patch("autostart._macos_is_enabled", return_value=False) as mock:
            result = is_autostart_enabled()
        mock.assert_called_once()
        assert result is False
