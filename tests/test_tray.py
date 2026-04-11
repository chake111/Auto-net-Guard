"""Unit tests for tray.py – AppState, NetStatus, and icon generation.

pystray is stubbed out in conftest.py so no GUI display is required.
"""

from __future__ import annotations

import threading
from unittest.mock import MagicMock

import pytest
from PIL import Image

from tray import AppState, NetStatus, TrayController, _make_icon, _ICON_SIZE, _get_notify_message


# ---------------------------------------------------------------------------
# NetStatus
# ---------------------------------------------------------------------------

class TestNetStatus:
    def test_all_expected_variants_exist(self):
        assert NetStatus.UNKNOWN
        assert NetStatus.ONLINE
        assert NetStatus.OFFLINE
        assert NetStatus.LOGGING_IN

    def test_variants_are_distinct(self):
        variants = [NetStatus.UNKNOWN, NetStatus.ONLINE, NetStatus.OFFLINE, NetStatus.LOGGING_IN]
        assert len(set(variants)) == 4

    def test_is_enum_member(self):
        import enum
        assert isinstance(NetStatus.ONLINE, enum.Enum)


# ---------------------------------------------------------------------------
# AppState – basic property access
# ---------------------------------------------------------------------------

class TestAppStateDefaults:
    def test_initial_status_is_unknown(self):
        state = AppState()
        assert state.status == NetStatus.UNKNOWN

    def test_initial_last_login_time_is_dash(self):
        state = AppState()
        assert state.last_login_time == "—"

    def test_initial_disconnect_count_is_zero(self):
        state = AppState()
        assert state.disconnect_count == 0


# ---------------------------------------------------------------------------
# AppState – status property
# ---------------------------------------------------------------------------

class TestAppStateStatus:
    @pytest.mark.parametrize("status", list(NetStatus))
    def test_status_setter_and_getter(self, status):
        state = AppState()
        state.status = status
        assert state.status == status

    def test_status_change_fires_callback(self):
        state = AppState()
        callback = MagicMock()
        state.on_status_change = callback
        state.status = NetStatus.ONLINE
        callback.assert_called_once()

    def test_same_status_does_not_fire_callback(self):
        state = AppState()
        state.status = NetStatus.ONLINE  # first assignment (changes from UNKNOWN)
        callback = MagicMock()
        state.on_status_change = callback
        state.status = NetStatus.ONLINE  # identical – should be silent
        callback.assert_not_called()

    def test_status_change_to_different_value_fires_callback(self):
        state = AppState()
        state.status = NetStatus.ONLINE
        callback = MagicMock()
        state.on_status_change = callback
        state.status = NetStatus.OFFLINE
        callback.assert_called_once()


# ---------------------------------------------------------------------------
# AppState – last_login_time property
# ---------------------------------------------------------------------------

class TestAppStateLastLoginTime:
    def test_setter_updates_value(self):
        state = AppState()
        state.last_login_time = "2024-01-01 12:00:00"
        assert state.last_login_time == "2024-01-01 12:00:00"

    def test_setter_fires_callback(self):
        state = AppState()
        callback = MagicMock()
        state.on_status_change = callback
        state.last_login_time = "2024-06-15 08:30:00"
        callback.assert_called_once()


# ---------------------------------------------------------------------------
# AppState – disconnect_count / increment_disconnect
# ---------------------------------------------------------------------------

class TestAppStateDisconnectCount:
    def test_increment_increases_count_by_one(self):
        state = AppState()
        state.increment_disconnect()
        assert state.disconnect_count == 1

    def test_multiple_increments_accumulate(self):
        state = AppState()
        for _ in range(5):
            state.increment_disconnect()
        assert state.disconnect_count == 5

    def test_increment_fires_callback(self):
        state = AppState()
        callback = MagicMock()
        state.on_status_change = callback
        state.increment_disconnect()
        callback.assert_called_once()


# ---------------------------------------------------------------------------
# AppState – summary()
# ---------------------------------------------------------------------------

class TestAppStateSummary:
    @pytest.mark.parametrize("status, expected_text", [
        (NetStatus.UNKNOWN, "检测中"),
        (NetStatus.ONLINE, "已联网"),
        (NetStatus.OFFLINE, "未联网"),
        (NetStatus.LOGGING_IN, "登录中"),
    ])
    def test_summary_contains_correct_status_text(self, status, expected_text):
        state = AppState()
        state._status = status
        assert expected_text in state.summary()

    def test_summary_contains_login_time(self):
        state = AppState()
        state.last_login_time = "2024-05-01 10:30:00"
        assert "2024-05-01 10:30:00" in state.summary()

    def test_summary_contains_disconnect_count(self):
        state = AppState()
        state.increment_disconnect()
        state.increment_disconnect()
        assert "2" in state.summary()

    def test_summary_returns_string(self):
        state = AppState()
        assert isinstance(state.summary(), str)

    def test_summary_contains_app_name(self):
        state = AppState()
        assert "AutoNetGuard" in state.summary()


# ---------------------------------------------------------------------------
# AppState – thread safety
# ---------------------------------------------------------------------------

class TestAppStateThreadSafety:
    def test_concurrent_status_updates_do_not_corrupt_state(self):
        state = AppState()
        errors: list[Exception] = []

        def worker(status: NetStatus) -> None:
            try:
                for _ in range(100):
                    state.status = status
                    state.increment_disconnect()
                    _ = state.summary()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(s,))
            for s in [NetStatus.ONLINE, NetStatus.OFFLINE, NetStatus.LOGGING_IN]
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors

    def test_concurrent_reads_never_raise(self):
        state = AppState()
        state.status = NetStatus.ONLINE
        errors: list[Exception] = []

        def reader() -> None:
            try:
                for _ in range(200):
                    _ = state.status
                    _ = state.last_login_time
                    _ = state.disconnect_count
                    _ = state.summary()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors


# ---------------------------------------------------------------------------
# _make_icon
# ---------------------------------------------------------------------------

class TestMakeIcon:
    @pytest.mark.parametrize("status", list(NetStatus))
    def test_returns_pil_image_for_every_status(self, status):
        img = _make_icon(status)
        assert isinstance(img, Image.Image)

    def test_image_has_correct_size(self):
        img = _make_icon(NetStatus.ONLINE)
        assert img.size == (_ICON_SIZE, _ICON_SIZE)

    def test_image_mode_is_rgba(self):
        img = _make_icon(NetStatus.ONLINE)
        assert img.mode == "RGBA"

    def test_different_statuses_may_differ_in_appearance(self):
        online = _make_icon(NetStatus.ONLINE).tobytes()
        offline = _make_icon(NetStatus.OFFLINE).tobytes()
        # Different status → different colour → different pixel bytes
        assert online != offline


# ---------------------------------------------------------------------------
# TrayController – basic construction
# ---------------------------------------------------------------------------

class TestTrayController:
    def test_sets_on_status_change_callback(self):
        state = AppState()
        stop_event = threading.Event()
        controller = TrayController(state, stop_event)
        # Bound methods are re-created on each attribute access, so compare
        # the underlying function and the bound instance instead of using `is`.
        assert callable(state.on_status_change)
        assert state.on_status_change.__func__ is TrayController._refresh_icon
        assert state.on_status_change.__self__ is controller

    def test_refresh_icon_is_noop_before_run(self):
        state = AppState()
        stop_event = threading.Event()
        controller = TrayController(state, stop_event)
        # _icon is None; _refresh_icon must not raise
        controller._refresh_icon()

    def test_on_login_now_sets_status_to_offline(self):
        state = AppState()
        state.status = NetStatus.ONLINE
        stop_event = threading.Event()
        controller = TrayController(state, stop_event)
        controller._on_login_now(MagicMock(), MagicMock())
        assert state.status == NetStatus.OFFLINE

    def test_on_quit_sets_stop_event_and_stops_icon(self):
        state = AppState()
        stop_event = threading.Event()
        controller = TrayController(state, stop_event)
        mock_icon = MagicMock()
        controller._on_quit(mock_icon, MagicMock())
        assert stop_event.is_set()
        mock_icon.stop.assert_called_once()


# ---------------------------------------------------------------------------
# _get_notify_message
# ---------------------------------------------------------------------------

class TestGetNotifyMessage:
    def test_online_to_logging_in_returns_message(self):
        result = _get_notify_message(NetStatus.ONLINE, NetStatus.LOGGING_IN)
        assert result is not None
        title, message = result
        assert "断网" in message

    def test_logging_in_to_online_returns_message(self):
        result = _get_notify_message(NetStatus.LOGGING_IN, NetStatus.ONLINE)
        assert result is not None
        title, message = result
        assert "恢复" in message or "成功" in message

    def test_logging_in_to_offline_returns_message(self):
        result = _get_notify_message(NetStatus.LOGGING_IN, NetStatus.OFFLINE)
        assert result is not None
        title, message = result
        assert "失败" in message

    def test_unknown_transitions_return_none(self):
        assert _get_notify_message(NetStatus.UNKNOWN, NetStatus.ONLINE) is None
        assert _get_notify_message(NetStatus.ONLINE, NetStatus.OFFLINE) is None
        assert _get_notify_message(NetStatus.OFFLINE, NetStatus.LOGGING_IN) is None

    def test_same_status_returns_none(self):
        for status in NetStatus:
            assert _get_notify_message(status, status) is None

    def test_result_is_two_strings(self):
        result = _get_notify_message(NetStatus.ONLINE, NetStatus.LOGGING_IN)
        assert result is not None
        title, message = result
        assert isinstance(title, str) and isinstance(message, str)


# ---------------------------------------------------------------------------
# AppState – on_notify callback
# ---------------------------------------------------------------------------

class TestAppStateOnNotify:
    def test_on_notify_fires_on_noteworthy_transition(self):
        state = AppState()
        state.status = NetStatus.ONLINE
        notify_cb = MagicMock()
        state.on_notify = notify_cb
        state.status = NetStatus.LOGGING_IN
        notify_cb.assert_called_once()
        title, message = notify_cb.call_args[0]
        assert isinstance(title, str) and isinstance(message, str)

    def test_on_notify_not_fired_for_silent_transition(self):
        state = AppState()
        state.status = NetStatus.UNKNOWN
        notify_cb = MagicMock()
        state.on_notify = notify_cb
        state.status = NetStatus.ONLINE  # UNKNOWN→ONLINE is not noteworthy
        notify_cb.assert_not_called()

    def test_on_notify_not_fired_when_status_unchanged(self):
        state = AppState()
        state.status = NetStatus.ONLINE
        notify_cb = MagicMock()
        state.on_notify = notify_cb
        state.status = NetStatus.ONLINE  # no change
        notify_cb.assert_not_called()

    def test_full_disconnect_reconnect_sequence(self):
        state = AppState()
        state.status = NetStatus.ONLINE
        notifications: list[tuple[str, str]] = []
        state.on_notify = lambda t, m: notifications.append((t, m))

        state.status = NetStatus.LOGGING_IN   # disconnect detected
        state.status = NetStatus.ONLINE       # reconnected

        assert len(notifications) == 2
        assert "断网" in notifications[0][1]
        assert "恢复" in notifications[1][1] or "成功" in notifications[1][1]

    def test_full_disconnect_fail_sequence(self):
        state = AppState()
        state.status = NetStatus.ONLINE
        notifications: list[tuple[str, str]] = []
        state.on_notify = lambda t, m: notifications.append((t, m))

        state.status = NetStatus.LOGGING_IN   # disconnect detected
        state.status = NetStatus.OFFLINE      # all retries failed

        assert len(notifications) == 2
        assert "断网" in notifications[0][1]
        assert "失败" in notifications[1][1]


# ---------------------------------------------------------------------------
# TrayController – notification wiring
# ---------------------------------------------------------------------------

class TestTrayControllerNotifications:
    def test_on_notify_wired_to_send_notification(self):
        state = AppState()
        stop_event = threading.Event()
        TrayController(state, stop_event)
        assert callable(state.on_notify)

    def test_send_notification_is_noop_before_run(self):
        state = AppState()
        stop_event = threading.Event()
        controller = TrayController(state, stop_event)
        # _icon is None; _send_notification must not raise
        controller._send_notification("AutoNetGuard", "test message")

    def test_send_notification_calls_icon_notify_when_enabled(self, monkeypatch):
        import config as _cfg
        monkeypatch.setattr(_cfg, "ENABLE_NOTIFICATIONS", True)

        state = AppState()
        stop_event = threading.Event()
        controller = TrayController(state, stop_event)
        mock_icon = MagicMock()
        controller._icon = mock_icon

        controller._send_notification("AutoNetGuard", "网络已恢复")
        mock_icon.notify.assert_called_once_with("网络已恢复", "AutoNetGuard")

    def test_send_notification_skipped_when_disabled(self, monkeypatch):
        import config as _cfg
        monkeypatch.setattr(_cfg, "ENABLE_NOTIFICATIONS", False)

        state = AppState()
        stop_event = threading.Event()
        controller = TrayController(state, stop_event)
        mock_icon = MagicMock()
        controller._icon = mock_icon

        controller._send_notification("AutoNetGuard", "网络已恢复")
        mock_icon.notify.assert_not_called()

    def test_send_notification_swallows_exceptions(self, monkeypatch):
        import config as _cfg
        monkeypatch.setattr(_cfg, "ENABLE_NOTIFICATIONS", True)

        state = AppState()
        stop_event = threading.Event()
        controller = TrayController(state, stop_event)
        mock_icon = MagicMock()
        mock_icon.notify.side_effect = RuntimeError("platform error")
        controller._icon = mock_icon

        # Must not raise
        controller._send_notification("AutoNetGuard", "test")


# ---------------------------------------------------------------------------
# AppState – wakeup_event
# ---------------------------------------------------------------------------

class TestAppStateWakeupEvent:
    def test_wakeup_event_is_threading_event(self):
        state = AppState()
        assert isinstance(state.wakeup_event, threading.Event)

    def test_wakeup_event_initially_not_set(self):
        state = AppState()
        assert not state.wakeup_event.is_set()

    def test_wakeup_event_can_be_set_and_cleared(self):
        state = AppState()
        state.wakeup_event.set()
        assert state.wakeup_event.is_set()
        state.wakeup_event.clear()
        assert not state.wakeup_event.is_set()


# ---------------------------------------------------------------------------
# TrayController – profile switching
# ---------------------------------------------------------------------------

class TestTrayControllerProfileSwitch:
    def test_on_switch_profile_sets_config_changed_and_wakeup_events(self, monkeypatch):
        import config as _cfg

        monkeypatch.setattr(_cfg, "switch_profile", lambda name: None)
        monkeypatch.setattr(_cfg, "list_profiles", lambda: ["school", "company"])
        monkeypatch.setattr(_cfg, "get_active_profile", lambda: "school")

        state = AppState()
        stop_event = threading.Event()
        controller = TrayController(state, stop_event)

        controller._on_switch_profile("company")

        assert state.config_changed.is_set()
        assert state.wakeup_event.is_set()

    def test_on_switch_profile_refreshes_menu_when_icon_present(self, monkeypatch):
        import config as _cfg

        monkeypatch.setattr(_cfg, "switch_profile", lambda name: None)
        monkeypatch.setattr(_cfg, "list_profiles", lambda: ["school", "company"])
        monkeypatch.setattr(_cfg, "get_active_profile", lambda: "company")

        state = AppState()
        stop_event = threading.Event()
        controller = TrayController(state, stop_event)
        mock_icon = MagicMock()
        controller._icon = mock_icon

        controller._on_switch_profile("company")

        mock_icon.update_menu.assert_called()

    def test_build_profile_submenu_with_no_profiles_returns_disabled_item(self, monkeypatch):
        import config as _cfg

        monkeypatch.setattr(_cfg, "list_profiles", lambda: [])
        monkeypatch.setattr(_cfg, "get_active_profile", lambda: "")

        state = AppState()
        controller = TrayController(state, threading.Event())
        submenu = controller._build_profile_submenu()
        # Should return a Menu object (not raise)
        assert submenu is not None

    def test_build_profile_submenu_with_profiles_returns_menu(self, monkeypatch):
        import config as _cfg

        monkeypatch.setattr(_cfg, "list_profiles", lambda: ["school", "company"])
        monkeypatch.setattr(_cfg, "get_active_profile", lambda: "school")

        state = AppState()
        controller = TrayController(state, threading.Event())
        submenu = controller._build_profile_submenu()
        assert submenu is not None
