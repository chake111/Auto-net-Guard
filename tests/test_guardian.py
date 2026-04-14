"""Unit tests for guardian.py – network helpers and guardian loop."""

from __future__ import annotations

import os
import threading
from unittest.mock import MagicMock, patch

import pytest
import requests

import guardian
from guardian import (
    _normalize_mac,
    _is_process_running,
    _next_check_interval,
    _wait_for_wakeup_or_timeout,
    acquire_instance_lock,
    check_connectivity,
    guardian_target,
    login_with_retry,
    release_instance_lock,
)
from auth_plugins import DrcomAuthenticator
from tray import AppState, NetStatus


# ---------------------------------------------------------------------------
# _normalize_mac
# ---------------------------------------------------------------------------

class TestNormalizeMac:
    def test_colon_separated_uppercased(self):
        assert _normalize_mac("AA:BB:CC:DD:EE:FF") == "aabbccddeeff"

    def test_dash_separated(self):
        assert _normalize_mac("AA-BB-CC-DD-EE-FF") == "aabbccddeeff"

    def test_bare_12_hex_characters(self):
        assert _normalize_mac("aabbccddeeff") == "aabbccddeeff"

    def test_all_zeros_returns_empty_string(self):
        assert _normalize_mac("00:00:00:00:00:00") == ""

    def test_short_string_returns_empty_string(self):
        assert _normalize_mac("AABB") == ""

    def test_long_string_returns_empty_string(self):
        assert _normalize_mac("AA:BB:CC:DD:EE:FF:00") == ""

    def test_strips_surrounding_whitespace(self):
        assert _normalize_mac("  aa:bb:cc:dd:ee:ff  ") == "aabbccddeeff"

    def test_mixed_case_is_lowercased(self):
        assert _normalize_mac("Aa:Bb:Cc:Dd:Ee:Ff") == "aabbccddeeff"

    def test_mixed_separators_are_removed(self):
        # Hyphens and colons stripped before length check
        assert _normalize_mac("aa-bb:cc-dd:ee-ff") == "aabbccddeeff"


# ---------------------------------------------------------------------------
# check_connectivity
# ---------------------------------------------------------------------------

class TestCheckConnectivity:
    def test_returns_true_on_http_204(self):
        session = MagicMock()
        response = MagicMock()
        response.status_code = 204
        session.get.return_value = response
        assert check_connectivity(session) is True

    def test_returns_false_on_http_200(self):
        session = MagicMock()
        response = MagicMock()
        response.status_code = 200
        session.get.return_value = response
        assert check_connectivity(session) is False

    def test_returns_false_on_http_302(self):
        session = MagicMock()
        response = MagicMock()
        response.status_code = 302
        session.get.return_value = response
        assert check_connectivity(session) is False

    def test_returns_false_on_connection_error(self):
        session = MagicMock()
        session.get.side_effect = requests.ConnectionError("unreachable")
        assert check_connectivity(session) is False

    def test_returns_false_on_timeout(self):
        session = MagicMock()
        session.get.side_effect = requests.Timeout("timed out")
        assert check_connectivity(session) is False

    def test_passes_allow_redirects_false(self):
        session = MagicMock()
        response = MagicMock()
        response.status_code = 204
        session.get.return_value = response
        check_connectivity(session)
        _, kwargs = session.get.call_args
        assert kwargs.get("allow_redirects") is False

    def test_uses_dedicated_connectivity_timeout(self):
        session = MagicMock()
        response = MagicMock()
        response.status_code = 204
        session.get.return_value = response

        check_connectivity(session)

        _, kwargs = session.get.call_args
        assert kwargs.get("timeout") == guardian._cfg.CONNECTIVITY_TIMEOUT_SECONDS


# ---------------------------------------------------------------------------
# login_with_retry
# ---------------------------------------------------------------------------

class TestLoginWithRetry:
    def _make_authenticator(self, return_value: bool = True) -> MagicMock:
        auth = MagicMock(spec=DrcomAuthenticator)
        auth.login.return_value = return_value
        return auth

    def test_returns_true_on_first_successful_attempt(self):
        session = MagicMock()
        auth = self._make_authenticator(return_value=True)
        with (
            patch("guardian.get_active_ip", return_value="10.0.0.1"),
            patch("guardian.get_active_mac", return_value="aabbccddeeff"),
        ):
            assert login_with_retry(session, auth) is True

    def test_returns_false_when_all_retries_fail(self):
        session = MagicMock()
        auth = self._make_authenticator(return_value=False)
        with (
            patch("guardian.get_active_ip", return_value="10.0.0.1"),
            patch("guardian.get_active_mac", return_value="aabbccddeeff"),
            patch("guardian.time.sleep"),
        ):
            assert login_with_retry(session, auth) is False

    def test_succeeds_on_second_attempt_after_first_rejection(self):
        session = MagicMock()
        call_count = {"n": 0}

        def fake_login(**kwargs):
            call_count["n"] += 1
            return call_count["n"] >= 2

        auth = MagicMock(spec=DrcomAuthenticator)
        auth.login.side_effect = fake_login

        with (
            patch("guardian.get_active_ip", return_value="10.0.0.1"),
            patch("guardian.get_active_mac", return_value="aabbccddeeff"),
            patch("guardian.time.sleep"),
        ):
            result = login_with_retry(session, auth)

        assert result is True
        assert call_count["n"] == 2

    def test_exception_in_attempt_is_handled_and_loop_continues(self):
        session = MagicMock()
        call_count = {"n": 0}

        def fake_login(**kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise requests.ConnectionError("network error")
            return True

        auth = MagicMock(spec=DrcomAuthenticator)
        auth.login.side_effect = fake_login

        with (
            patch("guardian.get_active_ip", return_value="10.0.0.1"),
            patch("guardian.get_active_mac", return_value="aabbccddeeff"),
            patch("guardian.time.sleep"),
        ):
            assert login_with_retry(session, auth) is True

    def test_backoff_sleep_called_between_retries(self):
        session = MagicMock()
        auth = self._make_authenticator(return_value=False)
        sleep_calls = []

        with (
            patch("guardian.get_active_ip", return_value="10.0.0.1"),
            patch("guardian.get_active_mac", return_value="aabbccddeeff"),
            patch("guardian.time.sleep", side_effect=lambda t: sleep_calls.append(t)),
        ):
            login_with_retry(session, auth)

        # sleep is called between retries, not after the last one
        import config as cfg
        assert len(sleep_calls) == cfg.LOGIN_RETRY_COUNT - 1

    def test_uses_config_authenticator_when_none_provided(self):
        """When no authenticator is passed, one is created from config."""
        session = MagicMock()
        mock_auth = self._make_authenticator(return_value=True)
        with (
            patch("guardian.get_active_ip", return_value="10.0.0.1"),
            patch("guardian.get_active_mac", return_value="aabbccddeeff"),
            patch("guardian.auth_plugins.get_authenticator", return_value=mock_auth),
        ):
            assert login_with_retry(session) is True
        mock_auth.login.assert_called_once()

    def test_reuses_cached_mac_when_ip_stays_the_same(self):
        session = MagicMock()
        auth = self._make_authenticator(return_value=False)

        with (
            patch("guardian.get_active_ip", return_value="10.0.0.1") as get_ip,
            patch("guardian.get_active_mac", return_value="aabbccddeeff") as get_mac,
            patch("guardian.time.sleep"),
        ):
            login_with_retry(session, auth)

        get_ip.assert_called_once()
        get_mac.assert_called_once_with("10.0.0.1")


# ---------------------------------------------------------------------------
# _is_process_running
# ---------------------------------------------------------------------------

class TestIsProcessRunning:
    def test_current_process_is_running(self):
        assert _is_process_running(os.getpid()) is True

    def test_nonexistent_pid_returns_false(self):
        assert _is_process_running(999_999_999) is False

    def test_pid_zero_returns_false(self):
        # PID 0 is not a user process
        assert _is_process_running(0) is False


# ---------------------------------------------------------------------------
# acquire_instance_lock / release_instance_lock
# ---------------------------------------------------------------------------

class TestInstanceLock:
    def test_acquire_creates_pid_file_with_current_pid(self, tmp_path):
        pid_file = tmp_path / "guardian.pid"
        with patch.object(guardian, "PID_FILE", pid_file):
            acquire_instance_lock()
            assert pid_file.exists()
            assert int(pid_file.read_text()) == os.getpid()
            pid_file.unlink()  # cleanup

    def test_acquire_overwrites_stale_pid_file(self, tmp_path):
        pid_file = tmp_path / "guardian.pid"
        pid_file.write_text("999999999", encoding="utf-8")  # stale PID
        with patch.object(guardian, "PID_FILE", pid_file):
            acquire_instance_lock()
            assert int(pid_file.read_text()) == os.getpid()
            pid_file.unlink()

    def test_release_removes_pid_file(self, tmp_path):
        pid_file = tmp_path / "guardian.pid"
        pid_file.write_text(str(os.getpid()), encoding="utf-8")
        with patch.object(guardian, "PID_FILE", pid_file):
            release_instance_lock()
            assert not pid_file.exists()

    def test_release_on_missing_pid_file_does_not_raise(self, tmp_path):
        pid_file = tmp_path / "nonexistent.pid"
        with patch.object(guardian, "PID_FILE", pid_file):
            release_instance_lock()  # must not raise

    def test_acquire_exits_when_another_instance_is_running(self, tmp_path):
        pid_file = tmp_path / "guardian.pid"
        # Write our own PID so _is_process_running returns True
        pid_file.write_text(str(os.getpid()), encoding="utf-8")
        with patch.object(guardian, "PID_FILE", pid_file):
            with pytest.raises(SystemExit):
                acquire_instance_lock()


# ---------------------------------------------------------------------------
# guardian_target
# ---------------------------------------------------------------------------

class TestGuardianTarget:
    def _make_auth(self, return_value: bool = True) -> MagicMock:
        auth = MagicMock(spec=DrcomAuthenticator)
        auth.login.return_value = return_value
        return auth

    def test_loop_skipped_when_stop_event_already_set(self):
        state = AppState()
        stop_event = threading.Event()
        stop_event.set()  # signal before entry

        with (
            patch("guardian.setup_logging"),
            patch("guardian.auth_plugins.get_authenticator", return_value=self._make_auth()),
        ):
            guardian_target(state, stop_event)

        # Loop body never executed; state stays at default
        assert state.status == NetStatus.UNKNOWN

    def test_status_becomes_online_when_connectivity_ok(self):
        state = AppState()
        stop_event = threading.Event()

        def fake_check(session):
            stop_event.set()  # exit after one iteration
            return True

        with (
            patch("guardian.get_active_ip", return_value="10.0.0.1"),
            patch("guardian.check_connectivity", side_effect=fake_check),
            patch("guardian.setup_logging"),
            patch("guardian.auth_plugins.get_authenticator", return_value=self._make_auth()),
        ):
            guardian_target(state, stop_event)

        assert state.status == NetStatus.ONLINE

    def test_first_connectivity_failure_is_debounced(self):
        state = AppState()
        stop_event = threading.Event()

        def fake_check(session):
            stop_event.set()
            return False

        login_mock = MagicMock(return_value=False)

        with (
            patch("guardian.get_active_ip", return_value="10.0.0.1"),
            patch("guardian.check_connectivity", side_effect=fake_check),
            patch("guardian.login_with_retry", login_mock),
            patch("guardian.setup_logging"),
            patch("guardian.auth_plugins.get_authenticator", return_value=self._make_auth()),
        ):
            guardian_target(state, stop_event)

        assert state.status == NetStatus.UNKNOWN
        assert state.disconnect_count == 0
        login_mock.assert_not_called()

    def test_second_consecutive_failure_triggers_offline_and_login(self):
        state = AppState()
        stop_event = threading.Event()
        call_count = {"n": 0}

        def fake_check(session):
            call_count["n"] += 1
            if call_count["n"] >= 2:
                stop_event.set()
            return False

        login_mock = MagicMock(return_value=False)

        with (
            patch("guardian.get_active_ip", return_value="10.0.0.1"),
            patch("guardian.check_connectivity", side_effect=fake_check),
            patch("guardian.login_with_retry", login_mock),
            patch("guardian.setup_logging"),
            patch("guardian.auth_plugins.get_authenticator", return_value=self._make_auth()),
        ):
            guardian_target(state, stop_event)

        assert state.status == NetStatus.OFFLINE
        assert state.disconnect_count == 1
        login_mock.assert_called_once()

    def test_login_triggered_and_status_offline_when_connectivity_fails_and_login_fails(self):
        state = AppState()
        stop_event = threading.Event()
        call_count = {"n": 0}

        def fake_check(session):
            call_count["n"] += 1
            if call_count["n"] >= 2:
                stop_event.set()
            return False

        def fake_login(session, authenticator, active_ip=None):  # noqa: ARG001
            assert state.status == NetStatus.LOGGING_IN
            return False

        with (
            patch("guardian.get_active_ip", return_value="10.0.0.1"),
            patch("guardian.check_connectivity", side_effect=fake_check),
            patch("guardian.login_with_retry", side_effect=fake_login),
            patch("guardian.setup_logging"),
            patch("guardian.auth_plugins.get_authenticator", return_value=self._make_auth()),
        ):
            guardian_target(state, stop_event)

        assert state.status == NetStatus.OFFLINE

    def test_status_online_after_successful_login_restores_connectivity(self):
        state = AppState()
        stop_event = threading.Event()
        check_calls = {"n": 0}

        def fake_check(session):
            check_calls["n"] += 1
            if check_calls["n"] >= 3:
                stop_event.set()
                return True
            return False

        def fake_login(session, authenticator, active_ip=None):  # noqa: ARG001
            assert state.status == NetStatus.LOGGING_IN
            return True

        with (
            patch("guardian.get_active_ip", return_value="10.0.0.1"),
            patch("guardian.check_connectivity", side_effect=fake_check),
            patch("guardian.login_with_retry", side_effect=fake_login),
            patch("guardian.setup_logging"),
            patch("guardian.auth_plugins.get_authenticator", return_value=self._make_auth()),
        ):
            guardian_target(state, stop_event)

        assert state.status == NetStatus.ONLINE

    def test_disconnect_counter_incremented_on_connectivity_loss(self):
        state = AppState()
        stop_event = threading.Event()
        call_count = {"n": 0}

        def fake_check(session):
            call_count["n"] += 1
            if call_count["n"] >= 2:
                stop_event.set()
            return False

        with (
            patch("guardian.get_active_ip", return_value="10.0.0.1"),
            patch("guardian.check_connectivity", side_effect=fake_check),
            patch("guardian.login_with_retry", return_value=False),
            patch("guardian.setup_logging"),
            patch("guardian.auth_plugins.get_authenticator", return_value=self._make_auth()),
        ):
            guardian_target(state, stop_event)

        assert state.disconnect_count == 1

    def test_status_unknown_on_unhandled_exception(self):
        state = AppState()
        stop_event = threading.Event()

        def exploding_ip():
            stop_event.set()
            raise RuntimeError("unexpected failure")

        with (
            patch("guardian.get_active_ip", side_effect=exploding_ip),
            patch("guardian.setup_logging"),
            patch("guardian.auth_plugins.get_authenticator", return_value=self._make_auth()),
        ):
            guardian_target(state, stop_event)

        assert state.status == NetStatus.UNKNOWN

    def test_ip_change_logged_on_new_ip(self):
        state = AppState()
        stop_event = threading.Event()

        original_get_ip = iter(["10.0.0.1", "10.0.0.2"])

        def fake_get_ip():
            try:
                return next(original_get_ip)
            except StopIteration:
                stop_event.set()
                return "10.0.0.2"

        call_count = {"n": 0}

        def fake_check(session):
            call_count["n"] += 1
            if call_count["n"] >= 2:
                stop_event.set()
            return True

        with (
            patch("guardian.get_active_ip", side_effect=fake_get_ip),
            patch("guardian.check_connectivity", side_effect=fake_check),
            patch("guardian.setup_logging"),
            patch("guardian.auth_plugins.get_authenticator", return_value=self._make_auth()),
        ):
            guardian_target(state, stop_event)

    def test_authenticator_recreated_on_config_changed(self):
        """When config_changed is set, guardian recreates the authenticator."""
        state = AppState()
        stop_event = threading.Event()
        state.config_changed.set()  # simulate a config save before the loop

        auth1 = self._make_auth()
        auth2 = self._make_auth()
        get_auth_calls = {"n": 0}

        def fake_get_authenticator():
            get_auth_calls["n"] += 1
            return auth1 if get_auth_calls["n"] == 1 else auth2

        call_count = {"n": 0}

        def fake_check(session):
            call_count["n"] += 1
            if call_count["n"] >= 2:
                stop_event.set()
            return True

        with (
            patch("guardian.get_active_ip", return_value="10.0.0.1"),
            patch("guardian.check_connectivity", side_effect=fake_check),
            patch("guardian.setup_logging"),
            patch("guardian.auth_plugins.get_authenticator", side_effect=fake_get_authenticator),
            patch("guardian._cfg.reload_config"),
        ):
            guardian_target(state, stop_event)

        # get_authenticator should have been called at least twice (once at
        # startup and once after config_changed was detected).
        assert get_auth_calls["n"] >= 2

    def test_config_reload_failure_keeps_existing_authenticator(self):
        state = AppState()
        stop_event = threading.Event()
        state.config_changed.set()

        def fake_check(session):
            stop_event.set()
            return True

        mock_auth = self._make_auth()

        with (
            patch("guardian.get_active_ip", return_value="10.0.0.1"),
            patch("guardian.check_connectivity", side_effect=fake_check),
            patch("guardian.setup_logging"),
            patch("guardian.auth_plugins.get_authenticator", return_value=mock_auth) as get_auth,
            patch("guardian._cfg.reload_config", side_effect=RuntimeError("boom")),
        ):
            guardian_target(state, stop_event)

        get_auth.assert_called_once()
        assert state.status == NetStatus.ONLINE

    def test_wait_helper_returns_immediately_on_wakeup(self):
        class FakeEvent:
            def __init__(self) -> None:
                self.wait_calls: list[float | None] = []
                self.cleared = False

            def is_set(self) -> bool:
                return False

            def wait(self, timeout: float | None = None) -> bool:
                self.wait_calls.append(timeout)
                return True

            def clear(self) -> None:
                self.cleared = True

        stop_event = FakeEvent()
        wakeup_event = FakeEvent()

        _wait_for_wakeup_or_timeout(stop_event, wakeup_event, 10.0)

        assert wakeup_event.wait_calls
        assert wakeup_event.wait_calls[0] is not None
        assert wakeup_event.wait_calls[0] <= 0.5
        assert wakeup_event.cleared is True

    @pytest.mark.parametrize(
        "status, expected",
        [
            (NetStatus.ONLINE, 1.0),
            (NetStatus.UNKNOWN, 1.0),
            (NetStatus.OFFLINE, 1.0),
            (NetStatus.LOGGING_IN, float(guardian._cfg.CHECK_INTERVAL_SECONDS)),
        ],
    )
    def test_next_check_interval_prefers_fast_online_polling(self, status, expected):
        assert _next_check_interval(status) == expected
