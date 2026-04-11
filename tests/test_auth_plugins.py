"""Unit tests for the auth_plugins package."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

import auth_plugins
from auth_plugins import (
    BaseAuthenticator,
    DrcomAuthenticator,
    GenericPostAuthenticator,
    SrunAuthenticator,
    get_authenticator,
)


# ---------------------------------------------------------------------------
# BaseAuthenticator – interface contract
# ---------------------------------------------------------------------------

class TestBaseAuthenticator:
    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            BaseAuthenticator()  # type: ignore[abstract]

    def test_concrete_subclass_must_implement_login(self):
        class Incomplete(BaseAuthenticator):  # type: ignore[abstract]
            pass

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]

    def test_minimal_concrete_subclass_is_instantiable(self):
        class Minimal(BaseAuthenticator):
            def login(self, session, ip, mac):
                return True

        assert Minimal().login(MagicMock(), "10.0.0.1", "aabbccddeeff") is True


# ---------------------------------------------------------------------------
# DrcomAuthenticator – _build_params
# ---------------------------------------------------------------------------

class TestDrcomAuthenticatorBuildParams:
    def _auth(self):
        return DrcomAuthenticator()

    def _params(self):
        return self._auth()._build_params(ip="192.168.1.100", mac="aabbccddeeff")

    def test_all_required_keys_present(self):
        required = [
            "callback",
            "login_method",
            "user_account",
            "user_password",
            "wlan_user_ip",
            "wlan_user_mac",
            "wlan_ac_ip",
            "wlan_ac_name",
            "jsVersion",
            "lang",
        ]
        params = self._params()
        for key in required:
            assert key in params, f"Missing param key: {key!r}"

    def test_ip_and_mac_injected_correctly(self):
        params = self._auth()._build_params(ip="10.0.0.1", mac="112233445566")
        assert params["wlan_user_ip"] == "10.0.0.1"
        assert params["wlan_user_mac"] == "112233445566"

    def test_callback_is_dr1003(self):
        assert self._params()["callback"] == "dr1003"

    def test_all_param_values_are_strings(self):
        params = self._params()
        for k, v in params.items():
            assert isinstance(v, str), f"Param {k!r} has non-string value: {v!r}"

    def test_lang_is_chinese(self):
        assert self._params()["lang"] == "zh-cn"


# ---------------------------------------------------------------------------
# DrcomAuthenticator – login
# ---------------------------------------------------------------------------

class TestDrcomAuthenticatorLogin:
    def _make_session(self, text: str, status: int = 200) -> MagicMock:
        session = MagicMock()
        response = MagicMock()
        response.status_code = status
        response.text = text
        response.raise_for_status = MagicMock()
        session.get.return_value = response
        return session

    def _auth(self):
        return DrcomAuthenticator()

    def test_success_keyword_in_response(self):
        session = self._make_session("auth success")
        assert self._auth().login(session, ip="10.0.0.1", mac="aabbccddeeff") is True

    def test_portal_success_marker(self):
        session = self._make_session("portal_success redirect_url")
        assert self._auth().login(session, ip="10.0.0.1", mac="aabbccddeeff") is True

    def test_result_1_json_string_marker(self):
        session = self._make_session('{"result":"1","msg":"ok"}')
        assert self._auth().login(session, ip="10.0.0.1", mac="aabbccddeeff") is True

    def test_result_1_integer_json_marker(self):
        session = self._make_session('{"result":1}')
        assert self._auth().login(session, ip="10.0.0.1", mac="aabbccddeeff") is True

    def test_chinese_success_marker(self):
        session = self._make_session("登录成功，欢迎使用")
        assert self._auth().login(session, ip="10.0.0.1", mac="aabbccddeeff") is True

    def test_no_success_marker_returns_false(self):
        session = self._make_session("authentication failed")
        assert self._auth().login(session, ip="10.0.0.1", mac="aabbccddeeff") is False

    def test_http_error_propagates(self):
        session = MagicMock()
        response = MagicMock()
        response.raise_for_status.side_effect = requests.HTTPError("403 Forbidden")
        session.get.return_value = response
        with pytest.raises(requests.HTTPError):
            self._auth().login(session, ip="10.0.0.1", mac="aabbccddeeff")

    def test_referer_header_included(self):
        session = self._make_session("success")
        self._auth().login(session, ip="10.0.0.1", mac="aabbccddeeff")
        _, kwargs = session.get.call_args
        assert "Referer" in kwargs.get("headers", {})

    def test_uses_get_method(self):
        session = self._make_session("success")
        self._auth().login(session, ip="10.0.0.1", mac="aabbccddeeff")
        session.get.assert_called_once()
        session.post.assert_not_called()


# ---------------------------------------------------------------------------
# GenericPostAuthenticator – _resolve_params
# ---------------------------------------------------------------------------

class TestGenericPostAuthenticatorResolveParams:
    def _auth(self):
        return GenericPostAuthenticator()

    def test_ip_placeholder_substituted(self):
        with patch("config.AUTH_PARAMS", {"user_ip": "{ip}"}):
            params = self._auth()._resolve_params(ip="1.2.3.4", mac="aabb")
        assert params["user_ip"] == "1.2.3.4"

    def test_mac_placeholder_substituted(self):
        with patch("config.AUTH_PARAMS", {"mac_addr": "{mac}"}):
            params = self._auth()._resolve_params(ip="1.2.3.4", mac="aabbccddeeff")
        assert params["mac_addr"] == "aabbccddeeff"

    def test_user_account_placeholder_substituted(self):
        with (
            patch("config.AUTH_PARAMS", {"username": "{user_account}"}),
            patch("config.USER_ACCOUNT", "alice@unicom"),
        ):
            params = self._auth()._resolve_params(ip="1.2.3.4", mac="aabb")
        assert params["username"] == "alice@unicom"

    def test_user_password_placeholder_substituted(self):
        with (
            patch("config.AUTH_PARAMS", {"password": "{user_password}"}),
            patch("config.USER_PASSWORD", "s3cr3t"),
        ):
            params = self._auth()._resolve_params(ip="1.2.3.4", mac="aabb")
        assert params["password"] == "s3cr3t"

    def test_static_value_unchanged(self):
        with patch("config.AUTH_PARAMS", {"ac_id": "1"}):
            params = self._auth()._resolve_params(ip="1.2.3.4", mac="aabb")
        assert params["ac_id"] == "1"

    def test_multiple_placeholders_in_one_value(self):
        with (
            patch("config.AUTH_PARAMS", {"info": "{ip}-{mac}"}),
        ):
            params = self._auth()._resolve_params(ip="10.0.0.1", mac="aabbccddeeff")
        assert params["info"] == "10.0.0.1-aabbccddeeff"


# ---------------------------------------------------------------------------
# GenericPostAuthenticator – login (POST)
# ---------------------------------------------------------------------------

class TestGenericPostAuthenticatorLoginPost:
    def _make_session(self, text: str, status: int = 200) -> MagicMock:
        session = MagicMock()
        response = MagicMock()
        response.status_code = status
        response.text = text
        response.raise_for_status = MagicMock()
        session.post.return_value = response
        session.get.return_value = response
        return session

    def _auth(self):
        return GenericPostAuthenticator()

    def test_success_marker_detected_in_post_response(self):
        session = self._make_session("auth success ok")
        with (
            patch("config.AUTH_METHOD", "POST"),
            patch("config.AUTH_SUCCESS_MARKERS", "success,登录成功"),
            patch("config.AUTH_PARAMS", {}),
        ):
            assert self._auth().login(session, ip="10.0.0.1", mac="aabb") is True
        session.post.assert_called_once()

    def test_no_marker_returns_false(self):
        session = self._make_session("login rejected")
        with (
            patch("config.AUTH_METHOD", "POST"),
            patch("config.AUTH_SUCCESS_MARKERS", "success,登录成功"),
            patch("config.AUTH_PARAMS", {}),
        ):
            assert self._auth().login(session, ip="10.0.0.1", mac="aabb") is False

    def test_uses_post_method_when_configured(self):
        session = self._make_session("success")
        with (
            patch("config.AUTH_METHOD", "POST"),
            patch("config.AUTH_SUCCESS_MARKERS", "success"),
            patch("config.AUTH_PARAMS", {}),
        ):
            self._auth().login(session, ip="10.0.0.1", mac="aabb")
        session.post.assert_called_once()
        session.get.assert_not_called()

    def test_uses_get_method_when_configured(self):
        session = self._make_session("success")
        with (
            patch("config.AUTH_METHOD", "GET"),
            patch("config.AUTH_SUCCESS_MARKERS", "success"),
            patch("config.AUTH_PARAMS", {}),
        ):
            self._auth().login(session, ip="10.0.0.1", mac="aabb")
        session.get.assert_called_once()
        session.post.assert_not_called()

    def test_http_error_propagates(self):
        session = MagicMock()
        response = MagicMock()
        response.raise_for_status.side_effect = requests.HTTPError("500")
        session.post.return_value = response
        with (
            patch("config.AUTH_METHOD", "POST"),
            patch("config.AUTH_SUCCESS_MARKERS", "success"),
            patch("config.AUTH_PARAMS", {}),
        ):
            with pytest.raises(requests.HTTPError):
                self._auth().login(session, ip="10.0.0.1", mac="aabb")

    def test_referer_header_included_in_post(self):
        session = self._make_session("success")
        with (
            patch("config.AUTH_METHOD", "POST"),
            patch("config.AUTH_SUCCESS_MARKERS", "success"),
            patch("config.AUTH_PARAMS", {}),
        ):
            self._auth().login(session, ip="10.0.0.1", mac="aabb")
        _, kwargs = session.post.call_args
        assert "Referer" in kwargs.get("headers", {})

    def test_chinese_success_marker(self):
        session = self._make_session("用户登录成功")
        with (
            patch("config.AUTH_METHOD", "POST"),
            patch("config.AUTH_SUCCESS_MARKERS", "success,登录成功"),
            patch("config.AUTH_PARAMS", {}),
        ):
            assert self._auth().login(session, ip="10.0.0.1", mac="aabb") is True


# ---------------------------------------------------------------------------
# get_authenticator – factory function
# ---------------------------------------------------------------------------

class TestGetAuthenticator:
    def test_drcom_auth_type_returns_drcom_instance(self):
        with patch("config.AUTH_TYPE", "drcom"):
            auth = get_authenticator()
        assert isinstance(auth, DrcomAuthenticator)

    def test_generic_post_auth_type_returns_generic_instance(self):
        with patch("config.AUTH_TYPE", "generic_post"):
            auth = get_authenticator()
        assert isinstance(auth, GenericPostAuthenticator)

    def test_auth_type_is_case_insensitive(self):
        with patch("config.AUTH_TYPE", "DRCOM"):
            auth = get_authenticator()
        assert isinstance(auth, DrcomAuthenticator)

    def test_unknown_auth_type_raises_value_error(self):
        with patch("config.AUTH_TYPE", "nonexistent_protocol"):
            with pytest.raises(ValueError, match="nonexistent_protocol"):
                get_authenticator()

    def test_returned_instance_has_login_method(self):
        with patch("config.AUTH_TYPE", "drcom"):
            auth = get_authenticator()
        assert callable(getattr(auth, "login", None))

    def test_registry_contains_expected_types(self):
        assert "drcom" in auth_plugins._REGISTRY
        assert "generic_post" in auth_plugins._REGISTRY
        assert "srun" in auth_plugins._REGISTRY

    def test_srun_auth_type_returns_srun_instance(self):
        with patch("config.AUTH_TYPE", "srun"):
            auth = get_authenticator()
        assert isinstance(auth, SrunAuthenticator)


# ---------------------------------------------------------------------------
# BaseAuthenticator – check_status (default implementation)
# ---------------------------------------------------------------------------

class TestBaseAuthenticatorCheckStatus:
    def _make_session(self, status_code: int) -> MagicMock:
        session = MagicMock()
        response = MagicMock()
        response.status_code = status_code
        response.raise_for_status = MagicMock()
        session.get.return_value = response
        return session

    def _make_minimal_auth(self) -> BaseAuthenticator:
        class Minimal(BaseAuthenticator):
            def login(self, session, ip, mac):
                return True

        return Minimal()

    def test_returns_true_on_http_204(self):
        auth = self._make_minimal_auth()
        session = self._make_session(204)
        assert auth.check_status(session) is True

    def test_returns_false_on_non_204(self):
        auth = self._make_minimal_auth()
        for code in (200, 301, 302, 404, 503):
            session = self._make_session(code)
            assert auth.check_status(session) is False

    def test_returns_false_on_request_exception(self):
        auth = self._make_minimal_auth()
        session = MagicMock()
        session.get.side_effect = requests.ConnectionError("timeout")
        assert auth.check_status(session) is False

    def test_drcom_inherits_default_check_status(self):
        auth = DrcomAuthenticator()
        session = self._make_session(204)
        assert auth.check_status(session) is True

    def test_generic_post_inherits_default_check_status(self):
        auth = GenericPostAuthenticator()
        session = self._make_session(204)
        assert auth.check_status(session) is True


# ---------------------------------------------------------------------------
# SrunAuthenticator – encoding helpers
# ---------------------------------------------------------------------------

from auth_plugins.srun import (  # noqa: E402
    _encode_info,
    _hmac_md5_password,
    _parse_jsonp,
    _sha1_chksum,
    _srun_b64encode,
    _xencode,
)


class TestSrunEncodingHelpers:
    def test_xencode_empty_returns_empty_bytes(self):
        assert _xencode("", "key") == b""

    def test_xencode_returns_bytes(self):
        result = _xencode("hello", "mykey")
        assert isinstance(result, bytes)

    def test_xencode_same_input_same_output(self):
        assert _xencode("test message", "secret") == _xencode("test message", "secret")

    def test_xencode_different_keys_different_output(self):
        a = _xencode("same message", "key_a")
        b = _xencode("same message", "key_b")
        assert a != b

    def test_srun_b64encode_returns_str(self):
        result = _srun_b64encode(b"hello world")
        assert isinstance(result, str)

    def test_srun_b64encode_length_matches_standard_b64(self):
        data = b"test data 12345"
        import base64

        std = base64.b64encode(data).decode()
        srun = _srun_b64encode(data)
        assert len(srun) == len(std)

    def test_srun_b64encode_uses_custom_alphabet(self):
        # Standard base64 of b'\x00' is 'AAAA=='; Srun maps A→L so starts with 'L'
        result = _srun_b64encode(b"\x00\x00\x00")
        assert result.startswith("L"), f"Expected 'L' prefix, got {result!r}"

    def test_hmac_md5_password_format(self):
        result = _hmac_md5_password("password", "challenge")
        assert result.startswith("{MD5}")
        hex_part = result[5:]
        assert len(hex_part) == 32
        assert all(c in "0123456789abcdef" for c in hex_part)

    def test_hmac_md5_password_differs_by_challenge(self):
        a = _hmac_md5_password("pw", "challenge_a")
        b = _hmac_md5_password("pw", "challenge_b")
        assert a != b

    def test_encode_info_has_srbx1_prefix(self):
        result = _encode_info("user", "pass", "1.2.3.4", "1", "challenge_token")
        assert result.startswith("{SRBX1}")

    def test_encode_info_is_deterministic(self):
        a = _encode_info("user", "pass", "1.2.3.4", "1", "tok")
        b = _encode_info("user", "pass", "1.2.3.4", "1", "tok")
        assert a == b

    def test_encode_info_varies_with_challenge(self):
        a = _encode_info("user", "pass", "1.2.3.4", "1", "token_a")
        b = _encode_info("user", "pass", "1.2.3.4", "1", "token_b")
        assert a != b

    def test_sha1_chksum_returns_40_hex_chars(self):
        result = _sha1_chksum("ch", "user", "{MD5}abc", "1", "1.2.3.4", "200", "1", "{SRBX1}xyz")
        assert len(result) == 40
        assert all(c in "0123456789abcdef" for c in result)

    def test_sha1_chksum_varies_with_challenge(self):
        a = _sha1_chksum("ch_a", "user", "{MD5}abc", "1", "1.2.3.4", "200", "1", "{SRBX1}xyz")
        b = _sha1_chksum("ch_b", "user", "{MD5}abc", "1", "1.2.3.4", "200", "1", "{SRBX1}xyz")
        assert a != b

    def test_parse_jsonp_extracts_dict(self):
        jsonp = 'jQuery({"res":"ok","challenge":"abc123"})'
        result = _parse_jsonp(jsonp)
        assert result == {"res": "ok", "challenge": "abc123"}

    def test_parse_jsonp_raises_on_invalid(self):
        import pytest

        with pytest.raises(ValueError):
            _parse_jsonp("not jsonp at all")


# ---------------------------------------------------------------------------
# SrunAuthenticator – login
# ---------------------------------------------------------------------------

from auth_plugins.srun import SrunAuthenticator  # noqa: E402


class TestSrunAuthenticatorLogin:
    def _make_session(
        self,
        challenge_text: str,
        login_text: str,
        challenge_status: int = 200,
        login_status: int = 200,
    ) -> MagicMock:
        """Build a mock session whose first GET returns the challenge response
        and whose second GET returns the login response."""
        session = MagicMock()
        ch_resp = MagicMock()
        ch_resp.status_code = challenge_status
        ch_resp.text = challenge_text
        ch_resp.raise_for_status = MagicMock()

        login_resp = MagicMock()
        login_resp.status_code = login_status
        login_resp.text = login_text
        login_resp.raise_for_status = MagicMock()

        session.get.side_effect = [ch_resp, login_resp]
        return session

    def _challenge_jsonp(self, challenge: str = "test_challenge_token") -> str:
        return f'jQuery({{"res":"ok","challenge":"{challenge}","client_ip":"10.0.0.1"}})'

    def test_login_success_res_ok(self):
        session = self._make_session(
            self._challenge_jsonp(),
            'jQuery({"res":"ok","suc_msg":"login_ok"})',
        )
        auth = SrunAuthenticator()
        assert auth.login(session, ip="10.0.0.1", mac="aabbccddeeff") is True

    def test_login_success_login_ok_marker(self):
        session = self._make_session(
            self._challenge_jsonp(),
            'jQuery({"res":"login_ok"})',
        )
        assert SrunAuthenticator().login(session, ip="10.0.0.1", mac="aabbccddeeff") is True

    def test_login_success_already_online(self):
        session = self._make_session(
            self._challenge_jsonp(),
            'jQuery({"res":"ip_already_online_error"})',
        )
        assert SrunAuthenticator().login(session, ip="10.0.0.1", mac="aabbccddeeff") is True

    def test_login_failure_returns_false(self):
        session = self._make_session(
            self._challenge_jsonp(),
            'jQuery({"res":"login_error","error":"wrong password"})',
        )
        assert SrunAuthenticator().login(session, ip="10.0.0.1", mac="aabbccddeeff") is False

    def test_challenge_failure_raises_value_error(self):
        session = MagicMock()
        error_resp = MagicMock()
        error_resp.text = 'jQuery({"res":"fail","error":"bad request"})'
        error_resp.raise_for_status = MagicMock()
        session.get.return_value = error_resp
        with pytest.raises(ValueError, match="challenge"):
            SrunAuthenticator().login(session, ip="10.0.0.1", mac="aabbccddeeff")

    def test_http_error_on_challenge_propagates(self):
        session = MagicMock()
        resp = MagicMock()
        resp.raise_for_status.side_effect = requests.HTTPError("503")
        session.get.return_value = resp
        with pytest.raises(requests.HTTPError):
            SrunAuthenticator().login(session, ip="10.0.0.1", mac="aabbccddeeff")

    def test_http_error_on_login_propagates(self):
        session = MagicMock()
        ch_resp = MagicMock()
        ch_resp.text = self._challenge_jsonp()
        ch_resp.raise_for_status = MagicMock()
        login_resp = MagicMock()
        login_resp.raise_for_status.side_effect = requests.HTTPError("403")
        session.get.side_effect = [ch_resp, login_resp]
        with pytest.raises(requests.HTTPError):
            SrunAuthenticator().login(session, ip="10.0.0.1", mac="aabbccddeeff")

    def test_two_get_requests_made_per_login(self):
        session = self._make_session(
            self._challenge_jsonp(),
            'jQuery({"res":"ok"})',
        )
        SrunAuthenticator().login(session, ip="10.0.0.1", mac="aabbccddeeff")
        assert session.get.call_count == 2

    def test_challenge_url_called_first(self):
        session = self._make_session(
            self._challenge_jsonp(),
            'jQuery({"res":"ok"})',
        )
        SrunAuthenticator().login(session, ip="10.0.0.1", mac="aabbccddeeff")
        first_call_url = session.get.call_args_list[0][0][0]
        assert "get_challenge" in first_call_url

    def test_login_url_called_second(self):
        session = self._make_session(
            self._challenge_jsonp(),
            'jQuery({"res":"ok"})',
        )
        SrunAuthenticator().login(session, ip="10.0.0.1", mac="aabbccddeeff")
        second_call_url = session.get.call_args_list[1][0][0]
        assert "srun_portal" in second_call_url


# ---------------------------------------------------------------------------
# SrunAuthenticator – check_status
# ---------------------------------------------------------------------------

class TestSrunAuthenticatorCheckStatus:
    def _make_session_with_info_response(self, info_text: str) -> MagicMock:
        session = MagicMock()
        resp = MagicMock()
        resp.text = info_text
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        session.get.return_value = resp
        return session

    def test_online_when_portal_returns_ok(self):
        session = self._make_session_with_info_response(
            'jQuery({"res":"ok","online_ip":"10.0.0.1"})'
        )
        auth = SrunAuthenticator()
        with patch.object(auth, "_get_active_ip", return_value="10.0.0.1"):
            result = auth.check_status(session)
        assert result is True

    def test_offline_when_portal_returns_non_ok(self):
        session = self._make_session_with_info_response(
            'jQuery({"res":"not_online_error"})'
        )
        auth = SrunAuthenticator()
        with patch.object(auth, "_get_active_ip", return_value="10.0.0.1"):
            result = auth.check_status(session)
        assert result is False

    def test_falls_back_on_request_exception(self):
        session = MagicMock()
        session.get.side_effect = requests.ConnectionError("timeout")
        auth = SrunAuthenticator()
        with patch.object(auth, "_get_active_ip", return_value="10.0.0.1"):
            # Should not raise – falls back to default connectivity check
            result = auth.check_status(session)
        assert isinstance(result, bool)
