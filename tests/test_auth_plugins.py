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
