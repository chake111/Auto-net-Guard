"""Unit tests for config.py – encryption helpers and configuration loading."""

from __future__ import annotations

import configparser
from pathlib import Path

import pytest

import config as cfg


# ---------------------------------------------------------------------------
# _is_encrypted
# ---------------------------------------------------------------------------

class TestIsEncrypted:
    def test_encrypted_prefix_returns_true(self):
        assert cfg._is_encrypted("ENC:sometoken") is True

    def test_plain_text_returns_false(self):
        assert cfg._is_encrypted("plaintext") is False

    def test_empty_string_returns_false(self):
        assert cfg._is_encrypted("") is False

    def test_lowercase_enc_prefix_returns_false(self):
        assert cfg._is_encrypted("enc:token") is False

    def test_enc_prefix_alone_returns_true(self):
        assert cfg._is_encrypted("ENC:") is True


# ---------------------------------------------------------------------------
# _encrypt_value / _decrypt_value
# ---------------------------------------------------------------------------

class TestEncryptDecryptRoundTrip:
    def test_basic_round_trip(self):
        plaintext = "hello_world"
        encrypted = cfg._encrypt_value(plaintext)
        assert cfg._decrypt_value(encrypted) == plaintext

    def test_encrypt_returns_enc_prefixed_string(self):
        result = cfg._encrypt_value("test")
        assert isinstance(result, str)
        assert result.startswith("ENC:")

    def test_different_plaintexts_produce_different_ciphertexts(self):
        enc1 = cfg._encrypt_value("abc")
        enc2 = cfg._encrypt_value("xyz")
        assert enc1 != enc2

    def test_unicode_round_trip(self):
        plaintext = "用户名@校园网"
        encrypted = cfg._encrypt_value(plaintext)
        assert cfg._decrypt_value(encrypted) == plaintext

    def test_empty_string_round_trip(self):
        plaintext = ""
        encrypted = cfg._encrypt_value(plaintext)
        assert cfg._decrypt_value(encrypted) == plaintext

    def test_special_characters_round_trip(self):
        plaintext = "P@$$w0rd!#%&*()"
        encrypted = cfg._encrypt_value(plaintext)
        assert cfg._decrypt_value(encrypted) == plaintext

    def test_same_plaintext_same_key_decryptable(self):
        plaintext = "consistent"
        enc1 = cfg._encrypt_value(plaintext)
        enc2 = cfg._encrypt_value(plaintext)
        # Fernet tokens are non-deterministic (include random IV) but both must decrypt
        assert cfg._decrypt_value(enc1) == plaintext
        assert cfg._decrypt_value(enc2) == plaintext


# ---------------------------------------------------------------------------
# _derive_fernet_key
# ---------------------------------------------------------------------------

class TestDeriveFernetKey:
    def test_returns_bytes(self):
        key = cfg._derive_fernet_key("test_machine_id")
        assert isinstance(key, bytes)

    def test_different_machine_ids_produce_different_keys(self):
        key1 = cfg._derive_fernet_key("machine_a")
        key2 = cfg._derive_fernet_key("machine_b")
        assert key1 != key2

    def test_same_machine_id_produces_same_key(self):
        key1 = cfg._derive_fernet_key("machine_x")
        key2 = cfg._derive_fernet_key("machine_x")
        assert key1 == key2

    def test_derived_key_is_valid_fernet_key(self):
        from cryptography.fernet import Fernet

        key = cfg._derive_fernet_key("any_machine")
        # Fernet constructor raises ValueError for invalid keys
        fernet = Fernet(key)
        assert fernet is not None

    def test_key_length_correct_for_fernet(self):
        import base64

        key = cfg._derive_fernet_key("machine")
        # Fernet keys are 32 raw bytes encoded as URL-safe base64 (44 chars)
        raw = base64.urlsafe_b64decode(key)
        assert len(raw) == 32


# ---------------------------------------------------------------------------
# _get_machine_id
# ---------------------------------------------------------------------------

class TestGetMachineId:
    def test_returns_nonempty_string(self):
        machine_id = cfg._get_machine_id()
        assert isinstance(machine_id, str)
        assert len(machine_id) > 0

    def test_stable_across_calls(self):
        id1 = cfg._get_machine_id()
        id2 = cfg._get_machine_id()
        assert id1 == id2


# ---------------------------------------------------------------------------
# _maybe_encrypt_credentials
# ---------------------------------------------------------------------------

class TestMaybeEncryptCredentials:
    def test_encrypts_plaintext_and_rewrites_file(self, tmp_path):
        ini_file = tmp_path / "config.ini"
        ini_file.write_text(
            "[credentials]\nuser_account = alice\nuser_password = secret\n",
            encoding="utf-8",
        )
        parser = configparser.ConfigParser()
        parser.read(ini_file, encoding="utf-8")

        cfg._maybe_encrypt_credentials(parser, ini_file)

        content = ini_file.read_text(encoding="utf-8")
        assert "ENC:" in content
        assert cfg._is_encrypted(parser.get("credentials", "user_account"))
        assert cfg._is_encrypted(parser.get("credentials", "user_password"))

    def test_encrypted_values_are_decryptable(self, tmp_path):
        ini_file = tmp_path / "config.ini"
        ini_file.write_text(
            "[credentials]\nuser_account = alice\nuser_password = secret\n",
            encoding="utf-8",
        )
        parser = configparser.ConfigParser()
        parser.read(ini_file, encoding="utf-8")

        cfg._maybe_encrypt_credentials(parser, ini_file)

        assert cfg._decrypt_value(parser.get("credentials", "user_account")) == "alice"
        assert cfg._decrypt_value(parser.get("credentials", "user_password")) == "secret"

    def test_already_encrypted_values_are_not_rewritten(self, tmp_path):
        enc_account = cfg._encrypt_value("alice")
        enc_password = cfg._encrypt_value("secret")
        original_content = (
            f"[credentials]\nuser_account = {enc_account}\nuser_password = {enc_password}\n"
        )
        ini_file = tmp_path / "config.ini"
        ini_file.write_text(original_content, encoding="utf-8")

        parser = configparser.ConfigParser()
        parser.read(ini_file, encoding="utf-8")
        cfg._maybe_encrypt_credentials(parser, ini_file)

        # File must not have been rewritten (content unchanged)
        assert ini_file.read_text(encoding="utf-8") == original_content

    def test_missing_file_is_noop(self, tmp_path):
        missing = tmp_path / "nonexistent.ini"
        parser = configparser.ConfigParser()
        cfg._maybe_encrypt_credentials(parser, missing)  # must not raise

    def test_no_credentials_section_is_noop(self, tmp_path):
        ini_file = tmp_path / "config.ini"
        ini_file.write_text("[network]\ngateway_ip = 1.2.3.4\n", encoding="utf-8")
        parser = configparser.ConfigParser()
        parser.read(ini_file, encoding="utf-8")
        cfg._maybe_encrypt_credentials(parser, ini_file)  # must not raise


# ---------------------------------------------------------------------------
# _get (internal reader)
# ---------------------------------------------------------------------------

class TestGet:
    def test_returns_credentials_loaded_from_test_config(self):
        # USER_ACCOUNT / USER_PASSWORD were loaded from the bootstrap config.ini
        assert isinstance(cfg.USER_ACCOUNT, str) and len(cfg.USER_ACCOUNT) > 0
        assert isinstance(cfg.USER_PASSWORD, str) and len(cfg.USER_PASSWORD) > 0

    def test_raises_key_error_for_missing_key_without_fallback(self):
        with pytest.raises(KeyError):
            cfg._get("credentials", "nonexistent_key_xyz")

    def test_fallback_returned_when_key_missing(self):
        result = cfg._get("nonexistent_section", "any_key", fallback="my_default")
        assert result == "my_default"

    def test_returns_plain_string_for_non_encrypted_value(self):
        # Timing section values are plain integers-as-strings
        val = cfg._get("timing", "request_timeout_seconds")
        assert val.isdigit()

    def test_encrypted_value_is_decrypted_transparently(self):
        # Directly verify _decrypt_value path by round-tripping through helpers
        plaintext = "roundtrip_test"
        encrypted = cfg._encrypt_value(plaintext)
        assert cfg._is_encrypted(encrypted)
        assert cfg._decrypt_value(encrypted) == plaintext


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

class TestModuleConstants:
    def test_gateway_ip_is_string(self):
        assert isinstance(cfg.GATEWAY_IP, str)

    def test_login_url_starts_with_http(self):
        assert cfg.LOGIN_URL.startswith("http")

    def test_request_timeout_is_positive_int(self):
        assert isinstance(cfg.REQUEST_TIMEOUT_SECONDS, int)
        assert cfg.REQUEST_TIMEOUT_SECONDS > 0

    def test_check_interval_is_positive_int(self):
        assert isinstance(cfg.CHECK_INTERVAL_SECONDS, int)
        assert cfg.CHECK_INTERVAL_SECONDS > 0

    def test_login_retry_count_is_positive_int(self):
        assert isinstance(cfg.LOGIN_RETRY_COUNT, int)
        assert cfg.LOGIN_RETRY_COUNT > 0

    def test_backoff_base_is_non_negative_int(self):
        assert isinstance(cfg.BACKOFF_BASE_SECONDS, int)
        assert cfg.BACKOFF_BASE_SECONDS >= 0

    def test_log_file_is_string(self):
        assert isinstance(cfg.LOG_FILE, str)
        assert len(cfg.LOG_FILE) > 0


# ---------------------------------------------------------------------------
# ENABLE_NOTIFICATIONS constant
# ---------------------------------------------------------------------------

class TestEnableNotifications:
    def test_is_bool(self):
        assert isinstance(cfg.ENABLE_NOTIFICATIONS, bool)

    def test_default_is_true_from_test_config(self):
        # conftest.py writes [ui] enable_notifications = true
        assert cfg.ENABLE_NOTIFICATIONS is True
