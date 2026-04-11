"""Srun (深澜) portal authenticator.

Implements the challenge–response authentication used by Srun / 深澜 network
portals, which are deployed at many Chinese university campuses.

Protocol flow
-------------
1. GET ``/cgi-bin/get_challenge?username=…&ip=…``  → receive a *challenge*
   token from the portal.
2. Derive an HMAC-MD5 password hash keyed by the challenge.
3. XXTEA-encode a JSON *info* payload (username, password, ip, acid,
   enc_ver) using the challenge as the cipher key, then encode the result
   with Srun's custom Base-64 alphabet.
4. Compute a SHA-1 *chksum* over all login parameters with the challenge
   interleaved as separator.
5. GET ``/cgi-bin/srun_portal?action=login&…`` with all derived parameters
   and check the response for a success indicator.

Configuration (``config.ini``)
-------------------------------
* ``[credentials] user_account`` / ``user_password``
* ``[network]    gateway_ip``   – portal host (e.g. ``10.10.10.10``)
* ``[srun]       acid``         – AC-ID shown on the portal page (default: ``1``)

Example ``config.ini`` snippet
--------------------------------
.. code-block:: ini

    [auth]
    auth_type = srun

    [network]
    gateway_ip = 10.10.10.10

    [srun]
    acid = 1
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac_mod
import json
import re
import time

import requests

from .base import BaseAuthenticator

# ---------------------------------------------------------------------------
# Srun encoding helpers
# ---------------------------------------------------------------------------

# Srun uses a non-standard Base-64 alphabet for the ``info`` parameter.
_STD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_SRUN_B64 = "LVoJPiCN2R8G90yg+hmFHuacZ1OWX4Trail6wtqkdEJSfI5bPzD7Qev3/TBU8KMA"
_B64_TRANS: dict[int, int] = str.maketrans(_STD_B64, _SRUN_B64)

# Standard XXTEA delta constant.
_XXTEA_DELTA = 0x9E3779B9


def _str_to_words(data: bytes, append_len: bool = True) -> list[int]:
    """Pack *data* into 32-bit little-endian words.

    When *append_len* is ``True`` the original byte-length is stored as an
    extra trailing word – this is required for the message vector but not
    for the key vector.
    """
    c = len(data)
    n_words = (c + 3) // 4
    words = [0] * (n_words + (1 if append_len else 0))
    for i, byte in enumerate(data):
        words[i >> 2] |= byte << ((i % 4) * 8)
    if append_len:
        words[-1] = c
    return words


def _words_to_bytes(words: list[int]) -> bytes:
    """Unpack 32-bit little-endian *words* into a byte string."""
    n = len(words) * 4
    result = bytearray(n)
    for i in range(n):
        result[i] = (words[i >> 2] >> ((i % 4) * 8)) & 0xFF
    return bytes(result)


def _xencode(msg: str, key: str) -> bytes:
    """Encrypt *msg* with *key* using the XXTEA block cipher (Srun variant).

    This is a standard Corrected Block TEA (XXTEA) implementation operating
    on 32-bit word arrays derived from UTF-8 strings.  The message vector
    includes the original byte-length as a trailing sentinel word; the result
    is returned as raw bytes (without the length sentinel).

    Parameters
    ----------
    msg:
        Plaintext string to encrypt (UTF-8 encoded internally).
    key:
        Cipher key string (UTF-8 encoded, padded with zero-words to 4 words).

    Returns
    -------
    bytes
        Encrypted byte string.  An empty *msg* returns ``b""``.
    """
    if not msg:
        return b""

    v = _str_to_words(msg.encode("utf-8"), append_len=True)
    k = _str_to_words(key.encode("utf-8"), append_len=False)
    # Key must be exactly 4 words for XXTEA.
    if len(k) < 4:
        k += [0] * (4 - len(k))

    n = len(v) - 1  # index of the length sentinel word
    if n < 1:
        # Degenerate case: message is one word or less – return as-is.
        return _words_to_bytes(v)

    z = v[n]
    q = 6 + 52 // (n + 1)
    d = 0

    for _ in range(q):
        d = (d + _XXTEA_DELTA) & 0xFFFFFFFF
        e = (d >> 2) & 3
        for p in range(n):
            y = v[p + 1]
            mx = (
                ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4))
                ^ ((d ^ y) + (k[(p & 3) ^ e] ^ z))
            )
            v[p] = (v[p] + mx) & 0xFFFFFFFF
            z = v[p]
        y = v[0]
        mx = (
            ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4))
            ^ ((d ^ y) + (k[(n & 3) ^ e] ^ z))
        )
        v[n] = (v[n] + mx) & 0xFFFFFFFF
        z = v[n]

    # Return all words except the length sentinel.
    return _words_to_bytes(v[:-1])


def _srun_b64encode(data: bytes) -> str:
    """Base-64 encode *data* using Srun's custom alphabet."""
    return base64.b64encode(data).decode("ascii").translate(_B64_TRANS)


def _encode_info(
    user: str, password: str, ip: str, acid: str, challenge: str
) -> str:
    """Build the ``{SRBX1}``-prefixed *info* parameter for the login request.

    Serialises the login context as JSON, encrypts it with :func:`_xencode`
    using the challenge as the key, and encodes the result with
    :func:`_srun_b64encode`.
    """
    payload = json.dumps(
        {
            "username": user,
            "password": password,
            "ip": ip,
            "acid": acid,
            "enc_ver": "srun_bx1",
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return "{SRBX1}" + _srun_b64encode(_xencode(payload, challenge))


def _hmac_md5_password(password: str, challenge: str) -> str:
    """Return the ``{MD5}``-prefixed HMAC-MD5 of *password* keyed by *challenge*.

    MD5 is required here by the Srun portal protocol specification; it is not
    used for password *storage*.  ``usedforsecurity=False`` signals this to
    static analysers.
    """
    digest = _hmac_mod.new(
        challenge.encode("utf-8"),
        password.encode("utf-8"),
        lambda: hashlib.md5(usedforsecurity=False),  # type: ignore[call-arg]
    ).hexdigest()
    return "{MD5}" + digest


def _sha1_chksum(
    challenge: str,
    user: str,
    password_md5: str,
    acid: str,
    ip: str,
    n: str,
    type_: str,
    info: str,
) -> str:
    """Compute the SHA-1 checksum required by the Srun login request.

    The checksum covers all key parameters interleaved with the challenge
    as a separator (no additional delimiter between values).

    SHA-1 is required here by the Srun portal protocol specification; it is
    not used for password storage.  ``usedforsecurity=False`` signals this
    to static analysers.
    """
    sep = challenge
    data = sep.join([user, password_md5, acid, ip, n, type_, info])
    # Prepend and append challenge as well (matching the portal expectation).
    chkstr = challenge + data + challenge
    return hashlib.sha1(chkstr.encode("utf-8"), usedforsecurity=False).hexdigest()  # type: ignore[call-arg]


def _parse_jsonp(text: str) -> dict:
    """Extract the JSON object from a JSONP response such as ``jQuery(…)``."""
    match = re.search(r"\((\{.*\})\)", text, re.DOTALL)
    if not match:
        raise ValueError(f"Cannot parse JSONP response: {text!r}")
    return json.loads(match.group(1))


# ---------------------------------------------------------------------------
# Authenticator class
# ---------------------------------------------------------------------------


class SrunAuthenticator(BaseAuthenticator):
    """Authenticator for Srun (深澜) campus-network portals.

    Srun portals use a challenge–response mechanism that combines XXTEA
    encoding, HMAC-MD5, and SHA-1 to authenticate clients.  This is
    distinctly different from the simpler GET-parameter approach used by
    Dr.COM portals.

    Configuration keys read from the ``config`` module
    ---------------------------------------------------
    * ``USER_ACCOUNT`` / ``USER_PASSWORD`` – campus-network credentials
    * ``GATEWAY_IP``                       – portal host address
    * ``SRUN_ACID``                        – AC-ID from the portal page
    * ``REQUEST_TIMEOUT_SECONDS``          – per-request network timeout
    """

    _CHALLENGE_PATH = "/cgi-bin/get_challenge"
    _LOGIN_PATH = "/cgi-bin/srun_portal"
    _INFO_PATH = "/cgi-bin/srun_portal"

    # Substrings in the login response that indicate success.
    _SUCCESS_MARKERS: tuple[str, ...] = (
        '"res":"ok"',
        "login_ok",
        "ip_already_online_error",  # already logged in counts as success
        "成功",
    )

    # Fixed login parameters.
    _N = "200"
    _TYPE = "1"

    def _base_url(self) -> str:
        import config as _cfg  # noqa: PLC0415

        return f"http://{_cfg.GATEWAY_IP}"

    def _fetch_challenge(
        self, session: requests.Session, ip: str, user: str
    ) -> str:
        """GET the challenge token from the portal.

        Returns
        -------
        str
            The challenge string returned by the portal.

        Raises
        ------
        requests.RequestException
            On connection or timeout failures.
        ValueError
            When the response cannot be parsed or the portal returns an error.
        """
        import config as _cfg  # noqa: PLC0415

        url = self._base_url() + self._CHALLENGE_PATH
        ts = str(int(time.time() * 1000))
        params = {
            "callback": "jQuery",
            "username": user,
            "ip": ip,
            "_": ts,
        }
        response = session.get(
            url,
            params=params,
            timeout=_cfg.REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()

        data = _parse_jsonp(response.text)
        if data.get("res") != "ok":
            raise ValueError(
                f"Srun challenge request failed: {data.get('res')!r} – {data}"
            )
        challenge = data.get("challenge", "")
        if not challenge:
            raise ValueError(f"Srun challenge token is empty: {data}")
        return challenge

    def login(self, session: requests.Session, ip: str, mac: str) -> bool:
        """Perform a Srun challenge–response login and return success status.

        Raises
        ------
        requests.RequestException
            On connection or timeout failures during either the challenge or
            login requests.
        ValueError
            When the challenge response cannot be parsed.
        """
        import config as _cfg  # noqa: PLC0415

        user = _cfg.USER_ACCOUNT
        password = _cfg.USER_PASSWORD
        acid = _cfg.SRUN_ACID

        # Step 1: obtain challenge token.
        challenge = self._fetch_challenge(session, ip=ip, user=user)

        # Step 2: derive authentication parameters.
        info = _encode_info(
            user=user,
            password=password,
            ip=ip,
            acid=acid,
            challenge=challenge,
        )
        password_md5 = _hmac_md5_password(password=password, challenge=challenge)
        chksum = _sha1_chksum(
            challenge=challenge,
            user=user,
            password_md5=password_md5,
            acid=acid,
            ip=ip,
            n=self._N,
            type_=self._TYPE,
            info=info,
        )

        # Step 3: submit login request.
        url = self._base_url() + self._LOGIN_PATH
        ts = str(int(time.time() * 1000))
        params = {
            "callback": "jQuery",
            "action": "login",
            "username": user,
            "password": password_md5,
            "ip": ip,
            "acid": acid,
            "info": info,
            "chksum": chksum,
            "n": self._N,
            "type": self._TYPE,
            "_": ts,
        }
        response = session.get(
            url,
            params=params,
            timeout=_cfg.REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()

        text = response.text
        return any(marker in text for marker in self._SUCCESS_MARKERS)

    def check_status(self, session: requests.Session) -> bool:
        """Query the Srun portal's info endpoint to check authentication status.

        Sends a ``get_info`` action request to the portal and returns
        ``True`` when the portal reports the current IP as online.

        Falls back to the default connectivity check on any error so that
        the guardian loop can continue operating even if the portal's info
        endpoint is unavailable.
        """
        import config as _cfg  # noqa: PLC0415

        try:
            active_ip = self._get_active_ip(_cfg.GATEWAY_IP)
            url = self._base_url() + self._INFO_PATH
            ts = str(int(time.time() * 1000))
            params = {
                "callback": "jQuery",
                "action": "get_info",
                "ip": active_ip,
                "_": ts,
            }
            response = session.get(
                url,
                params=params,
                timeout=_cfg.REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            data = _parse_jsonp(response.text)
            # The portal returns "res": "ok" when the IP is currently online.
            return data.get("res") == "ok"
        except (requests.RequestException, ValueError, json.JSONDecodeError):
            # Fall back to connectivity URL check.
            return super().check_status(session)

    @staticmethod
    def _get_active_ip(gateway_ip: str) -> str:
        """Return the local IPv4 used to reach *gateway_ip*."""
        import socket  # noqa: PLC0415

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((gateway_ip, 53))
            return sock.getsockname()[0]
