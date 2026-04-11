"""Generic HTTP form authenticator.

Provides a flexible, configuration-driven authenticator that submits an
HTTP GET or POST request to an arbitrary login URL.  All form parameters
are read from the ``[auth_params]`` section of ``config.ini`` and may
contain the following placeholders, which are substituted at login time:

* ``{ip}``           – active local IPv4 address
* ``{mac}``          – active interface MAC (12 lower-hex digits, no separators)
* ``{user_account}`` – value of ``[credentials] user_account``
* ``{user_password}``– value of ``[credentials] user_password``

Example ``config.ini`` snippet
-------------------------------
.. code-block:: ini

    [auth]
    auth_type           = generic_post
    auth_method         = POST
    auth_success_markers = success,登录成功

    [auth_params]
    username   = {user_account}
    password   = {user_password}
    user_ip    = {ip}
    user_mac   = {mac}
    ac_id      = 1
"""

from __future__ import annotations

import requests

from .base import BaseAuthenticator


class GenericPostAuthenticator(BaseAuthenticator):
    """Config-driven HTTP form authenticator (GET or POST).

    Configuration keys read from the ``config`` module
    ---------------------------------------------------
    * ``LOGIN_URL``             – target URL for the authentication request
    * ``REFERER``               – ``Referer`` header to include
    * ``REQUEST_TIMEOUT_SECONDS``
    * ``AUTH_METHOD``           – ``"GET"`` or ``"POST"`` (default ``"POST"``)
    * ``AUTH_SUCCESS_MARKERS``  – comma-separated substrings that indicate
                                  a successful response (case-insensitive)
    * ``AUTH_PARAMS``           – ``dict[str, str]`` of form parameters;
                                  values may contain ``{ip}``, ``{mac}``,
                                  ``{user_account}``, and ``{user_password}``
                                  placeholders
    """

    def _resolve_params(self, ip: str, mac: str) -> dict[str, str]:
        """Substitute runtime placeholders in every configured parameter value."""
        import config as _cfg  # noqa: PLC0415

        substitutions = {
            "ip": ip,
            "mac": mac,
            "user_account": _cfg.USER_ACCOUNT,
            "user_password": _cfg.USER_PASSWORD,
        }
        return {
            k: v.format_map(substitutions)
            for k, v in _cfg.AUTH_PARAMS.items()
        }

    def _parse_success_markers(self) -> list[str]:
        import config as _cfg  # noqa: PLC0415

        return [
            m.strip()
            for m in _cfg.AUTH_SUCCESS_MARKERS.split(",")
            if m.strip()
        ]

    def login(self, session: requests.Session, ip: str, mac: str) -> bool:
        """Submit the configured HTTP form and check the response for success.

        Raises
        ------
        requests.HTTPError
            When the server returns a non-2xx HTTP status.
        requests.RequestException
            On connection or timeout failures.
        """
        import config as _cfg  # noqa: PLC0415

        method = _cfg.AUTH_METHOD.upper()
        url = _cfg.LOGIN_URL
        headers = {"Referer": _cfg.REFERER}
        timeout = _cfg.REQUEST_TIMEOUT_SECONDS
        params = self._resolve_params(ip=ip, mac=mac)

        if method == "POST":
            response = session.post(
                url,
                data=params,
                headers=headers,
                timeout=timeout,
            )
        else:
            response = session.get(
                url,
                params=params,
                headers=headers,
                timeout=timeout,
            )

        response.raise_for_status()

        text = response.text.lower()
        success_markers = self._parse_success_markers()
        return any(marker in text for marker in success_markers)
