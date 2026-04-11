"""Dr.COM Portal authenticator.

Encapsulates the existing campus-network login logic that was previously
hard-coded inside ``guardian.py``.  The request format targets the common
Dr.COM / iPortal endpoint (``/eportal/portal/login``) used by many Chinese
university campus networks.
"""

from __future__ import annotations

import time

import requests

from .base import BaseAuthenticator


class DrcomAuthenticator(BaseAuthenticator):
    """Authenticator for Dr.COM / Ruijie iPortal captive portals.

    Sends a ``GET`` request to the configured ``login_url`` with a fixed set
    of query parameters expected by the Dr.COM portal software.

    Configuration keys read from ``config`` module
    -----------------------------------------------
    * ``USER_ACCOUNT`` / ``USER_PASSWORD`` – campus-network credentials
    * ``LOGIN_URL`` – full URL of the portal login endpoint
    * ``REFERER`` – ``Referer`` header value expected by the portal
    * ``WLAN_AC_IP`` / ``WLAN_AC_NAME`` – wireless-controller identifiers
    * ``REQUEST_TIMEOUT_SECONDS`` – per-request network timeout
    """

    # Response body substrings that indicate a successful login.
    _SUCCESS_MARKERS: tuple[str, ...] = (
        "success",
        "portal_success",
        '"result":"1"',
        '"result":1',
        "登录成功",
    )

    def _build_params(self, ip: str, mac: str) -> dict[str, str]:
        """Construct the query-parameter dict for the Dr.COM login request."""
        import config as _cfg  # noqa: PLC0415  (deferred to support hot-reload)

        return {
            "callback": "dr1003",
            "login_method": "1",
            "user_account": _cfg.USER_ACCOUNT,
            "user_password": _cfg.USER_PASSWORD,
            "wlan_user_ip": ip,
            "wlan_user_ipv6": "",
            "wlan_user_mac": mac,
            "wlan_vlan_id": "0",
            "wlan_ac_ip": _cfg.WLAN_AC_IP,
            "wlan_ac_name": _cfg.WLAN_AC_NAME,
            "authex_enable": "",
            "jsVersion": "4.2.2",
            "terminal_type": "1",
            "lang": "zh-cn",
            "v": str(int(time.time()) % 10000),
        }

    def login(self, session: requests.Session, ip: str, mac: str) -> bool:
        """Send a Dr.COM portal login request and interpret the response.

        Raises
        ------
        requests.HTTPError
            When the portal returns a non-2xx HTTP status.
        requests.RequestException
            On connection or timeout failures.
        """
        import config as _cfg  # noqa: PLC0415

        params = self._build_params(ip=ip, mac=mac)
        response = session.get(
            _cfg.LOGIN_URL,
            params=params,
            headers={"Referer": _cfg.REFERER},
            timeout=_cfg.REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()

        text = response.text.lower()
        return any(marker in text for marker in self._SUCCESS_MARKERS)
