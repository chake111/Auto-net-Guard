"""Base authenticator interface (Strategy Pattern).

All concrete authenticators must inherit from ``BaseAuthenticator`` and
implement the :meth:`login` method.  They may also override
:meth:`check_status` to provide a portal-specific online-state query.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import requests


class BaseAuthenticator(ABC):
    """Abstract base class for network authentication strategies.

    Concrete sub-classes encapsulate a specific portal/authentication
    protocol.  The :class:`~guardian.guardian_target` loop instantiates
    the appropriate sub-class at startup (via :func:`auth_plugins.get_authenticator`)
    and delegates every re-authentication attempt to :meth:`login`.
    """

    @abstractmethod
    def login(self, session: requests.Session, ip: str, mac: str) -> bool:
        """Attempt to authenticate the device on the captive portal.

        Parameters
        ----------
        session:
            A ``requests.Session`` pre-configured with common headers
            (User-Agent, Accept …).  Re-using the session across calls
            allows persistent cookies / TCP keep-alive where the portal
            supports it.
        ip:
            The local IPv4 address that should be registered with the portal
            (the address of the active outbound interface).
        mac:
            Normalised 12-digit lowercase hex MAC address of the active
            interface (no separators, e.g. ``"aabbccddeeff"``).

        Returns
        -------
        bool
            ``True`` if authentication succeeded; ``False`` if the portal
            explicitly rejected the attempt.  Raises on network / HTTP errors
            so that the caller can handle retries.
        """

    def check_status(self, session: requests.Session) -> bool:
        """Return whether the device is currently authenticated on the network.

        The default implementation issues an HTTP GET to the connectivity
        check URL (``[connectivity] check_url``) and treats an HTTP 204
        response as "online / authenticated".  Sub-classes may override this
        with a portal-specific query (e.g. querying the portal's info
        endpoint) for a more accurate result.

        Parameters
        ----------
        session:
            Shared ``requests.Session`` carrying any existing session cookies.

        Returns
        -------
        bool
            ``True`` if the device appears to be authenticated and online;
            ``False`` otherwise.  Never raises – connectivity failures are
            caught and returned as ``False``.
        """
        import config as _cfg  # noqa: PLC0415  (deferred to support hot-reload)

        try:
            response = session.get(
                _cfg.CONNECTIVITY_URL,
                timeout=_cfg.REQUEST_TIMEOUT_SECONDS,
                allow_redirects=False,
            )
            return response.status_code == 204
        except requests.RequestException:
            return False
