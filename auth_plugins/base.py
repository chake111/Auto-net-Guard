"""Base authenticator interface (Strategy Pattern).

All concrete authenticators must inherit from ``BaseAuthenticator`` and
implement the :meth:`login` method.
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
