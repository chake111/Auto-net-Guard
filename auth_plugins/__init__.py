"""AutoNetGuard authentication plugins.

This package implements the **Strategy Pattern** for network authentication,
allowing different captive-portal protocols to be selected and swapped at
runtime without modifying the guardian loop.

Public API
----------
* :class:`BaseAuthenticator`      – abstract interface every strategy must implement
* :class:`DrcomAuthenticator`     – Dr.COM / Ruijie iPortal campus-network login
* :class:`GenericPostAuthenticator` – config-driven HTTP form authenticator
* :class:`SrunAuthenticator`      – Srun / 深澜 challenge–response portal
* :func:`get_authenticator`       – factory that instantiates the strategy selected
  in ``config.ini`` (key ``[auth] auth_type``)

Adding a new protocol
---------------------
1. Create a new module inside ``auth_plugins/`` (e.g. ``my_proto.py``).
2. Define a class that inherits from :class:`BaseAuthenticator` and implements
   :meth:`~BaseAuthenticator.login`.  Optionally override
   :meth:`~BaseAuthenticator.check_status` for portal-specific status queries.
3. Register it in the ``_REGISTRY`` dict below.
4. Set ``auth_type = my_proto`` in ``config.ini``.

No changes to ``guardian.py`` or ``config.py`` are required.
"""

from __future__ import annotations

from .base import BaseAuthenticator
from .drcom import DrcomAuthenticator
from .generic_post import GenericPostAuthenticator
from .srun import SrunAuthenticator

__all__ = [
    "BaseAuthenticator",
    "DrcomAuthenticator",
    "GenericPostAuthenticator",
    "SrunAuthenticator",
    "get_authenticator",
]

# Registry maps config auth_type string → authenticator class.
# Extend this dict to register new protocol plugins.
_REGISTRY: dict[str, type[BaseAuthenticator]] = {
    "drcom": DrcomAuthenticator,
    "generic_post": GenericPostAuthenticator,
    "srun": SrunAuthenticator,
}


def get_authenticator() -> BaseAuthenticator:
    """Instantiate and return the authenticator selected in ``config.ini``.

    Reads ``config.AUTH_TYPE`` (from ``[auth] auth_type``) and looks up the
    corresponding class in :data:`_REGISTRY`.

    Returns
    -------
    BaseAuthenticator
        A ready-to-use authenticator instance.

    Raises
    ------
    ValueError
        When ``auth_type`` names an unregistered strategy.
    """
    import config as _cfg  # noqa: PLC0415  (deferred to support hot-reload)

    auth_type = _cfg.AUTH_TYPE.strip().lower()
    cls = _REGISTRY.get(auth_type)
    if cls is None:
        supported = ", ".join(sorted(_REGISTRY))
        raise ValueError(
            f"Unsupported auth_type {auth_type!r} in config.ini. "
            f"Supported values: {supported}"
        )
    return cls()
