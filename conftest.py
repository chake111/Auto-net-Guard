"""Pytest root conftest – executed before test-file collection.

Two responsibilities
--------------------
1. Stub out the GUI-only ``pystray`` library so that modules importing
   ``tray.py`` can be loaded on headless CI machines.
2. Create a temporary ``config.ini`` with plaintext test credentials so
   that ``config.py`` can be imported without a real campus-network account.
   The file is written *at module load time* (before test files are
   imported) to guarantee that ``config.py`` sees it immediately.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# 1. Stub pystray before any test file triggers an import of tray.py
# ---------------------------------------------------------------------------
_pystray_stub = MagicMock()
sys.modules["pystray"] = _pystray_stub

# ---------------------------------------------------------------------------
# 2. Bootstrap config.ini so config.py can be imported during collection
# ---------------------------------------------------------------------------
_CONFIG_PATH = Path(__file__).resolve().parent / "config.ini"

_SAMPLE_CONFIG = """\
[credentials]
user_account = testuser@unicom
user_password = testpass

[network]
gateway_ip = 10.10.10.2
login_url = http://10.10.10.2:801/eportal/portal/login
referer = http://10.10.10.2/
wlan_ac_ip = 10.0.253.2
wlan_ac_name = WS6812

[connectivity]
check_url = http://www.google.cn/generate_204

[timing]
request_timeout_seconds = 8
check_interval_seconds = 30
login_retry_count = 3
backoff_base_seconds = 1

[logging]
log_file = service.log

[ui]
enable_notifications = true

[auth]
auth_type = drcom
auth_method = POST
auth_success_markers = success,登录成功

[srun]
acid = 1
"""

# Only write if a real config.ini is absent so we never clobber user credentials.
if not _CONFIG_PATH.exists():
    _CONFIG_PATH.write_text(_SAMPLE_CONFIG, encoding="utf-8")
