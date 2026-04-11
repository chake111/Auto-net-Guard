"""Build AutoNetGuard into a background one-file Windows executable.

Post-build steps
----------------
* Copies ``config.ini.example`` next to the generated EXE so that end-users
  have a ready-made template to fill in their credentials.
* Prints a reminder to create ``config.ini`` before running the EXE.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


def build() -> None:
    root = Path(__file__).resolve().parent
    entry = root / "guardian.py"
    example_cfg = root / "config.ini.example"

    # Verify all required source files exist before starting PyInstaller
    required = [entry, example_cfg,
                root / "tray.py", root / "autostart.py", root / "config.py"]
    for f in required:
        if not f.exists():
            raise FileNotFoundError(f"Required file not found: {f}")

    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--noconsole",
        "--name",
        "AutoNetGuard",
        # Ensure hidden imports for pystray Windows backend and Pillow
        "--hidden-import", "pystray._win32",
        "--hidden-import", "PIL._tkinter_finder",
        # cryptography library backend (used for config encryption)
        "--hidden-import", "cryptography",
        "--hidden-import", "cryptography.fernet",
        "--hidden-import", "cryptography.hazmat.primitives.kdf.pbkdf2",
        "--hidden-import", "cryptography.hazmat.backends",
        "--hidden-import", "cryptography.hazmat.backends.openssl",
        "--hidden-import", "cryptography.hazmat.backends.openssl.backend",
        str(entry),
    ]

    print("Running:", " ".join(command))
    subprocess.run(command, cwd=root, check=True)

    # Copy config template to dist/ so users have it alongside the EXE
    dist_dir = root / "dist"
    dest = dist_dir / "config.ini.example"
    shutil.copy2(example_cfg, dest)
    print(f"Copied config template → {dest}")

    print("\nBuild completed: dist/AutoNetGuard.exe")
    print(
        "\n⚠️  Before running the EXE, copy config.ini.example to config.ini "
        "in the same directory and fill in your credentials:\n"
        "    cd dist\n"
        "    copy config.ini.example config.ini\n"
        "    notepad config.ini"
    )


if __name__ == "__main__":
    build()
