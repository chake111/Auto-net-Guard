"""Build AutoNetGuard into a background one-file executable.

Supports Windows, macOS, and Linux via platform detection.

Post-build steps
----------------
* Copies ``config.ini.example`` next to the generated binary so that
  end-users have a ready-made template to fill in their credentials.
* Prints a platform-appropriate reminder to create ``config.ini``.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


def _pyinstaller_python(root: Path) -> str:
    """Return the Python interpreter that should run PyInstaller.

    Prefer the project-local virtual environment when it exists so builds are
    reproducible even if the script is launched with a different interpreter.
    """
    if sys.platform == "win32":
        venv_python = root / ".venv" / "Scripts" / "python.exe"
    else:
        venv_python = root / ".venv" / "bin" / "python"

    if venv_python.exists():
        return str(venv_python)
    return sys.executable


def build() -> None:
    root = Path(__file__).resolve().parent
    entry = root / "guardian.py"
    example_cfg = root / "config.ini.example"

    # Verify all required source files exist before starting PyInstaller
    required = [entry, example_cfg,
                root / "tray.py", root / "autostart.py", root / "config.py",
                root / "gui_config.py"]
    for f in required:
        if not f.exists():
            raise FileNotFoundError(f"Required file not found: {f}")

    is_win = sys.platform == "win32"
    is_mac = sys.platform == "darwin"

    # Platform-specific pystray backend hidden imports
    if is_win:
        pystray_backends = ["pystray._win32"]
    elif is_mac:
        pystray_backends = ["pystray._darwin"]
    else:
        # Linux: try both GTK and AppIndicator backends
        pystray_backends = ["pystray._gtk", "pystray._appindicator"]

    command = [
        _pyinstaller_python(root),
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name",
        "AutoNetGuard",
    ]

    # Suppress the console window on desktop platforms that support it
    if is_win or is_mac:
        command.append("--noconsole")

    # pystray backend(s) for the current platform
    for backend in pystray_backends:
        command += ["--hidden-import", backend]

    command += [
        "--hidden-import", "PIL._tkinter_finder",
        # tkinter and its sub-modules (used by gui_config.py settings window)
        "--hidden-import", "tkinter",
        "--hidden-import", "tkinter.messagebox",
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

    # Copy config template to dist/ so users have it alongside the binary
    dist_dir = root / "dist"
    dest = dist_dir / "config.ini.example"
    shutil.copy2(example_cfg, dest)
    print(f"Copied config template → {dest}")

    out_name = "AutoNetGuard.exe" if is_win else "AutoNetGuard"
    print(f"\nBuild completed: dist/{out_name}")

    if is_win:
        copy_cmd = "copy config.ini.example config.ini"
        edit_cmd = "notepad config.ini"
    else:
        copy_cmd = "cp config.ini.example config.ini"
        edit_cmd = "nano config.ini"

    print(
        "\n⚠️  Before running the binary, copy config.ini.example to config.ini "
        "in the same directory and fill in your credentials:\n"
        "    cd dist\n"
        f"    {copy_cmd}\n"
        f"    {edit_cmd}"
    )


if __name__ == "__main__":
    build()
