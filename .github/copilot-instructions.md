# Project Guidelines

## Code Style
- Keep changes small and consistent with the existing module-docstring style and explicit helper functions.
- Preserve the current thread-safety patterns in [guardian.py](guardian.py) and [tray.py](tray.py); shared state is coordinated with locks and events.
- Prefer focused, testable changes over broad refactors.
- Refer to [README.md](README.md) for user-facing setup and to [config.ini.example](config.ini.example) for the authoritative config schema.

## Architecture
- The main entrypoint is [guardian.py](guardian.py).
- Tray orchestration lives in [tray.py](tray.py).
- Machine-bound config loading and encryption live in [config.py](config.py).
- Auth backends are a strategy layer under [auth_plugins/](auth_plugins/); add new portal types there instead of branching in guardian.py.
- GUI configuration runs from [gui_config.py](gui_config.py) on a separate daemon thread; do not call tkinter work directly from pystray callbacks.
- Autostart behavior is isolated in [autostart.py](autostart.py).

## Build and Test
- Install dependencies with `pip install -r requirements.txt`.
- Run the app with `python guardian.py`.
- Build with `python build.py`; this is the canonical PyInstaller path, and [AutoNetGuard.spec](AutoNetGuard.spec) is not the primary build driver.
- Run tests on Windows with `.\\.venv\\Scripts\\python.exe -m pytest tests\\`; if pytest is missing, install it with `.\\.venv\\Scripts\\python.exe -m pip install pytest`.
- CI build and release steps are defined in [.github/workflows/build.yml](.github/workflows/build.yml) and [.github/workflows/release.yml](.github/workflows/release.yml).

## Conventions
- [conftest.py](conftest.py) stubs `pystray` and creates a temporary `config.ini` before test collection; keep headless testability in mind.
- Do not assume real campus credentials in tests or examples.
- Treat `guardian.pid` single-instance handling as part of runtime behavior.
- On Windows, [tests/test_guardian.py](tests/test_guardian.py) may still show a known `TestIsProcessRunning::test_pid_zero_returns_false` failure that is unrelated to tray changes; verify whether it is actually caused by your edit before spending time on it.
- Prefer linking to existing docs instead of duplicating them; use [README.md](README.md) and [config.ini.example](config.ini.example) as the primary references.
