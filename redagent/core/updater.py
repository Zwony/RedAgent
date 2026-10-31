"""Automatic update checker and self-updater.

Provides release discovery and self-updating capabilities across
PyPI and GitHub Releases repositories.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Optional, Tuple

from redagent import __version__

CACHE_TTL_SECONDS = 86400
PYPI_URL = "https://pypi.org/pypi/redagent/json"
GITHUB_API_URL = "https://api.github.com/repos/Zwony/RedAgent/releases/latest"


def _get_cache_path() -> Path:
    """Returns the local filesystem path for update metadata caching.

    Returns:
        Path: Path object pointing to update_cache.json in the user profile.
    """
    cache_dir = Path.home() / ".redagent"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / "update_cache.json"


def _parse_version(v_str: str) -> Tuple[int, ...]:
    """Parses a semantic version string into a numeric tuple for comparison.

    Args:
        v_str: Version string (e.g., '0.2.0', 'v1.0.0-rc1').

    Returns:
        Tuple[int, ...]: Three-element tuple representing major, minor, patch.
    """
    clean = v_str.strip().lstrip("v")
    main_ver = clean.split("-")[0].split("+")[0]
    parts = []
    for piece in main_ver.split("."):
        try:
            parts.append(int(piece))
        except ValueError:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def is_newer_version(current_ver: str, candidate_ver: str) -> bool:
    """Evaluates whether a candidate version string is strictly newer than current.

    Args:
        current_ver: Active version string.
        candidate_ver: Remote version string.

    Returns:
        bool: True if candidate is strictly greater than current, False otherwise.
    """
    return _parse_version(candidate_ver) > _parse_version(current_ver)


def fetch_latest_version(timeout: float = 1.5) -> Optional[str]:
    """Retrieves the latest published version identifier from upstream repositories.

    Queries PyPI with a fallback to the GitHub Releases API.

    Args:
        timeout: Maximum network request duration in seconds.

    Returns:
        Optional[str]: Version string if discovery succeeded, None otherwise.
    """
    headers = {"User-Agent": f"RedAgent-CLI/{__version__}"}

    try:
        req = urllib.request.Request(PYPI_URL, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("info", {}).get("version")
    except Exception:
        pass

    try:
        req = urllib.request.Request(GITHUB_API_URL, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                tag_name = data.get("tag_name", "")
                if tag_name:
                    return tag_name.lstrip("v")
    except Exception:
        pass

    return None


def get_cached_latest_version(force: bool = False) -> Optional[str]:
    """Retrieves the cached release version or queries remotes if the cache expired.

    Args:
        force: If True, bypasses cache duration limits and triggers a fresh query.

    Returns:
        Optional[str]: Latest known version string or None if unresolvable.
    """
    cache_file = _get_cache_path()
    now = time.time()

    if not force and cache_file.exists():
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                cache_data = json.load(f)
            last_checked = cache_data.get("last_checked", 0)
            if now - last_checked < CACHE_TTL_SECONDS:
                return cache_data.get("latest_version")
        except Exception:
            pass

    latest = fetch_latest_version()
    if latest:
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump({"last_checked": now, "latest_version": latest}, f)
        except Exception:
            pass
    return latest


def perform_upgrade() -> bool:
    """Executes a package upgrade via pip in a subprocess.

    Returns:
        bool: True if the process completed with return code 0, False otherwise.
    """
    print("[UPGRADE] Running: pip install --upgrade redagent")
    try:
        cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "redagent"]
        result = subprocess.run(cmd, check=False)
        return result.returncode == 0
    except Exception as exc:
        print(f"[ERROR] Failed to run pip upgrade: {exc}")
        return False


def check_and_prompt_update(force: bool = False) -> None:
    """Checks for newer releases and presents an interactive upgrade prompt.

    Guards against non-interactive environments such as CI/CD runners, pipes,
    and background processes to avoid blocking execution.

    Args:
        force: If True, bypasses local TTL cache verification.
    """
    if os.environ.get("CI") or os.environ.get("REDAGENT_NO_UPDATE_CHECK"):
        return

    if not sys.stdin.isatty():
        return

    latest = get_cached_latest_version(force=force)
    if not latest:
        return

    if is_newer_version(__version__, latest):
        print("\n" + "=" * 65)
        print(f"[UPDATE AVAILABLE] A newer version of RedAgent is available: {__version__} -> {latest}")
        print("Release notes: https://github.com/Zwony/RedAgent/releases")
        print("=" * 65)

        try:
            choice = input(f"Would you like to upgrade to v{latest} now? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if choice in ("y", "yes"):
            success = perform_upgrade()
            if success:
                print(f"[OK] Successfully upgraded to RedAgent v{latest}. Please restart your command.\n")
                sys.exit(0)
            else:
                print("[WARNING] Automatic upgrade did not complete successfully.")
                print("You can manually upgrade using: pip install --upgrade redagent\n")
        else:
            print("[INFO] Update skipped. Continuing with current version...\n")
