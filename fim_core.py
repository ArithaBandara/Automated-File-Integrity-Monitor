from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

from watchdog.events import FileSystemEventHandler

"""
fim_core.py
Core engine for the File Integrity Monitor (FIM).

Contains:
    - SHA-256 hashing utilities
    - Recursive directory scanning
    - Baseline load/save (JSON)
    - Hash comparison logic
    - Webhook alerting (Discord / Telegram)
    - Watchdog event handler for real-time monitoring

This module has no CLI logic of its own -- it is imported by fim.py.
"""

# --------------------------------------------------------------------------
# Configuration constants
# --------------------------------------------------------------------------

DEFAULT_BASELINE_FILE = "baseline.json"
HASH_CHUNK_SIZE = 8192          # bytes read per chunk while hashing
HASH_ALGORITHM = "sha256"

# patterns for paths that should never be tracked
DEFAULT_IGNORE_PATTERNS = [
    "*.swp", "*.swx", "*.swpx", "*~", "*.tmp", "*.bak",
    ".DS_Store", "Thumbs.db",
    "__pycache__/*", "*.pyc",
    ".git/*",
]


# --------------------------------------------------------------------------
# Hashing helpers
# --------------------------------------------------------------------------

def should_ignore(relative_path: str, ignore_patterns: list[str]) -> bool:
    """Return True if the given relative path matches an ignore pattern."""
    normalized = relative_path.replace(os.sep, "/")
    for pattern in ignore_patterns:
        if fnmatch.fnmatch(normalized, pattern):
            return True
        if fnmatch.fnmatch(os.path.basename(normalized), pattern):
            return True
    return False


def compute_file_hash(filepath: Path) -> Optional[str]:
    hasher = hashlib.new(HASH_ALGORITHM)
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(HASH_CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except PermissionError:
        return None
    except FileNotFoundError:
        return None
    except OSError:
        return None


def scan_directory(
    target_dir: Path,
    ignore_patterns: Optional[list[str]] = None,
    exclude_paths: Optional[set[Path]] = None,
) -> tuple[dict[str, str], list[str]]:
    ignore_patterns = ignore_patterns or DEFAULT_IGNORE_PATTERNS
    exclude_paths = exclude_paths or set()
    hashes: dict[str, str] = {}
    skipped: list[str] = []
    target_dir = target_dir.resolve()

    for root, dirs, files in os.walk(target_dir):
        pruned = []
        for d in dirs:
            rel_dir = str(Path(root, d).relative_to(target_dir)) + "/"
            if not should_ignore(rel_dir, ignore_patterns):
                pruned.append(d)
        dirs[:] = pruned

        for filename in files:
            full_path = Path(root, filename)
            rel_path = str(full_path.relative_to(target_dir))
            if should_ignore(rel_path, ignore_patterns):
                continue
            if full_path.resolve() in exclude_paths:
                continue
            digest = compute_file_hash(full_path)
            if digest is None:
                skipped.append(rel_path)
            else:
                hashes[rel_path] = digest

    return hashes, skipped


# --------------------------------------------------------------------------
# Baseline persistence
# --------------------------------------------------------------------------

def save_baseline(
    baseline_path: Path,
    target_dir: Path,
    hashes: dict[str, str],
) -> None:
    """Write the baseline hashes to disk as JSON, with metadata."""
    payload = {
        "target_dir": str(target_dir.resolve()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": HASH_ALGORITHM,
        "file_count": len(hashes),
        "hashes": hashes,
    }
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)


def load_baseline(baseline_path: Path) -> dict:
    if not baseline_path.exists():
        raise FileNotFoundError(
            f"No baseline found at '{baseline_path}'. "
            f"Run `python fim.py init <directory>` first."
        )
    with open(baseline_path, "r", encoding="utf-8") as f:
        return json.load(f)


# --------------------------------------------------------------------------
# Comparison logic
# --------------------------------------------------------------------------

def compare_hashes(
    baseline_hashes: dict[str, str],
    current_hashes: dict[str, str],
) -> dict[str, list[str]]:
    baseline_paths = set(baseline_hashes)
    current_paths = set(current_hashes)

    created = sorted(current_paths - baseline_paths)
    deleted = sorted(baseline_paths - current_paths)
    modified = sorted(
        path for path in (baseline_paths & current_paths)
        if baseline_hashes[path] != current_hashes[path]
    )
    unchanged = sorted(
        path for path in (baseline_paths & current_paths)
        if baseline_hashes[path] == current_hashes[path]
    )

    return {
        "modified": modified,
        "created": created,
        "deleted": deleted,
        "unchanged": unchanged,
    }


# --------------------------------------------------------------------------
# Webhook alerting
# --------------------------------------------------------------------------

def send_webhook_alert(
    webhook_url: str,
    event_type: str,
    relative_path: str,
    telegram_chat_id: Optional[str] = None,
    timeout: float = 5.0,
) -> bool:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    message = f"[FIM] {event_type.upper()}: {relative_path} at {timestamp}"

    try:
        if "discord.com" in webhook_url:
            payload = {
                "embeds": [{
                    "title": f"File Integrity Alert: {event_type.upper()}",
                    "description": relative_path,
                    "color": _discord_color_for(event_type),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }]
            }
            response = requests.post(webhook_url, json=payload, timeout=timeout)

        elif "api.telegram.org" in webhook_url:
            payload = {"chat_id": telegram_chat_id, "text": message}
            response = requests.post(webhook_url, json=payload, timeout=timeout)

        else:
            response = requests.post(
                webhook_url, json={"content": message}, timeout=timeout
            )

        return response.ok

    except requests.RequestException:
        return False


def _discord_color_for(event_type: str) -> int:
    """Map an event type to a Discord embed color (decimal RGB)."""
    return {
        "modified": 0xE74C3C,  
        "deleted": 0xE74C3C,   
        "created": 0x2ECC71,  
    }.get(event_type, 0x3498DB) 


# --------------------------------------------------------------------------
# Real-time watchdog event handler
# --------------------------------------------------------------------------

class FIMEventHandler(FileSystemEventHandler):

    def __init__(
        self,
        target_dir: Path,
        baseline_hashes: dict[str, str],
        console,
        ignore_patterns: Optional[list[str]] = None,
        webhook_url: Optional[str] = None,
        telegram_chat_id: Optional[str] = None,
        exclude_paths: Optional[set[Path]] = None,
    ) -> None:
        super().__init__()
        self.target_dir = target_dir.resolve()
        self.baseline_hashes = dict(baseline_hashes)
        self.console = console
        self.ignore_patterns = ignore_patterns or DEFAULT_IGNORE_PATTERNS
        self.webhook_url = webhook_url
        self.telegram_chat_id = telegram_chat_id
        self.exclude_paths = exclude_paths or set()

    def _relative(self, path: str) -> Optional[str]:
        resolved = Path(path).resolve()
        if resolved in self.exclude_paths:
            return None
        try:
            rel = str(resolved.relative_to(self.target_dir))
        except ValueError:
            return None
        if should_ignore(rel, self.ignore_patterns):
            return None
        return rel

    def _log(self, event_type: str, relative_path: str) -> None:
        style = {
            "created": "bold green",
            "modified": "bold red",
            "deleted": "bold red",
        }.get(event_type, "bold blue")
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.print(
            f"[{style}][{timestamp}] {event_type.upper():<9}[/{style}] "
            f"{relative_path}"
        )
        if self.webhook_url:
            send_webhook_alert(
                self.webhook_url, event_type, relative_path,
                telegram_chat_id=self.telegram_chat_id,
            )

    # -- watchdog callbacks ---------------------------------------------

    def on_created(self, event) -> None:
        if event.is_directory:
            return
        rel = self._relative(event.src_path)
        if rel is None:
            return
        digest = compute_file_hash(Path(event.src_path))
        if digest is not None:
            self.baseline_hashes[rel] = digest
        self._log("created", rel)

    def on_modified(self, event) -> None:
        if event.is_directory:
            return
        rel = self._relative(event.src_path)
        if rel is None:
            return
        digest = compute_file_hash(Path(event.src_path))
        if digest is None:
            return  # file unreadable
        if self.baseline_hashes.get(rel) == digest:
            return  # metadata-only touch
        self.baseline_hashes[rel] = digest
        self._log("modified", rel)

    def on_deleted(self, event) -> None:
        if event.is_directory:
            return
        rel = self._relative(event.src_path)
        if rel is None:
            return
        self.baseline_hashes.pop(rel, None)
        self._log("deleted", rel)

    def on_moved(self, event) -> None:
        if event.is_directory:
            return
        old_rel = self._relative(event.src_path)
        new_rel = self._relative(event.dest_path)
        if old_rel:
            self.baseline_hashes.pop(old_rel, None)
            self._log("deleted", old_rel)
        if new_rel:
            digest = compute_file_hash(Path(event.dest_path))
            if digest is not None:
                self.baseline_hashes[new_rel] = digest
            self._log("created", new_rel)
