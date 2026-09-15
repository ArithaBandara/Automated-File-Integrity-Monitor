#!/usr/bin/env python3
"""
fim.py
Automated File Integrity Monitor (FIM) -- CLI entry point.

Commands:
    init      Scan a directory and save a SHA-256 baseline.
    check     Compare current file state against the saved baseline
              (one-time audit).
    monitor   Watch a directory in real time and flag any drift.

Usage examples:
    python fim.py init ./target_dir
    python fim.py check ./target_dir
    python fim.py monitor ./target_dir \\
        --webhook https://discord.com/api/webhooks/XXX/YYY

See fim_core.py for the hashing, comparison, and alerting engine.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from watchdog.observers import Observer

import fim_core

console = Console()


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fim",
        description="Automated File Integrity Monitor (SHA-256 based).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Options shared by every subcommand -------------------------------
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "directory", type=Path, help="Target directory to protect."
    )
    common.add_argument(
        "--baseline", type=Path, default=Path(fim_core.DEFAULT_BASELINE_FILE),
        help=f"Path to the baseline JSON file "
             f"(default: {fim_core.DEFAULT_BASELINE_FILE}).",
    )

    # Options shared by commands that can raise alerts -------------------
    webhook_common = argparse.ArgumentParser(add_help=False)
    webhook_common.add_argument(
        "--webhook", type=str, default=None,
        help="Discord or Telegram webhook URL for tamper alerts.",
    )
    webhook_common.add_argument(
        "--telegram-chat-id", type=str, default=None,
        help="Required alongside --webhook for a Telegram bot URL "
             "(api.telegram.org/bot<TOKEN>/sendMessage).",
    )

    subparsers.add_parser(
        "init", parents=[common],
        help="Scan a directory and create a new baseline.",
    )
    subparsers.add_parser(
        "check", parents=[common, webhook_common],
        help="Run a one-time audit against the saved baseline.",
    )
    subparsers.add_parser(
        "monitor", parents=[common, webhook_common],
        help="Continuously watch the directory for real-time changes.",
    )

    return parser


# --------------------------------------------------------------------------
# Command implementations
# --------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> int:
    if not args.directory.is_dir():
        console.print(
            f"[bold red]Error:[/bold red] '{args.directory}' is not "
            f"a directory."
        )
        return 1

    console.print(f"[bold blue]Scanning[/bold blue] {args.directory} ...")
    hashes, skipped = fim_core.scan_directory(
        args.directory, exclude_paths={args.baseline.resolve()}
    )
    fim_core.save_baseline(args.baseline, args.directory, hashes)

    console.print(
        f"[bold green]Baseline created:[/bold green] "
        f"{len(hashes)} file(s) hashed -> {args.baseline}"
    )
    _warn_skipped(skipped)
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    try:
        baseline = fim_core.load_baseline(args.baseline)
    except FileNotFoundError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 1

    if not args.directory.is_dir():
        console.print(
            f"[bold red]Error:[/bold red] '{args.directory}' is not "
            f"a directory."
        )
        return 1

    if not _webhook_config_valid(args):
        return 1

    console.print(f"[bold blue]Auditing[/bold blue] {args.directory} ...")
    current_hashes, skipped = fim_core.scan_directory(
        args.directory, exclude_paths={args.baseline.resolve()}
    )
    diff = fim_core.compare_hashes(baseline["hashes"], current_hashes)

    _print_diff_table(diff)
    _warn_skipped(skipped)

    total = len(diff["modified"]) + len(diff["created"]) + len(diff["deleted"])
    if args.webhook and total:
        for event_type in ("modified", "created", "deleted"):
            for path in diff[event_type]:
                fim_core.send_webhook_alert(
                    args.webhook, event_type, path,
                    telegram_chat_id=args.telegram_chat_id,
                )

    if total == 0:
        console.print(
            "[bold green]Integrity check passed -- no changes "
            "detected.[/bold green]"
        )
        return 0

    console.print(f"[bold red]{total} integrity violation(s) detected.[/bold red]")
    return 2


def cmd_monitor(args: argparse.Namespace) -> int:
    try:
        baseline = fim_core.load_baseline(args.baseline)
    except FileNotFoundError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 1

    if not args.directory.is_dir():
        console.print(
            f"[bold red]Error:[/bold red] '{args.directory}' is not "
            f"a directory."
        )
        return 1

    if not _webhook_config_valid(args):
        return 1

    handler = fim_core.FIMEventHandler(
        target_dir=args.directory,
        baseline_hashes=baseline["hashes"],
        console=console,
        webhook_url=args.webhook,
        telegram_chat_id=args.telegram_chat_id,
        exclude_paths={args.baseline.resolve()},
    )

    observer = Observer()
    observer.schedule(handler, str(args.directory), recursive=True)
    observer.start()

    console.print(Panel.fit(
        f"[bold blue]Monitoring[/bold blue] {args.directory}\n"
        f"Baseline: {args.baseline} ({len(baseline['hashes'])} files)\n"
        f"Webhook: {'enabled' if args.webhook else 'disabled'}\n"
        f"Press Ctrl+C to stop.",
        title="File Integrity Monitor",
    ))

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        console.print("\n[bold blue]Stopping monitor...[/bold blue]")
    observer.join()
    return 0


# --------------------------------------------------------------------------
# Output / validation helpers
# --------------------------------------------------------------------------

def _webhook_config_valid(args: argparse.Namespace) -> bool:
    """Reject a Telegram webhook that's missing its required chat id."""
    if (
        args.webhook
        and "api.telegram.org" in args.webhook
        and not args.telegram_chat_id
    ):
        console.print(
            "[bold red]Error:[/bold red] Telegram webhooks require "
            "--telegram-chat-id."
        )
        return False
    return True


def _warn_skipped(skipped: list[str]) -> None:
    if not skipped:
        return
    console.print(
        f"[bold yellow]Warning:[/bold yellow] {len(skipped)} file(s) "
        f"could not be read (permissions?) and were skipped:"
    )
    for path in skipped:
        console.print(f"  [yellow]-[/yellow] {path}")


def _print_diff_table(diff: dict[str, list[str]]) -> None:
    if not diff["modified"] and not diff["deleted"] and not diff["created"]:
        console.print("[bold green]No changes since baseline.[/bold green]")
        return

    table = Table(title="Integrity Check Results")
    table.add_column("Status", style="bold")
    table.add_column("File Path")

    for path in diff["modified"]:
        table.add_row("[bold red]MODIFIED[/bold red]", path)
    for path in diff["deleted"]:
        table.add_row("[bold red]DELETED[/bold red]", path)
    for path in diff["created"]:
        table.add_row("[bold green]CREATED[/bold green]", path)

    console.print(table)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "init": cmd_init,
        "check": cmd_check,
        "monitor": cmd_monitor,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
