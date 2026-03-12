"""Primary orchestrator: loads config, fetches logs, and drives reporting."""

import re
import sys
from pathlib import Path

import paramiko
from colorama import Fore, Style
from colorama import init as colorama_init
from querycontacts import ContactFinder

from abuse_reporter.config import ConfigError, load_config
from abuse_reporter.db import ReportsDatabase
from abuse_reporter.discord import DiscordWebhook
from abuse_reporter.handlers import group_logs_by_ip, process_logs, run_ssh_command


def run_agent(dry_run: bool = False) -> None:
    """Load configuration and run the abuse-reporter pipeline.

    Args:
        dry_run: When True, skip all sends/writes and print what would happen.
            Overrides the ``dry_run`` flag in ``config.toml`` if True.

    Exits with a non-zero status on configuration or SSH errors.
    """
    colorama_init(autoreset=False)

    try:
        cfg = load_config()
    except ConfigError as exc:
        print(f"{Fore.RED}[!] Configuration error:{Style.RESET_ALL}\n{exc}")
        sys.exit(1)

    # CLI --dry-run overrides whatever is in config.toml
    effective_dry_run = dry_run or cfg.app.dry_run

    if effective_dry_run:
        print(
            f"{Fore.YELLOW}[!] DRY-RUN — no emails, Discord messages, "
            f"or DB writes will occur.{Style.RESET_ALL}"
        )

    project_root = Path(__file__).resolve().parent.parent.parent

    qf = ContactFinder()
    reports = ReportsDatabase(str(project_root / "reported_history.db"))
    discord_webhook = DiscordWebhook(cfg.discord.webhook_url)

    command = (
        f"zgrep -vE 'GET /(robots.txt)? |HEAD '"
        f" logs/{cfg.remote.external_host}/https/access.log*"
        " | sed 's|^[^:]*:||' | sort -t'[' -k2,2"
    )

    try:
        data = run_ssh_command(
            cfg.remote.host,
            cfg.remote.port,
            cfg.remote.user,
            cfg.remote.password,
            command,
        )
    except (paramiko.SSHException, RuntimeError) as exc:
        print(f"{Fore.RED}[!] SSH error: {exc}{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)

    log_lines = [line for line in re.split(r"[\r\n]+", data) if line]
    print(f"Log lines fetched: {Fore.RED}{len(log_lines)}{Style.RESET_ALL}")

    logs_by_ip = group_logs_by_ip(
        log_lines,
        cfg.remote.external_host,
        max_age_days=3,
    )
    process_logs(
        cfg, logs_by_ip, reports, qf, discord_webhook, dry_run=effective_dry_run
    )
