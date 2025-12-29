"""Primary runner module for the Abuse Reporter program."""

import os
import re
import sys

import paramiko
from querycontacts import ContactFinder

from abuse_reporter import Fore, Style, app_root
from abuse_reporter.constants import (
    DISCORD_WEBHOOK_URL,
    EXTERNAL_HOSTNAME,
    REMOTE_HOST,
    REMOTE_PASS,
    REMOTE_PORT,
    REMOTE_USER,
    TESTING,
)
from abuse_reporter.db import ReportsDatabase
from abuse_reporter.discord import DiscordWebhook
from abuse_reporter.handlers import (
    group_logs_by_ip,
    process_logs,
    run_ssh_command,
)


if TESTING:
    print(
        f"{Fore.YELLOW}[!] TESTING MODE ENABLED - No actual reports will be sent."
        f"{Style.RESET_ALL}"
    )


def run() -> None:
    """Run the Abuse Reporter program."""
    print(f"{Fore.GREEN}Abuse Reporter is running...{Style.RESET_ALL}")

    qf = ContactFinder()
    reports = ReportsDatabase(os.path.join(app_root, "reports.db"))
    discord_webhook = DiscordWebhook(DISCORD_WEBHOOK_URL)

    command = (
        f"zgrep -vE 'GET /(robots.txt)? |HEAD ' logs/{EXTERNAL_HOSTNAME}/https/access.log*"
        " | sed 's|^[^:]*:||' | sort -t'[' -k2,2"
    )

    try:
        data = run_ssh_command(
            REMOTE_HOST,
            REMOTE_PORT,
            REMOTE_USER,
            REMOTE_PASS,
            command,
        )
    except (paramiko.SSHException, RuntimeError) as e:
        print(
            f"{Fore.RED}[!] SSH command execution failed: {e}{Style.RESET_ALL}"
        )
        sys.exit(1)

    log_lines = [l for l in re.split(r"[\r\n]+", data) if l]
    print(
        f"Total Log Lines Fetched: {Fore.RED}{len(log_lines)}{Style.RESET_ALL}"
    )

    logs_by_ip = group_logs_by_ip(log_lines, EXTERNAL_HOSTNAME, max_age_days=3)
    process_logs(logs_by_ip, reports, qf, discord_webhook)
