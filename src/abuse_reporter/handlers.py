"""Log processing, flagging logic, and per-IP report handling."""

import re
import sys
from datetime import datetime
from smtplib import SMTPDataError, SMTPRecipientsRefused

import paramiko
from colorama import Fore, Style
from querycontacts import ContactFinder
from rich.progress import Progress

from abuse_reporter.config import Config
from abuse_reporter.constants import (
    ABUSE_REPORT_BASELINE,
    LOG_PATTERN,
    METHOD_FLAGS,
    PATHNAME_EXCLUSIONS,
    URI_FLAGS,
    WHITELISTED_URIS,
)
from abuse_reporter.db import ReportsDatabase
from abuse_reporter.discord import DiscordWebhook
from abuse_reporter.mailing import send_abuse_report
from abuse_reporter.networking import get_hostname_from_ip


def run_ssh_command(
    hostname: str,
    port: int,
    username: str,
    password: str,
    command: str,
) -> str:
    """Execute a command on a remote server over SSH and return stdout.

    Args:
        hostname: The hostname or IP address of the remote server.
        port: The SSH port number.
        username: The SSH username.
        password: The SSH password.
        command: The shell command to run on the remote host.

    Returns:
        The standard output of the command as a string.

    Raises:
        RuntimeError: If the remote command exits with a non-zero status.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            timeout=15,
        )
        _, stdout, stderr = client.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        output: str = stdout.read().decode()
        error: str = stderr.read().decode()

        if exit_status != 0:
            raise RuntimeError(error)

        return output
    finally:
        client.close()


def redact_hostname(txt: str, hostname: str, filler: str = "[REDACTED]") -> str:
    """Replace all occurrences of a hostname in text with a filler string.

    Both ``hostname`` and ``www.<hostname>`` are redacted, case-insensitively.

    Args:
        txt: The input text to redact.
        hostname: The hostname string to remove.  Returns ``txt`` unchanged
            when empty or equal to ``"Unknown"``.
        filler: Replacement string.  Defaults to ``"[REDACTED]"``.

    Returns:
        The redacted text.
    """
    if not hostname or hostname == "Unknown":
        return txt

    patterns = [re.escape(hostname)]
    if not hostname.startswith("www."):
        patterns.insert(0, re.escape("www." + hostname))

    combined = re.compile("|".join(patterns), re.IGNORECASE)
    return combined.sub(filler, txt)


def is_request_flagged(log: dict[str, str]) -> bool:
    """Return True if a parsed log entry should be flagged for abuse review.

    A request is flagged when its HTTP method is in METHOD_FLAGS, or when its
    URI path matches any URI_FLAGS pattern (and is not whitelisted).

    Args:
        log: A parsed log dict with at least ``method`` and ``uri_path`` keys.

    Returns:
        True if the request is suspicious, False otherwise.
    """
    method = log.get("method", "")
    uri_path = log.get("uri_path", "")

    if method in METHOD_FLAGS:
        return True

    if any(re.search(pattern, uri_path) for pattern in WHITELISTED_URIS):
        return False

    if any(re.search(pattern, uri_path, re.IGNORECASE) for pattern in URI_FLAGS):
        return True

    return False


def process_log_line(
    log_line: str,
    external_hostname: str,
) -> dict[str, object] | None:
    """Parse a single nginx combined-log-format line into a structured dict.

    The operator's hostname is redacted from the line before parsing.

    Args:
        log_line: A raw log line string.
        external_hostname: The hostname to redact from log output.

    Returns:
        A dict of parsed fields plus ``timestamp``, ``method``,
        ``uri_path``, ``http_protocol``, and ``raw``; or None if parsing
        fails.
    """
    log_line = redact_hostname(log_line, external_hostname)
    match = LOG_PATTERN.match(log_line)
    if not match:
        print(f"Failed to parse log line: {log_line}", file=sys.stderr)
        return None

    log_data: dict[str, object] = dict(match.groupdict())

    time_local_str = match.group("time_local")
    time_local = None
    if time_local_str:
        try:
            time_local = datetime.strptime(time_local_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError as exc:
            print(
                f"Failed to parse time_local: {time_local_str}: {exc}",
                file=sys.stderr,
            )

    request = match.group("request")
    parts = request.split(" ")
    if len(parts) != 3:
        print(f"Failed to parse request field: {request}", file=sys.stderr)
        return None

    method, uri_path, http_protocol = parts
    log_data.update(
        {
            "timestamp": time_local,
            "method": method,
            "uri_path": uri_path,
            "http_protocol": http_protocol,
            "raw": log_line,
        }
    )
    return log_data


def group_logs_by_ip(
    log_lines: list[str],
    external_hostname: str,
    max_age_days: int = 3,
) -> dict[str, list[dict[str, object]]]:
    """Group parsed log entries by originating IP address.

    Entries are excluded when they:
    - fail to parse
    - lack a ``remote_addr`` field
    - match PATHNAME_EXCLUSIONS (unless the method is flagged)
    - are older than ``max_age_days``

    Args:
        log_lines: Raw log lines to process.
        external_hostname: The hostname to redact during parsing.
        max_age_days: Maximum age of entries to retain.  Defaults to 3.

    Returns:
        A dict mapping IP address strings to lists of parsed log dicts.
    """
    logs_by_ip: dict[str, list[dict[str, object]]] = {}

    for log_line in log_lines:
        log_data = process_log_line(log_line, external_hostname)
        if not log_data:
            continue

        remote_addr = log_data.get("remote_addr")
        if not remote_addr or not isinstance(remote_addr, str):
            continue

        uri_path = str(log_data.get("uri_path", ""))
        method = str(log_data.get("method", ""))

        if (
            any(re.search(p, uri_path) for p in PATHNAME_EXCLUSIONS)
            and method not in METHOD_FLAGS
        ):
            continue

        time_local = log_data.get("timestamp")
        if not isinstance(time_local, datetime):
            continue

        if (datetime.now(time_local.tzinfo) - time_local).days > max_age_days:
            continue

        logs_by_ip.setdefault(remote_addr, []).append(log_data)

    return {ip: logs for ip, logs in logs_by_ip.items() if logs}


def handle_flagged_ip(
    cfg: Config,
    ip_addr: str,
    hostname: str,
    logs: list[dict[str, object]],
    reports: ReportsDatabase,
    abuse_contact: str,
    dry_run: bool = False,
) -> None:
    """Send an abuse report for a flagged IP address.

    Skips sending when the abuse contact is absent or blacklisted.
    Records the IP in the database after a successful send (unless dry_run).

    Args:
        cfg: The active application configuration.
        ip_addr: The flagged IP address.
        hostname: The reverse-DNS hostname for the IP.
        logs: Parsed log entries attributed to this IP.
        reports: The reports database instance.
        abuse_contact: The abuse contact email address resolved for this IP.
        dry_run: When True, print what would happen but skip all sends/writes.
    """
    print(
        f"Received traffic from "
        f"{Fore.CYAN}{ip_addr}{Style.RESET_ALL} — "
        f"{Fore.BLUE}{hostname}{Style.RESET_ALL}"
    )
    print(
        f"\tFlagged for unwanted traffic — reporting to "
        f"{Fore.RED}{abuse_contact}{Style.RESET_ALL}"
    )
    print("\tLatest logs:")
    for log in logs:
        print(f"\t    {log['raw']}")

    if not abuse_contact:
        print(f"\tNo abuse contact found for {ip_addr}, skipping.")
        return

    blacklisted = [e.lower() for e in cfg.filters.blacklisted_emails]
    if abuse_contact.lower() in blacklisted:
        print(
            f"\t{Fore.YELLOW}[!] {abuse_contact} is blacklisted — "
            f"skipping send.{Style.RESET_ALL}"
        )
        if not dry_run:
            reports.add_reported_ip_addr(ip_addr)
        return

    raw_logs = "\n".join(str(log["raw"]) for log in logs)
    body = ABUSE_REPORT_BASELINE.format(
        ip_addr=ip_addr,
        hostname=hostname,
        raw_logs=raw_logs,
    )
    subject = f"Unwanted Traffic from {ip_addr}"

    try:
        send_abuse_report(
            cfg.smtp,
            abuse_contact,
            subject,
            body,
            dry_run=dry_run,
        )
        if not dry_run:
            reports.add_reported_ip_addr(ip_addr)

    except SMTPRecipientsRefused:
        # DreamHost returns a 450 when the hourly quota is hit.
        # Ref: https://help.dreamhost.com/hc/en-us/articles/215730437
        print(
            f"{Fore.RED}[!] SMTP recipients refused — "
            f"likely hit hourly quota limit, exiting.{Style.RESET_ALL}"
        )
        sys.exit(1)

    except SMTPDataError as exc:
        print(
            f"{Fore.RED}[!] SMTP error sending report for {ip_addr}: "
            f"{exc}{Style.RESET_ALL}"
        )


def process_logs(
    cfg: Config,
    logs_by_ip: dict[str, list[dict[str, object]]],
    reports: ReportsDatabase,
    qf: ContactFinder,
    discord_webhook: DiscordWebhook,
    dry_run: bool = False,
) -> None:
    """Process all grouped log entries and send reports for flagged IPs.

    Args:
        cfg: The active application configuration.
        logs_by_ip: Log entries keyed by IP address.
        reports: The reports database instance.
        qf: A ContactFinder instance for resolving abuse contacts.
        discord_webhook: A DiscordWebhook instance for notifications.
        dry_run: When True, skip all sends and DB writes.
    """
    untracked = [
        (ip, logs) for ip, logs in logs_by_ip.items() if not reports.get_reported_ip(ip)
    ]
    already_reported = [ip for ip in logs_by_ip if reports.get_reported_ip(ip)]
    newly_reported: list[str] = []

    with Progress() as progress:
        task = progress.add_task(
            "[cyan]Processing IPs...",
            total=len(untracked),
        )

        for ip_addr, logs in untracked:
            if any(is_request_flagged(log) for log in logs):  # type: ignore[arg-type]
                hostname = get_hostname_from_ip(ip_addr)
                contacts = qf.find(ip_addr)
                abuse_contact = contacts[0] if contacts else ""

                handle_flagged_ip(
                    cfg,
                    ip_addr,
                    hostname,
                    logs,
                    reports,
                    abuse_contact,
                    dry_run=dry_run,
                )
                newly_reported.append(ip_addr)

                discord_webhook.send_message(
                    f":no_entry: Report sent for `{ip_addr}`"
                    f" (`{hostname}`) to `{abuse_contact}`",
                    dry_run=dry_run,
                )
            else:
                print(
                    f"\t{Fore.GREEN}[+] Valid traffic from {ip_addr}{Style.RESET_ALL}"
                )
                for log in logs:
                    print(f"\t    {log['raw']}")

            progress.update(task, advance=1)

    print()
    print(f"Already reported:  {Fore.YELLOW}{len(already_reported)}{Style.RESET_ALL}")
    print(f"Newly reported:    {Fore.GREEN}{len(newly_reported)}{Style.RESET_ALL}")
