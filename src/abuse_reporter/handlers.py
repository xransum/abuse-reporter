"""Module providing functionality for processing and analyzing request logs."""

import re
import sys
from datetime import datetime
from smtplib import SMTPDataError, SMTPRecipientsRefused

import paramiko
from querycontacts import ContactFinder
from rich.progress import Progress

from abuse_reporter import Fore, Style
from abuse_reporter.constants import (
    ABUSE_REPORT_BASELINE,
    LOG_PATTERN,
    METHOD_FLAGS,
    NO_SEND,
    PATHNAME_EXCLUSIONS,
    SMTP_USER,
    TESTING,
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
    """
    Executes a command on a remote server over SSH.

    Args:
        hostname (str): The hostname or IP address of the remote server.
        port (int): The port number for the SSH connection.
        username (str): The username for authentication.
        password (str): The password for authentication.
        command (str): The command to execute on the remote server.

    Returns:
        str: The standard output of the executed command.

    Raises:
        RuntimeError: If the command execution fails (non-zero exit status).
    """
    timeout = 15
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
        )

        _, stdout, stderr = client.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()

        output = stdout.read().decode()
        error = stderr.read().decode()

        if exit_status != 0:
            raise RuntimeError(error)

        return output
    finally:
        client.close()


def handle_already_reported_ip(
    ip_addr: str, logs: list[dict], report: dict
) -> None:
    """
    Handles the case where an IP address has already been reported.

    Args:
        ip_addr (str): The IP address.
        logs (list[dict]): The logs associated with the IP address.
        report (dict): The report details from the database.
    """
    print(
        f"\t{Fore.YELLOW}[!] Already reported {ip_addr} on "
        f"{report['date_added']}.{Style.RESET_ALL}"
    )
    print("\tLatest Logs:")
    print("\n".join(["\t[?] " + log["raw"] for log in logs]))


def handle_flagged_ip(
    ip_addr: str,
    hostname: str,
    logs: list[dict],
    reports: ReportsDatabase,
    abuse_contact: str,
) -> None:
    """
    Handles the case where an IP address is flagged for unwanted traffic.

    Args:
        ip_addr (str): The IP address.
        hostname (str): The hostname associated with the IP address.
        logs (list[dict]): The logs associated with the IP address.
        reports (ReportsDatabase): The reports database instance.
        abuse_contact (str): The abuse contact email address.
    """
    print(
        "Received Traffic from "
        f"{Fore.CYAN}{ip_addr}{Style.RESET_ALL} - "
        f"{Fore.BLUE}{hostname}{Style.RESET_ALL}"
    )
    print(
        "\tIP Address Flagged for Unwanted Traffic - Reporting Party "
        f"{Fore.RED}{abuse_contact}{Style.RESET_ALL}"
    )
    print("\tLatest Logs:")
    print("\n".join(["\t[?] " + log["raw"] for log in logs]))

    if not abuse_contact:
        print(f"\tNo abuse contact found for {ip_addr}, skipping.")
        return

    raw_logs = "\n".join([log["raw"] for log in logs])
    abuse_report = ABUSE_REPORT_BASELINE.format(
        ip_addr=ip_addr,
        hostname=hostname,
        raw_logs=raw_logs,
    )
    subject = f"Unwanted Traffic from {ip_addr}"

    # Set testing attributes if in testing mode
    if TESTING:
        abuse_contact = SMTP_USER
        subject = f"[TESTING] {subject}"

    try:
        send_abuse_report(abuse_contact, subject, abuse_report)
        if not TESTING:
            reports.add_reported_ip_addr(ip_addr)

    except (SMTPDataError, SMTPRecipientsRefused) as e:
        # It seems that when we hit our hourly quota, DreamHost's SMTP server
        # will return a 450 error code. To avoid further attempts that are
        # likely to fail, we exit the script here.
        # REF: https://help.dreamhost.com/hc/en-us/articles/215730437-SMTP-quota-limits
        if isinstance(e, SMTPRecipientsRefused):
            # This is very likely quota related as well
            print(
                f"{Fore.RED}[!] SMTP Recipients Refused - Likely hit hourly "
                f"quota limit, exiting.{Style.RESET_ALL}"
            )
            sys.exit(1)
        else:
            print(
                f"{Fore.RED}[!] Unknown SMTP Error - Failed to send abuse report"
                f"for {ip_addr}: {e}{Style.RESET_ALL}"
            )


def process_logs(
    logs_by_ip: dict[str, list[dict]],
    reports: ReportsDatabase,
    qf: ContactFinder,
    discord_webhook: DiscordWebhook,
) -> None:
    """
    Processes logs grouped by IP address.

    Args:
        logs_by_ip (dict): Logs grouped by IP address.
        reports (ReportsDatabase): The reports database instance.
        qf (ContactFinder): The contact finder instance.
    """
    reported_ip_addrs = []

    untracked_log_items = [
        (ip_addr, logs)
        for ip_addr, logs in logs_by_ip.items()
        if not reports.get_reported_ip(ip_addr)
    ]
    already_reported_ip_addrs = [
        ip_addr
        for ip_addr in logs_by_ip.keys()
        if reports.get_reported_ip(ip_addr)
    ]

    with Progress() as p:
        task = p.add_task(
            "[cyan]Processing untracked IP addresses...",
            total=len(untracked_log_items),
        )

        for ip_addr, logs in untracked_log_items:
            ip_flagged = any(is_request_flagged(log) for log in logs)
            if ip_flagged:
                hostname = get_hostname_from_ip(ip_addr)
                contacts = qf.find(ip_addr)
                abuse_contact = contacts[0] if contacts else ""

                handle_flagged_ip(
                    ip_addr, hostname, logs, reports, abuse_contact
                )
                reported_ip_addrs.append(ip_addr)

                if not NO_SEND:
                    discord_webhook.send_message(
                        f":no_entry: Report sent for `{ip_addr}` (`{hostname}`) to `{abuse_contact}`"
                    )
            else:
                print(
                    f"\t{Fore.GREEN}[+] Valid traffic detected from "
                    f"{ip_addr}.{Style.RESET_ALL}"
                )
                print("\tLatest Logs:")
                print("\n".join(["\t[?] " + log["raw"] for log in logs]))

            p.update(task, advance=1)

    print()
    print(
        f"Total Already Reported IP Address(es): {Fore.YELLOW}"
        f"{len(already_reported_ip_addrs)}{Style.RESET_ALL}"
    )
    print(
        f"Total Reported IP Address(es): {Fore.GREEN}"
        f"{len(reported_ip_addrs)}{Style.RESET_ALL}"
    )


def redact_hostname(txt: str, hostname: str, filler: str = "[REDACTED]") -> str:
    """
    Redacts occurrences of a specified hostname in the given text.

    This function replaces all instances of the specified hostname in the input
    text with a filler string. It ensures that both the hostname and its variant
    with "www." are redacted, regardless of case sensitivity.

    Args:
        txt (str): The input text where the hostname should be redacted.
        hostname (str): The hostname to be redacted. If empty or "Unknown",
                        the function returns the original hostname.
        filler (str, optional): The string to replace the hostname with.
                                Defaults to "[REDACTED]".

    Returns:
        str: The text with the hostname redacted.
    """
    if not hostname or hostname == "Unknown":
        return hostname

    # When the hostname doesn't include a sub-domain of www, then we need to
    # redact both the hostname and www.hostname.
    # NOTE: This does not cover other sub-domains, this is just a simple approach.
    patterns = [
        re.escape(hostname),
    ]
    if not hostname.startswith("www."):
        # Prepend pattern with www. the original escaped hostname,
        # otherwise it may match first and leave www. unredacted
        patterns.insert(0, re.escape("www." + hostname))

    # Combine patterns into a single regex pattern
    combined_pattern = re.compile("|".join(patterns), re.IGNORECASE)

    return combined_pattern.sub(filler, txt)


def is_request_flagged(log: dict) -> bool:
    """
    Determines if a given request log should be flagged based on its HTTP method
    and URI path.

    Args:
        log (dict): A dictionary containing request log details. Expected keys are:
            - "method" (str): The HTTP method of the request (e.g., "GET", "POST").
            - "uri_path" (str): The URI path of the request.

    Returns:
        bool: True if the request is flagged, False otherwise.
    """
    method = log.get("method", "")
    uri_path = log.get("uri_path", "")

    # Flag based on HTTP method
    if method in METHOD_FLAGS:
        return True

    # Check against whitelisted URIs
    if any(
        re.search(re.compile(pattern), uri_path) for pattern in WHITELISTED_URIS
    ):
        return False

    # Check for flagged substrings in the URI path
    if any(re.search(pattern, uri_path, re.I) for pattern in URI_FLAGS):
        return True

    return False


def group_logs_by_ip(
    log_lines: list[str], external_hostname: str, max_age_days: int = 3
) -> dict[str, list[dict]]:
    """
    Groups log lines by IP address.

    Args:
        log_lines (list[str]): A list of raw log lines.
        external_hostname (str): The hostname to redact.

    Returns:
        dict: A dictionary where keys are IP addresses and values are lists of log data.
    """
    logs_by_ip: dict[str, list[dict]] = {}
    for log_line in log_lines:
        log_data = process_log_line(log_line, external_hostname)
        if not log_data:
            continue

        # Ensure remote_addr exists
        remote_addr = log_data.get("remote_addr", None)
        if not remote_addr:
            continue

        # Exclude logs that match the exclusion paths, but not method flags
        uri_path = log_data.get("uri_path", "")
        method = log_data.get("method", "")
        if (
            any(re.search(pattern, uri_path) for pattern in PATHNAME_EXCLUSIONS)
            and method not in METHOD_FLAGS
        ):
            continue

        # Filter for log lines that are within the last N days only
        time_local = log_data.get("timestamp", None)
        if not time_local:
            continue

        time_diff = datetime.now(time_local.tzinfo) - time_local
        if time_diff.days > max_age_days:
            continue

        # Group logs by remote_addr
        if remote_addr not in logs_by_ip:
            logs_by_ip[remote_addr] = []

        logs_by_ip[remote_addr].append(log_data)

    # Remove IPs with no logs
    logs_by_ip = {ip: logs for ip, logs in logs_by_ip.items() if logs}

    return logs_by_ip


def process_log_line(log_line: str, external_hostname: str) -> dict | None:
    """
    Processes a single log line, extracting relevant data.

    Args:
        log_line (str): The raw log line.
        external_hostname (str): The hostname to redact.

    Returns:
        dict | None: A dictionary containing parsed log data, or None if parsing fails.
    """
    log_line = redact_hostname(log_line, external_hostname)
    match = LOG_PATTERN.match(log_line)
    if not match:
        print(f"Failed to parse log line: {log_line}", file=sys.stderr)
        return None

    log_data = match.groupdict()
    time_local_str = log_data.get("time_local", None)
    time_local = None
    if time_local_str:
        try:
            time_local = datetime.strptime(
                time_local_str, "%d/%b/%Y:%H:%M:%S %z"
            )
        except ValueError as e:
            print(
                f"Failed to parse time_local: {time_local_str}, error: {e}",
                file=sys.stderr,
            )

    request = log_data.get("request", "")
    try:
        method, uri_path, http_protocol = request.split(" ")
    except ValueError:
        print(f"Failed to parse request field: {request}", file=sys.stderr)
        return None

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
