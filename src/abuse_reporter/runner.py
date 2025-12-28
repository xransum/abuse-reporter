"""Primary runner module for the Abuse Reporter program."""

import os
import re
import smtplib
import socket
import sys
from datetime import datetime
from email.message import EmailMessage

import paramiko
import requests
import whois
from querycontacts import ContactFinder
from rich.progress import Progress

from abuse_reporter import Fore, Style, environ
from abuse_reporter.db import ReportsDatabase


TESTING = environ.get("TESTING", "false").lower() == "true"
EXTERNAL_HOSTNAME = os.environ["EXTERNAL_HOST"]
REMOTE_HOST = os.environ["REMOTE_HOST"]
REMOTE_PORT = int(os.environ["REMOTE_PORT"])
REMOTE_USER = os.environ["REMOTE_USER"]
REMOTE_PASS = os.environ["REMOTE_PASS"]
SMTP_HOST = os.environ["SMTP_HOST"]
SMTP_PORT = int(os.environ["SMTP_PORT"])
SMTP_USER = os.environ["SMTP_USER"]
SMTP_PASS = os.environ["SMTP_PASS"]

LOG_PATTERN = re.compile(
    r"(?P<remote_addr>\S+) - (?P<remote_user>\S+) \[(?P<time_local>[^\]]+)\] "
    r'"(?P<request>[^"]+)" (?P<status>\d+) (?P<bytes_sent>\d+) '
    r'"(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"'
)

ABUSE_REPORT_BASELINE = """Unwanted Traffic from {ip_addr}

IP Address: {ip_addr}
Hostname: {hostname}

<logs>

{raw_logs}

</logs>
"""

if TESTING:
    print(
        f"{Fore.YELLOW}[!] TESTING MODE ENABLED - No actual reports will be sent."
        f"{Style.RESET_ALL}"
    )


def run_ssh_command(
    hostname: str,
    port: int,
    username: str,
    password: str,
    command: str,
):
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


def get_whois_info(
    ip_addr: str, retry: int = 0, max_retries: int = 3
) -> whois.WhoisEntry | None:
    """
    Retrieves WHOIS information for a given IP address.

    Args:
        ip_addr (str): The IP address to query.
        retry (int): The current retry attempt.
        max_retries (int): The maximum number of retry attempts.

    Returns:
        whois.WhoisEntry | None: The WHOIS information or None if the query fails.
    """
    try:
        w = whois.whois(ip_addr)
        return w
    except whois.parser.PywhoisError as e:
        if retry < max_retries:
            return get_whois_info(ip_addr, retry + 1, max_retries)
        print(f"Failed to get WHOIS info for {ip_addr}: {e}", file=sys.stderr)
        return None


def get_ip_info(ip_addr: str) -> dict | None:
    """
    Fetches information about a given IP address using the ipinfo.io API.

    Args:
        ip_addr (str): The IP address to retrieve information for.

    Returns:
        dict | None: A dictionary containing the IP address information if the request is successful,
                     or None if an error occurs during the request.

    Notes:
        - This function uses the ipinfo.io API to fetch IP address details.
        - A timeout of 10 seconds is set for the API request.
        - If the request fails, an error message is printed to stderr, and None is returned.
    """
    try:
        response = requests.get(
            f"https://ipinfo.io/{ip_addr}/json",
            timeout=10,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
                )
            },
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Failed to get IP info for {ip_addr}: {e}", file=sys.stderr)
        return None


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

    # if the hostname doesn't include www, we need to ensure it's also included
    # in the redaction
    patterns = [
        re.escape(hostname),
    ]
    if not hostname.startswith("www."):
        # Prepend pattern with www. the original escaped hostname,
        # otherwise it may match first and leave www. unredacted
        patterns.insert(0, re.escape("www." + hostname))

    combined_pattern = re.compile("|".join(patterns), re.IGNORECASE)
    return combined_pattern.sub(filler, txt)


METHOD_FLAGS = ["POST", "PUT", "DELETE"]
WHITELISTED_URIS = [
    r"/static/",
    r"^.+?favicon.ico",
    r"^.+?robots.txt",
    r"^.+?sitemap(\.[a-z]+)?",
    r"^\/$",
    r"^\/pp.html$",
    r"^\/tou.html$",
]
URI_FLAGS = [
    r"(sign-?in)|login|logout|register|create-?account|create-?user|signup|sign-?up",
    r"(.+)?\.(git|env)(.+)?",
    r"(.+)?accesson(.+)?",
    r"(.+)?admin(.+)?",
    r"(.+)?admin(.+)?",
    r"(.+)?config(.+)?",
    r"(.+)?login(.+)?",
    r"(.+)?uploads(.+)?",
    r"(.+)?users(.+)?",
    r"(.+)?wp-?admin(.+)?",
    r"(.+)?xmlrpc(.+)?",
    r"(.+)?\/txets\.php",
    r"(\.alfa)|alfa.+\.php",
    r"\/node_modules\/",
]


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
    if any(re.search(pattern, uri_path) for pattern in WHITELISTED_URIS):
        return False

    # Check for flagged substrings in the URI path
    if any(re.search(pattern, uri_path) for pattern in URI_FLAGS):
        return True

    return False


def send_abuse_report(to_address: str, subject: str, body: str):
    """
    Sends an abuse report email to the specified recipient.

    Args:
        to_address (str): The recipient's email address.
        subject (str): The subject of the email.
        body (str): The content of the email.
    """
    msg = create_email_message(to_address, subject, body)
    send_email_via_smtp(msg)


def get_hostname_from_ip(ip_addr: str) -> str:
    """
    Performs a reverse DNS lookup to get the hostname for a given IP address.

    Args:
        ip_addr (str): The IP address to look up.

    Returns:
        str: The hostname associated with the IP address, or "Unknown" if not found.
    """
    try:
        hostname, *_ = socket.gethostbyaddr(ip_addr)
        return hostname
    except socket.herror:
        return "Unknown"


def create_email_message(
    to_address: str, subject: str, body: str
) -> EmailMessage:
    """
    Creates an email message object.

    Args:
        to_address (str): The recipient's email address.
        subject (str): The subject of the email.
        body (str): The content of the email.

    Returns:
        EmailMessage: The constructed email message object.
    """
    msg = EmailMessage()
    msg["From"] = SMTP_USER
    msg["To"] = to_address
    msg["Cc"] = SMTP_USER
    msg["Subject"] = subject
    msg.set_content(body)
    return msg


def send_email_via_smtp(msg: EmailMessage):
    """
    Sends an email message using the SMTP server.

    Args:
        msg (EmailMessage): The email message to send.
    """
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)


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

    return logs_by_ip


def handle_already_reported_ip(ip_addr: str, logs: list[dict], report: dict):
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
    ip_addr: str, logs: list[dict], reports: ReportsDatabase, qf: ContactFinder
):
    """
    Handles the case where an IP address is flagged for unwanted traffic.

    Args:
        ip_addr (str): The IP address.
        logs (list[dict]): The logs associated with the IP address.
        reports (ReportsDatabase): The reports database instance.
        qf (ContactFinder): The contact finder instance.
    """
    hostname = get_hostname_from_ip(ip_addr)
    contacts = qf.find(ip_addr)
    abuse_contact = contacts[0] if contacts else None

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

    except (smtplib.SMTPDataError, smtplib.SMTPRecipientsRefused) as e:
        # It seems that when we hit our hourly quota, DreamHost's SMTP server
        # will return a 450 error code. To avoid further attempts that are
        # likely to fail, we exit the script here.
        # REF: https://help.dreamhost.com/hc/en-us/articles/215730437-SMTP-quota-limits
        if isinstance(e, smtplib.SMTPRecipientsRefused):
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


def process_logs(logs_by_ip: dict, reports: ReportsDatabase, qf: ContactFinder):
    """
    Processes logs grouped by IP address.

    Args:
        logs_by_ip (dict): Logs grouped by IP address.
        reports (ReportsDatabase): The reports database instance.
        qf (ContactFinder): The contact finder instance.
    """
    already_reported_ip_addrs = []
    reported_ip_addrs = []

    with Progress() as p:
        log_items = list(logs_by_ip.items())
        task = p.add_task(
            "[cyan]Processing IP addresses...", total=len(log_items)
        )

        for ip_addr, logs in log_items:
            report = reports.get_reported_ip(ip_addr)
            if report:
                handle_already_reported_ip(ip_addr, logs, report)
                already_reported_ip_addrs.append(ip_addr)
            else:
                ip_flagged = any(is_request_flagged(log) for log in logs)
                if ip_flagged:
                    handle_flagged_ip(ip_addr, logs, reports, qf)
                    reported_ip_addrs.append(ip_addr)
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


def run() -> None:
    """Run the Abuse Reporter program."""
    print(f"{Fore.GREEN}Abuse Reporter is running...{Style.RESET_ALL}")
    # Placeholder for future implementation
    # Actual abuse reporting logic will be added here
