"""Primary runner module for the Abuse Reporter program."""

import os
import re
import smtplib
import socket
import sys
from datetime import datetime
from email.message import EmailMessage

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


def run() -> None:
    """Run the Abuse Reporter program."""
    print(f"{Fore.GREEN}Abuse Reporter is running...{Style.RESET_ALL}")
    # Placeholder for future implementation
    # Actual abuse reporting logic will be added here
