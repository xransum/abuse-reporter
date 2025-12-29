"""Constants module."""

import re

from abuse_reporter import environ


TESTING = environ.get("TESTING", "false").lower() == "true"
NO_SEND = environ.get("NO_SEND", "false").lower() == "true"
EXTERNAL_HOSTNAME = environ["EXTERNAL_HOST"]
REMOTE_HOST = environ["REMOTE_HOST"]
REMOTE_PORT = int(environ["REMOTE_PORT"])
REMOTE_USER = environ["REMOTE_USER"]
REMOTE_PASS = environ["REMOTE_PASS"]
SMTP_HOST = environ["SMTP_HOST"]
SMTP_PORT = int(environ["SMTP_PORT"])
SMTP_USER = environ["SMTP_USER"]
SMTP_PASS = environ["SMTP_PASS"]
DISCORD_WEBHOOK_URL = environ.get("DISCORD_WEBHOOK_URL", "")

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

METHOD_FLAGS: list[str] = ["POST", "PUT", "DELETE"]
WHITELISTED_URIS: list[str] = [
    r"\/static\/",
    r"^.+?favicon.ico",
    r"^.+?robots.txt",
    r"^.+?sitemap(\.[a-z]+)?",
    r"^\/$",
    r"^\/pp.html$",
    r"^\/tou.html$",
]
URI_FLAGS: list[str] = [
    (
        r"(sign-?in)|login|logout|register|create-?account|create-?user|signup"
        r"|sign-?up"
    ),
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
PATHNAME_EXCLUSIONS: list[str] = [
    r"^\/+?(index(\.[a-z]+)?)?$",
    r"^\/+?pp(\.[a-z]+)?$",
    r"^\/+?tou(\.[a-z]+)?$",
    r"^\/+?static\/",
    r"^\/+?([a-z_.-]+)?sitemap([a-z_.-]+)?(\.[a-z]+)?$",
]
