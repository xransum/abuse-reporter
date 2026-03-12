"""Pure-code constants: regex patterns, URI flags, and report templates.

No secrets or environment-specific values live here.  All sensitive
configuration is loaded via :mod:`abuse_reporter.config`.
"""

import re

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
    r"^.+?favicon\.ico",
    r"^.+?robots\.txt",
    r"^.+?sitemap(\.[a-z]+)?",
    r"^\/$",
    r"^\/pp\.html$",
    r"^\/tou\.html$",
]

URI_FLAGS: list[str] = [
    r"(sign-?in)|login|logout|register|create-?account|create-?user|signup|sign-?up",
    r"(.+)?\.(git|env)(.+)?",
    r"(.+)?accesson(.+)?",
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
