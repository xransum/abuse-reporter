"""Constants module."""

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
