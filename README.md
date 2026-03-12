# Abuse Reporter

Abuse Reporter analyses web server logs, identifies suspicious traffic, and
automatically sends abuse reports to the responsible parties via email and
Discord.

## Features

- **Log analysis** — fetches nginx access logs over SSH and parses them
- **WHOIS lookup** — resolves abuse contact addresses for flagged IPs
- **Automated reporting** — sends abuse reports via SMTP with Discord
  notifications
- **Duplicate prevention** — tracks reported IPs in a local SQLite database
- **Dry-run mode** — preview what would be sent without touching anything
- **Single config file** — one `config.toml`, never committed to git

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) for dependency management

## Installation

```bash
git clone https://github.com/xransum/abuse-reporter.git
cd abuse-reporter
uv sync
```

## Configuration

Copy the example template and fill in your credentials:

```bash
cp config.example.toml config.toml
# edit config.toml — replace every CHANGE_ME value
```

`config.toml` is git-ignored and will never be committed.
`config.example.toml` is the reference template committed to the repo.

### Config structure

```toml
[app]
dry_run = false   # set true to always skip sends without --dry-run flag

[remote]
external_host = "yourdomain.com"   # public hostname of your site
host          = "your.server.com"  # SSH hostname
port          = 22
user          = "ssh_user"
pass          = "ssh_password"

[smtp]
host = "smtp.example.com"
port = 587
user = "abuse@yourdomain.com"
pass = "smtp_password"

[discord]
webhook_url = ""   # leave empty to disable notifications

[filters]
blacklisted_emails = [
    # "noreply@example.com",
]
```

## Usage

```bash
# Normal run — fetches logs and sends real reports
uv run abusereport

# Dry-run — fetch and process logs, but skip all emails, Discord, and DB writes
uv run abusereport --dry-run
```

You can also set `dry_run = true` in `config.toml` to make dry-run the
persistent default (useful while you're setting things up).

## Development

### Install dev dependencies

```bash
uv sync --extra dev
```

### Linting and formatting

```bash
uv run ruff check src tests        # lint
uv run ruff check --fix src tests  # lint + auto-fix
uv run ruff format src tests       # format
```

### Type checking

```bash
uv run mypy src
```

### Tests

```bash
uv run pytest
```

### Pre-commit hooks

```bash
uv run pre-commit install
uv run pre-commit run --all-files
```

## License

MIT — see [LICENSE](LICENSE).
