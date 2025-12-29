# Abuse Reporter

Abuse Reporter is a tool designed to analyze server logs, identify unwanted traffic, and automatically report abuse to the responsible parties. It integrates with WHOIS services, email, and Discord for streamlined reporting.

## Features

- **Log Analysis**: Processes server logs to detect suspicious activity.
- **WHOIS Lookup**: Retrieves abuse contact information for flagged IPs.
- **Automated Reporting**: Sends abuse reports via email and notifies via Discord.
- **Database Tracking**: Maintains a record of reported IPs to avoid duplicate reports.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/abuse-reporter.git
   cd abuse-reporter
   ```

2. Install Poetry (if not already installed):
   ```bash
   curl -sSL https://install.python-poetry.org | python3 -
   ```

3. Install dependencies using Poetry:
   ```bash
   poetry install
   ```

4. Set up the environment file:
   Create a `.env` file in the root directory with the following content:
   ```
   EXTERNAL_HOST="<REDACTED>"    # External Host / Domain
   REMOTE_HOST="<REDACTED>"     # Remote Server Hostname
   REMOTE_USER="<REDACTED>"     # Remote Login Username
   REMOTE_PORT="<REDACTED>"     # Remote Service Port
   REMOTE_PASS="<REDACTED>"     # Remote Authentication Secret
   SMTP_HOST="<REDACTED>"       # SMTP Server Hostname
   SMTP_PORT="<REDACTED>"       # SMTP Service Port
   SMTP_USER="<REDACTED>"       # SMTP Username / Identity
   SMTP_PASS="<REDACTED>"       # SMTP Authentication Secret
   DISCORD_WEBHOOK_URL="<REDACTED>"  # Discord Webhook Url For Notifications
   ```

## Usage

Run the Abuse Reporter program using Poetry:
```bash
poetry run python -m abuse_reporter
```

### Testing Mode

To enable testing mode, set the `TESTING` constant in `abuse_reporter/constants.py` to `True`. This prevents actual reports from being sent.

Alternatively, you can use the `NO_SEND` environment variable to disable sending SMTP and Discord notifications:
```bash
NO_SEND=1 poetry run python -m abuse_reporter
```

## Contributing

1. Fork the repository.
2. Create a new branch for your feature or bug fix:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Description of changes"
   ```
4. Push to your branch:
   ```bash
   git push origin feature-name
   ```
5. Open a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
