"""Configuration loading and validation for abuse-reporter."""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PLACEHOLDER = "CHANGE_ME"


class ConfigError(Exception):
    """Raised when the configuration is invalid or incomplete."""


@dataclass
class AppConfig:
    """Application-level flags."""

    dry_run: bool = False


@dataclass
class RemoteConfig:
    """SSH connection settings for the target server."""

    external_host: str = PLACEHOLDER
    host: str = PLACEHOLDER
    port: int = 22
    user: str = PLACEHOLDER
    password: str = PLACEHOLDER


@dataclass
class SmtpConfig:
    """SMTP outbound mail settings."""

    host: str = PLACEHOLDER
    port: int = 587
    user: str = PLACEHOLDER
    password: str = PLACEHOLDER


@dataclass
class DiscordConfig:
    """Discord webhook settings."""

    webhook_url: str = ""


@dataclass
class FiltersConfig:
    """Filtering rules applied during log processing."""

    blacklisted_emails: list[str] = field(default_factory=list)


@dataclass
class Config:
    """Top-level configuration object passed throughout the application."""

    app: AppConfig
    remote: RemoteConfig
    smtp: SmtpConfig
    discord: DiscordConfig
    filters: FiltersConfig


def _find_placeholders(data: dict[str, Any], path: str = "") -> list[str]:
    """Walk a nested dict and return dot-paths of any CHANGE_ME values.

    Args:
        data: The dictionary to inspect.
        path: The current dot-path prefix (used for recursion).

    Returns:
        A list of dot-path strings where placeholder values were found.
    """
    found: list[str] = []
    for key, value in data.items():
        current_path = f"{path}.{key}" if path else key
        if isinstance(value, dict):
            found.extend(_find_placeholders(value, current_path))
        elif value == PLACEHOLDER:
            found.append(current_path)
    return found


def _build_config(data: dict[str, Any]) -> Config:
    """Construct a Config dataclass from a config dictionary.

    Args:
        data: The configuration dictionary loaded from TOML.

    Returns:
        A populated Config instance.

    Raises:
        ConfigError: If a required section is missing from the data.
    """
    required_sections = ("app", "remote", "smtp", "discord", "filters")
    for section in required_sections:
        if section not in data:
            raise ConfigError(
                f"Missing required config section [{section}]. "
                f"Check your config file against config.example.toml."
            )

    raw_remote = data["remote"]
    raw_smtp = data["smtp"]

    return Config(
        app=AppConfig(**data["app"]),
        remote=RemoteConfig(
            external_host=raw_remote["external_host"],
            host=raw_remote["host"],
            port=int(raw_remote["port"]),
            user=raw_remote["user"],
            password=raw_remote["pass"],
        ),
        smtp=SmtpConfig(
            host=raw_smtp["host"],
            port=int(raw_smtp["port"]),
            user=raw_smtp["user"],
            password=raw_smtp["pass"],
        ),
        discord=DiscordConfig(**data["discord"]),
        filters=FiltersConfig(**data["filters"]),
    )


def load_config(config_dir: str | None = None) -> Config:
    """Load and validate ``config.toml`` from the project root.

    Args:
        config_dir: Directory containing ``config.toml``.  Defaults to the
            project root (three levels above this file).

    Returns:
        A fully populated and validated Config instance.

    Raises:
        ConfigError: If ``config.toml`` is missing, a required section is
            absent, or any field still contains the ``CHANGE_ME`` placeholder.
    """
    if config_dir is None:
        # src/abuse_reporter/config.py -> go up 3 levels to project root
        config_dir = str(Path(__file__).resolve().parent.parent.parent)

    config_path = Path(config_dir) / "config.toml"

    if not config_path.exists():
        raise ConfigError(
            f"Config file not found: {config_path}\n"
            "Copy config.example.toml to config.toml and fill in your values."
        )

    with config_path.open("rb") as f:
        data: dict[str, Any] = tomllib.load(f)

    placeholders = _find_placeholders(data)
    if placeholders:
        paths = "\n  ".join(placeholders)
        raise ConfigError(
            f"The following config fields still contain placeholder values:\n"
            f"  {paths}\n"
            "Edit config.toml and replace all CHANGE_ME values."
        )

    return _build_config(data)
