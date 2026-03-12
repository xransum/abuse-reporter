"""Smoke tests for the abuse_reporter package."""

import abuse_reporter
from abuse_reporter.config import (
    AppConfig,
    Config,
    ConfigError,
    DiscordConfig,
    FiltersConfig,
    RemoteConfig,
    SmtpConfig,
)
from abuse_reporter.constants import (
    ABUSE_REPORT_BASELINE,
    LOG_PATTERN,
    METHOD_FLAGS,
    PATHNAME_EXCLUSIONS,
    URI_FLAGS,
    WHITELISTED_URIS,
)


def test_package_importable() -> None:
    """The top-level package must be importable."""
    assert abuse_reporter is not None


def test_config_classes_exist() -> None:
    """All config dataclasses must be importable."""
    assert AppConfig
    assert RemoteConfig
    assert SmtpConfig
    assert DiscordConfig
    assert FiltersConfig
    assert Config
    assert ConfigError


def test_constants_exist() -> None:
    """Key constants must be present and non-empty."""
    assert LOG_PATTERN is not None
    assert ABUSE_REPORT_BASELINE
    assert len(METHOD_FLAGS) > 0
    assert len(WHITELISTED_URIS) > 0
    assert len(URI_FLAGS) > 0
    assert len(PATHNAME_EXCLUSIONS) > 0
