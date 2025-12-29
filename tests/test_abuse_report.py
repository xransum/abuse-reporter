"""Test suite for the abuse_reporter package."""

import pytest


def test_import() -> None:
    """Test package import."""
    try:
        import abuse_reporter  # noqa: F401
    except ImportError:
        pytest.fail("Package import failed")
