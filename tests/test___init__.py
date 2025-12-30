"""Unit tests for the abuse_reporter package initialization."""

import os
from unittest.mock import patch

from abuse_reporter import Fore, Style, app_root


@patch("os.path.abspath")
@patch("os.path.dirname")
def test_app_root(mock_dirname, mock_abspath):
    """Test that app_root is correctly determined."""
    # Mock the behavior of os.path.abspath and os.path.dirname
    mock_abspath.return_value = "/abuse-reporter/src/abuse_reporter/__init__.py"
    mock_dirname.side_effect = lambda path: os.path.split(path)[0]

    # Expected app_root value
    expected_app_root = "abuse-reporter"

    # We really just check if app_root ends with the expected path
    # as it'd be hard to match the full path in different environments
    assert app_root.endswith(expected_app_root)


def test_environ_import():
    """Test that environ is imported correctly."""
    assert "environ" in dir(os)


def test_fore_and_style_import():
    """Test that Fore and Style are imported correctly."""
    assert Fore is not None
    assert Style is not None
