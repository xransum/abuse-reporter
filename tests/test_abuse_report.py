import pytest


def test_import() -> None:
    """Test package import."""
    try:
        # noqa: F401
        import abuse_reporter  # pylint: disable=unused-import,import-outside-toplevel
    except ImportError:
        pytest.fail("Package import failed")
