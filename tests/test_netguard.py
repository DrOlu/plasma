"""Network fetch guard: HTTPS only, no embedded credentials."""
import pytest

from plasma import netguard


def test_https_urls_are_accepted():
    assert netguard.require_https("https://github.com/DrOlu/plasma") == \
        "https://github.com/DrOlu/plasma"


@pytest.mark.parametrize("url", [
    "http://example.com/file",
    "file:///etc/passwd",
    "ftp://example.com/x",
    "https://user:pass@example.com/x",
    "https:///missing-host",
    "https://example.com/\r\nInjected: yes",
    "",
])
def test_unsafe_urls_are_refused(url):
    with pytest.raises(netguard.UrlRefused):
        netguard.require_https(url)
