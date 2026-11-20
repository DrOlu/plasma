"""Small URL safety guard for the few network fetches Plasma performs.

Every fetch in Plasma is an HTTPS download from a fixed project endpoint
(GitHub releases, the Microsoft MSI). This guard makes that contract
explicit: plain HTTP, file URLs, embedded credentials and control
characters are refused before urllib sees them.
"""

from __future__ import annotations

from urllib.parse import urlparse


class UrlRefused(ValueError):
    """The requested URL is outside Plasma's HTTPS-only contract."""


def require_https(url) -> str:
    text = str(url or "").strip()
    if not text or any(ch in text for ch in "\r\n\t"):
        raise UrlRefused("URL is empty or contains control characters")
    parsed = urlparse(text)
    if parsed.scheme.lower() != "https":
        raise UrlRefused(f"refusing non-HTTPS URL scheme: {parsed.scheme or 'none'}")
    if not parsed.netloc:
        raise UrlRefused("URL has no host")
    if parsed.username or parsed.password:
        raise UrlRefused("URL must not embed credentials")
    return text
