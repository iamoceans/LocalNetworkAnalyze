"""
Website visitor tracking module.

Tracks HTTP/HTTPS requests to build statistics
about most visited websites.
"""

import re
from typing import Dict, Optional
from collections import defaultdict
from datetime import datetime, timedelta

from src.capture.base import PacketInfo
from src.core.logger import get_logger


# Hostname validation pattern (RFC 952 and RFC 1123)
# Allows: letters, digits, hyphens, dots for subdomains
# Max 253 characters total, each label max 63 characters
_HOSTNAME_PATTERN = re.compile(
    r"^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)*"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.?$"
)
_MAX_HOSTNAME_LENGTH = 253


def is_valid_hostname(hostname: str) -> bool:
    """Validate hostname according to RFC standards.

    Args:
        hostname: Hostname to validate

    Returns:
        True if hostname appears valid, False otherwise
    """
    if not hostname or not isinstance(hostname, str):
        return False

    # Length check
    if len(hostname) > _MAX_HOSTNAME_LENGTH or len(hostname) == 0:
        return False

    # Basic format check using regex
    if not _HOSTNAME_PATTERN.match(hostname):
        return False

    # Additional checks
    # Must not start or end with hyphen or dot
    if hostname.startswith('-') or hostname.endswith('-'):
        return False
    if hostname.startswith('.') or hostname.endswith('.'):
        return False

    # No consecutive dots
    if '..' in hostname:
        return False

    return True


class WebsiteStats:
    """Statistics for a single website."""

    def __init__(
        self,
        host: str,
        first_seen: Optional[datetime] = None,
    ) -> None:
        """Initialize website statistics.

        Args:
            host: Website hostname
            first_seen: When the website was first accessed
        """
        self.host = host
        self.first_seen = first_seen or datetime.now()
        self.last_seen = self.first_seen
        self.request_count = 1
        self.total_bytes = 0
        self.paths = set()  # Unique paths accessed

    def update(self, packet: PacketInfo) -> None:
        """Update statistics with a new packet.

        Args:
            packet: Captured packet
        """
        self.last_seen = datetime.now()
        self.request_count += 1
        self.total_bytes += packet.length

        # Track unique paths
        if packet.url:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(packet.url)
                if parsed.path:
                    self.paths.add(parsed.path)
            except Exception:
                pass


class WebsiteTracker:
    """Tracks website access statistics with rate limiting."""

    # Rate limiting: maximum updates per second per host
    DEFAULT_MAX_RATE_PER_SECOND = 100
    RATE_LIMIT_WINDOW_SECONDS = 1.0

    def __init__(
        self,
        max_websites: int = 1000,
        retention_hours: int = 24,
        max_rate_per_second: int = DEFAULT_MAX_RATE_PER_SECOND,
    ) -> None:
        """Initialize website tracker.

        Args:
            max_websites: Maximum number of websites to track
            retention_hours: How long to keep statistics (hours)
            max_rate_per_second: Max updates per second per host (DoS protection)
        """
        self._max_websites = max_websites
        self._retention_hours = retention_hours
        self._max_rate_per_second = max_rate_per_second

        # Statistics by host
        self._websites: Dict[str, WebsiteStats] = {}

        # Rate limiting: track last update time per host
        self._last_update_time: Dict[str, datetime] = {}
        self._rate_limited_count: Dict[str, int] = {}  # Track rate-limited requests

        logger = get_logger(__name__)
        self._logger = logger

    def update(self, packet: PacketInfo) -> None:
        """Update tracker with a new packet.

        Args:
            packet: Captured packet information
        """
        # Only track HTTP/HTTPS traffic
        if packet.dst_port not in (80, 443):
            return

        # Extract host from packet
        host = packet.host
        if not host:
            return

        # Validate hostname to prevent injection attacks
        if not is_valid_hostname(host):
            self._logger.warning(f"Invalid hostname rejected: {host[:100]}")
            return

        # Rate limiting: check if this host is being updated too frequently
        now = datetime.now()
        if host in self._last_update_time:
            time_since_last = (now - self._last_update_time[host]).total_seconds()
            if time_since_last < (1.0 / self._max_rate_per_second):
                # Rate limited - increment counter and skip
                self._rate_limited_count[host] = self._rate_limited_count.get(host, 0) + 1

                # Log rate limiting periodically (every 1000th rate-limited request)
                if self._rate_limited_count[host] % 1000 == 0:
                    self._logger.warning(
                        f"Rate limiting in effect for {host}: "
                        f"{self._rate_limited_count[host]} requests skipped"
                    )
                return

        # Update or create stats
        if host in self._websites:
            self._websites[host].update(packet)
        else:
            # Check if we've reached the max
            if len(self._websites) >= self._max_websites:
                # Remove oldest entry
                oldest = min(
                    self._websites.items(),
                    key=lambda x: x[1].last_seen
                )
                del self._websites[oldest[0]]

            self._websites[host] = WebsiteStats(host)
            self._websites[host].update(packet)

        # Update last update time for rate limiting
        self._last_update_time[host] = now

        # Clean up old entries periodically
        self._cleanup()

    def get_top_websites(self, limit: int = 10) -> list[Dict[str, any]]:
        """Get most visited websites.

        Args:
            limit: Maximum number of websites to return

        Returns:
            List of website statistics dictionaries
        """
        # Sort by request count
        sorted_websites = sorted(
            self._websites.values(),
            key=lambda w: w.request_count,
            reverse=True
        )

        result = []
        for site in sorted_websites[:limit]:
            result.append({
                'host': site.host,
                'request_count': site.request_count,
                'total_bytes': site.total_bytes,
                'unique_paths': len(site.paths),
                'first_seen': site.first_seen,
                'last_seen': site.last_seen,
            })

        return result

    def get_stats_for_host(self, host: str) -> Optional[WebsiteStats]:
        """Get statistics for a specific host.

        Args:
            host: Website hostname

        Returns:
            WebsiteStats or None if not found
        """
        return self._websites.get(host)

    def _cleanup(self) -> None:
        """Remove old entries based on retention policy."""
        cutoff = datetime.now() - timedelta(hours=self._retention_hours)

        old_hosts = [
            host for host, stats in self._websites.items()
            if stats.last_seen < cutoff
        ]

        for host in old_hosts:
            del self._websites[host]

        if old_hosts:
            self._logger.debug(f"Cleaned up {len(old_hosts)} old website entries")

    def get_total_requests(self) -> int:
        """Get total number of HTTP requests tracked.

        Returns:
            Total request count
        """
        return sum(stats.request_count for stats in self._websites.values())

    def get_unique_hosts(self) -> int:
        """Get number of unique hosts tracked.

        Returns:
            Number of unique hosts
        """
        return len(self._websites)

    def reset(self) -> None:
        """Reset all statistics including rate limiting counters."""
        self._websites.clear()
        self._last_update_time.clear()
        self._rate_limited_count.clear()
        self._logger.info("Website tracker reset")

    def get_rate_limit_stats(self) -> Dict[str, int]:
        """Get rate limiting statistics.

        Returns:
            Dictionary with rate-limited counts per host
        """
        return self._rate_limited_count.copy()


def create_website_tracker(
    max_websites: int = 1000,
    retention_hours: int = 24,
    max_rate_per_second: int = WebsiteTracker.DEFAULT_MAX_RATE_PER_SECOND,
) -> WebsiteTracker:
    """Create a website tracker instance.

    Args:
        max_websites: Maximum number of websites to track
        retention_hours: How long to keep statistics (hours)
        max_rate_per_second: Max updates per second per host (DoS protection)

    Returns:
        Configured WebsiteTracker instance
    """
    return WebsiteTracker(
        max_websites=max_websites,
        retention_hours=retention_hours,
        max_rate_per_second=max_rate_per_second,
    )


__all__ = [
    "WebsiteTracker",
    "WebsiteStats",
    "create_website_tracker",
]
