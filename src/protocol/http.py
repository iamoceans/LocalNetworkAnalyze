"""
HTTP protocol parser.

Parses HTTP/1.x requests and responses from TCP payload data.
"""

import re
from datetime import datetime
from typing import Optional

from src.core.logger import get_logger
from .base import (
    ProtocolParser,
    ParsedHTTP,
    ProtocolDirection,
    ParseResult,
    get_direction_from_ports,
    is_text_content,
)
from src.utils.constants import HTTPMethod, HTTPStatus

logger = get_logger(__name__)


class HTTPParser(ProtocolParser):
    """HTTP/1.x protocol parser.

    Parses HTTP requests and responses from TCP data.
    Supports HTTP/1.0 and HTTP/1.1.
    """

    # Pre-compiled regex patterns
    REQUEST_LINE_RE = re.compile(
        r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP/(\d\.\d)\r?$",
        re.MULTILINE,
    )
    STATUS_LINE_RE = re.compile(
        r"^HTTP/(\d\.\d)\s+(\d{3})\s+(.+)\r?$",
        re.MULTILINE,
    )
    HEADER_RE = re.compile(r"^([^:\r\n]+):\s*([^\r\n]+)\r?$", re.MULTILINE)

    # Max header size to prevent excessive memory usage
    MAX_HEADER_SIZE = 8192
    MAX_BODY_SIZE = 10 * 1024 * 1024  # 10MB

    def __init__(self) -> None:
        """Initialize HTTP parser."""
        self._parse_count = 0
        self._error_count = 0

    def can_parse(self, packet_data: bytes, protocol: str) -> bool:
        """Check if data contains HTTP.

        Args:
            packet_data: Raw packet bytes
            protocol: Protocol name from packet info

        Returns:
            True if data looks like HTTP
        """
        if protocol not in ("TCP", "HTTP"):
            return False

        if not packet_data:
            return False

        # Try to decode as text
        try:
            text = packet_data.decode("utf-8", errors="ignore")
        except Exception:
            return False

        # Check for HTTP request or response
        text_stripped = text.strip()

        # Check for request
        if self.REQUEST_LINE_RE.match(text_stripped):
            return True

        # Check for response
        if self.STATUS_LINE_RE.match(text_stripped):
            return True

        return False

    def parse(self, packet_data: bytes, protocol: str) -> ParseResult:
        """Parse HTTP data from packet.

        Args:
            packet_data: Raw packet bytes
            protocol: Protocol name (should be TCP or HTTP)

        Returns:
            ParseResult with ParsedHTTP or error
        """
        self._parse_count += 1

        try:
            # Decode data
            try:
                text = packet_data.decode("utf-8", errors="ignore")
            except Exception as e:
                self._error_count += 1
                return ParseResult.fail(f"Failed to decode HTTP data: {e}")

            # Try to parse as request
            if self._is_request(text):
                return self._parse_request(text, packet_data)

            # Try to parse as response
            if self._is_response(text):
                return self._parse_response(text, packet_data)

            self._error_count += 1
            return ParseResult.fail("Data does not appear to be HTTP")

        except Exception as e:
            self._error_count += 1
            logger.error(f"Error parsing HTTP: {e}")
            return ParseResult.fail(f"Parse error: {e}")

    def _is_request(self, text: str) -> bool:
        """Check if text is an HTTP request.

        Args:
            text: Decoded HTTP text

        Returns:
            True if this looks like a request
        """
        first_line = text.split("\r\n", 1)[0].strip()
        return bool(self.REQUEST_LINE_RE.match(first_line))

    def _is_response(self, text: str) -> bool:
        """Check if text is an HTTP response.

        Args:
            text: Decoded HTTP text

        Returns:
            True if this looks like a response
        """
        first_line = text.split("\r\n", 1)[0].strip()
        return bool(self.STATUS_LINE_RE.match(first_line))

    def _parse_request(self, text: str, raw_data: bytes) -> ParseResult:
        """Parse HTTP request.

        Args:
            text: Decoded request text
            raw_data: Original raw bytes

        Returns:
            ParseResult with parsed request
        """
        lines = text.split("\r\n")

        if not lines:
            return ParseResult.fail("Empty request")

        # Parse request line
        request_line = lines[0]
        match = self.REQUEST_LINE_RE.match(request_line)
        if not match:
            return ParseResult.fail(f"Invalid request line: {request_line}")

        method = match.group(1)
        path = match.group(2)
        version = f"HTTP/{match.group(3)}"

        # Parse headers
        headers = {}
        body_start = 1

        for i, line in enumerate(lines[1:], start=1):
            if not line.strip():  # Empty line = end of headers
                body_start = i + 1
                break

            header_match = self.HEADER_RE.match(line)
            if header_match:
                name = header_match.group(1)
                value = header_match.group(2)
                headers[name] = value

        # Extract body
        body_lines = lines[body_start:]
        body = "\r\n".join(body_lines).encode("utf-8", errors="ignore")

        # Create parsed data
        parsed = ParsedHTTP(
            protocol="HTTP",
            direction=ProtocolDirection.REQUEST,
            timestamp=datetime.now(),
            raw_data=raw_data,
            method=method,
            path=path,
            version=version,
            headers=headers,
            body=body,
        )

        return ParseResult.ok(parsed)

    def _parse_response(self, text: str, raw_data: bytes) -> ParseResult:
        """Parse HTTP response.

        Args:
            text: Decoded response text
            raw_data: Original raw bytes

        Returns:
            ParseResult with parsed response
        """
        lines = text.split("\r\n")

        if not lines:
            return ParseResult.fail("Empty response")

        # Parse status line
        status_line = lines[0]
        match = self.STATUS_LINE_RE.match(status_line)
        if not match:
            return ParseResult.fail(f"Invalid status line: {status_line}")

        version = f"HTTP/{match.group(1)}"
        status_code = int(match.group(2))
        reason = match.group(3)

        # Parse headers
        headers = {}
        body_start = 1

        for i, line in enumerate(lines[1:], start=1):
            if not line.strip():  # Empty line = end of headers
                body_start = i + 1
                break

            header_match = self.HEADER_RE.match(line)
            if header_match:
                name = header_match.group(1)
                value = header_match.group(2)
                headers[name] = value

        # Extract body
        body_lines = lines[body_start:]
        body = "\r\n".join(body_lines).encode("utf-8", errors="ignore")

        # Create parsed data
        parsed = ParsedHTTP(
            protocol="HTTP",
            direction=ProtocolDirection.RESPONSE,
            timestamp=datetime.now(),
            raw_data=raw_data,
            version=version,
            status_code=status_code,
            reason=reason,
            headers=headers,
            body=body,
        )

        return ParseResult.ok(parsed)

    def get_statistics(self) -> dict:
        """Get parser statistics.

        Returns:
            Dictionary with parse statistics
        """
        success_count = self._parse_count - self._error_count
        success_rate = (
            success_count / self._parse_count if self._parse_count > 0 else 0
        )

        return {
            "parse_count": self._parse_count,
            "error_count": self._error_count,
            "success_count": success_count,
            "success_rate": success_rate,
        }

    def reset_statistics(self) -> None:
        """Reset parser statistics."""
        self._parse_count = 0
        self._error_count = 0


class HTTPUtils:
    """Utility functions for HTTP parsing and analysis."""

    @staticmethod
    def extract_url(parsed: ParsedHTTP) -> Optional[str]:
        """Extract full URL from parsed HTTP request.

        Args:
            parsed: Parsed HTTP request

        Returns:
            Full URL or None
        """
        if not parsed.is_request():
            return None

        host = parsed.get_header("Host")
        if not host:
            return None

        # Check if path already includes protocol
        if parsed.path.startswith(("http://", "https://")):
            return parsed.path

        # Construct URL
        scheme = "https" if parsed.get_header("Upgrade-Insecure-Requests") else "http"
        return f"{scheme}://{host}{parsed.path}"

    @staticmethod
    def get_content_type(parsed: ParsedHTTP) -> Optional[str]:
        """Get content type from parsed HTTP.

        Args:
            parsed: Parsed HTTP data

        Returns:
            Content-Type header value or None
        """
        return parsed.get_header("Content-Type")

    @staticmethod
    def get_content_length(parsed: ParsedHTTP) -> Optional[int]:
        """Get content length from parsed HTTP.

        Args:
            parsed: Parsed HTTP data

        Returns:
            Content-Length value or None
        """
        length_str = parsed.get_header("Content-Length")
        if length_str:
            try:
                return int(length_str)
            except ValueError:
                pass
        return None

    @staticmethod
    def is_chunked(parsed: ParsedHTTP) -> bool:
        """Check if HTTP uses chunked transfer encoding.

        Args:
            parsed: Parsed HTTP data

        Returns:
            True if Transfer-Encoding is chunked
        """
        encoding = parsed.get_header("Transfer-Encoding")
        return encoding is not None and "chunked" in encoding.lower()

    @staticmethod
    def get_user_agent(parsed: ParsedHTTP) -> Optional[str]:
        """Get User-Agent from HTTP request.

        Args:
            parsed: Parsed HTTP request

        Returns:
            User-Agent header value or None
        """
        return parsed.get_header("User-Agent")

    @staticmethod
    def get_server(parsed: ParsedHTTP) -> Optional[str]:
        """Get Server header from HTTP response.

        Args:
            parsed: Parsed HTTP response

        Returns:
            Server header value or None
        """
        return parsed.get_header("Server")

    @staticmethod
    def is_compressed(parsed: ParsedHTTP) -> bool:
        """Check if content is compressed.

        Args:
            parsed: Parsed HTTP data

        Returns:
            True if Content-Encoding indicates compression
        """
        encoding = parsed.get_header("Content-Encoding")
        if encoding:
            return encoding.lower() in ("gzip", "deflate", "br", "compress")
        return False

    @staticmethod
    def is_websocket(parsed: ParsedHTTP) -> bool:
        """Check if this is a WebSocket upgrade.

        Args:
            parsed: Parsed HTTP data

        Returns:
            True if this is a WebSocket upgrade
        """
        if not parsed.is_request():
            return False

        upgrade = parsed.get_header("Upgrade")
        connection = parsed.get_header("Connection")

        return (
            upgrade is not None
            and upgrade.lower() == "websocket"
            and connection is not None
            and "upgrade" in connection.lower()
        )

    @staticmethod
    def is_https_used(parsed: ParsedHTTP) -> bool:
        """Check if HTTPS is being used (via header inference).

        Args:
            parsed: Parsed HTTP data

        Returns:
            True if likely HTTPS
        """
        if parsed.is_response():
            # Check for Strict-Transport-Security header
            return parsed.get_header("Strict-Transport-Security") is not None
        return False


def create_http_parser() -> HTTPParser:
    """Create HTTP parser instance.

    Returns:
        New HTTPParser instance
    """
    return HTTPParser()
