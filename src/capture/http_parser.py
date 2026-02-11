"""
HTTP/HTTPS request parser module.

Extracts URLs, hostnames, and HTTP method information
from network packet data.
"""

from typing import Optional, Tuple
from urllib.parse import urlparse

from src.core.logger import get_logger


class HTTPRequest:
    """Parsed HTTP request information.

    Attributes:
        method: HTTP method (GET, POST, etc.)
        path: Request path
        host: Host header value
        url: Full URL (http://host/path)
        protocol: HTTP protocol version
    """

    def __init__(
        self,
        method: str,
        path: str,
        host: str,
        url: str,
        protocol: str = "HTTP/1.1",
    ) -> None:
        """Initialize HTTP request info.

        Args:
            method: HTTP method
            path: Request path
            host: Host header value
            url: Full URL
            protocol: HTTP protocol version
        """
        self.method = method
        self.path = path
        self.host = host
        self.url = url
        self.protocol = protocol

    def __repr__(self) -> str:
        return f"HTTPRequest({self.method} {self.url})"


def parse_http_request(raw_data: bytes) -> Optional[HTTPRequest]:
    """Parse HTTP request from raw packet data.

    Args:
        raw_data: Raw packet bytes

    Returns:
        HTTPRequest object if successful, None otherwise
    """
    if not raw_data:
        return None

    try:
        # Decode as UTF-8 with error handling
        payload_str = raw_data.decode('utf-8', errors='ignore')

        # Split into lines (handle both \r\n and \n)
        lines = payload_str.replace('\r\n', '\n').split('\n')
        if not lines:
            return None

        # Parse request line
        request_line = lines[0].strip()
        parts = request_line.split(' ')

        # Validate HTTP request format
        if len(parts) < 2:
            return None

        # Check if it's a valid HTTP method
        valid_methods = ('GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'CONNECT', 'TRACE')
        method = parts[0].upper()
        if method not in valid_methods:
            return None

        path = parts[1]

        # Extract Host header
        host = None
        for line in lines[1:]:
            line = line.strip()
            if not line:
                break  # Empty line means end of headers
            if line.lower().startswith('host:'):
                # Split on first colon only
                if ':' in line:
                    host = line.split(':', 1)[1].strip()
                break

        # Construct URL if we have a host
        url = None
        if host:
            url = f"http://{host}{path}"

        # Get protocol version if available
        protocol = parts[2] if len(parts) >= 3 else "HTTP/1.1"

        return HTTPRequest(
            method=method,
            path=path,
            host=host,
            url=url,
            protocol=protocol,
        )

    except (UnicodeDecodeError, ValueError, IndexError) as e:
        # Expected errors for non-HTTP traffic
        logger = get_logger(__name__)
        logger.debug(f"Failed to parse HTTP request: {e}")
        return None
    except Exception as e:
        # Unexpected error - log warning
        logger = get_logger(__name__)
        logger.warning(f"Unexpected error parsing HTTP request: {e}")
        return None


def parse_http_from_packet(
    raw_data: bytes,
    dst_port: int,
    src_port: int,
) -> Tuple[Optional[str], Optional[str]]:
    """Parse HTTP information from packet data.

    Convenience function that returns URL and host separately.

    Args:
        raw_data: Raw packet bytes
        dst_port: Destination port
        src_port: Source port

    Returns:
        Tuple of (url, host) - both can be None
    """
    # Only check HTTP traffic (port 80)
    if dst_port != 80 and src_port != 80:
        return None, None

    # Quick check for HTTP methods before parsing
    if not any(method in raw_data for method in (b"GET ", b"POST ", b"HEAD ")):
        return None, None

    http_req = parse_http_request(raw_data)

    if http_req:
        return http_req.url, http_req.host

    return None, None


def is_tls_client_hello(raw_data: bytes) -> bool:
    """Check if packet data looks like a TLS ClientHello.

    Args:
        raw_data: Raw packet bytes

    Returns:
        True if this appears to be a TLS ClientHello
    """
    if not raw_data or len(raw_data) < 3:
        return False

    # TLS records start with 0x16 (handshake) and 0x03 (SSLv3/TLS version)
    return raw_data[:2] == b'\x16\x03'


def extract_sni_from_tls_client_hello(raw_data: bytes) -> Optional[str]:
    """Extract SNI (Server Name Indication) hostname from TLS ClientHello.

    Args:
        raw_data: Raw packet bytes (TCP payload only)

    Returns:
        SNI hostname if found, None otherwise
    """
    logger = get_logger(__name__)

    if not raw_data or len(raw_data) < 50:
        return None

    try:
        # Check if this is a TLS ClientHello
        if not is_tls_client_hello(raw_data):
            return None

        # Skip TLS record header (5 bytes)
        # 0x16 (handshake), version (2 bytes), length (2 bytes)
        offset = 5

        if len(raw_data) < offset + 4:
            return None

        # Check for ClientHello handshake type (0x01)
        if raw_data[offset] != 0x01:
            return None

        # Skip handshake message header (4 bytes)
        # type (1 byte) + length (3 bytes)
        offset += 4

        # Skip version (2 bytes) and random (32 bytes)
        offset += 34

        if len(raw_data) < offset + 1:
            return None

        # Skip session_id (first byte is length)
        session_id_len = raw_data[offset]
        offset += 1 + session_id_len

        if len(raw_data) < offset + 2:
            return None

        # Skip cipher_suites (2 bytes length + suites)
        cipher_suites_len = (raw_data[offset] << 8) | raw_data[offset + 1]
        offset += 2 + cipher_suites_len

        if len(raw_data) < offset + 1:
            return None

        # Skip compression_methods (1 byte length + methods)
        compression_len = raw_data[offset]
        offset += 1 + compression_len

        if len(raw_data) < offset + 2:
            return None

        # Check for extensions length
        extensions_len = (raw_data[offset] << 8) | raw_data[offset + 1]
        offset += 2

        # Parse extensions
        extensions_end = offset + extensions_len
        while offset < extensions_end:
            if len(raw_data) < offset + 4:
                break

            # Extension type (2 bytes) and length (2 bytes)
            ext_type = (raw_data[offset] << 8) | raw_data[offset + 1]
            ext_len = (raw_data[offset + 2] << 8) | raw_data[offset + 3]
            offset += 4

            # SNI extension type is 0x0000
            if ext_type == 0:
                if len(raw_data) < offset + ext_len:
                    break

                # Skip SNI list length (2 bytes)
                sni_offset = offset + 2

                if len(raw_data) < sni_offset + 3:
                    break

                # Skip entry type (1 byte, should be 0x00 for hostname)
                # and name length (2 bytes)
                name_len = (raw_data[sni_offset + 1] << 8) | raw_data[sni_offset + 2]
                sni_offset += 3

                if len(raw_data) < sni_offset + name_len:
                    break

                # Extract hostname
                hostname = raw_data[sni_offset:sni_offset + name_len].decode('ascii', errors='ignore')
                logger.info(f"SNI extracted: {hostname}")
                return hostname

            # Move to next extension
            offset += ext_len

    except Exception as e:
        logger.debug(f"Failed to extract SNI: {e}")

    return None


def parse_tls_sni(raw_data: bytes, dst_port: int, src_port: int) -> Tuple[Optional[str], Optional[str]]:
    """Parse TLS SNI from packet data.

    Args:
        raw_data: Raw packet bytes
        dst_port: Destination port
        src_port: Source port

    Returns:
        Tuple of (url, host) - url is None for TLS, host is SNI if available
    """
    # Only check HTTPS traffic (port 443)
    if dst_port != 443 and src_port != 443:
        return None, None

    # Check for TLS ClientHello
    if not is_tls_client_hello(raw_data):
        return None, None

    # Extract SNI
    sni = extract_sni_from_tls_client_hello(raw_data)
    if sni:
        return None, sni  # URL is None for HTTPS, but we have hostname from SNI

    return None, None


__all__ = [
    "HTTPRequest",
    "parse_http_request",
    "parse_http_from_packet",
    "is_tls_client_hello",
    "extract_sni_from_tls_client_hello",
    "parse_tls_sni",
]
