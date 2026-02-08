"""
Protocol parsing module.

Provides functionality for parsing network protocols
from captured packet data.
"""

from typing import Optional, List
from collections import OrderedDict

from .base import (
    ProtocolParser,
    ParsedData,
    ParsedHTTP,
    ParsedDNS,
    ParsedTCP,
    ParsedUDP,
    ParseResult,
    ProtocolDirection,
)
from .http import HTTPParser, HTTPUtils, create_http_parser
from .dns import DNSParser, DNSUtils, create_dns_parser
from .tcp_udp import TCPParser, UDPParser, TCPUtils, UDPUtils, create_tcp_parser, create_udp_parser

__all__ = [
    # Base classes
    "ProtocolParser",
    "ParsedData",
    "ParsedHTTP",
    "ParsedDNS",
    "ParsedTCP",
    "ParsedUDP",
    "ParseResult",
    "ProtocolDirection",
    # Parsers
    "HTTPParser",
    "DNSParser",
    "TCPParser",
    "UDPParser",
    # Factory
    "ParserFactory",
    "create_parser_factory",
    # Utilities
    "HTTPUtils",
    "DNSUtils",
    "TCPUtils",
    "UDPUtils",
    # Factory functions
    "create_http_parser",
    "create_dns_parser",
    "create_tcp_parser",
    "create_udp_parser",
]


class ParserFactory:
    """Factory for protocol parsers.

    Manages registered protocol parsers and provides
    automatic parser selection based on protocol type.
    """

    # Default maximum parsers to cache
    DEFAULT_MAX_PARSERS = 10

    def __init__(self, max_parsers: int = DEFAULT_MAX_PARSERS) -> None:
        """Initialize parser factory.

        Args:
            max_parsers: Maximum number of parsers to cache
        """
        self._parsers: OrderedDict[str, ProtocolParser] = OrderedDict()
        self._max_parsers = max_parsers
        self._parse_count = 0
        self._error_count = 0

        # Register default parsers
        self._register_defaults()

    def _register_defaults(self) -> None:
        """Register default protocol parsers.

        Note: Register higher-level parsers first (HTTP before TCP)
        so they get priority when data can be parsed by multiple parsers.
        """
        self.register_parser("http", create_http_parser())
        self.register_parser("dns", create_dns_parser())
        self.register_parser("tcp", create_tcp_parser())
        self.register_parser("udp", create_udp_parser())

    def register_parser(self, protocol: str, parser: ProtocolParser) -> None:
        """Register a protocol parser.

        Args:
            protocol: Protocol name (lowercase)
            parser: Parser instance to register

        Raises:
            TypeError: If parser is not a ProtocolParser instance
        """
        if not isinstance(parser, ProtocolParser):
            raise TypeError(f"Expected ProtocolParser, got {type(parser)}")

        protocol_lower = protocol.lower()

        # Remove existing parser for this protocol
        if protocol_lower in self._parsers:
            del self._parsers[protocol_lower]

        # Add new parser
        self._parsers[protocol_lower] = parser

        # Enforce max parsers limit (LRU eviction)
        while len(self._parsers) > self._max_parsers:
            self._parsers.popitem(last=False)

    def unregister_parser(self, protocol: str) -> bool:
        """Unregister a protocol parser.

        Args:
            protocol: Protocol name to unregister

        Returns:
            True if parser was removed, False if not found
        """
        protocol_lower = protocol.lower()
        if protocol_lower in self._parsers:
            del self._parsers[protocol_lower]
            return True
        return False

    def get_parser(self, protocol: str) -> Optional[ProtocolParser]:
        """Get parser for specific protocol.

        Args:
            protocol: Protocol name

        Returns:
            Parser instance or None if not found
        """
        return self._parsers.get(protocol.lower())

    def has_parser(self, protocol: str) -> bool:
        """Check if parser is registered for protocol.

        Args:
            protocol: Protocol name

        Returns:
            True if parser exists
        """
        return protocol.lower() in self._parsers

    def list_protocols(self) -> List[str]:
        """Get list of registered protocols.

        Returns:
            List of protocol names
        """
        return list(self._parsers.keys())

    def parse(
        self,
        packet_data: bytes,
        protocol: str,
    ) -> ParseResult:
        """Parse packet data using appropriate parser.

        Automatically selects parser based on protocol name.

        Args:
            packet_data: Raw packet bytes
            protocol: Protocol name from packet info

        Returns:
            ParseResult with parsed data or error

        Example:
            >>> factory = ParserFactory()
            >>> result = factory.parse(packet_bytes, "HTTP")
            >>> if result:
            ...     data = result.data
            ...     print(f"Parsed {data.protocol}")
        """
        self._parse_count += 1

        # Find appropriate parser
        parser = self._find_parser(packet_data, protocol)

        if parser is None:
            self._error_count += 1
            return ParseResult.fail(f"No parser available for protocol: {protocol}")

        # Parse with found parser
        result = parser.parse(packet_data, protocol)

        if not result:
            self._error_count += 1

        return result

    def _find_parser(
        self,
        packet_data: bytes,
        protocol: str,
    ) -> Optional[ProtocolParser]:
        """Find appropriate parser for protocol.

        Tries exact match first, then attempts to find parser
        that can handle the data. Prefers higher-level protocols
        (HTTP, DNS) over transport protocols (TCP, UDP).

        Args:
            packet_data: Raw packet bytes
            protocol: Protocol name

        Returns:
            Parser instance or None
        """
        protocol_lower = protocol.lower()

        # Transport protocols that should only be used as fallback
        transport_protocols = {"tcp", "udp"}

        # Collect parsers that can parse this data
        candidates = []
        transport_fallbacks = []

        for parser_protocol, parser in self._parsers.items():
            try:
                if parser.can_parse(packet_data, protocol):
                    if parser_protocol in transport_protocols:
                        transport_fallbacks.append(parser)
                    else:
                        candidates.append(parser)
            except Exception:
                continue

        # Prefer application layer parsers over transport
        if candidates:
            return candidates[0]

        # Use transport parser as fallback or exact match
        if transport_fallbacks:
            return transport_fallbacks[0]

        # Try exact match as last resort
        if protocol_lower in self._parsers:
            return self._parsers[protocol_lower]

        return None

    def parse_all(
        self,
        packet_data: bytes,
        protocol: str,
    ) -> List[ParseResult]:
        """Parse packet data with all compatible parsers.

        Useful for getting multiple protocol interpretations
        of the same data.

        Args:
            packet_data: Raw packet bytes
            protocol: Protocol name hint

        Returns:
            List of ParseResults from all parsers that can handle the data
        """
        results = []

        for parser in self._parsers.values():
            try:
                if parser.can_parse(packet_data, protocol):
                    result = parser.parse(packet_data, protocol)
                    results.append(result)
            except Exception:
                continue

        return results

    def get_statistics(self) -> dict:
        """Get factory statistics.

        Returns:
            Dictionary with statistics
        """
        parser_stats = {}
        for protocol, parser in self._parsers.items():
            if hasattr(parser, "get_statistics"):
                parser_stats[protocol] = parser.get_statistics()

        success_count = self._parse_count - self._error_count
        success_rate = (
            success_count / self._parse_count if self._parse_count > 0 else 0
        )

        return {
            "parse_count": self._parse_count,
            "error_count": self._error_count,
            "success_count": success_count,
            "success_rate": success_rate,
            "registered_parsers": len(self._parsers),
            "protocols": self.list_protocols(),
            "parser_statistics": parser_stats,
        }

    def reset_statistics(self) -> None:
        """Reset factory and all parser statistics."""
        self._parse_count = 0
        self._error_count = 0

        for parser in self._parsers.values():
            if hasattr(parser, "reset_statistics"):
                parser.reset_statistics()


def create_parser_factory() -> ParserFactory:
    """Create a new parser factory with default parsers.

    Returns:
        ParserFactory instance with HTTP, DNS, TCP, UDP parsers
    """
    return ParserFactory()


# Global default factory instance
_default_factory: Optional[ParserFactory] = None


def get_default_factory() -> ParserFactory:
    """Get the global default parser factory.

    Creates the factory on first call.

    Returns:
        Default ParserFactory instance
    """
    global _default_factory
    if _default_factory is None:
        _default_factory = create_parser_factory()
    return _default_factory


def parse_packet(
    packet_data: bytes,
    protocol: str,
) -> ParseResult:
    """Parse packet using default factory.

    Convenience function that uses the global factory.

    Args:
        packet_data: Raw packet bytes
        protocol: Protocol name

    Returns:
        ParseResult with parsed data or error

    Example:
        >>> result = parse_packet(data, "HTTP")
        >>> if result:
        ...     print(f"Parsed: {result.data.protocol}")
    """
    factory = get_default_factory()
    return factory.parse(packet_data, protocol)
