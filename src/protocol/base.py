"""
Base classes for protocol parsing.

Defines the abstract interface for protocol parsers and
common data structures for parsed protocol information.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Any, Protocol
from collections.abc import MutableMapping


class ProtocolDirection(Enum):
    """Direction of protocol traffic.

    Attributes:
        REQUEST: Client to server (request)
        RESPONSE: Server to client (response)
        UNKNOWN: Direction cannot be determined
    """
    REQUEST = "request"
    RESPONSE = "response"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ParsedHeader:
    """A single parsed protocol header.

    Attributes:
        name: Header name
        value: Header value
    """
    name: str
    value: str


@dataclass(frozen=True)
class ParsedData:
    """Base class for parsed protocol data.

    Attributes:
        protocol: Protocol name (HTTP, DNS, etc.)
        direction: Traffic direction (request/response)
        timestamp: When the data was parsed
        raw_data: Original raw bytes
    """
    protocol: str
    direction: ProtocolDirection
    timestamp: datetime
    raw_data: bytes

    def to_dict(self) -> dict[str, Any]:
        """Convert parsed data to dictionary.

        Returns:
            Dictionary representation of parsed data
        """
        return {
            "protocol": self.protocol,
            "direction": self.direction.value,
            "timestamp": self.timestamp.isoformat(),
            "raw_size": len(self.raw_data),
        }


@dataclass(frozen=True)
class ParsedHTTP(ParsedData):
    """Parsed HTTP data.

    Attributes:
        method: HTTP method (GET, POST, etc.) for requests
        path: Request path for requests
        version: HTTP version
        status_code: HTTP status code for responses
        reason: Reason phrase for responses
        headers: Dictionary of headers
        body: HTTP body bytes
    """
    method: Optional[str] = None
    path: Optional[str] = None
    version: Optional[str] = None
    status_code: Optional[int] = None
    reason: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    def __post_init__(self) -> None:
        """Validate HTTP data."""
        # Request should have method and path
        if self.direction == ProtocolDirection.REQUEST:
            if not self.method:
                raise ValueError("HTTP request must have method")
            if not self.path:
                raise ValueError("HTTP request must have path")
        # Response should have status code
        elif self.direction == ProtocolDirection.RESPONSE:
            if self.status_code is None:
                raise ValueError("HTTP response must have status code")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        data = super().to_dict()
        data.update({
            "method": self.method,
            "path": self.path,
            "version": self.version,
            "status_code": self.status_code,
            "reason": self.reason,
            "headers": dict(self.headers),
            "body_size": len(self.body),
        })
        return data

    def is_request(self) -> bool:
        """Check if this is an HTTP request.

        Returns:
            True if this is a request
        """
        return self.direction == ProtocolDirection.REQUEST

    def is_response(self) -> bool:
        """Check if this is an HTTP response.

        Returns:
            True if this is a response
        """
        return self.direction == ProtocolDirection.RESPONSE

    def is_successful(self) -> Optional[bool]:
        """Check if HTTP response indicates success.

        Returns:
            True if successful status code, False if error, None if request
        """
        if self.status_code is None:
            return None
        return 200 <= self.status_code < 400

    def get_header(self, name: str) -> Optional[str]:
        """Get a header value by name (case-insensitive).

        Args:
            name: Header name

        Returns:
            Header value or None if not found
        """
        name_lower = name.lower()
        for header_name, header_value in self.headers.items():
            if header_name.lower() == name_lower:
                return header_value
        return None


@dataclass(frozen=True)
class DNSQuestion:
    """A DNS question record.

    Attributes:
        name: Domain name being queried
        type: DNS query type (A, AAAA, MX, etc.)
        class: DNS query class (usually IN)
    """
    name: str
    type: str
    class_: str = "IN"


@dataclass(frozen=True)
class DNSResourceRecord:
    """A DNS resource record.

    Attributes:
        name: Domain name
        type: Record type (A, AAAA, CNAME, etc.)
        class_: DNS class (usually IN)
        ttl: Time to live in seconds
        data: Record data (IP address, domain, etc.)
    """
    name: str
    type: str
    class_: str
    ttl: int
    data: str


@dataclass(frozen=True)
class ParsedDNS(ParsedData):
    """Parsed DNS data.

    Attributes:
        transaction_id: DNS transaction ID
        flags: DNS flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
        is_query: True if this is a query
        is_response: True if this is a response
        questions: List of questions
        answers: List of answer records
        authorities: List of authority records
        additionals: List of additional records
        rcode: Response code (0 = NoError)
    """
    transaction_id: int
    flags: int
    is_query: bool
    is_response: bool
    questions: tuple[DNSQuestion, ...] = field(default_factory=tuple)
    answers: tuple[DNSResourceRecord, ...] = field(default_factory=tuple)
    authorities: tuple[DNSResourceRecord, ...] = field(default_factory=tuple)
    additionals: tuple[DNSResourceRecord, ...] = field(default_factory=tuple)
    rcode: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        data = super().to_dict()
        data.update({
            "transaction_id": self.transaction_id,
            "flags": self.flags,
            "is_query": self.is_query,
            "is_response": self.is_response,
            "questions_count": len(self.questions),
            "answers_count": len(self.answers),
            "rcode": self.rcode,
        })
        return data

    def get_domain(self) -> Optional[str]:
        """Get the first domain name from questions.

        Returns:
            Domain name or None if no questions
        """
        if self.questions:
            return self.questions[0].name
        return None

    def has_error(self) -> bool:
        """Check if DNS response indicates an error.

        Returns:
            True if response has error (rcode != 0)
        """
        return self.is_response and self.rcode != 0


@dataclass(frozen=True)
class ParsedTCP(ParsedData):
    """Parsed TCP segment data.

    Attributes:
        seq_number: Sequence number
        ack_number: Acknowledgment number
        flags: TCP flags (SYN, ACK, FIN, RST, etc.)
        window_size: Window size
        urgent_pointer: Urgent pointer
        options: TCP options
    """
    seq_number: int
    ack_number: int
    flags: int
    window_size: int
    urgent_pointer: int = 0
    options: bytes = b""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        data = super().to_dict()
        data.update({
            "seq_number": self.seq_number,
            "ack_number": self.ack_number,
            "flags": self.flags,
            "window_size": self.window_size,
            "urgent_pointer": self.urgent_pointer,
        })
        return data

    def has_flag(self, flag: int) -> bool:
        """Check if TCP flag is set.

        Args:
            flag: Flag value to check (use TCPFlag constants)

        Returns:
            True if flag is set
        """
        return (self.flags & flag) != 0

    def is_syn(self) -> bool:
        """Check if SYN flag is set.

        Returns:
            True if SYN is set
        """
        return self.has_flag(0x02)

    def is_ack(self) -> bool:
        """Check if ACK flag is set.

        Returns:
            True if ACK is set
        """
        return self.has_flag(0x10)

    def is_fin(self) -> bool:
        """Check if FIN flag is set.

        Returns:
            True if FIN is set
        """
        return self.has_flag(0x01)

    def is_rst(self) -> bool:
        """Check if RST flag is set.

        Returns:
            True if RST is set
        """
        return self.has_flag(0x04)

    def is_syn_ack(self) -> bool:
        """Check if both SYN and ACK flags are set.

        Returns:
            True if SYN-ACK
        """
        return self.is_syn() and self.is_ack()


@dataclass(frozen=True)
class ParsedUDP(ParsedData):
    """Parsed UDP datagram data.

    Attributes:
        length: UDP length (header + data)
        checksum: UDP checksum
    """
    length: int
    checksum: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        data = super().to_dict()
        data.update({
            "length": self.length,
            "checksum": self.checksum,
        })
        return data


class ProtocolParser(ABC):
    """Abstract base class for protocol parsers.

    All protocol parsers must inherit from this class and implement
    the can_parse and parse methods.
    """

    @abstractmethod
    def can_parse(self, packet_data: bytes, protocol: str) -> bool:
        """Check if this parser can handle the given data.

        Args:
            packet_data: Raw packet bytes
            protocol: Protocol name from packet info

        Returns:
            True if this parser can parse the data
        """
        pass

    @abstractmethod
    def parse(self, packet_data: bytes, protocol: str) -> Optional[ParsedData]:
        """Parse protocol data from packet bytes.

        Args:
            packet_data: Raw packet bytes
            protocol: Protocol name from packet info

        Returns:
            Parsed data object or None if parsing fails
        """
        pass

    def get_protocol_name(self) -> str:
        """Get the name of the protocol this parser handles.

        Returns:
            Protocol name
        """
        return self.__class__.__name__.replace("Parser", "")


class ParseResult:
    """Result of a parsing operation.

    Contains either successfully parsed data or error information.
    """

    def __init__(
        self,
        success: bool,
        data: Optional[ParsedData] = None,
        error: Optional[str] = None,
    ) -> None:
        """Initialize parse result.

        Args:
            success: Whether parsing succeeded
            data: Parsed data (if successful)
            error: Error message (if failed)
        """
        self.success = success
        self.data = data
        self.error = error

    @classmethod
    def ok(cls, data: ParsedData) -> "ParseResult":
        """Create successful result.

        Args:
            data: Parsed data

        Returns:
            Successful ParseResult
        """
        return cls(success=True, data=data)

    @classmethod
    def fail(cls, error: str) -> "ParseResult":
        """Create failed result.

        Args:
            error: Error message

        Returns:
            Failed ParseResult
        """
        return cls(success=False, error=error)

    def __bool__(self) -> bool:
        """Check if result is successful."""
        return self.success

    def __repr__(self) -> str:
        """String representation."""
        if self.success:
            return f"ParseResult.ok({self.data.protocol})"
        return f"ParseResult.fail({self.error})"


def get_direction_from_ports(src_port: int, dst_port: int) -> ProtocolDirection:
    """Determine traffic direction based on ports.

    Uses well-known ports to determine client vs server direction.

    Args:
        src_port: Source port
        dst_port: Destination port

    Returns:
        ProtocolDirection
    """
    # Well-known ports (0-1023) are typically server ports
    # If dst_port is well-known, this is likely a request
    # If src_port is well-known, this is likely a response

    from src.utils.constants import Port

    # Check for well-known ports
    if dst_port in (
        Port.HTTP,
        Port.HTTPS,
        Port.DNS,
        Port.SMTP,
        Port.POP3,
        Port.IMAP,
        Port.SSH,
        Port.FTP,
        Port.TELNET,
    ):
        return ProtocolDirection.REQUEST
    elif src_port in (
        Port.HTTP,
        Port.HTTPS,
        Port.DNS,
        Port.SMTP,
        Port.POP3,
        Port.IMAP,
        Port.SSH,
        Port.FTP,
        Port.TELNET,
    ):
        return ProtocolDirection.RESPONSE

    # For ephemeral ports (1024+), make an educated guess
    if dst_port < 1024:
        return ProtocolDirection.REQUEST
    elif src_port < 1024:
        return ProtocolDirection.RESPONSE

    return ProtocolDirection.UNKNOWN


def is_text_content(content_type: Optional[str]) -> bool:
    """Check if content type indicates text content.

    Args:
        content_type: Content-Type header value

    Returns:
        True if content type is text-based
    """
    if not content_type:
        return False

    content_type_lower = content_type.lower()

    text_types = (
        "text/",
        "application/json",
        "application/xml",
        "application/javascript",
        "application/x-www-form-urlencoded",
    )

    return any(content_type_lower.startswith(t) for t in text_types)
