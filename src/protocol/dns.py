"""
DNS protocol parser.

Parses DNS queries and responses from UDP/TCP payload data.
"""

import struct
from datetime import datetime
from typing import Optional

from src.core.logger import get_logger
from .base import (
    ProtocolParser,
    ParsedDNS,
    DNSQuestion,
    DNSResourceRecord,
    ProtocolDirection,
    ParseResult,
)
from src.utils.constants import Port

logger = get_logger(__name__)


class DNSParser(ProtocolParser):
    """DNS protocol parser.

    Parses DNS queries and responses following RFC 1035.
    Supports both UDP (standard) and TCP (zone transfers) transport.
    """

    # DNS record type mapping
    TYPE_MAP = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        255: "ANY",
    }

    # DNS class mapping
    CLASS_MAP = {
        1: "IN",
        2: "CS",
        3: "CH",
        4: "HS",
        255: "ANY",
    }

    # DNS response code mapping
    RCODE_MAP = {
        0: "NoError",
        1: "FormErr",
        2: "ServFail",
        3: "NXDomain",
        4: "NotImp",
        5: "Refused",
        6: "YXDomain",
        7: "YXRRSet",
        8: "NXRRSet",
        9: "NotAuth",
        10: "NotZone",
    }

    def __init__(self) -> None:
        """Initialize DNS parser."""
        self._parse_count = 0
        self._error_count = 0

    def can_parse(self, packet_data: bytes, protocol: str) -> bool:
        """Check if data contains DNS.

        Args:
            packet_data: Raw packet bytes
            protocol: Protocol name from packet info

        Returns:
            True if data looks like DNS
        """
        if protocol not in ("UDP", "TCP", "DNS"):
            return False

        if len(packet_data) < 12:  # DNS header is 12 bytes
            return False

        return True  # Assume DNS if protocol is DNS or using DNS port

    def parse(self, packet_data: bytes, protocol: str) -> ParseResult:
        """Parse DNS data from packet.

        Args:
            packet_data: Raw packet bytes
            protocol: Protocol name

        Returns:
            ParseResult with ParsedDNS or error
        """
        self._parse_count += 1

        try:
            # Remove DNS length prefix if using TCP
            if protocol == "TCP" and len(packet_data) > 12:
                # TCP DNS messages have a 2-byte length prefix
                if len(packet_data) >= 14:
                    dns_length = struct.unpack("!H", packet_data[:2])[0]
                    if dns_length == len(packet_data) - 2:
                        packet_data = packet_data[2:]

            # Parse header
            if len(packet_data) < 12:
                self._error_count += 1
                return ParseResult.fail("DNS packet too short")

            header = packet_data[:12]
            (
                transaction_id,
                flags,
                questions_count,
                answers_count,
                authorities_count,
                additionals_count,
            ) = struct.unpack("!HHHHHH", header)

            # Extract flag bits
            qr = (flags >> 15) & 0x1  # Query/Response
            opcode = (flags >> 11) & 0xF  # Operation code
            aa = (flags >> 10) & 0x1  # Authoritative answer
            tc = (flags >> 9) & 0x1  # Truncated
            rd = (flags >> 8) & 0x1  # Recursion desired
            ra = (flags >> 7) & 0x1  # Recursion available
            rcode = flags & 0xF  # Response code

            is_query = qr == 0
            is_response = qr == 1

            # Parse questions
            offset = 12
            questions = []
            for _ in range(questions_count):
                result = self._parse_question(packet_data, offset)
                if result is None:
                    break
                question, offset = result
                questions.append(question)

            # Parse resource records
            answers = []
            for _ in range(answers_count):
                result = self._parse_resource_record(packet_data, offset)
                if result is None:
                    break
                record, offset = result
                answers.append(record)

            authorities = []
            for _ in range(authorities_count):
                result = self._parse_resource_record(packet_data, offset)
                if result is None:
                    break
                record, offset = result
                authorities.append(record)

            additionals = []
            for _ in range(additionals_count):
                result = self._parse_resource_record(packet_data, offset)
                if result is None:
                    break
                record, offset = result
                additionals.append(record)

            # Determine direction
            direction = (
                ProtocolDirection.RESPONSE if is_response else ProtocolDirection.REQUEST
            )

            # Create parsed data
            parsed = ParsedDNS(
                protocol="DNS",
                direction=direction,
                timestamp=datetime.now(),
                raw_data=packet_data,
                transaction_id=transaction_id,
                flags=flags,
                is_query=is_query,
                is_response=is_response,
                questions=tuple(questions),
                answers=tuple(answers),
                authorities=tuple(authorities),
                additionals=tuple(additionals),
                rcode=rcode,
            )

            return ParseResult.ok(parsed)

        except Exception as e:
            self._error_count += 1
            logger.error(f"Error parsing DNS: {e}")
            return ParseResult.fail(f"Parse error: {e}")

    def _parse_question(
        self, data: bytes, offset: int
    ) -> Optional[tuple[DNSQuestion, int]]:
        """Parse DNS question.

        Args:
            data: DNS packet data
            offset: Current offset in data

        Returns:
            Tuple of (DNSQuestion, new_offset) or None
        """
        try:
            # Parse domain name
            name_result = self._parse_name(data, offset)
            if name_result is None:
                return None
            name, offset = name_result

            # Parse type and class (4 bytes)
            if len(data) < offset + 4:
                return None

            type_int, class_int = struct.unpack("!HH", data[offset : offset + 4])
            offset += 4

            type_str = self.TYPE_MAP.get(type_int, f"TYPE{type_int}")
            class_str = self.CLASS_MAP.get(class_int, f"CLASS{class_int}")

            question = DNSQuestion(name=name, type=type_str, class_=class_str)
            return (question, offset)

        except Exception:
            return None

    def _parse_resource_record(
        self, data: bytes, offset: int
    ) -> Optional[tuple[DNSResourceRecord, int]]:
        """Parse DNS resource record.

        Args:
            data: DNS packet data
            offset: Current offset in data

        Returns:
            Tuple of (DNSResourceRecord, new_offset) or None
        """
        try:
            # Parse domain name
            name_result = self._parse_name(data, offset)
            if name_result is None:
                return None
            name, offset = name_result

            # Parse type, class, ttl, and data length (10 bytes)
            if len(data) < offset + 10:
                return None

            type_int, class_int, ttl, data_len = struct.unpack(
                "!HHIH", data[offset : offset + 10]
            )
            offset += 10

            # Parse record data
            if len(data) < offset + data_len:
                return None

            record_data = self._parse_record_data(
                data[offset : offset + data_len], type_int, name
            )
            offset += data_len

            type_str = self.TYPE_MAP.get(type_int, f"TYPE{type_int}")
            class_str = self.CLASS_MAP.get(class_int, f"CLASS{class_int}")

            record = DNSResourceRecord(
                name=name,
                type=type_str,
                class_=class_str,
                ttl=ttl,
                data=record_data,
            )

            return (record, offset)

        except Exception:
            return None

    def _parse_name(self, data: bytes, offset: int) -> Optional[tuple[str, int]]:
        """Parse DNS domain name (supports compression).

        Args:
            data: DNS packet data
            offset: Current offset in data

        Returns:
            Tuple of (domain_name, new_offset) or None
        """
        try:
            labels = []
            original_offset = offset
            jumped = False

            while True:
                if offset >= len(data):
                    return None

                length_byte = data[offset]

                # Check for compression pointer (top 2 bits set)
                if (length_byte & 0xC0) == 0xC0:
                    if not jumped:
                        original_offset = offset + 2
                    jumped = True

                    # Extract pointer offset
                    pointer = ((length_byte & 0x3F) << 8) | data[offset + 1]
                    offset = pointer

                    # Continue parsing from new offset
                    continue

                # End of name
                if length_byte == 0:
                    if jumped:
                        offset = original_offset
                    else:
                        offset += 1
                    break

                # Regular label
                offset += 1
                if offset + length_byte > len(data):
                    return None

                label = data[offset : offset + length_byte].decode(
                    "ascii", errors="replace"
                )
                labels.append(label)
                offset += length_byte

            return (".".join(labels), offset)

        except Exception:
            return None

    def _parse_record_data(
        self, data: bytes, type_int: int, name: str
    ) -> str:
        """Parse resource record data based on type.

        Args:
            data: Record data bytes
            type_int: Record type integer
            name: Domain name (for some record types)

        Returns:
            String representation of record data
        """
        try:
            # A record - IPv4 address
            if type_int == 1:
                if len(data) == 4:
                    import socket

                    return socket.inet_ntoa(data)

            # AAAA record - IPv6 address
            elif type_int == 28:
                if len(data) == 16:
                    import socket

                    return socket.inet_ntop(socket.AF_INET6, data)

            # NS, CNAME, PTR records - domain names
            elif type_int in (2, 5, 12):
                result = self._parse_name(data, 0)
                if result:
                    return result[0]
                return data.hex()

            # MX record - mail exchange with preference
            elif type_int == 15:
                if len(data) >= 2:
                    preference = struct.unpack("!H", data[:2])[0]
                    result = self._parse_name(data, 2)
                    if result:
                        return f"{preference} {result[0]}"
                return data.hex()

            # TXT record - text strings
            elif type_int == 16:
                parts = []
                offset = 0
                while offset < len(data):
                    length = data[offset]
                    offset += 1
                    if offset + length > len(data):
                        break
                    text = data[offset : offset + length].decode(
                        "ascii", errors="replace"
                    )
                    parts.append(text)
                    offset += length
                return " ".join(parts)

            # SRV record - service location
            elif type_int == 33:
                if len(data) >= 6:
                    priority, weight, port = struct.unpack("!HHH", data[:6])
                    result = self._parse_name(data, 6)
                    if result:
                        return f"{priority} {weight} {port} {result[0]}"
                return data.hex()

            # Default to hex representation
            return data.hex()

        except Exception:
            return data.hex()

    def get_rcode_text(self, rcode: int) -> str:
        """Get text description of response code.

        Args:
            rcode: Response code integer

        Returns:
            Text description
        """
        return self.RCODE_MAP.get(rcode, f"RCODE{rcode}")

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


class DNSUtils:
    """Utility functions for DNS analysis."""

    @staticmethod
    def is_query(parsed: ParsedDNS) -> bool:
        """Check if parsed DNS is a query.

        Args:
            parsed: Parsed DNS data

        Returns:
            True if this is a query
        """
        return parsed.is_query

    @staticmethod
    def is_response(parsed: ParsedDNS) -> bool:
        """Check if parsed DNS is a response.

        Args:
            parsed: Parsed DNS data

        Returns:
            True if this is a response
        """
        return parsed.is_response

    @staticmethod
    def has_answer(parsed: ParsedDNS) -> bool:
        """Check if DNS response has answers.

        Args:
            parsed: Parsed DNS data

        Returns:
            True if response has answers
        """
        return len(parsed.answers) > 0

    @staticmethod
    def is_nxdomain(parsed: ParsedDNS) -> bool:
        """Check if DNS response indicates domain not found.

        Args:
            parsed: Parsed DNS data

        Returns:
            True if RCODE is NXDomain (3)
        """
        return parsed.rcode == 3

    @staticmethod
    def is_servfail(parsed: ParsedDNS) -> bool:
        """Check if DNS response indicates server failure.

        Args:
            parsed: Parsed DNS data

        Returns:
            True if RCODE is ServFail (2)
        """
        return parsed.rcode == 2

    @staticmethod
    def get_a_records(parsed: ParsedDNS) -> list[str]:
        """Get all A (IPv4) records from DNS response.

        Args:
            parsed: Parsed DNS data

        Returns:
            List of IPv4 addresses
        """
        return [r.data for r in parsed.answers if r.type == "A"]

    @staticmethod
    def get_aaaa_records(parsed: ParsedDNS) -> list[str]:
        """Get all AAAA (IPv6) records from DNS response.

        Args:
            parsed: Parsed DNS data

        Returns:
            List of IPv6 addresses
        """
        return [r.data for r in parsed.answers if r.type == "AAAA"]

    @staticmethod
    def get_cname_records(parsed: ParsedDNS) -> list[str]:
        """Get all CNAME records from DNS response.

        Args:
            parsed: Parsed DNS data

        Returns:
            List of CNAME values
        """
        return [r.data for r in parsed.answers if r.type == "CNAME"]

    @staticmethod
    def is_recursive_desired(parsed: ParsedDNS) -> bool:
        """Check if RD (recursion desired) flag is set.

        Args:
            parsed: Parsed DNS data

        Returns:
            True if recursion was requested
        """
        return (parsed.flags >> 8) & 0x1 == 1

    @staticmethod
    def is_recursive_available(parsed: ParsedDNS) -> bool:
        """Check if RA (recursion available) flag is set.

        Args:
            parsed: Parsed DNS data

        Returns:
            True if server supports recursion
        """
        return (parsed.flags >> 7) & 0x1 == 1


def create_dns_parser() -> DNSParser:
    """Create DNS parser instance.

    Returns:
        New DNSParser instance
    """
    return DNSParser()
