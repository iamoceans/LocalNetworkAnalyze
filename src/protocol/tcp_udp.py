"""
TCP and UDP protocol parsers.

Parses TCP segment headers and UDP datagram headers.
"""

import struct
from datetime import datetime
from typing import Optional

from src.core.logger import get_logger
from .base import (
    ProtocolParser,
    ParsedTCP,
    ParsedUDP,
    ParseResult,
)

logger = get_logger(__name__)


class TCPParser(ProtocolParser):
    """TCP protocol parser.

    Parses TCP segment headers including flags, sequence numbers,
    and options.
    """

    # TCP header minimum size
    MIN_HEADER_SIZE = 20

    # TCP flag constants
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    def __init__(self) -> None:
        """Initialize TCP parser."""
        self._parse_count = 0
        self._error_count = 0

    def can_parse(self, packet_data: bytes, protocol: str) -> bool:
        """Check if data contains TCP.

        Args:
            packet_data: Raw packet bytes
            protocol: Protocol name from packet info

        Returns:
            True if protocol is TCP
        """
        return protocol == "TCP"

    def parse(self, packet_data: bytes, protocol: str) -> ParseResult:
        """Parse TCP segment data.

        Args:
            packet_data: Raw packet bytes (should include TCP header)
            protocol: Protocol name (should be TCP)

        Returns:
            ParseResult with ParsedTCP or error
        """
        self._parse_count += 1

        try:
            # TCP header is minimum 20 bytes
            if len(packet_data) < self.MIN_HEADER_SIZE:
                self._error_count += 1
                return ParseResult.fail("TCP packet too short")

            # Parse fixed header (20 bytes)
            # src_port (2) + dst_port (2) + seq (4) + ack (4) +
            # data_offset (1) + flags (1) + window (2) + checksum (2) + urgent (2)
            (
                src_port,
                dst_port,
                seq_number,
                ack_number,
                data_offset,
                flags,
                window_size,
                checksum,
                urgent_pointer,
            ) = struct.unpack("!HHIIBBHHH", packet_data[:20])

            # Extract data offset (number of 32-bit words)
            header_size = ((data_offset >> 4) & 0x0F) * 4

            # Parse options if present
            options = b""
            if header_size > 20:
                if len(packet_data) >= header_size:
                    options = packet_data[20:header_size]

            # Create parsed data
            parsed = ParsedTCP(
                protocol="TCP",
                direction=self._determine_direction(src_port, dst_port),
                timestamp=datetime.now(),
                raw_data=packet_data,
                seq_number=seq_number,
                ack_number=ack_number,
                flags=flags,
                window_size=window_size,
                urgent_pointer=urgent_pointer,
                options=options,
            )

            return ParseResult.ok(parsed)

        except Exception as e:
            self._error_count += 1
            logger.error(f"Error parsing TCP: {e}")
            return ParseResult.fail(f"Parse error: {e}")

    def _determine_direction(self, src_port: int, dst_port: int) -> str:
        """Determine traffic direction from ports.

        Args:
            src_port: Source port
            dst_port: Destination port

        Returns:
            Direction string
        """
        # This is a simplified determination
        # Real direction determination requires connection state tracking
        return "unknown"

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


class UDPParser(ProtocolParser):
    """UDP protocol parser.

    Parses UDP datagram headers including length and checksum.
    """

    # UDP header size
    HEADER_SIZE = 8

    def __init__(self) -> None:
        """Initialize UDP parser."""
        self._parse_count = 0
        self._error_count = 0

    def can_parse(self, packet_data: bytes, protocol: str) -> bool:
        """Check if data contains UDP.

        Args:
            packet_data: Raw packet bytes
            protocol: Protocol name from packet info

        Returns:
            True if protocol is UDP
        """
        return protocol == "UDP"

    def parse(self, packet_data: bytes, protocol: str) -> ParseResult:
        """Parse UDP datagram data.

        Args:
            packet_data: Raw packet bytes (should include UDP header)
            protocol: Protocol name (should be UDP)

        Returns:
            ParseResult with ParsedUDP or error
        """
        self._parse_count += 1

        try:
            # UDP header is 8 bytes
            if len(packet_data) < self.HEADER_SIZE:
                self._error_count += 1
                return ParseResult.fail("UDP packet too short")

            # Parse header: src_port (2) + dst_port (2) + length (2) + checksum (2)
            src_port, dst_port, length, checksum = struct.unpack(
                "!HHHH", packet_data[:8]
            )

            # Create parsed data
            parsed = ParsedUDP(
                protocol="UDP",
                direction=self._determine_direction(src_port, dst_port),
                timestamp=datetime.now(),
                raw_data=packet_data,
                length=length,
                checksum=checksum,
            )

            return ParseResult.ok(parsed)

        except Exception as e:
            self._error_count += 1
            logger.error(f"Error parsing UDP: {e}")
            return ParseResult.fail(f"Parse error: {e}")

    def _determine_direction(self, src_port: int, dst_port: int) -> str:
        """Determine traffic direction from ports.

        Args:
            src_port: Source port
            dst_port: Destination port

        Returns:
            Direction string
        """
        return "unknown"

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


class TCPUtils:
    """Utility functions for TCP analysis."""

    @staticmethod
    def is_syn_packet(flags: int) -> bool:
        """Check if packet has SYN flag set.

        Args:
            flags: TCP flags byte

        Returns:
            True if SYN is set
        """
        return (flags & TCPParser.SYN) != 0

    @staticmethod
    def is_ack_packet(flags: int) -> bool:
        """Check if packet has ACK flag set.

        Args:
            flags: TCP flags byte

        Returns:
            True if ACK is set
        """
        return (flags & TCPParser.ACK) != 0

    @staticmethod
    def is_fin_packet(flags: int) -> bool:
        """Check if packet has FIN flag set.

        Args:
            flags: TCP flags byte

        Returns:
            True if FIN is set
        """
        return (flags & TCPParser.FIN) != 0

    @staticmethod
    def is_rst_packet(flags: int) -> bool:
        """Check if packet has RST flag set.

        Args:
            flags: TCP flags byte

        Returns:
            True if RST is set
        """
        return (flags & TCPParser.RST) != 0

    @staticmethod
    def is_syn_ack(flags: int) -> bool:
        """Check if packet has SYN and ACK flags set.

        Args:
            flags: TCP flags byte

        Returns:
            True if SYN and ACK are set
        """
        return TCPUtils.is_syn_packet(flags) and TCPUtils.is_ack_packet(flags)

    @staticmethod
    def is_fin_ack(flags: int) -> bool:
        """Check if packet has FIN and ACK flags set.

        Args:
            flags: TCP flags byte

        Returns:
            True if FIN and ACK are set
        """
        return TCPUtils.is_fin_packet(flags) and TCPUtils.is_ack_packet(flags)

    @staticmethod
    def get_packet_type(flags: int) -> str:
        """Get human-readable packet type from flags.

        Args:
            flags: TCP flags byte

        Returns:
            Packet type description
        """
        if TCPUtils.is_syn_ack(flags):
            return "SYN-ACK"
        elif TCPUtils.is_fin_ack(flags):
            return "FIN-ACK"
        elif TCPUtils.is_syn_packet(flags):
            return "SYN"
        elif TCPUtils.is_fin_packet(flags):
            return "FIN"
        elif TCPUtils.is_rst_packet(flags):
            return "RST"
        elif TCPUtils.is_ack_packet(flags):
            return "ACK"
        else:
            return "DATA"

    @staticmethod
    def get_flags_string(flags: int) -> str:
        """Get string representation of TCP flags.

        Args:
            flags: TCP flags byte

        Returns:
            String representation (e.g., "SYN,ACK")
        """
        flag_names = []
        if flags & TCPParser.FIN:
            flag_names.append("FIN")
        if flags & TCPParser.SYN:
            flag_names.append("SYN")
        if flags & TCPParser.RST:
            flag_names.append("RST")
        if flags & TCPParser.PSH:
            flag_names.append("PSH")
        if flags & TCPParser.ACK:
            flag_names.append("ACK")
        if flags & TCPParser.URG:
            flag_names.append("URG")
        if flags & TCPParser.ECE:
            flag_names.append("ECE")
        if flags & TCPParser.CWR:
            flag_names.append("CWR")

        return ",".join(flag_names) if flag_names else "NONE"


class UDPUtils:
    """Utility functions for UDP analysis."""

    @staticmethod
    def get_payload_length(total_length: int) -> int:
        """Get UDP payload length.

        Args:
            total_length: Total UDP length (header + data)

        Returns:
            Payload data length
        """
        payload_length = total_length - 8  # Subtract 8-byte header
        return max(0, payload_length)

    @staticmethod
    def is_dns(src_port: int, dst_port: int) -> bool:
        """Check if UDP traffic is DNS.

        Args:
            src_port: Source port
            dst_port: Destination port

        Returns:
            True if using DNS port (53)
        """
        return src_port == 53 or dst_port == 53

    @staticmethod
    def is_dhcp(src_port: int, dst_port: int) -> bool:
        """Check if UDP traffic is DHCP.

        Args:
            src_port: Source port
            dst_port: Destination port

        Returns:
            True if using DHCP ports (67/68)
        """
        return (src_port in (67, 68)) or (dst_port in (67, 68))

    @staticmethod
    def get_service_name(port: int) -> Optional[str]:
        """Get service name for well-known UDP port.

        Args:
            port: UDP port number

        Returns:
            Service name or None
        """
        from src.utils.constants import Port

        service_map = {
            Port.DNS: "DNS",
            Port.DHCP_SERVER: "DHCP",
            Port.DHCP_CLIENT: "DHCP",
        }

        return service_map.get(port)


def create_tcp_parser() -> TCPParser:
    """Create TCP parser instance.

    Returns:
        New TCPParser instance
    """
    return TCPParser()


def create_udp_parser() -> UDPParser:
    """Create UDP parser instance.

    Returns:
        New UDPParser instance
    """
    return UDPParser()
