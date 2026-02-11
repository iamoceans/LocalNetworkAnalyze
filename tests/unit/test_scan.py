"""
Unit tests for network scanning module.
"""

import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch

from src.scan.base import (
    ScanResult,
    ScanReport,
    ScanType,
    ScanState,
    validate_targets,
    parse_ip_range,
    is_valid_ip,
    is_valid_cidr,
    get_local_network,
)
from src.scan import (
    ARPScanner,
    ICMPScanner,
    PortScanner,
    create_scanner,
    create_arp_scanner,
    create_icmp_scanner,
    create_port_scanner,
    quick_scan,
    scan_hosts,
    NetworkScannerWrapper,
    create_network_scanner,
)


@pytest.mark.unit
class TestScanType:
    """Test ScanType enum."""

    def test_scan_type_values(self):
        """Test scan type enum values."""
        assert ScanType.ARP.value == "arp"
        assert ScanType.ICMP.value == "icmp"
        assert ScanType.TCP_SYN.value == "tcp_syn"
        assert ScanType.TCP_CONNECT.value == "tcp_connect"
        assert ScanType.UDP.value == "udp"


@pytest.mark.unit
class TestScanState:
    """Test ScanState enum."""

    def test_state_values(self):
        """Test state enum values."""
        assert ScanState.IDLE.value == "idle"
        assert ScanState.SCANNING.value == "scanning"
        assert ScanState.COMPLETED.value == "completed"


@pytest.mark.unit
class TestScanResult:
    """Test ScanResult data class."""

    def test_create_basic_result(self):
        """Test creating a basic scan result."""
        result = ScanResult(
            ip="192.168.1.1",
            is_alive=True,
            response_time=10.5,
        )

        assert result.ip == "192.168.1.1"
        assert result.is_alive
        assert result.response_time == 10.5

    def test_create_with_mac(self):
        """Test creating result with MAC address."""
        result = ScanResult(
            ip="192.168.1.1",
            mac="00:11:22:33:44:55",
            is_alive=True,
        )

        assert result.mac == "00:11:22:33:44:55"

    def test_invalid_ip_raises_error(self):
        """Test that invalid IP raises ValueError."""
        with pytest.raises(ValueError, match="Invalid IP address"):
            ScanResult(
                ip="invalid-ip",
                is_alive=False,
            )

    def test_negative_response_time_raises_error(self):
        """Test that negative response time raises error."""
        with pytest.raises(ValueError, match="Response time cannot be negative"):
            ScanResult(
                ip="192.168.1.1",
                is_alive=False,
                response_time=-1.0,
            )

    def test_to_dict(self):
        """Test converting to dictionary."""
        result = ScanResult(
            ip="192.168.1.1",
            mac="00:11:22:33:44:55",
            is_alive=True,
            response_time=10.5,
            open_ports=frozenset({80, 443}),
        )

        data = result.to_dict()

        assert data["ip"] == "192.168.1.1"
        assert data["mac"] == "00:11:22:33:44:55"
        assert data["is_alive"] is True
        assert data["response_time"] == 10.5
        assert sorted(data["open_ports"]) == [80, 443]

    def test_with_hostname(self):
        """Test creating result with new hostname."""
        original = ScanResult(
            ip="192.168.1.1",
            is_alive=True,
        )

        updated = original.with_hostname("test-host")

        assert updated.hostname == "test-host"
        assert updated.ip == original.ip

    def test_with_open_ports(self):
        """Test creating result with new open ports."""
        original = ScanResult(
            ip="192.168.1.1",
            is_alive=True,
        )

        updated = original.with_open_ports([22, 80, 443])

        assert updated.open_ports == frozenset({22, 80, 443})

    def test_frozen_dataclass(self):
        """Test that ScanResult is frozen (immutable)."""
        result = ScanResult(
            ip="192.168.1.1",
            is_alive=True,
        )

        # Attempting to modify should raise an error
        with pytest.raises(Exception):
            result.is_alive = False


@pytest.mark.unit
class TestScanReport:
    """Test ScanReport data class."""

    def test_create_report(self):
        """Test creating a scan report."""
        results = [
            ScanResult(ip="192.168.1.1", is_alive=True),
            ScanResult(ip="192.168.1.2", is_alive=False),
        ]

        report = ScanReport(
            scan_type=ScanType.ARP,
            start_time=datetime.now(),
            end_time=datetime.now(),
            targets=["192.168.1.0/24"],
            results=results,
            alive_count=1,
        )

        assert report.scan_type == ScanType.ARP
        assert report.alive_count == 1
        assert len(report.results) == 2

    def test_get_alive_hosts(self):
        """Test getting only alive hosts."""
        results = [
            ScanResult(ip="192.168.1.1", is_alive=True),
            ScanResult(ip="192.168.1.2", is_alive=False),
            ScanResult(ip="192.168.1.3", is_alive=True),
        ]

        report = ScanReport(
            scan_type=ScanType.ARP,
            start_time=datetime.now(),
            end_time=datetime.now(),
            targets=["192.168.1.0/24"],
            results=results,
            alive_count=2,
        )

        alive = report.get_alive_hosts()

        assert len(alive) == 2
        assert all(r.is_alive for r in alive)

    def test_get_host_by_ip(self):
        """Test getting host by IP address."""
        results = [
            ScanResult(ip="192.168.1.1", is_alive=True),
            ScanResult(ip="192.168.1.2", is_alive=False),
        ]

        report = ScanReport(
            scan_type=ScanType.ARP,
            start_time=datetime.now(),
            end_time=datetime.now(),
            targets=["192.168.1.0/24"],
            results=results,
        )

        result = report.get_host_by_ip("192.168.1.1")
        assert result is not None
        assert result.ip == "192.168.1.1"

    def test_completion_rate(self):
        """Test completion rate calculation."""
        report = ScanReport(
            scan_type=ScanType.ARP,
            start_time=datetime.now(),
            end_time=datetime.now(),
            targets=["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"],
            results=[
                ScanResult(ip="192.168.1.1", is_alive=True),
                ScanResult(ip="192.168.1.2", is_alive=False),
            ],
        )

        # 2 results out of 4 targets = 50%
        assert report.completion_rate == 50.0


@pytest.mark.unit
class TestValidateTargets:
    """Test target validation."""

    def test_single_ip(self):
        """Test validating single IP."""
        targets = validate_targets(["192.168.1.1"])
        assert targets == ["192.168.1.1"]

    def test_cidr_range(self):
        """Test validating CIDR range."""
        targets = validate_targets(["192.168.1.0/30"])
        # Should expand to 192.168.1.1, 192.168.1.2
        assert len(targets) == 2
        assert "192.168.1.1" in targets
        assert "192.168.1.2" in targets

    def test_multiple_targets(self):
        """Test validating multiple targets."""
        targets = validate_targets([
            "192.168.1.1",
            "192.168.1.2",
            "192.168.2.0/31",
        ])

        assert len(targets) == 4  # 2 singles + 2 from /31
        assert "192.168.1.1" in targets
        assert "192.168.1.2" in targets


@pytest.mark.unit
class TestParseIPRange:
    """Test IP range parsing."""

    def test_parse_range(self):
        """Test parsing IP range."""
        ips = parse_ip_range("192.168.1.1", "192.168.1.3")

        assert len(ips) == 3
        assert ips[0] == "192.168.1.1"
        assert ips[1] == "192.168.1.2"
        assert ips[2] == "192.168.1.3"

    def test_invalid_range_raises_error(self):
        """Test that invalid range raises error."""
        # Start > End
        with pytest.raises(Exception):  # InvalidRangeError
            parse_ip_range("192.168.1.5", "192.168.1.1")


@pytest.mark.unit
class TestIsValidIP:
    """Test IP validation."""

    def test_valid_ipv4(self):
        """Test valid IPv4 addresses."""
        assert is_valid_ip("192.168.1.1")
        assert is_valid_ip("8.8.8.8")
        assert is_valid_ip("255.255.255.255")

    def test_invalid_ip(self):
        """Test invalid IP addresses."""
        assert not is_valid_ip("256.1.1.1")
        assert not is_valid_ip("invalid")
        assert not is_valid_ip("")


@pytest.mark.unit
class TestIsValidCIDR:
    """Test CIDR validation."""

    def test_valid_cidr(self):
        """Test valid CIDR notation."""
        assert is_valid_cidr("192.168.1.0/24")
        assert is_valid_cidr("10.0.0.0/8")
        assert is_valid_cidr("0.0.0.0/0")

    def test_invalid_cidr(self):
        """Test invalid CIDR notation."""
        assert not is_valid_cidr("192.168.1.0/33")
        assert not is_valid_cidr("invalid/24")


@pytest.mark.unit
class TestARPScanner:
    """Test ARP scanner."""

    def test_init_default(self):
        """Test initialization with defaults."""
        scanner = ARPScanner(targets=["192.168.1.1"])

        assert scanner.get_scan_type() == ScanType.ARP
        assert scanner.state == ScanState.IDLE

    def test_init_with_params(self):
        """Test initialization with parameters."""
        scanner = ARPScanner(
            targets=["192.168.1.0/24"],
            timeout=2.0,
            threads=20,
            interface="eth0",
        )

        assert scanner._timeout == 2.0
        assert scanner._threads == 20
        assert scanner._interface == "eth0"


@pytest.mark.unit
class TestICMPScanner:
    """Test ICMP scanner."""

    def test_init(self):
        """Test initialization."""
        scanner = ICMPScanner(targets=["192.168.1.1"])

        assert scanner.get_scan_type() == ScanType.ICMP
        assert scanner.state == ScanState.IDLE


@pytest.mark.unit
class TestPortScanner:
    """Test Port scanner."""

    def test_init_default_ports(self):
        """Test initialization with default ports."""
        scanner = PortScanner(targets=["192.168.1.1"])

        assert scanner._ports
        assert len(scanner._ports) > 0
        assert 80 in scanner._ports
        assert 443 in scanner._ports

    def test_init_custom_ports(self):
        """Test initialization with custom ports."""
        scanner = PortScanner(
            targets=["192.168.1.1"],
            ports=[22, 80, 8080],
        )

        assert scanner._ports == [22, 80, 8080]

    def test_scan_type_tcp_syn(self):
        """Test TCP SYN scan type."""
        scanner = PortScanner(
            targets=["192.168.1.1"],
            scan_type=ScanType.TCP_SYN,
        )

        assert scanner.get_scan_type() == ScanType.TCP_SYN

    def test_scan_type_tcp_connect(self):
        """Test TCP connect scan type."""
        scanner = PortScanner(
            targets=["192.168.1.1"],
            scan_type=ScanType.TCP_CONNECT,
        )

        assert scanner.get_scan_type() == ScanType.TCP_CONNECT


@pytest.mark.unit
class TestCreateScanner:
    """Test scanner factory function."""

    def test_create_arp_scanner(self):
        """Test creating ARP scanner."""
        scanner = create_scanner(
            ScanType.ARP,
            targets=["192.168.1.0/24"],
        )

        assert isinstance(scanner, ARPScanner)

    def test_create_icmp_scanner(self):
        """Test creating ICMP scanner."""
        scanner = create_scanner(
            ScanType.ICMP,
            targets=["192.168.1.0/24"],
        )

        assert isinstance(scanner, ICMPScanner)

    def test_create_port_scanner(self):
        """Test creating port scanner."""
        scanner = create_scanner(
            ScanType.TCP_SYN,
            targets=["192.168.1.1"],
        )

        assert isinstance(scanner, PortScanner)

    def test_invalid_scan_type_raises_error(self):
        """Test that invalid scan type raises error."""
        with pytest.raises(ValueError, match="Unsupported scan type"):
            create_scanner("invalid", ["192.168.1.1"])


@pytest.mark.unit
class TestFactoryFunctions:
    """Test factory functions."""

    def test_create_arp_scanner_factory(self):
        """Test ARP scanner factory function."""
        scanner = create_arp_scanner(["192.168.1.1"])

        assert isinstance(scanner, ARPScanner)
        assert scanner.get_scan_type() == ScanType.ARP

    def test_create_icmp_scanner_factory(self):
        """Test ICMP scanner factory function."""
        scanner = create_icmp_scanner(["192.168.1.1"])

        assert isinstance(scanner, ICMPScanner)
        assert scanner.get_scan_type() == ScanType.ICMP

    def test_create_port_scanner_factory(self):
        """Test port scanner factory function."""
        scanner = create_port_scanner(["192.168.1.1"])

        assert isinstance(scanner, PortScanner)
        assert scanner.get_scan_type() == ScanType.TCP_SYN


@pytest.mark.unit
class TestCreateScanner:
    """Test create_scanner function."""

    @patch('src.scan.create_arp_scanner')
    def test_create_scanner_arp(self, mock_create_arp):
        """Test creating ARP scanner."""
        mock_scanner = MagicMock()
        mock_create_arp.return_value = mock_scanner

        scanner = create_scanner(ScanType.ARP, ["192.168.1.0/24"])

        mock_create_arp.assert_called_once()
        assert scanner is not None

    @patch('src.scan.create_icmp_scanner')
    def test_create_scanner_icmp(self, mock_create_icmp):
        """Test creating ICMP scanner."""
        mock_scanner = MagicMock()
        mock_create_icmp.return_value = mock_scanner

        scanner = create_scanner(ScanType.ICMP, ["192.168.1.1"])

        mock_create_icmp.assert_called_once()
        assert scanner is not None

    @patch('src.scan.create_port_scanner')
    def test_create_scanner_tcp_syn(self, mock_create_port):
        """Test creating TCP SYN scanner."""
        mock_scanner = MagicMock()
        mock_create_port.return_value = mock_scanner

        scanner = create_scanner(
            ScanType.TCP_SYN,
            ["192.168.1.1"],
            ports=[80, 443]
        )

        mock_create_port.assert_called_once()
        assert scanner is not None

    @patch('src.scan.create_port_scanner')
    def test_create_scanner_tcp_connect(self, mock_create_port):
        """Test creating TCP CONNECT scanner."""
        mock_scanner = MagicMock()
        mock_create_port.return_value = mock_scanner

        scanner = create_scanner(
            ScanType.TCP_CONNECT,
            ["192.168.1.1"],
            ports=[22, 80]
        )

        mock_create_port.assert_called_once()
        assert scanner is not None

    @patch('src.scan.create_port_scanner')
    def test_create_scanner_udp(self, mock_create_port):
        """Test creating UDP scanner."""
        mock_scanner = MagicMock()
        mock_create_port.return_value = mock_scanner

        scanner = create_scanner(
            ScanType.UDP,
            ["192.168.1.1"],
            ports=[53, 67]
        )

        mock_create_port.assert_called_once()
        assert scanner is not None

    def test_create_scanner_invalid_type(self):
        """Test creating scanner with invalid type."""
        with pytest.raises(ValueError):
            create_scanner("invalid_type", ["192.168.1.1"])


@pytest.mark.unit
class TestQuickScan:
    """Test quick_scan function."""

    @patch('src.scan.create_scanner')
    @patch('src.scan.get_local_network')
    def test_quick_scan_auto_network(self, mock_get_network, mock_create_scanner):
        """Test quick_scan with auto network detection."""
        mock_get_network.return_value = "192.168.1.0/24"
        mock_scanner = MagicMock()
        mock_report = MagicMock()
        mock_scanner.scan.return_value = mock_report
        mock_create_scanner.return_value = mock_scanner

        report = quick_scan(network="auto")

        mock_get_network.assert_called_once()
        mock_scanner.scan.assert_called_once()
        assert report is not None

    @patch('src.scan.create_scanner')
    def test_quick_scan_custom_network(self, mock_create_scanner):
        """Test quick_scan with custom network."""
        mock_scanner = MagicMock()
        mock_report = MagicMock()
        mock_scanner.scan.return_value = mock_report
        mock_create_scanner.return_value = mock_scanner

        report = quick_scan(network="10.0.0.0/24")

        mock_create_scanner.assert_called_once()
        assert report is not None


@pytest.mark.unit
class TestScanHosts:
    """Test scan_hosts function."""

    @patch('src.scan.create_port_scanner')
    def test_scan_hosts_default_ports(self, mock_create_port):
        """Test scanning hosts with default ports."""
        mock_scanner = MagicMock()
        mock_report = MagicMock()
        mock_scanner.scan.return_value = mock_report
        mock_create_port.return_value = mock_scanner

        report = scan_hosts(["192.168.1.1", "192.168.1.2"])

        mock_create_port.assert_called_once()
        mock_scanner.scan.assert_called_once()
        assert report is not None

    @patch('src.scan.create_port_scanner')
    def test_scan_hosts_custom_ports(self, mock_create_port):
        """Test scanning hosts with custom ports."""
        mock_scanner = MagicMock()
        mock_report = MagicMock()
        mock_scanner.scan.return_value = mock_report
        mock_create_port.return_value = mock_scanner

        report = scan_hosts(
            ["192.168.1.1"],
            ports=[22, 80, 443],
            timeout=2.0
        )

        mock_create_port.assert_called_once()
        assert report is not None


@pytest.mark.unit
class TestNetworkScannerWrapper:
    """Test NetworkScannerWrapper class."""

    @patch('src.scan.create_arp_scanner')
    def test_arp_scan(self, mock_create_arp):
        """Test ARP scan through wrapper."""
        mock_scanner = MagicMock()
        mock_report = MagicMock()
        mock_result = MagicMock()
        mock_result.ip = "192.168.1.1"
        mock_result.is_alive = True
        mock_result.mac = "00:11:22:33:44:55"
        mock_result.hostname = "test.local"
        mock_result.response_time = 5.0
        mock_result.open_ports = {80, 443}
        mock_report.results = [mock_result]
        mock_scanner.scan.return_value = mock_report
        mock_create_arp.return_value = mock_scanner

        wrapper = NetworkScannerWrapper(timeout=1.0, threads=5)
        results = wrapper.arp_scan("192.168.1.0/24")

        assert len(results) == 1
        assert results[0]["ip"] == "192.168.1.1"
        assert results[0]["alive"] is True
        assert results[0]["mac"] == "00:11:22:33:44:55"

    @patch('src.scan.create_icmp_scanner')
    def test_icmp_scan(self, mock_create_icmp):
        """Test ICMP scan through wrapper."""
        mock_scanner = MagicMock()
        mock_report = MagicMock()
        mock_result = MagicMock()
        mock_result.ip = "192.168.1.1"
        mock_result.is_alive = True
        mock_result.mac = None
        mock_result.hostname = None
        mock_result.response_time = 10.0
        mock_result.open_ports = set()
        mock_report.results = [mock_result]
        mock_scanner.scan.return_value = mock_report
        mock_create_icmp.return_value = mock_scanner

        wrapper = NetworkScannerWrapper()
        results = wrapper.icmp_scan("192.168.1.1")

        assert len(results) == 1
        assert results[0]["alive"] is True

    @patch('src.scan.create_port_scanner')
    def test_port_scan(self, mock_create_port):
        """Test port scan through wrapper."""
        mock_scanner = MagicMock()
        mock_report = MagicMock()
        mock_result = MagicMock()
        mock_result.ip = "192.168.1.1"
        mock_result.is_alive = True
        mock_result.mac = None
        mock_result.hostname = None
        mock_result.response_time = None
        mock_result.open_ports = {22, 80, 443}
        mock_report.results = [mock_result]
        mock_scanner.scan.return_value = mock_report
        mock_create_port.return_value = mock_scanner

        wrapper = NetworkScannerWrapper()
        results = wrapper.port_scan("192.168.1.1", [22, 80, 443, 8080])

        assert len(results) == 1
        assert set(results[0]["ports"]) == {22, 80, 443}

    def test_wrapper_initialization(self):
        """Test wrapper initialization."""
        wrapper = NetworkScannerWrapper(timeout=2.0, threads=20)
        assert wrapper._timeout == 2.0
        assert wrapper._threads == 20


@pytest.mark.unit
class TestCreateNetworkScanner:
    """Test create_network_scanner function."""

    def test_create_with_defaults(self):
        """Test creating scanner with default values."""
        scanner = create_network_scanner()
        assert isinstance(scanner, NetworkScannerWrapper)
        assert scanner._timeout == 1.0
        assert scanner._threads == 10

    def test_create_with_custom_values(self):
        """Test creating scanner with custom values."""
        scanner = create_network_scanner(timeout=5.0, threads=50)
        assert scanner._timeout == 5.0
        assert scanner._threads == 50
