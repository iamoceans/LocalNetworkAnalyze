"""
Constants for the Local Network Analyzer application.

Centralizes all magic numbers, protocol identifiers, and other
constant values used throughout the application.
"""

# Version info
__version__ = "0.1.0"
__app_name__ = "Local Network Analyzer"
__author__ = "Local Network Analyzer Team"


# Network protocol constants
class Protocol:
    """Network protocol identifiers."""

    ETHERNET = "Ethernet"
    IP = "IP"
    IPv6 = "IPv6"
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    DHCP = "DHCP"
    ARP = "ARP"
    RAW = "RAW"

    # Protocol numbers (IP protocol field)
    IP_PROTOCOL_ICMP = 1
    IP_PROTOCOL_TCP = 6
    IP_PROTOCOL_UDP = 17

    # Ethernet types
    ETH_TYPE_IP = 0x0800
    ETH_TYPE_ARP = 0x0806
    ETH_TYPE_IPV6 = 0x86DD


# TCP flags
class TCPFlag:
    """TCP flag definitions."""

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    # Common flag combinations
    SYN_ACK = SYN | ACK
    FIN_ACK = FIN | ACK


# TCP connection states
class TCPState:
    """TCP connection states."""

    CLOSED = "CLOSED"
    LISTEN = "LISTEN"
    SYN_SENT = "SYN_SENT"
    SYN_RECEIVED = "SYN_RECEIVED"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT_1 = "FIN_WAIT_1"
    FIN_WAIT_2 = "FIN_WAIT_2"
    CLOSE_WAIT = "CLOSE_WAIT"
    CLOSING = "CLOSING"
    LAST_ACK = "LAST_ACK"
    TIME_WAIT = "TIME_WAIT"


# ICMP types
class ICMPType:
    """ICMP message types."""

    ECHO_REPLY = 0
    DESTINATION_UNREACHABLE = 3
    SOURCE_QUENCH = 4
    REDIRECT = 5
    ECHO_REQUEST = 8
    TIME_EXCEEDED = 11
    PARAMETER_PROBLEM = 12
    TIMESTAMP_REQUEST = 13
    TIMESTAMP_REPLY = 14


# HTTP methods
class HTTPMethod:
    """HTTP request methods."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    CONNECT = "CONNECT"
    TRACE = "TRACE"


# HTTP status codes
class HTTPStatus:
    """HTTP status codes."""

    # Informational
    CONTINUE = 100
    SWITCHING_PROTOCOLS = 101

    # Success
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NO_CONTENT = 204

    # Redirection
    MOVED_PERMANENTLY = 301
    FOUND = 302
    NOT_MODIFIED = 304

    # Client error
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    REQUEST_TIMEOUT = 408

    # Server error
    INTERNAL_SERVER_ERROR = 500
    NOT_IMPLEMENTED = 501
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503
    GATEWAY_TIMEOUT = 504


# Common ports
class Port:
    """Well-known network ports."""

    # HTTP/HTTPS
    HTTP = 80
    HTTPS = 443

    # DNS
    DNS = 53

    # DHCP
    DHCP_SERVER = 67
    DHCP_CLIENT = 68

    # SSH
    SSH = 22

    # FTP
    FTP = 20
    FTP_CONTROL = 21

    # Telnet
    TELNET = 23

    # SMTP
    SMTP = 25

    # POP3
    POP3 = 110

    # IMAP
    IMAP = 143
    IMAPS = 993

    # RDP
    RDP = 3389

    # SMB
    SMB = 445

    # MySQL
    MYSQL = 3306

    # PostgreSQL
    POSTGRESQL = 5432

    # Redis
    REDIS = 6379

    # MongoDB
    MONGODB = 27017


# Alert severity levels
class Severity:
    """Alert severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    # For sorting/display order
    ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3}

    @classmethod
    def sort_key(cls, severity: str) -> int:
        """Get sort key for severity level.

        Args:
            severity: Severity level string

        Returns:
            Integer sort key
        """
        return cls.ORDER.get(severity, 0)


# Scan types
class ScanType:
    """Network scan types."""

    ARP = "ARP Scan"
    ICMP = "ICMP Ping"
    TCP_SYN = "TCP SYN Scan"
    TCP_CONNECT = "TCP Connect Scan"
    UDP = "UDP Scan"
    PORT_SCAN = "Port Scan"
    HOST_DISCOVERY = "Host Discovery"


# Alert types
class AlertType:
    """Alert types for security events."""

    PORT_SCAN = "Port Scan"
    DOS_ATTACK = "Denial of Service"
    DDOS_ATTACK = "Distributed DoS"
    BRUTE_FORCE = "Brute Force Attack"
    MALFORMED_PACKET = "Malformed Packet"
    SUSPICIOUS_TRAFFIC = "Suspicious Traffic"
    ANOMALY = "Traffic Anomaly"
    NEW_DEVICE = "New Device Detected"
    POLICY_VIOLATION = "Policy Violation"


# Data export formats
class ExportFormat:
    """Supported data export formats."""

    CSV = "csv"
    JSON = "json"
    PCAP = "pcap"
    XML = "xml"


# Time constants (in seconds)
class Time:
    """Time-related constants."""

    SECOND = 1
    MINUTE = 60
    HOUR = 3600
    DAY = 86400

    # Common intervals
    UPDATE_INTERVAL = 1  # GUI update interval
    SCAN_TIMEOUT = 60  # Default scan timeout
    CAPTURE_TIMEOUT = 30  # Default capture timeout


# Size constants (in bytes)
class Size:
    """Size-related constants."""

    KB = 1024
    MB = 1024 * KB
    GB = 1024 * MB

    # Buffer sizes
    PACKET_BUFFER = 1000  # Default packet buffer size
    SOCKET_BUFFER = 64 * KB  # Socket receive buffer

    # File size limits
    MAX_LOG_SIZE = 10 * MB
    MAX_EXPORT_SIZE = 100 * MB


# GUI constants
class GUI:
    """GUI-related constants."""

    # Default window size
    DEFAULT_WIDTH = 1280
    DEFAULT_HEIGHT = 720
    MIN_WIDTH = 800
    MIN_HEIGHT = 600

    # Dashboard
    MAX_CHART_POINTS = 100
    MAX_TABLE_ROWS = 1000

    # Colors (hex)
    COLOR_PRIMARY = "#1a5fb4"
    COLOR_SUCCESS = "#26a269"
    COLOR_WARNING = "#e5a50a"
    COLOR_ERROR = "#c01c28"
    COLOR_INFO = "#3584e4"

    # Icons
    ICON_APP = "app_icon.png"
    ICON_ALERT = "alert_icon.png"
    ICON_INFO = "info_icon.png"


# Database constants
class Database:
    """Database-related constants."""

    # Connection
    DEFAULT_TIMEOUT = 5  # seconds
    MAX_RETRIES = 3

    # Tables
    TABLE_PACKETS = "packets"
    TABLE_SCANS = "scans"
    TABLE_ALERTS = "alerts"
    TABLE_DEVICES = "devices"
    TABLE_CONNECTIONS = "connections"

    # Batch operations
    BATCH_INSERT_SIZE = 100
    VACUUM_INTERVAL = 3600  # seconds


# Performance constants
class Performance:
    """Performance-related constants."""

    # Threading
    MAX_WORKERS = 4
    QUEUE_SIZE = 10000

    # Processing
    BATCH_SIZE = 100
    FLUSH_INTERVAL = 5  # seconds


# MAC address helpers
MAC_BROADCAST = "FF:FF:FF:FF:FF:FF"
MAC_MULTICAST_PREFIX = "01:00:5E"

# IP address helpers
IP_BROADCAST = "255.255.255.255"
IP_LOCALHOST = "127.0.0.1"
IP_ANY = "0.0.0.0"

# Private IP ranges (RFC 1918)
PRIVATE_IP_RANGES = [
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
]


# Application metadata
class Meta:
    """Application metadata."""

    NAME = __app_name__
    VERSION = __version__
    AUTHOR = __author__
    DESCRIPTION = "Local network traffic analysis and monitoring tool"
    LICENSE = "MIT"
    HOMEPAGE = "https://github.com/your-org/local-network-analyzer"
    REPOSITORY = "https://github.com/your-org/local-network-analyzer"
