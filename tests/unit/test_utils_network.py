"""Tests for src.utils.network module."""

import pytest
from unittest.mock import patch, Mock
from src.utils.network import get_active_wifi_interface


class TestGetActiveWifiInterface:
    """Tests for get_active_wifi_interface function."""

    @patch('src.utils.network.socket.socket')
    @patch('src.utils.network.psutil.net_if_addrs')
    def test_returns_wifi_interface(self, mock_net_if, mock_socket):
        """Test that function returns WiFi interface when found."""
        # Mock socket connection to get local IP
        mock_sock = Mock()
        mock_sock.getsockname.return_value = ('192.168.1.100', '')
        mock_socket.return_value = mock_sock
        
        # Mock network interfaces
        mock_net_if.return_value = {
            'Wi-Fi': [
                Mock(address='192.168.1.100')
            ]
        }
        
        result = get_active_wifi_interface()
        assert result is not None
        assert isinstance(result, tuple)
        assert len(result) == 2

    @patch('src.utils.network.socket.socket')
    def test_returns_none_on_socket_error(self, mock_socket):
        """Test that function returns None when socket fails."""
        mock_socket.return_value.connect.side_effect = OSError("Network error")
        result = get_active_wifi_interface()
        assert result is None

    @patch('src.utils.network.socket.socket')
    @patch('src.utils.network.psutil.net_if_addrs')
    @patch('src.utils.network.subprocess.run')
    def test_returns_none_when_no_wifi(self, mock_run, mock_net_if, mock_socket):
        """Test that function returns None when no WiFi interface found."""
        mock_sock = Mock()
        mock_sock.getsockname.return_value = ('192.168.1.100', '')
        mock_socket.return_value = mock_sock

        # Mock netsh command to return empty result
        mock_run.return_value = Mock(stdout=b'', stderr=b'')

        # Mock non-WiFi interface
        mock_net_if.return_value = {
            'Ethernet': [
                Mock(address='192.168.1.100')
            ]
        }

        result = get_active_wifi_interface()
        assert result is None
