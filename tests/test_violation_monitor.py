"""Unit tests for ViolationMonitor.

Tests the ViolationMonitor class that detects and logs isolation boundary
violations per Requirement 6.5.
"""

import pytest
from datetime import datetime, timezone

# Add src to path for imports
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.violation_monitor import ViolationMonitor, Violation


class TestViolationMonitor:
    """Test ViolationMonitor detection and logging."""

    @pytest.fixture
    def monitor(self):
        """Create a ViolationMonitor instance for testing."""
        return ViolationMonitor()

    def test_is_internal_ip_rfc1918(self, monitor):
        """Test detection of RFC 1918 private IP addresses."""
        assert monitor.is_internal_ip('10.0.0.1') is True
        assert monitor.is_internal_ip('10.255.255.254') is True
        assert monitor.is_internal_ip('172.16.0.1') is True
        assert monitor.is_internal_ip('172.31.255.254') is True
        assert monitor.is_internal_ip('192.168.0.1') is True
        assert monitor.is_internal_ip('192.168.255.254') is True

    def test_is_internal_ip_localhost(self, monitor):
        """Test detection of localhost addresses."""
        assert monitor.is_internal_ip('127.0.0.1') is True
        assert monitor.is_internal_ip('::1') is True
        assert monitor.is_internal_ip('localhost') is True
        assert monitor.is_internal_ip('0.0.0.0') is True

    def test_is_internal_ip_ipv6_ula(self, monitor):
        """Test detection of IPv6 Unique Local Addresses."""
        assert monitor.is_internal_ip('fc00::1') is True
        assert monitor.is_internal_ip('fd00::1') is True

    def test_is_internal_ip_metadata_service(self, monitor):
        """Test detection of cloud metadata service addresses."""
        assert monitor.is_internal_ip('169.254.169.254') is True

    def test_is_internal_ip_link_local(self, monitor):
        """Test detection of link-local IPv4 addresses."""
        assert monitor.is_internal_ip('169.254.1.1') is True
        assert monitor.is_internal_ip('169.254.255.255') is True

    def test_is_internal_ip_public(self, monitor):
        """Test that public IPs are not detected as internal."""
        assert monitor.is_internal_ip('8.8.8.8') is False
        assert monitor.is_internal_ip('1.1.1.1') is False
        assert monitor.is_internal_ip('2001:4860:4860::8888') is False

    def test_is_internal_ip_additional_ranges(self, monitor):
        """Test detection of additional IANA special-use ranges via is_global."""
        # IPv6 link-local
        assert monitor.is_internal_ip('fe80::1') is True
        # IPv6 unspecified
        assert monitor.is_internal_ip('::') is True
        # Carrier-grade NAT (100.64.0.0/10)
        assert monitor.is_internal_ip('100.64.0.1') is True
        # Note: IPv6 multicast (ff00::/8) is considered global by Python's ipaddress module
        # This is consistent with IANA allocation - multicast addresses are routable

    def test_log_filesystem_violation(self, monitor):
        """Test logging filesystem write violations."""
        violation = monitor.log_filesystem_violation(
            path='/etc/passwd',
            container_id='abc123',
            details={'attempted_write': True}
        )

        assert violation.violation_type == "filesystem_write"
        assert violation.target == '/etc/passwd'
        assert violation.container_id == 'abc123'
        assert violation.details['attempted_write'] is True
        assert isinstance(violation.timestamp, datetime)

        assert monitor.has_violations() is True

    def test_log_process_violation(self, monitor):
        """Test logging process creation violations."""
        violation = monitor.log_process_violation(
            process_name='bash',
            container_id='abc123',
            details={'pid': 1234}
        )

        assert violation.violation_type == "process_creation"
        assert violation.target == 'bash'
        assert violation.container_id == 'abc123'
        assert violation.details['pid'] == 1234

        assert monitor.has_violations() is True

    def test_log_network_violation(self, monitor):
        """Test logging internal network connection violations."""
        violation = monitor.log_network_violation(
            ip_address='192.168.1.1',
            container_id='abc123',
            details={'port': 80}
        )

        assert violation.violation_type == "internal_network"
        assert violation.target == '192.168.1.1'
        assert violation.container_id == 'abc123'
        assert violation.details['port'] == 80

        assert monitor.has_violations() is True

    def test_get_violations(self, monitor):
        """Test retrieving all violations as dictionaries."""
        monitor.log_filesystem_violation(path='/etc/passwd')
        monitor.log_process_violation(process_name='bash')

        violations = monitor.get_violations()

        assert len(violations) == 2
        assert all(isinstance(v, dict) for v in violations)
        assert violations[0]['violation_type'] == "filesystem_write"
        assert violations[1]['violation_type'] == "process_creation"

    def test_clear_violations(self, monitor):
        """Test clearing violation history."""
        monitor.log_filesystem_violation(path='/etc/passwd')
        assert monitor.has_violations() is True

        monitor.clear_violations()
        assert monitor.has_violations() is False
        assert len(monitor.violations) == 0

    def test_has_violations(self, monitor):
        """Test has_violations method."""
        assert monitor.has_violations() is False

        monitor.log_filesystem_violation(path='/etc/passwd')
        assert monitor.has_violations() is True

    def test_violation_to_dict(self, monitor):
        """Test Violation to_dict conversion."""
        violation = monitor.log_filesystem_violation(path='/etc/passwd')
        violation_dict = violation.to_dict()

        assert 'violation_type' in violation_dict
        assert 'timestamp' in violation_dict
        assert 'target' in violation_dict
        assert 'container_id' in violation_dict
        assert 'details' in violation_dict
        assert violation_dict['violation_type'] == "filesystem_write"
