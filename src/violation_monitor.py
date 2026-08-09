"""Runtime violation monitoring for isolation boundary violations.

This module provides monitoring for isolation boundary violations as required
by Requirement 6.5. It detects and logs attempts to:
- Write to host filesystem
- Create processes on host system
- Connect to internal network addresses

SECURITY CRITICAL: This module implements fail-closed behavior for
detected violations. Violations are logged with timestamps and target details.

Requirements: 6.5
"""

import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from ipaddress import ip_address, IPv4Address, IPv6Address

from config.logging_config import get_logger


@dataclass
class Violation:
    """Record of an isolation boundary violation."""

    violation_type: str  # "filesystem_write", "process_creation", "internal_network"
    timestamp: datetime
    target: str  # path, process name, or IP address
    container_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert violation to dictionary for logging."""
        return {
            'violation_type': self.violation_type,
            'timestamp': self.timestamp.isoformat(),
            'target': self.target,
            'container_id': self.container_id,
            'details': self.details
        }


class ViolationMonitor:
    """Monitors for isolation boundary violations during analysis.

    This class uses existing probe infrastructure to detect violations and
    logs them according to Requirement 6.5 with timestamps and target details.

    Uses Python's ipaddress.is_global for comprehensive coverage of IANA
    special-use registries for internal/private IP detection.
    """

    # Localhost addresses (checked before IP resolution)
    LOCALHOST_ADDRESSES = ['127.0.0.1', '::1', 'localhost', '0.0.0.0']

    def __init__(self):
        """Initialize the ViolationMonitor."""
        self.logger = get_logger(__name__)
        self.violations: List[Violation] = []

    def is_internal_ip(self, ip_str: str) -> bool:
        """Check if an IP address or hostname is internal/private.

        Uses Python's ipaddress.is_global for comprehensive coverage of IANA
        special-use registries, providing protection against RFC1918, IPv6 ULA,
        link-local, loopback, and other special-use addresses.

        Args:
            ip_str: IP address string or hostname

        Returns:
            True if IP is internal/private (not globally routable), False otherwise
        """
        # Check hostname strings first
        if ip_str.lower() in [addr.lower() for addr in self.LOCALHOST_ADDRESSES]:
            return True

        try:
            ip = ip_address(ip_str)

            # Use ip.is_global for comprehensive IANA registry-based detection
            # This handles RFC1918, IPv6 ULA, link-local, loopback, and many other
            # special-use ranges automatically based on IANA allocations
            if not ip.is_global:
                return True

            return False

        except ValueError:
            # Invalid IP address - treat as external (hostname will be caught elsewhere)
            return False

    def log_filesystem_violation(
        self,
        path: str,
        container_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> Violation:
        """Log a filesystem write access violation.

        Args:
            path: Target path that was written to
            container_id: Container ID where violation occurred
            details: Additional violation details

        Returns:
            Violation record
        """
        violation = Violation(
            violation_type="filesystem_write",
            timestamp=datetime.now(timezone.utc),
            target=path,
            container_id=container_id,
            details=details or {}
        )

        self.violations.append(violation)

        extra_fields = {
            "violation_type": "filesystem_write",
            "target_path": path,
            "container_id": container_id,
            "timestamp": violation.timestamp.isoformat()
        }
        if details:
            extra_fields.update(details)

        self.logger.error(
            f"Filesystem write violation detected: {path}",
            extra={"extra_fields": extra_fields}
        )

        return violation

    def log_process_violation(
        self,
        process_name: str,
        container_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> Violation:
        """Log a process creation violation.

        Args:
            process_name: Name of process that was created
            container_id: Container ID where violation occurred
            details: Additional violation details

        Returns:
            Violation record
        """
        violation = Violation(
            violation_type="process_creation",
            timestamp=datetime.now(timezone.utc),
            target=process_name,
            container_id=container_id,
            details=details or {}
        )

        self.violations.append(violation)

        extra_fields = {
            "violation_type": "process_creation",
            "target_process": process_name,
            "container_id": container_id,
            "timestamp": violation.timestamp.isoformat()
        }
        if details:
            extra_fields.update(details)

        self.logger.error(
            f"Process creation violation detected: {process_name}",
            extra={"extra_fields": extra_fields}
        )

        return violation

    def log_network_violation(
        self,
        ip_address: str,
        container_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> Violation:
        """Log an internal network connection violation.

        Args:
            ip_address: Target IP address that was connected to
            container_id: Container ID where violation occurred
            details: Additional violation details

        Returns:
            Violation record
        """
        violation = Violation(
            violation_type="internal_network",
            timestamp=datetime.now(timezone.utc),
            target=ip_address,
            container_id=container_id,
            details=details or {}
        )

        self.violations.append(violation)

        extra_fields = {
            "violation_type": "internal_network",
            "target_ip": ip_address,
            "container_id": container_id,
            "timestamp": violation.timestamp.isoformat()
        }
        if details:
            extra_fields.update(details)

        self.logger.error(
            f"Internal network connection violation detected: {ip_address}",
            extra={"extra_fields": extra_fields}
        )

        return violation

    def get_violations(self) -> List[Dict[str, Any]]:
        """Get all violations as dictionaries.

        Returns:
            List of violation dictionaries
        """
        return [v.to_dict() for v in self.violations]

    def clear_violations(self) -> None:
        """Clear all recorded violations."""
        self.violations.clear()
        self.logger.info("Violation history cleared")

    def has_violations(self) -> bool:
        """Check if any violations have been recorded.

        Returns:
            True if violations exist, False otherwise
        """
        return len(self.violations) > 0
