"""Runtime network isolation evidence probes for container validation.

This module provides probes that collect evidence about network namespace state,
network interfaces, routing configuration, and DNS configuration inside containers.
These probes run inside the container and return structured evidence for later
aggregation.

SECURITY CRITICAL: All probes are designed to be non-destructive and fail
closed on errors. These probes provide EVIDENCE, not absolute proof of
network isolation from the host.

IMPORTANT: Runtime evidence alone does NOT prove:
- Complete impossibility of network container escape
- Absence of kernel vulnerabilities
- Absolute host network isolation
- That network traffic cannot reach internal hosts

Evidence from these probes should be combined with trusted host-side
Docker configuration validation (ContainerValidator._check_network_mode)
to form a complete security assessment.
"""

import os
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone


@dataclass
class ProbeResult:
    """Result of a single network evidence probe."""
    
    probe_name: str
    passed: bool
    observed_value: Any
    expected_condition: str
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert probe result to dictionary for JSON serialization."""
        return {
            'probe_name': self.probe_name,
            'passed': self.passed,
            'observed_value': self.observed_value,
            'expected_condition': self.expected_condition,
            'error': self.error,
            'timestamp': self.timestamp.isoformat()
        }


class NetworkProbes:
    """Runtime network evidence probes for container isolation validation.
    
    These probes collect evidence about network namespace state, interfaces,
    routing, and DNS configuration inside containers. They are designed to be
    non-destructive and fail closed on errors.
    """
    
    def __init__(self):
        """Initialize network probes."""
        self.logger = None  # Optional logger for debugging
    
    def probe_network_namespace_evidence(self) -> ProbeResult:
        """Probe A: Collect network namespace evidence.
        
        Reads namespace identifiers for /proc/self/ns/net and /proc/1/ns/net
        to determine if current process and PID 1 belong to the same container
        network namespace.
        
        NOTE: This comparison only provides evidence that the current process
        and PID 1 share the same network namespace. It does NOT prove that
        this namespace is different from the host network namespace. Host-side
        Docker configuration (NetworkMode) must be combined with this evidence
        for a complete security assessment.
        
        Returns:
            ProbeResult with network namespace evidence.
        """
        try:
            # Read self network namespace
            self_ns_path = '/proc/self/ns/net'
            if not os.path.exists(self_ns_path):
                return ProbeResult(
                    probe_name='network_namespace_evidence',
                    passed=False,
                    observed_value='self_ns_not_found',
                    expected_condition='/proc/self/ns/net should be readable',
                    error='/proc/self/ns/net not found (network namespace not available)'
                )
            
            self_ns_inode = os.stat(self_ns_path).st_ino
            
            # Read PID 1 network namespace
            pid1_ns_path = '/proc/1/ns/net'
            if not os.path.exists(pid1_ns_path):
                return ProbeResult(
                    probe_name='network_namespace_evidence',
                    passed=False,
                    observed_value='pid1_ns_not_found',
                    expected_condition='/proc/1/ns/net should be readable',
                    error='/proc/1/ns/net not found (PID 1 not accessible)'
                )
            
            pid1_ns_inode = os.stat(pid1_ns_path).st_ino
            
            # Compare namespace identifiers
            same_namespace = self_ns_inode == pid1_ns_inode
            
            return ProbeResult(
                probe_name='network_namespace_evidence',
                passed=True,  # Evidence collection succeeded
                observed_value={
                    'self_ns_inode': self_ns_inode,
                    'pid1_ns_inode': pid1_ns_inode,
                    'same_namespace': same_namespace,
                    'current_pid': os.getpid()
                },
                expected_condition='Current process and PID 1 should be in same network namespace',
                error=None
            )
            
        except PermissionError as e:
            return ProbeResult(
                probe_name='network_namespace_evidence',
                passed=False,
                observed_value='permission_denied',
                expected_condition='/proc/*/ns/net should be readable',
                error=f'Permission denied reading namespace: {e}'
            )
        except Exception as e:
            return ProbeResult(
                probe_name='network_namespace_evidence',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='/proc/*/ns/net should be readable',
                error=f'Unexpected error reading namespace: {e}'
            )
    
    def probe_network_interface_evidence(self) -> ProbeResult:
        """Probe B: Collect network interface evidence.
        
        Reads /proc/net/dev to enumerate visible network interfaces and their
        basic statistics. This provides diagnostic information about network
        visibility inside the container.
        
        Returns:
            ProbeResult with network interface evidence.
        """
        proc_net_dev_path = '/proc/net/dev'
        
        try:
            if not os.path.exists(proc_net_dev_path):
                return ProbeResult(
                    probe_name='network_interface_evidence',
                    passed=False,
                    observed_value='proc_net_dev_not_found',
                    expected_condition='/proc/net/dev should be readable',
                    error='/proc/net/dev not found (procfs not available)'
                )
            
            with open(proc_net_dev_path, 'r') as f:
                lines = f.readlines()
            
            # Skip header lines (first 2 lines)
            # Format: Interface: Receive-Bytes Receive-Packets ... Transmit-Bytes Transmit-Packets ...
            interfaces = []
            for line in lines[2:]:
                line = line.strip()
                if not line:
                    continue
                
                # Split on colon to separate interface name from stats
                if ':' not in line:
                    continue
                
                parts = line.split(':', 1)
                interface_name = parts[0].strip()
                stats_str = parts[1].strip()
                
                # Parse statistics
                stats = stats_str.split()
                if len(stats) >= 8:
                    interface_data = {
                        'name': interface_name,
                        'receive_bytes': int(stats[0]) if stats[0].isdigit() else 0,
                        'receive_packets': int(stats[1]) if stats[1].isdigit() else 0,
                        'transmit_bytes': int(stats[8]) if len(stats) > 8 and stats[8].isdigit() else 0,
                        'transmit_packets': int(stats[9]) if len(stats) > 9 and stats[9].isdigit() else 0
                    }
                    interfaces.append(interface_data)
            
            return ProbeResult(
                probe_name='network_interface_evidence',
                passed=True,  # Evidence collection succeeded
                observed_value={
                    'interface_count': len(interfaces),
                    'interfaces': interfaces
                },
                expected_condition='Network interfaces should be enumerable',
                error=None
            )
            
        except PermissionError as e:
            return ProbeResult(
                probe_name='network_interface_evidence',
                passed=False,
                observed_value='permission_denied',
                expected_condition='/proc/net/dev should be readable',
                error=f'Permission denied reading /proc/net/dev: {e}'
            )
        except Exception as e:
            return ProbeResult(
                probe_name='network_interface_evidence',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='/proc/net/dev should be readable',
                error=f'Unexpected error reading /proc/net/dev: {e}'
            )
    
    def probe_routing_table_evidence(self) -> ProbeResult:
        """Probe C: Collect routing table evidence.
        
        Reads /proc/net/route to examine routing table entries. This provides
        diagnostic information about network routing configuration inside the
        container.
        
        Returns:
            ProbeResult with routing table evidence.
        """
        proc_net_route_path = '/proc/net/route'
        
        try:
            if not os.path.exists(proc_net_route_path):
                return ProbeResult(
                    probe_name='routing_table_evidence',
                    passed=False,
                    observed_value='proc_net_route_not_found',
                    expected_condition='/proc/net/route should be readable',
                    error='/proc/net/route not found (procfs not available)'
                )
            
            with open(proc_net_route_path, 'r') as f:
                lines = f.readlines()
            
            # Skip header line
            # Format: Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
            routes = []
            for line in lines[1:]:
                line = line.strip()
                if not line:
                    continue
                
                parts = line.split()
                if len(parts) >= 8:
                    route_data = {
                        'interface': parts[0],
                        'destination': parts[1],
                        'gateway': parts[2],
                        'flags': parts[3],
                        'metric': parts[7] if len(parts) > 7 else '0'
                    }
                    routes.append(route_data)
            
            return ProbeResult(
                probe_name='routing_table_evidence',
                passed=True,  # Evidence collection succeeded
                observed_value={
                    'route_count': len(routes),
                    'routes': routes
                },
                expected_condition='Routing table should be enumerable',
                error=None
            )
            
        except PermissionError as e:
            return ProbeResult(
                probe_name='routing_table_evidence',
                passed=False,
                observed_value='permission_denied',
                expected_condition='/proc/net/route should be readable',
                error=f'Permission denied reading /proc/net/route: {e}'
            )
        except Exception as e:
            return ProbeResult(
                probe_name='routing_table_evidence',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='/proc/net/route should be readable',
                error=f'Unexpected error reading /proc/net/route: {e}'
            )
    
    def probe_dns_configuration_evidence(self) -> ProbeResult:
        """Probe D: Collect DNS configuration evidence.
        
        Reads /etc/resolv.conf to examine DNS configuration. This provides
        diagnostic information about DNS resolution configuration inside the
        container.
        
        Returns:
            ProbeResult with DNS configuration evidence.
        """
        resolv_conf_path = '/etc/resolv.conf'
        
        try:
            if not os.path.exists(resolv_conf_path):
                return ProbeResult(
                    probe_name='dns_configuration_evidence',
                    passed=False,
                    observed_value='resolv_conf_not_found',
                    expected_condition='/etc/resolv.conf should be readable',
                    error='/etc/resolv.conf not found'
                )
            
            with open(resolv_conf_path, 'r') as f:
                lines = f.readlines()
            
            dns_servers = []
            search_domains = []
            options = []
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split()
                if len(parts) >= 2:
                    keyword = parts[0].lower()
                    
                    if keyword == 'nameserver':
                        dns_servers.append(parts[1])
                    elif keyword == 'search':
                        search_domains.extend(parts[1:])
                    elif keyword == 'options':
                        options.extend(parts[1:])
            
            return ProbeResult(
                probe_name='dns_configuration_evidence',
                passed=True,  # Evidence collection succeeded
                observed_value={
                    'dns_servers': dns_servers,
                    'search_domains': search_domains,
                    'options': options
                },
                expected_condition='DNS configuration should be readable',
                error=None
            )
            
        except PermissionError as e:
            return ProbeResult(
                probe_name='dns_configuration_evidence',
                passed=False,
                observed_value='permission_denied',
                expected_condition='/etc/resolv.conf should be readable',
                error=f'Permission denied reading /etc/resolv.conf: {e}'
            )
        except Exception as e:
            return ProbeResult(
                probe_name='dns_configuration_evidence',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='/etc/resolv.conf should be readable',
                error=f'Unexpected error reading /etc/resolv.conf: {e}'
            )
    
    def probe_networkmode_verification(self) -> ProbeResult:
        """Probe E: Verify network mode consistency.
        
        Combines network namespace evidence, interface evidence, and routing
        evidence to infer the actual network mode and verify consistency with
        expected Docker configuration.
        
        NOTE: This probe provides EVIDENCE about runtime network state, not
        absolute proof of network isolation. Host-side Docker configuration
        (ContainerValidator._check_network_mode) must be combined with this
        evidence for a complete security assessment.
        
        Returns:
            ProbeResult with network mode verification evidence.
        """
        try:
            # Collect evidence from other probes
            namespace_result = self.probe_network_namespace_evidence()
            interface_result = self.probe_network_interface_evidence()
            routing_result = self.probe_routing_table_evidence()
            
            # Aggregate evidence
            evidence = {
                'namespace_evidence': namespace_result.to_dict(),
                'interface_evidence': interface_result.to_dict(),
                'routing_evidence': routing_result.to_dict()
            }
            
            # Infer network mode based on evidence
            # Note: This is a heuristic inference, not absolute proof
            inferred_mode = 'unknown'
            
            if namespace_result.passed and interface_result.passed:
                # Check if only loopback interface is present
                interface_count = interface_result.observed_value.get('interface_count', 0)
                interface_names = [iface['name'] for iface in interface_result.observed_value.get('interfaces', [])]
                
                if interface_count == 1 and 'lo' in interface_names:
                    inferred_mode = 'none_or_loopback_only'
                elif interface_count > 1:
                    inferred_mode = 'has_multiple_interfaces'
                else:
                    inferred_mode = 'unknown'
            
            # Check evidence consistency
            evidence_consistent = (
                namespace_result.passed and
                interface_result.passed and
                routing_result.passed
            )
            
            return ProbeResult(
                probe_name='networkmode_verification',
                passed=evidence_consistent,  # Evidence collection succeeded
                observed_value={
                    'inferred_mode': inferred_mode,
                    'evidence': evidence,
                    'evidence_consistent': evidence_consistent
                },
                expected_condition='All network evidence probes should succeed',
                error=None if evidence_consistent else 'Some evidence probes failed'
            )
            
        except Exception as e:
            return ProbeResult(
                probe_name='networkmode_verification',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='Network mode verification should succeed',
                error=f'Unexpected error during network mode verification: {e}'
            )

    def run_all_probes(self) -> Dict[str, ProbeResult]:
        """Run all network probes and return results.

        Returns:
            Dictionary mapping probe names to ProbeResult objects.
        """
        results = {}

        try:
            # Run all probes
            results['network_namespace_evidence'] = self.probe_network_namespace_evidence()
        except Exception as e:
            results['network_namespace_evidence'] = ProbeResult(
                probe_name='network_namespace_evidence',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='Probe should execute without errors',
                error=f'Unexpected error during probe: {e}'
            )

        try:
            results['network_interface_evidence'] = self.probe_network_interface_evidence()
        except Exception as e:
            results['network_interface_evidence'] = ProbeResult(
                probe_name='network_interface_evidence',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='Probe should execute without errors',
                error=f'Unexpected error during probe: {e}'
            )

        try:
            results['routing_table_evidence'] = self.probe_routing_table_evidence()
        except Exception as e:
            results['routing_table_evidence'] = ProbeResult(
                probe_name='routing_table_evidence',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='Probe should execute without errors',
                error=f'Unexpected error during probe: {e}'
            )

        try:
            results['dns_configuration_evidence'] = self.probe_dns_configuration_evidence()
        except Exception as e:
            results['dns_configuration_evidence'] = ProbeResult(
                probe_name='dns_configuration_evidence',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='Probe should execute without errors',
                error=f'Unexpected error during probe: {e}'
            )

        try:
            results['networkmode_verification'] = self.probe_networkmode_verification()
        except Exception as e:
            results['networkmode_verification'] = ProbeResult(
                probe_name='networkmode_verification',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='Probe should execute without errors',
                error=f'Unexpected error during probe: {e}'
            )

        return results
