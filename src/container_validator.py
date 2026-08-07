"""Host-side Docker container security configuration validation.

This module provides trusted host-side validation that inspects Docker
container configurations to determine whether containers were created with
required security properties.

This validates CONFIGURATION only. It does NOT prove runtime containment
(filesystem, process, network isolation) which require separate validation.

SECURITY CRITICAL: All validation fails closed - missing, malformed, or
unverifiable security configuration results in validation failure for
security-critical properties.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

try:
    import docker
    from docker.models.containers import Container
except ImportError:
    docker = None
    Container = None

from config.logging_config import get_logger


@dataclass
class SecurityCheck:
    """Result of a single security property check."""
    
    property_name: str
    passed: bool
    observed_value: Any
    expected_condition: str
    severity: str = "error"  # "error" for security-critical, "warning" for informational


@dataclass
class ValidationResult:
    """Structured result of container security validation."""
    
    valid: bool
    container_id: str
    checks: List[SecurityCheck] = field(default_factory=list)
    violations: List[SecurityCheck] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def add_check(self, check: SecurityCheck) -> None:
        """Add a security check result."""
        self.checks.append(check)
        if not check.passed and check.severity == "error":
            self.violations.append(check)
            self.valid = False


class ContainerValidator:
    """Validates Docker container security configuration from trusted host.
    
    This class inspects container configuration to verify security properties
    before allowing analysis. It validates CONFIGURATION only, not runtime
    containment behavior.
    """
    
    # Approved tmpfs destinations for Phase 3A
    APPROVED_TMPFS_DESTINATIONS = {'/tmp', '/analysis/temp'}
    
    # Maximum size for approved tmpfs mounts (64MB)
    MAX_TMPFS_SIZE_MB = 64
    
    # Required tmpfs mount options
    REQUIRED_TMPFS_OPTIONS = {'nosuid', 'nodev', 'noexec'}
    
    # Dangerous capabilities that must NOT be added
    DANGEROUS_CAPABILITIES = {
        'CAP_SYS_ADMIN',
        'CAP_SYS_MODULE',
        'CAP_SYS_PTRACE',
        'CAP_NET_ADMIN',
        'CAP_NET_RAW',
        'CAP_SYS_CHROOT',
        'CAP_SYS_BOOT',
        'CAP_SETPCAP',
    }
    
    # Capabilities that should be dropped for defense-in-depth
    RECOMMENDED_CAP_DROP = {
        'CAP_NET_RAW',
        'CAP_NET_BIND_SERVICE',
        'CAP_CHOWN',
        'CAP_DAC_OVERRIDE',
        'CAP_FSETID',
        'CAP_FOWNER',
        'CAP_IPC_OWNER',
        'CAP_KILL',
        'CAP_SETGID',
        'CAP_SETUID',
        'CAP_SETPCAP',
        'CAP_LINUX_IMMUTABLE',
        'CAP_NET_BIND_SERVICE',
        'CAP_NET_BROADCAST',
        'CAP_NET_ADMIN',
        'CAP_IPC_LOCK',
        'CAP_SYS_CHROOT',
        'CAP_SYS_PTRACE',
        'CAP_SYS_BOOT',
        'CAP_LEASE',
        'CAP_AUDIT_WRITE',
        'CAP_AUDIT_CONTROL',
        'CAP_SETFCAP',
        'CAP_MAC_OVERRIDE',
        'CAP_MAC_ADMIN',
    }
    
    def __init__(self):
        """Initialize the ContainerValidator."""
        self.logger = get_logger(__name__)
        
        if docker is None:
            raise ImportError(
                "Docker Python SDK not installed. "
                "Install with: pip install docker"
            )
        
        try:
            self.docker_client = docker.from_env()
            self.logger.info("Docker client initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize Docker client: {e}")
            raise
    
    def validate_container(self, container: Container) -> ValidationResult:
        """Validate container security configuration.
        
        Args:
            container: Docker container object to validate
            
        Returns:
            ValidationResult with detailed check results
        """
        container_id = container.id[:12]  # Short ID for logging
        result = ValidationResult(valid=True, container_id=container_id)
        
        self.logger.info(f"Starting security validation for container {container_id}")
        
        try:
            # Reload container to get fresh configuration
            container.reload()
            
            # Perform all security checks
            self._check_privileged(container, result)
            self._check_readonly_rootfs(container, result)
            self._check_bind_mounts(container, result)
            self._check_pid_mode(container, result)
            self._check_ipc_mode(container, result)
            self._check_network_mode(container, result)
            self._check_capabilities(container, result)
            self._check_no_new_privileges(container, result)
            self._check_memory_limit(container, result)
            self._check_pid_limit(container, result)
            self._check_cpu_limits(container, result)
            self._check_user(container, result)
            
            # Log validation result
            if result.valid:
                self.logger.info(
                    f"Container {container_id} passed all security validation checks",
                    extra={
                        "extra_fields": {
                            "container_id": container_id,
                            "checks_performed": len(result.checks),
                            "violations": len(result.violations)
                        }
                    }
                )
            else:
                self.logger.error(
                    f"Container {container_id} failed security validation",
                    extra={
                        "extra_fields": {
                            "container_id": container_id,
                            "violations": len(result.violations),
                            "failed_properties": [v.property_name for v in result.violations]
                        }
                    }
                )
            
            return result
            
        except Exception as e:
            self.logger.error(
                f"Error during container validation for {container_id}: {e}",
                exc_info=True
            )
            # Fail closed on validation errors
            result.add_check(SecurityCheck(
                property_name="validation_error",
                passed=False,
                observed_value=str(e),
                expected_condition="Successful validation without errors",
                severity="error"
            ))
            return result
    
    def _check_privileged(self, container: Container, result: ValidationResult) -> None:
        """Validate container is not running in privileged mode."""
        host_config = container.attrs.get('HostConfig', {})
        privileged = host_config.get('Privileged', False)
        
        check = SecurityCheck(
            property_name="privileged",
            passed=not privileged,
            observed_value=privileged,
            expected_condition="Privileged must be false"
        )
        result.add_check(check)
        
        if not check.passed:
            self.logger.error(
                f"Container {result.container_id} validation failed: privileged={privileged}",
                extra={
                    "extra_fields": {
                        "container_id": result.container_id,
                        "property": "privileged",
                        "observed": privileged,
                        "expected": False
                    }
                }
            )
    
    def _check_readonly_rootfs(self, container: Container, result: ValidationResult) -> None:
        """Validate container root filesystem is read-only."""
        host_config = container.attrs.get('HostConfig', {})
        readonly_rootfs = host_config.get('ReadonlyRootfs', False)
        
        check = SecurityCheck(
            property_name="readonly_rootfs",
            passed=readonly_rootfs,
            observed_value=readonly_rootfs,
            expected_condition="ReadonlyRootfs must be true for hardened configuration"
        )
        result.add_check(check)
        
        if not check.passed:
            self.logger.error(
                f"Container {result.container_id} validation failed: readonly_rootfs={readonly_rootfs}",
                extra={
                    "extra_fields": {
                        "container_id": result.container_id,
                        "property": "readonly_rootfs",
                        "observed": readonly_rootfs,
                        "expected": True
                    }
                }
            )
    
    def _check_bind_mounts(self, container: Container, result: ValidationResult) -> None:
        """Validate container mount configuration for Phase 3A tmpfs policy.
        
        Phase 3A allows ONLY approved tmpfs mounts:
        - tmpfs at /tmp (max 64MB, nosuid, nodev, noexec where compatible)
        - tmpfs at /analysis/temp (max 64MB, nosuid, nodev, noexec where compatible)
        
        Prohibited:
        - Host bind mounts
        - Named Docker volumes
        - Arbitrary tmpfs destinations
        - Unknown mount types
        - Source-backed mounts
        
        Fail closed on missing, malformed, or unverifiable mount information.
        """
        host_config = container.attrs.get('HostConfig', {})
        binds = host_config.get('Binds')
        
        # Check Docker Mounts configuration for all mount types
        mounts = container.attrs.get('Mounts', [])
        
        # Validate each mount
        invalid_mounts = []
        approved_tmpfs_mounts = []
        
        for mount in mounts:
            mount_type = mount.get('Type', 'unknown')
            destination = mount.get('Destination', '')
            source = mount.get('Source', None)
            
            # Check for host bind mounts
            if mount_type == 'bind':
                invalid_mounts.append({
                    'type': 'bind',
                    'destination': destination,
                    'source': source,
                    'reason': 'Host bind mounts are prohibited'
                })
                continue
            
            # Check for named volumes
            if mount_type == 'volume':
                invalid_mounts.append({
                    'type': 'volume',
                    'destination': destination,
                    'name': mount.get('Name', 'unknown'),
                    'reason': 'Named Docker volumes are prohibited'
                })
                continue
            
            # Check for unknown mount types
            if mount_type not in ('tmpfs',):
                invalid_mounts.append({
                    'type': mount_type,
                    'destination': destination,
                    'reason': f'Unknown mount type: {mount_type}'
                })
                continue
            
            # Validate tmpfs mounts
            if mount_type == 'tmpfs':
                # Check destination is approved
                if destination not in self.APPROVED_TMPFS_DESTINATIONS:
                    invalid_mounts.append({
                        'type': 'tmpfs',
                        'destination': destination,
                        'reason': f'Tmpfs destination not approved: {destination}'
                    })
                    continue
                
                # Check no source path (tmpfs should not have source)
                if source is not None:
                    invalid_mounts.append({
                        'type': 'tmpfs',
                        'destination': destination,
                        'source': source,
                        'reason': 'Tmpfs should not have source path'
                    })
                    continue
                
                # Get tmpfs options from host config
                tmpfs_opts = host_config.get('Tmpfs', {})
                destination_opts = tmpfs_opts.get(destination, '')
                
                # Parse size limit (e.g., "size=64m" or "size=64M")
                size_valid = False
                size_mb = 0
                if destination_opts:
                    opts_parts = destination_opts.split(',')
                    for part in opts_parts:
                        part = part.strip().lower()
                        # Handle "size=64m" format
                        if part.startswith('size='):
                            size_part = part[5:]  # Remove "size=" prefix
                            if size_part.endswith('m'):
                                size_str = size_part[:-1]  # Remove 'm' suffix
                                if size_str.isdigit():
                                    size_mb = int(size_str)
                                    size_valid = size_mb <= self.MAX_TMPFS_SIZE_MB
                                    break
                
                if not size_valid:
                    invalid_mounts.append({
                        'type': 'tmpfs',
                        'destination': destination,
                        'size_mb': size_mb,
                        'reason': f'Tmpfs size exceeds {self.MAX_TMPFS_SIZE_MB}MB or invalid'
                    })
                    continue
                
                # Check required options
                opts_lower = destination_opts.lower() if destination_opts else ''
                has_required = all(opt in opts_lower for opt in self.REQUIRED_TMPFS_OPTIONS)
                
                if not has_required:
                    invalid_mounts.append({
                        'type': 'tmpfs',
                        'destination': destination,
                        'options': destination_opts,
                        'reason': f'Missing required options: {self.REQUIRED_TMPFS_OPTIONS}'
                    })
                    continue
                
                # If all checks pass, it's an approved tmpfs
                approved_tmpfs_mounts.append({
                    'destination': destination,
                    'size_mb': size_mb,
                    'options': destination_opts
                })
        
        # ALSO validate tmpfs from HostConfig['Tmpfs'] directly
        # Docker tmpfs mounts may not appear in Mounts array on some platforms (e.g., Windows/WSL2)
        tmpfs_opts = host_config.get('Tmpfs', {})
        for destination, options in tmpfs_opts.items():
            # Skip if already validated from Mounts array
            if any(m['destination'] == destination for m in approved_tmpfs_mounts):
                continue
            if any(m['destination'] == destination for m in invalid_mounts):
                continue
            
            # Check destination is approved
            if destination not in self.APPROVED_TMPFS_DESTINATIONS:
                invalid_mounts.append({
                    'type': 'tmpfs',
                    'destination': destination,
                    'reason': f'Tmpfs destination not approved: {destination}'
                })
                continue
            
            # Parse size limit
            size_valid = False
            size_mb = 0
            if options:
                opts_parts = options.split(',')
                for part in opts_parts:
                    part = part.strip().lower()
                    if part.startswith('size='):
                        size_part = part[5:]
                        if size_part.endswith('m'):
                            size_str = size_part[:-1]
                            if size_str.isdigit():
                                size_mb = int(size_str)
                                size_valid = size_mb <= self.MAX_TMPFS_SIZE_MB
                                break
            
            if not size_valid:
                invalid_mounts.append({
                    'type': 'tmpfs',
                    'destination': destination,
                    'size_mb': size_mb,
                    'reason': f'Tmpfs size exceeds {self.MAX_TMPFS_SIZE_MB}MB or invalid'
                })
                continue
            
            # Check required options
            opts_lower = options.lower() if options else ''
            has_required = all(opt in opts_lower for opt in self.REQUIRED_TMPFS_OPTIONS)
            
            if not has_required:
                invalid_mounts.append({
                    'type': 'tmpfs',
                    'destination': destination,
                    'options': options,
                    'reason': f'Missing required options: {self.REQUIRED_TMPFS_OPTIONS}'
                })
                continue
            
            # If all checks pass, it's an approved tmpfs
            approved_tmpfs_mounts.append({
                'destination': destination,
                'size_mb': size_mb,
                'options': options
            })
        
        # Also check legacy Binds format
        if binds is not None and len(binds) > 0:
            for bind in binds:
                invalid_mounts.append({
                    'type': 'bind',
                    'bind': bind,
                    'reason': 'Legacy bind mounts format is prohibited'
                })
        
        # Validation passes if no invalid mounts and at least some approved tmpfs
        # (or no mounts at all is also acceptable for backward compatibility)
        has_invalid_mounts = len(invalid_mounts) > 0
        
        check = SecurityCheck(
            property_name="bind_mounts",
            passed=not has_invalid_mounts,
            observed_value={
                'invalid_mounts': invalid_mounts if has_invalid_mounts else "none",
                'approved_tmpfs_mounts': approved_tmpfs_mounts if approved_tmpfs_mounts else "none",
                'total_mounts': len(mounts)
            },
            expected_condition="Only approved tmpfs mounts at /tmp and /analysis/temp (max 64MB, nosuid, nodev, noexec)"
        )
        result.add_check(check)
        
        if not check.passed:
            self.logger.error(
                f"Container {result.container_id} validation failed: invalid mounts detected",
                extra={
                    "extra_fields": {
                        "container_id": result.container_id,
                        "property": "bind_mounts",
                        "invalid_mounts": invalid_mounts,
                        "approved_tmpfs_mounts": approved_tmpfs_mounts
                    }
                }
            )
    
    def _check_pid_mode(self, container: Container, result: ValidationResult) -> None:
        """Validate container does not share host PID namespace.
        
        Docker Desktop default/private PID namespace is represented by empty
        string "". We only reject explicit "host" mode.
        """
        host_config = container.attrs.get('HostConfig', {})
        pid_mode = host_config.get('PidMode', '')
        
        # Reject only explicit host PID namespace sharing
        is_host_pid = pid_mode == 'host'
        
        check = SecurityCheck(
            property_name="pid_mode",
            passed=not is_host_pid,
            observed_value=pid_mode if pid_mode else "default/private",
            expected_condition="PidMode must not be 'host'"
        )
        result.add_check(check)
        
        if not check.passed:
            self.logger.error(
                f"Container {result.container_id} validation failed: pid_mode={pid_mode}",
                extra={
                    "extra_fields": {
                        "container_id": result.container_id,
                        "property": "pid_mode",
                        "observed": pid_mode,
                        "expected": "not 'host'"
                    }
                }
            )
    
    def _check_ipc_mode(self, container: Container, result: ValidationResult) -> None:
        """Validate container does not share host IPC namespace.
        
        Docker Desktop reports "private" for private IPC namespace.
        We reject explicit "host" mode.
        """
        host_config = container.attrs.get('HostConfig', {})
        ipc_mode = host_config.get('IpcMode', '')
        
        # Reject only explicit host IPC namespace sharing
        is_host_ipc = ipc_mode == 'host'
        
        check = SecurityCheck(
            property_name="ipc_mode",
            passed=not is_host_ipc,
            observed_value=ipc_mode if ipc_mode else "default",
            expected_condition="IpcMode must not be 'host'"
        )
        result.add_check(check)
        
        if not check.passed:
            self.logger.error(
                f"Container {result.container_id} validation failed: ipc_mode={ipc_mode}",
                extra={
                    "extra_fields": {
                        "container_id": result.container_id,
                        "property": "ipc_mode",
                        "observed": ipc_mode,
                        "expected": "not 'host'"
                    }
                }
            )
    
    def _check_network_mode(self, container: Container, result: ValidationResult) -> None:
        """Validate container does not share host network namespace.
        
        For initial validation lifecycle, we require network=none.
        This will be relaxed in future phases for controlled network access.
        """
        host_config = container.attrs.get('HostConfig', {})
        network_mode = host_config.get('NetworkMode', '')
        
        # For Phase 2, require network=none for initial validation
        # Reject host network mode
        is_host_network = network_mode == 'host'
        is_none_network = network_mode == 'none'
        
        check = SecurityCheck(
            property_name="network_mode",
            passed=is_none_network and not is_host_network,
            observed_value=network_mode if network_mode else "default",
            expected_condition="NetworkMode must be 'none' for initial validation lifecycle"
        )
        result.add_check(check)
        
        if not check.passed:
            self.logger.error(
                f"Container {result.container_id} validation failed: network_mode={network_mode}",
                extra={
                    "extra_fields": {
                        "container_id": result.container_id,
                        "property": "network_mode",
                        "observed": network_mode,
                        "expected": "none"
                    }
                }
            )
    
    def _check_capabilities(self, container: Container, result: ValidationResult) -> None:
        """Validate container capabilities are properly restricted.
        
        Hardened configuration requires:
        - CapDrop must contain "ALL"
        - No CapAdd entries allowed
        """
        host_config = container.attrs.get('HostConfig', {})
        cap_add = host_config.get('CapAdd') or []
        cap_drop = host_config.get('CapDrop') or []
        
        # CapDrop must contain "ALL"
        has_all_drop = 'ALL' in cap_drop
        
        # Any CapAdd entry is rejected
        has_any_cap_add = len(cap_add) > 0
        
        check = SecurityCheck(
            property_name="capabilities",
            passed=has_all_drop and not has_any_cap_add,
            observed_value={
                'cap_add': cap_add,
                'cap_drop': cap_drop,
                'has_all_drop': has_all_drop,
                'has_any_cap_add': has_any_cap_add
            },
            expected_condition="CapDrop must contain 'ALL', no CapAdd entries allowed"
        )
        result.add_check(check)
        
        if not check.passed:
            self.logger.error(
                f"Container {result.container_id} validation failed: capabilities check failed",
                extra={
                    "extra_fields": {
                        "container_id": result.container_id,
                        "property": "capabilities",
                        "cap_add": cap_add,
                        "cap_drop": cap_drop,
                        "has_all_drop": has_all_drop,
                        "has_any_cap_add": has_any_cap_add
                    }
                }
            )
    
    def _check_no_new_privileges(self, container: Container, result: ValidationResult) -> None:
        """Validate container has no-new-privileges enabled."""
        host_config = container.attrs.get('HostConfig', {})
        security_opt = host_config.get('SecurityOpt') or []
        
        # Check for no-new-privileges in SecurityOpt
        has_no_new_privs = any('no-new-privileges' in str(opt) for opt in security_opt)
        
        check = SecurityCheck(
            property_name="no_new_privileges",
            passed=has_no_new_privs,
            observed_value=security_opt,
            expected_condition="no-new-privileges must be enabled in SecurityOpt"
        )
        result.add_check(check)
        
        if not check.passed:
            self.logger.error(
                f"Container {result.container_id} validation failed: no_new_privileges missing",
                extra={
                    "extra_fields": {
                        "container_id": result.container_id,
                        "property": "no_new_privileges",
                        "observed": security_opt,
                        "expected": "no-new-privileges enabled"
                    }
                }
            )
    
    def _check_memory_limit(self, container: Container, result: ValidationResult) -> None:
        """Validate container has memory limit configured."""
        host_config = container.attrs.get('HostConfig', {})
        memory_limit = host_config.get('Memory', 0)
        
        # Memory limit must be > 0
        has_memory_limit = memory_limit > 0
        
        check = SecurityCheck(
            property_name="memory_limit",
            passed=has_memory_limit,
            observed_value=memory_limit,
            expected_condition="Memory limit must be configured (> 0)"
        )
        result.add_check(check)
        
        if not check.passed:
            self.logger.error(
                f"Container {result.container_id} validation failed: memory_limit={memory_limit}",
                extra={
                    "extra_fields": {
                        "container_id": result.container_id,
                        "property": "memory_limit",
                        "observed": memory_limit,
                        "expected": "> 0"
                    }
                }
            )
    
    def _check_pid_limit(self, container: Container, result: ValidationResult) -> None:
        """Validate container has PID limit configured."""
        host_config = container.attrs.get('HostConfig', {})
        pid_limit = host_config.get('PidsLimit')
        
        # PidsLimit must be configured (not None)
        has_pid_limit = pid_limit is not None
        
        check = SecurityCheck(
            property_name="pid_limit",
            passed=has_pid_limit,
            observed_value=pid_limit,
            expected_condition="PID limit must be configured"
        )
        result.add_check(check)
        
        if not check.passed:
            self.logger.error(
                f"Container {result.container_id} validation failed: pid_limit={pid_limit}",
                extra={
                    "extra_fields": {
                        "container_id": result.container_id,
                        "property": "pid_limit",
                        "observed": pid_limit,
                        "expected": "configured (not None)"
                    }
                }
            )
    
    def _check_cpu_limits(self, container: Container, result: ValidationResult) -> None:
        """Validate container has CPU restrictions configured."""
        host_config = container.attrs.get('HostConfig', {})
        
        # Check for any CPU限制 configuration
        cpu_quota = host_config.get('CpuQuota', 0)
        cpu_period = host_config.get('CpuPeriod', 0)
        cpu_shares = host_config.get('CpuShares', 0)
        nano_cpus = host_config.get('NanoCpus', 0)
        cpuset_cpus = host_config.get('CpusetCpus', '')
        
        # At least one CPU restriction should be configured
        has_cpu_limit = (
            cpu_quota > 0 or
            cpu_period > 0 or
            cpu_shares > 0 or
            nano_cpus > 0 or
            len(cpuset_cpus) > 0
        )
        
        check = SecurityCheck(
            property_name="cpu_limits",
            passed=has_cpu_limit,
            observed_value={
                'cpu_quota': cpu_quota,
                'cpu_period': cpu_period,
                'cpu_shares': cpu_shares,
                'nano_cpus': nano_cpus,
                'cpuset_cpus': cpuset_cpus
            },
            expected_condition="At least one CPU restriction must be configured"
        )
        result.add_check(check)
        
        if not check.passed:
            self.logger.error(
                f"Container {result.container_id} validation failed: cpu_limits missing",
                extra={
                    "extra_fields": {
                        "container_id": result.container_id,
                        "property": "cpu_limits",
                        "observed": {
                            'cpu_quota': cpu_quota,
                            'cpu_period': cpu_period,
                            'cpu_shares': cpu_shares,
                            'nano_cpus': nano_cpus,
                            'cpuset_cpus': cpuset_cpus
                        },
                        "expected": "at least one restriction configured"
                    }
                }
            )
    
    def _check_user(self, container: Container, result: ValidationResult) -> None:
        """Validate container runs as non-root user."""
        config = container.attrs.get('Config', {})
        user = config.get('User', '')
        
        # User should be specified and not root/0
        is_root = user == '' or user == 'root' or user == '0'
        
        check = SecurityCheck(
            property_name="user",
            passed=not is_root,
            observed_value=user if user else "root (default)",
            expected_condition="Container must run as non-root user"
        )
        result.add_check(check)
        
        if not check.passed:
            self.logger.error(
                f"Container {result.container_id} validation failed: user={user}",
                extra={
                    "extra_fields": {
                        "container_id": result.container_id,
                        "property": "user",
                        "observed": user if user else "root (default)",
                        "expected": "non-root user"
                    }
                }
            )
