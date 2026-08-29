"""Docker container management with isolation validation.

This module provides ContainerManager class for creating and managing
Docker containers with comprehensive isolation validation before use.

SECURITY CRITICAL: This manager enforces fail-closed behavior for
container isolation. Containers are validated before being returned for use,
and any validation failure prevents container creation or reuse.

Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6
"""

import logging
from typing import Optional, Tuple
from datetime import datetime, timezone

try:
    import docker
    from docker.models.containers import Container
except ImportError:
    docker = None
    Container = None

from config.logging_config import get_logger


# Timeout for isolation validation failure (Requirement 6.2)
ISOLATION_FAILURE_TERMINATION_TIMEOUT = 2.0  # seconds


class ContainerManager:
    """Manages Docker container lifecycle with isolation validation.

    This class creates Docker containers with security-hardened configurations
    and validates isolation boundaries before allowing containers to be used
    for website analysis.

    Security Model:
    1. Create container with hardened configuration
    2. Validate isolation using ContainerValidator and runtime probes
    3. If validation fails, terminate within 2 seconds (Requirement 6.2)
    4. Return validated container for use
    5. Reset/revalidate between analyses (Requirement 6.6)
    """

    def __init__(self, sandbox_manager=None, violation_monitor=None):
        """Initialize the ContainerManager.

        Args:
            sandbox_manager: Optional SandboxManager to mark as validated
            violation_monitor: Optional ViolationMonitor for runtime violation detection
        """
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

        # Import validation components
        try:
            from src.container_validator import ContainerValidator
            from src.isolation_orchestrator import IsolationOrchestrator

            self.container_validator = ContainerValidator()
            self.isolation_orchestrator = IsolationOrchestrator()

            self.logger.info("Isolation validation components initialized")
        except ImportError as e:
            self.logger.error(f"Failed to import validation components: {e}")
            raise

        self.current_container: Optional[Container] = None
        self._is_validated = False
        self.sandbox_manager = sandbox_manager
        self.violation_monitor = violation_monitor

    def create_container(
        self,
        image: str = "python:3.11-slim",
        command: str = "tail -f /dev/null",
        **kwargs
    ) -> Container:
        """Create a hardened Docker container with isolation validation.

        Creates a container with security-hardened configuration, validates
        isolation boundaries, and returns the container only if validation passes.

        Args:
            image: Docker image to use
            command: Command to run in container
            **kwargs: Additional Docker container configuration

        Returns:
            Validated Docker Container instance

        Raises:
            RuntimeError: If container creation or validation fails
            TimeoutError: If validation timeout exceeded
        """
        self.logger.info(f"Creating hardened container with image: {image}")

        # Apply hardened defaults with comprehensive security isolation
        hardened_config = {
            "user": "nobody",  # Non-root user
            "network_mode": "bridge",  # Bridge networking for controlled external access
            "pid_mode": None,  # Isolated PID namespace (not host)
            "ipc_mode": "private",  # Isolated IPC namespace (not host)
            "mem_limit": "128m",  # Memory limit
            "pids_limit": 100,  # PID limit
            "cpu_quota": 50000,  # CPU quota (50% of 1 CPU)
            "cpu_period": 100000,  # CPU period for quota calculation
            "read_only": True,  # Read-only root filesystem
            "security_opt": ["no-new-privileges"],  # no-new-privileges flag
            "cap_drop": ["ALL"],  # Drop all capabilities
            "cap_add": [],  # No additional capabilities
            "privileged": False,  # No privileged mode
            "volumes": {},  # No volumes by default
            "tmpfs": {},  # No tmpfs by default
            "detach": True,
        }

        # Merge user-provided config but prevent security-critical overrides
        # Security-critical settings cannot be overridden by user config
        security_critical_keys = {
            "user", "privileged", "network_mode", "pid_mode", "ipc_mode",
            "read_only", "security_opt", "cap_drop", "cap_add",
            "pids_limit", "mem_limit", "cpu_quota", "cpu_period", "nano_cpus",
            "volumes", "binds", "tmpfs"
        }
        safe_kwargs = {k: v for k, v in kwargs.items() if k not in security_critical_keys}
        hardened_config.update(safe_kwargs)

        # Explicitly prevent Docker socket access
        self._check_no_docker_socket_access(kwargs)

        # Explicitly prevent host filesystem mounts
        self._check_no_host_filesystem_mounts(kwargs)

        try:
            # Create container
            container = self.docker_client.containers.create(
                image,
                command=command,
                **hardened_config
            )

            container.start()
            self.logger.info(f"Container created and started: {container.id[:12]}")

            # Validate isolation before returning
            is_valid, error_msg = self.validate_isolation(container)

            if not is_valid:
                # Validation failed - terminate within 2 seconds (Requirement 6.2)
                self.logger.error(
                    f"Container isolation validation failed: {error_msg}",
                    extra={
                        "extra_fields": {
                            "container_id": container.id[:12],
                            "validation_error": error_msg,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                    }
                )

                # Terminate container immediately
                try:
                    container.remove(force=True)
                    self.logger.info(f"Terminated invalid container: {container.id[:12]}")
                except Exception as e:
                    self.logger.error(f"Error terminating invalid container: {e}")

                raise RuntimeError(
                    f"Container isolation validation failed: {error_msg}. "
                    f"Container terminated per Requirement 6.2."
                )

            # Validation passed
            self.current_container = container
            self._is_validated = True
            self.logger.info(
                f"Container isolation validated successfully: {container.id[:12]}"
            )

            # Mark SandboxManager as validated if provided
            if self.sandbox_manager:
                self.sandbox_manager.set_isolation_validated(container.id[:12])
                self.logger.info(
                    f"SandboxManager marked as validated for container: {container.id[:12]}"
                )

            return container

        except Exception as e:
            self.logger.error(f"Failed to create container: {e}", exc_info=True)
            raise RuntimeError(f"Container creation failed: {e}")

    def validate_isolation(self, container: Container) -> Tuple[bool, str]:
        """Validate container isolation boundaries.

        Validates that the container meets all security requirements before
        allowing it to be used for website analysis.

        This method integrates:
        - ContainerValidator (trusted host-side configuration validation)
        - IsolationOrchestrator (runtime evidence aggregation)
        - ViolationMonitor (runtime violation detection, Requirement 6.5)

        Args:
            container: Docker container to validate

        Returns:
            Tuple of (is_valid: bool, error_message: str)
            - (True, "") if validation passes
            - (False, error_message) if validation fails
        """
        container_id = container.id[:12]
        self.logger.info(f"Starting isolation validation for container {container_id}")

        try:
            # Use IsolationOrchestrator for comprehensive validation
            assessment = self.isolation_orchestrator.validate_isolation(container)

            # Check for runtime violations in the evidence (Requirement 6.5)
            if self.violation_monitor:
                try:
                    self._check_for_violations(assessment, container_id)
                except Exception as e:
                    self.logger.error(f"Error checking for violations: {e}")
                    # Violation check errors fail closed for security
                    return False, f"Violation check error: {e}"

            # Check assessment result
            if assessment.valid and assessment.assessment_type == "PASS":
                self.logger.info(
                    f"Container {container_id} isolation validation PASSED",
                    extra={
                        "extra_fields": {
                            "container_id": container_id,
                            "assessment_type": assessment.assessment_type,
                            "timestamp": assessment.timestamp.isoformat()
                        }
                    }
                )
                return True, ""
            else:
                # Validation failed
                error_msg = assessment.error_message or "Unknown validation failure"
                failures = ", ".join(assessment.security_critical_failures)

                self.logger.error(
                    f"Container {container_id} isolation validation FAILED: {error_msg}",
                    extra={
                        "extra_fields": {
                            "container_id": container_id,
                            "assessment_type": assessment.assessment_type,
                            "failures": failures,
                            "timestamp": assessment.timestamp.isoformat()
                        }
                    }
                )

                return False, f"{error_msg} (failures: {failures})"

        except Exception as e:
            self.logger.error(
                f"Error during isolation validation for {container_id}: {e}",
                exc_info=True
            )
            return False, f"Validation error: {e}"

    def _check_for_violations(self, assessment, container_id: str) -> None:
        """Check isolation assessment for runtime violations (Requirement 6.5).

        Args:
            assessment: Isolation assessment from IsolationOrchestrator
            container_id: Container identifier
        """
        # Check network evidence for internal IP connections
        network_evidence = assessment.evidence.network_evidence
        if network_evidence and isinstance(network_evidence, dict):
            if 'network_interface_evidence' in network_evidence:
                evidence = network_evidence['network_interface_evidence']
                if hasattr(evidence, 'observed_value') and isinstance(evidence.observed_value, dict):
                    # Check for internal IP addresses in interface configuration
                    if 'addresses' in evidence.observed_value:
                        for addr in evidence.observed_value['addresses']:
                            if self.violation_monitor.is_internal_ip(addr):
                                self.violation_monitor.log_network_violation(
                                    ip_address=addr,
                                    container_id=container_id,
                                    details={'source': 'network_interface_evidence'}
                                )

        # Check if any critical probes failed - these may indicate violations
        if self.violation_monitor and isinstance(network_evidence, dict):
            for domain, probes in self.isolation_orchestrator.CRITICAL_ISOLATION_PROPERTIES.items():
                for probe in probes:
                    if domain == 'network' and probe in network_evidence:
                        probe_result = network_evidence[probe]
                        if hasattr(probe_result, 'passed') and not probe_result.passed:
                            # Network probe failed - could indicate internal network access
                            if hasattr(probe_result, 'observed_value') and isinstance(probe_result.observed_value, dict):
                                if 'addresses' in probe_result.observed_value:
                                    for addr in probe_result.observed_value['addresses']:
                                        if self.violation_monitor.is_internal_ip(addr):
                                            self.violation_monitor.log_network_violation(
                                                ip_address=addr,
                                                container_id=container_id,
                                                details={'source': f'probe_{probe}'}
                                            )

    def _check_no_docker_socket_access(self, kwargs: dict) -> None:
        """Explicitly prevent Docker socket access through volumes or binds.

        Args:
            kwargs: User-provided container configuration

        Raises:
            RuntimeError: If Docker socket access is detected
        """
        docker_socket_paths = [
            '/var/run/docker.sock',
            'docker.sock',
            '/var/run/docker.sock:/var/run/docker.sock',
            '//./pipe/docker_engine',  # Windows Docker socket
        ]

        # Check volumes
        volumes = kwargs.get('volumes', {})
        if volumes:
            for mount_path in volumes.keys():
                if any(socket_path in str(mount_path) for socket_path in docker_socket_paths):
                    raise RuntimeError(
                        f"Docker socket access denied: {mount_path}. "
                        "Docker socket access is security-critical and explicitly prohibited."
                    )

        # Check binds
        binds = kwargs.get('binds', [])
        if binds:
            for bind in binds:
                if any(socket_path in str(bind) for socket_path in docker_socket_paths):
                    raise RuntimeError(
                        f"Docker socket access denied: {bind}. "
                        "Docker socket access is security-critical and explicitly prohibited."
                    )

    def _check_no_host_filesystem_mounts(self, kwargs: dict) -> None:
        """Explicitly prevent arbitrary host filesystem mounts.

        Args:
            kwargs: User-provided container configuration

        Raises:
            RuntimeError: If host filesystem mount is detected
        """
        # Critical host paths that must never be mounted
        critical_host_paths = [
            '/',  # Root filesystem
            '/etc',  # System configuration
            '/home',  # User directories
            '/root',  # Root user directory
            '/var',  # Variable data
            '/var/run',  # Runtime data
            '/usr',  # System binaries
            '/bin',  # Binaries
            '/sbin',  # System binaries
            'C:\\',  # Windows root
            'C:\\Users',  # Windows user directories
            'C:\\Windows',  # Windows system
        ]

        # Check volumes
        volumes = kwargs.get('volumes', {})
        if volumes:
            for mount_path in volumes.keys():
                mount_str = str(mount_path)
                # Check if mount is from host (contains : separator for host:container)
                if ':' in mount_str:
                    host_path = mount_str.split(':')[0]
                    # Check against critical paths
                    for critical_path in critical_host_paths:
                        if host_path.startswith(critical_path) or critical_path in host_path:
                            raise RuntimeError(
                                f"Host filesystem mount denied: {host_path}. "
                                f"Mounting {critical_path} is security-critical and explicitly prohibited."
                            )

        # Check binds
        binds = kwargs.get('binds', [])
        if binds:
            for bind in binds:
                bind_str = str(bind)
                # Extract host path from bind specification
                if ':' in bind_str:
                    host_path = bind_str.split(':')[0]
                    # Check against critical paths
                    for critical_path in critical_host_paths:
                        if host_path.startswith(critical_path) or critical_path in host_path:
                            raise RuntimeError(
                                f"Host filesystem mount denied: {host_path}. "
                                f"Mounting {critical_path} is security-critical and explicitly prohibited."
                            )

    def get_container(self) -> Container:
        """Get the current validated container.

        Returns:
            Current validated Container instance

        Raises:
            RuntimeError: If no validated container exists
        """
        if self.current_container is None or not self._is_validated:
            raise RuntimeError(
                "No validated container exists. Call create_container() first."
            )
        return self.current_container

    def reset_container(self) -> Container:
        """Reset container environment between analyses.

        Terminates current container, creates fresh container with same
        configuration, and validates isolation before returning.

        Requirements: 6.6

        Returns:
            Newly validated Container instance

        Raises:
            RuntimeError: If reset or validation fails
        """
        self.logger.info("Resetting container environment")

        # Terminate current container
        if self.current_container is not None:
            try:
                self.current_container.remove(force=True)
                self.logger.info(f"Terminated previous container: {self.current_container.id[:12]}")
            except Exception as e:
                self.logger.error(f"Error terminating previous container: {e}")

        self.current_container = None
        self._is_validated = False

        # Create new container with same configuration
        # Note: In production, you would want to store and reuse the original config
        return self.create_container()

    def terminate_container(self, force: bool = False) -> None:
        """Terminate the current container.

        Args:
            force: If True, force terminate immediately
        """
        if self.current_container is None:
            self.logger.warning("No container to terminate")
            return

        self.logger.info(f"Terminating container (force={force})")

        try:
            self.current_container.remove(force=force)
            self.logger.info(f"Container terminated: {self.current_container.id[:12]}")
        except Exception as e:
            self.logger.error(f"Error terminating container: {e}")
        finally:
            self.current_container = None
            self._is_validated = False

    def cleanup(self) -> None:
        """Complete cleanup of all ContainerManager resources."""
        self.logger.info("Performing complete ContainerManager cleanup")
        self.terminate_container(force=True)
        self.logger.info("ContainerManager cleanup complete")
