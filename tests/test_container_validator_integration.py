"""Integration tests for container security configuration validation.

These tests use real Docker containers to validate actual Docker Desktop
behavior. Tests are safe - they do not open external websites or perform
malicious operations.
"""

import pytest
import docker
from docker.errors import NotFound

from src.container_validator import ContainerValidator


@pytest.fixture(scope="module")
def docker_client():
    """Create a Docker client for integration tests."""
    try:
        client = docker.from_env()
        # Verify Docker is available
        client.ping()
        return client
    except Exception as e:
        pytest.skip(f"Docker not available: {e}")


@pytest.fixture
def validator(docker_client):
    """Create ContainerValidator with real Docker client."""
    return ContainerValidator()


class TestDockerIntegration:
    """Integration tests with real Docker containers."""
    
    def test_default_container_observed_values(self, docker_client, validator):
        """Test inspection of default container to observe actual Docker Desktop values."""
        # Create a minimal container with default settings
        container = docker_client.containers.run(
            "python:3.11-slim",
            "sleep 30",
            detach=True,
            remove=False
        )
        
        try:
            # Inspect the container's actual configuration
            result = validator.validate_container(container)
            
            # Log observed values for documentation
            host_config = container.attrs.get('HostConfig', {})
            
            print("\n=== Docker Desktop Observed Values ===")
            print(f"PidMode: {repr(host_config.get('PidMode', ''))}")
            print(f"IpcMode: {repr(host_config.get('IpcMode', ''))}")
            print(f"NetworkMode: {repr(host_config.get('NetworkMode', ''))}")
            print(f"Privileged: {host_config.get('Privileged', False)}")
            print(f"ReadonlyRootfs: {host_config.get('ReadonlyRootfs', False)}")
            print(f"User: {repr(container.attrs.get('Config', {}).get('User', ''))}")
            print(f"========================================\n")
            
            # Default container should fail validation (not hardened)
            assert result.valid is False
            
            # But specific namespace checks should pass (not host mode)
            pid_check = next(c for c in result.checks if c.property_name == 'pid_mode')
            assert pid_check.passed is True, "Default PID mode should not be host"
            
            ipc_check = next(c for c in result.checks if c.property_name == 'ipc_mode')
            assert ipc_check.passed is True, "Default IPC mode should not be host"
            
        finally:
            try:
                container.stop()
                container.remove()
            except NotFound:
                pass
    
    def test_hardened_container_configuration(self, docker_client, validator):
        """Test a hardened container configuration passes validation."""
        # Create a container with security-hardened configuration
        container = docker_client.containers.run(
            "python:3.11-slim",
            "sleep 30",
            detach=True,
            remove=False,
            # Security settings
            privileged=False,
            read_only=True,
            network_mode="none",
            ipc_mode="private",
            pids_limit=100,
            mem_limit="512m",
            cpu_quota=50000,
            cpu_period=100000,
            security_opt=["no-new-privileges"],
            cap_drop=["ALL"],
            user="1000"
        )
        
        try:
            result = validator.validate_container(container)
            
            # Log validation results
            print("\n=== Hardened Container Validation ===")
            print(f"Valid: {result.valid}")
            print(f"Checks performed: {len(result.checks)}")
            print(f"Violations: {len(result.violations)}")
            if result.violations:
                for violation in result.violations:
                    print(f"  - {violation.property_name}: {violation.observed_value}")
            print("=====================================\n")
            
            # Hardened container should pass all security checks
            assert result.valid is True, f"Hardened container failed validation: {result.violations}"
            assert len(result.violations) == 0
            
        finally:
            try:
                container.stop()
                container.remove()
            except NotFound:
                pass
    
    def test_approved_tmpfs_configuration(self, docker_client, validator):
        """Test container with approved tmpfs configuration passes validation."""
        container = docker_client.containers.run(
            "python:3.11-slim",
            "sleep 30",
            detach=True,
            remove=False,
            # Security settings
            privileged=False,
            read_only=True,
            network_mode="none",
            ipc_mode="private",
            pids_limit=100,
            mem_limit="512m",
            cpu_quota=50000,
            cpu_period=100000,
            security_opt=["no-new-privileges"],
            cap_drop=["ALL"],
            user="1000",
            # Phase 3A approved tmpfs mounts
            tmpfs={
                '/tmp': 'size=64m,noexec,nosuid,nodev',
                '/analysis/temp': 'size=64m,noexec,nosuid,nodev'
            }
        )
        
        try:
            result = validator.validate_container(container)
            
            # Log validation results
            print("\n=== Approved Tmpfs Configuration ===")
            print(f"Valid: {result.valid}")
            print(f"Checks performed: {len(result.checks)}")
            print(f"Violations: {len(result.violations)}")
            if result.violations:
                for violation in result.violations:
                    print(f"  - {violation.property_name}: {violation.observed_value}")
            print("=====================================\n")
            
            # Container with approved tmpfs should pass validation
            assert result.valid is True, f"Approved tmpfs container failed validation: {result.violations}"
            assert len(result.violations) == 0
            
            # Check that tmpfs mounts are recognized as approved
            bind_check = next(c for c in result.checks if c.property_name == 'bind_mounts')
            assert bind_check.passed is True
            
            # Verify actual Docker attrs structure
            print("\n=== Actual Docker Tmpfs Configuration ===")
            host_config = container.attrs.get('HostConfig', {})
            tmpfs_config = host_config.get('Tmpfs', {})
            mounts = container.attrs.get('Mounts', [])
            print(f"Tmpfs config: {tmpfs_config}")
            print(f"Mounts: {mounts}")
            print("======================================\n")
            
        finally:
            try:
                container.stop()
                container.remove()
            except NotFound:
                pass
    
    def test_invalid_tmpfs_size_fails(self, docker_client, validator):
        """Test container with tmpfs size exceeding 64MB fails validation."""
        container = docker_client.containers.run(
            "python:3.11-slim",
            "sleep 30",
            detach=True,
            remove=False,
            # Security settings
            privileged=False,
            read_only=True,
            network_mode="none",
            ipc_mode="private",
            pids_limit=100,
            mem_limit="512m",
            cpu_quota=50000,
            cpu_period=100000,
            security_opt=["no-new-privileges"],
            cap_drop=["ALL"],
            user="1000",
            # Invalid tmpfs size (exceeds 64MB)
            tmpfs={
                '/tmp': 'size=128m,nosuid,nodev,noexec'
            }
        )
        
        try:
            result = validator.validate_container(container)
            
            # Container with oversized tmpfs should fail validation
            assert result.valid is False
            
            bind_check = next(c for c in result.checks if c.property_name == 'bind_mounts')
            assert bind_check.passed is False
            # Check that the failure is related to tmpfs size
            assert len(bind_check.observed_value['invalid_mounts']) > 0
            
        finally:
            try:
                container.stop()
                container.remove()
            except NotFound:
                pass
    
    def test_arbitrary_tmpfs_destination_fails(self, docker_client, validator):
        """Test container with tmpfs at non-approved destination fails validation."""
        container = docker_client.containers.run(
            "python:3.11-slim",
            "sleep 30",
            detach=True,
            remove=False,
            # Security settings
            privileged=False,
            read_only=True,
            network_mode="none",
            ipc_mode="private",
            pids_limit=100,
            mem_limit="512m",
            cpu_quota=50000,
            cpu_period=100000,
            security_opt=["no-new-privileges"],
            cap_drop=["ALL"],
            user="1000",
            # Invalid tmpfs destination
            tmpfs={
                '/var/tmp': 'size=64m,nosuid,nodev,noexec'
            }
        )
        
        try:
            result = validator.validate_container(container)
            
            # Container with arbitrary tmpfs destination should fail validation
            assert result.valid is False
            
            bind_check = next(c for c in result.checks if c.property_name == 'bind_mounts')
            assert bind_check.passed is False
            # Check that the failure is related to tmpfs destination
            assert len(bind_check.observed_value['invalid_mounts']) > 0
            
        finally:
            try:
                container.stop()
                container.remove()
            except NotFound:
                pass
    
    def test_privileged_container_fails(self, docker_client, validator):
        """Test that privileged container fails validation."""
        container = docker_client.containers.run(
            "python:3.11-slim",
            "sleep 30",
            detach=True,
            remove=False,
            privileged=True
        )
        
        try:
            result = validator.validate_container(container)
            
            assert result.valid is False
            privileged_check = next(c for c in result.checks if c.property_name == 'privileged')
            assert privileged_check.passed is False
            
        finally:
            try:
                container.stop()
                container.remove()
            except NotFound:
                pass
    
    def test_host_pid_namespace_fails(self, docker_client, validator):
        """Test that host PID namespace fails validation."""
        container = docker_client.containers.run(
            "python:3.11-slim",
            "sleep 30",
            detach=True,
            remove=False,
            pid_mode="host"
        )
        
        try:
            result = validator.validate_container(container)
            
            assert result.valid is False
            pid_check = next(c for c in result.checks if c.property_name == 'pid_mode')
            assert pid_check.passed is False
            assert pid_check.observed_value == 'host'
            
        finally:
            try:
                container.stop()
                container.remove()
            except NotFound:
                pass
    
    def test_host_ipc_namespace_fails(self, docker_client, validator):
        """Test that host IPC namespace fails validation."""
        container = docker_client.containers.run(
            "python:3.11-slim",
            "sleep 30",
            detach=True,
            remove=False,
            ipc_mode="host"
        )
        
        try:
            result = validator.validate_container(container)
            
            assert result.valid is False
            ipc_check = next(c for c in result.checks if c.property_name == 'ipc_mode')
            assert ipc_check.passed is False
            assert ipc_check.observed_value == 'host'
            
        finally:
            try:
                container.stop()
                container.remove()
            except NotFound:
                pass
    
    def test_host_network_namespace_fails(self, docker_client, validator):
        """Test that host network namespace fails validation."""
        container = docker_client.containers.run(
            "python:3.11-slim",
            "sleep 30",
            detach=True,
            remove=False,
            network_mode="host"
        )
        
        try:
            result = validator.validate_container(container)
            
            assert result.valid is False
            network_check = next(c for c in result.checks if c.property_name == 'network_mode')
            assert network_check.passed is False
            assert network_check.observed_value == 'host'
            
        finally:
            try:
                container.stop()
                container.remove()
            except NotFound:
                pass
    
    def test_root_user_fails(self, docker_client, validator):
        """Test that running as root user fails validation."""
        container = docker_client.containers.run(
            "python:3.11-slim",
            "sleep 30",
            detach=True,
            remove=False,
            user="root"
        )
        
        try:
            result = validator.validate_container(container)
            
            assert result.valid is False
            user_check = next(c for c in result.checks if c.property_name == 'user')
            assert user_check.passed is False
            
        finally:
            try:
                container.stop()
                container.remove()
            except NotFound:
                pass
    
    def test_bind_mount_fails(self, docker_client, validator):
        """Test that bind mounts fail validation."""
        # Create a temporary file for bind mount
        import tempfile
        import os
        
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.txt")
            with open(test_file, 'w') as f:
                f.write("test")
            
            container = docker_client.containers.run(
                "python:3.11-slim",
                "sleep 30",
                detach=True,
                remove=False,
                volumes={tmpdir: {'bind': '/mnt', 'mode': 'ro'}}
            )
            
            try:
                result = validator.validate_container(container)
                
                assert result.valid is False
                bind_check = next(c for c in result.checks if c.property_name == 'bind_mounts')
                assert bind_check.passed is False
                
            finally:
                try:
                    container.stop()
                    container.remove()
                except NotFound:
                    pass
    
    def test_non_root_user_passes(self, docker_client, validator):
        """Test that non-root user passes user validation."""
        container = docker_client.containers.run(
            "python:3.11-slim",
            "sleep 30",
            detach=True,
            remove=False,
            user="1000"
        )
        
        try:
            result = validator.validate_container(container)
            
            # User check should pass
            user_check = next(c for c in result.checks if c.property_name == 'user')
            assert user_check.passed is True
            assert user_check.observed_value == '1000'
            
        finally:
            try:
                container.stop()
                container.remove()
            except NotFound:
                pass


class TestDockerDesktopSpecificBehavior:
    """Tests for Docker Desktop specific behavior on Windows/WSL2."""
    
    def test_pid_mode_default_representation(self, docker_client, validator):
        """Document how Docker Desktop represents default PID mode."""
        container = docker_client.containers.run(
            "python:3.11-slim",
            "sleep 30",
            detach=True,
            remove=False
        )
        
        try:
            host_config = container.attrs.get('HostConfig', {})
            pid_mode = host_config.get('PidMode', '')
            
            print(f"\n=== Docker Desktop PID Mode ===")
            print(f"Observed PidMode value: {repr(pid_mode)}")
            print(f"Type: {type(pid_mode)}")
            print(f"Is empty string: {pid_mode == ''}")
            print(f"===============================\n")
            
            # Validate our understanding
            result = validator.validate_container(container)
            pid_check = next(c for c in result.checks if c.property_name == 'pid_mode')
            
            # Default PID mode should pass (not host)
            assert pid_check.passed is True
            
        finally:
            try:
                container.stop()
                container.remove()
            except NotFound:
                pass
    
    def test_ipc_mode_default_representation(self, docker_client, validator):
        """Document how Docker Desktop represents default IPC mode."""
        container = docker_client.containers.run(
            "python:3.11-slim",
            "sleep 30",
            detach=True,
            remove=False
        )
        
        try:
            host_config = container.attrs.get('HostConfig', {})
            ipc_mode = host_config.get('IpcMode', '')
            
            print(f"\n=== Docker Desktop IPC Mode ===")
            print(f"Observed IpcMode value: {repr(ipc_mode)}")
            print(f"Type: {type(ipc_mode)}")
            print(f"===============================\n")
            
            # Validate our understanding
            result = validator.validate_container(container)
            ipc_check = next(c for c in result.checks if c.property_name == 'ipc_mode')
            
            # Default IPC mode should pass (not host)
            assert ipc_check.passed is True
            
        finally:
            try:
                container.stop()
                container.remove()
            except NotFound:
                pass
    
    def test_network_mode_default_representation(self, docker_client, validator):
        """Document how Docker Desktop represents default network mode."""
        container = docker_client.containers.run(
            "python:3.11-slim",
            "sleep 30",
            detach=True,
            remove=False
        )
        
        try:
            host_config = container.attrs.get('HostConfig', {})
            network_mode = host_config.get('NetworkMode', '')
            
            print(f"\n=== Docker Desktop Network Mode ===")
            print(f"Observed NetworkMode value: {repr(network_mode)}")
            print(f"Type: {type(network_mode)}")
            print(f"===================================\n")
            
            # Validate our understanding
            result = validator.validate_container(container)
            network_check = next(c for c in result.checks if c.property_name == 'network_mode')
            
            # Default network mode (bridge) should fail in Phase 2 (requires none)
            assert network_check.passed is False
            
        finally:
            try:
                container.stop()
                container.remove()
            except NotFound:
                pass
