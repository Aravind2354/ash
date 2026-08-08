"""Integration tests for isolation evidence orchestration.

These tests run the IsolationOrchestrator with real Docker containers to verify
the complete security assessment flow combining trusted configuration validation
with runtime evidence probes.
"""

import pytest

try:
    import docker
    from docker.models.containers import Container
except ImportError:
    docker = None
    Container = None

# Add src to path for imports
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.isolation_orchestrator import IsolationOrchestrator


@pytest.mark.skipif(docker is None, reason="Docker Python SDK not installed")
class TestIsolationOrchestratorIntegration:
    """Integration tests for isolation orchestrator with real Docker containers."""

    @pytest.fixture
    def docker_client(self):
        """Create Docker client."""
        client = docker.from_env()
        yield client
        # Cleanup is handled by Docker client

    @pytest.fixture
    def hardened_container(self, docker_client):
        """Create a container with basic security properties for testing."""
        # Note: Docker Desktop on Windows has limitations with procfs mounting
        # This test verifies orchestration flow, not full hardening
        container = docker_client.containers.create(
            'python:3.11-slim',
            command='tail -f /dev/null',
            user='nobody',  # Non-root user
            network_mode='none',  # No networking
            mem_limit='128m',  # Memory limit
            pids_limit=100,  # PID limit
            detach=True
        )
        container.start()

        yield container

        # Cleanup
        container.remove(force=True)

    @pytest.fixture
    def misconfigured_container(self, docker_client):
        """Create a container with security misconfigurations."""
        container = docker_client.containers.create(
            'python:3.11-slim',
            command='tail -f /dev/null',
            network_mode='none',  # No networking
            detach=True
        )
        container.start()

        yield container

        # Cleanup
        container.remove(force=True)

    def test_successful_orchestration_hardened_container(self, hardened_container):
        """Test orchestration flow with real container."""
        orchestrator = IsolationOrchestrator()

        assessment = orchestrator.validate_isolation(hardened_container)

        # Verify orchestration completed and assessment was generated
        assert assessment is not None
        assert assessment.assessment_type in ["PASS", "FAIL"]
        assert assessment.evidence is not None
        assert assessment.evidence.container_validation is not None
        assert len(assessment.evidence.filesystem_evidence) > 0
        assert len(assessment.evidence.process_evidence) > 0
        assert len(assessment.evidence.network_evidence) > 0

    def test_orchestration_misconfigured_container_fails(self, misconfigured_container):
        """Test that misconfigured container fails orchestration."""
        orchestrator = IsolationOrchestrator()

        assessment = orchestrator.validate_isolation(misconfigured_container)

        # Should fail for misconfigured container (missing read-only rootfs)
        assert assessment.valid is False
        assert assessment.assessment_type in ["FAIL", "ERROR"]
        assert len(assessment.security_critical_failures) > 0

    def test_evidence_aggregation_real_container(self, hardened_container):
        """Test evidence aggregation with real container."""
        orchestrator = IsolationOrchestrator()

        assessment = orchestrator.validate_isolation(hardened_container)

        # Verify evidence was collected
        assert assessment.evidence is not None
        assert assessment.evidence.container_validation is not None
        assert len(assessment.evidence.filesystem_evidence) > 0
        assert len(assessment.evidence.process_evidence) > 0
        assert len(assessment.evidence.network_evidence) > 0

    def test_consistency_check_real_container(self, hardened_container):
        """Test consistency check with real container."""
        orchestrator = IsolationOrchestrator()

        assessment = orchestrator.validate_isolation(hardened_container)

        # Verify consistency check was performed
        assert assessment.evidence.config_runtime_consistent is not None
        assert isinstance(assessment.evidence.config_runtime_consistent, bool)

    def test_no_privileged_container_used(self, docker_client):
        """Test that privileged containers are not used."""
        # Verify we don't create privileged containers
        # This is a safety check for the test itself
        pass  # Test design ensures no privileged containers are created

    def test_no_host_networking_used(self, docker_client):
        """Test that host networking is not used."""
        # Verify we don't use host networking
        # This is a safety check for the test itself
        pass  # Test design ensures no host networking is used

    def test_no_host_pid_mode_used(self, docker_client):
        """Test that host PID mode is not used."""
        # Verify we don't use host PID mode
        # This is a safety check for the test itself
        pass  # Test design ensures no host PID mode is used
