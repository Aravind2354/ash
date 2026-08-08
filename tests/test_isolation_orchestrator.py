"""Unit tests for isolation evidence orchestration.

Tests the IsolationOrchestrator class that aggregates trusted Docker
configuration validation with runtime evidence from filesystem, process,
and network probes to produce comprehensive security assessments.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

# Add src to path for imports
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.isolation_orchestrator import IsolationOrchestrator, EvidenceAggregate, IsolationAssessment


@pytest.fixture
def orchestrator():
    """Create an IsolationOrchestrator instance for testing."""
    return IsolationOrchestrator()


@pytest.fixture
def mock_container():
    """Create a mock Docker container."""
    container = Mock(spec=['id', 'reload'])
    container.id = 'abc123def456789'
    return container


class TestEvidenceAggregate:
    """Test EvidenceAggregate dataclass."""

    def test_evidence_aggregate_initialization(self):
        """Test EvidenceAggregate initializes correctly."""
        aggregate = EvidenceAggregate()

        assert aggregate.container_validation is None
        assert aggregate.filesystem_evidence == {}
        assert aggregate.process_evidence == {}
        assert aggregate.network_evidence == {}
        assert aggregate.config_runtime_consistent is False
        assert aggregate.all_critical_evidence_collected is False
        assert aggregate.evidence_collection_errors == []
        assert isinstance(aggregate.timestamp, datetime)

    def test_evidence_aggregate_with_data(self):
        """Test EvidenceAggregate stores data correctly."""
        container_validation = Mock(valid=True)
        filesystem_evidence = {'rootfs_readonly': Mock(passed=True)}
        process_evidence = {'pid_namespace_evidence': Mock(passed=True)}
        network_evidence = {'network_namespace_evidence': Mock(passed=True)}

        aggregate = EvidenceAggregate(
            container_validation=container_validation,
            filesystem_evidence=filesystem_evidence,
            process_evidence=process_evidence,
            network_evidence=network_evidence,
            config_runtime_consistent=True,
            all_critical_evidence_collected=True
        )

        assert aggregate.container_validation == container_validation
        assert aggregate.filesystem_evidence == filesystem_evidence
        assert aggregate.process_evidence == process_evidence
        assert aggregate.network_evidence == network_evidence
        assert aggregate.config_runtime_consistent is True
        assert aggregate.all_critical_evidence_collected is True


class TestIsolationAssessment:
    """Test IsolationAssessment dataclass."""

    def test_isolation_assessment_initialization(self, orchestrator):
        """Test IsolationAssessment initializes correctly."""
        evidence = EvidenceAggregate()
        assessment = IsolationAssessment(
            valid=True,
            assessment_type="PASS",
            container_id="test123",
            evidence=evidence
        )

        assert assessment.valid is True
        assert assessment.assessment_type == "PASS"
        assert assessment.container_id == "test123"
        assert assessment.evidence == evidence
        assert assessment.security_critical_failures == []
        assert assessment.warnings == []
        assert assessment.error_message is None
        assert isinstance(assessment.timestamp, datetime)

    def test_isolation_assessment_with_failures(self, orchestrator):
        """Test IsolationAssessment stores failures correctly."""
        evidence = EvidenceAggregate()
        assessment = IsolationAssessment(
            valid=False,
            assessment_type="FAIL",
            container_id="test123",
            evidence=evidence,
            security_critical_failures=["config_privileged", "evidence_missing"]
        )

        assert assessment.valid is False
        assert assessment.assessment_type == "FAIL"
        assert "config_privileged" in assessment.security_critical_failures
        assert "evidence_missing" in assessment.security_critical_failures


class TestContainerValidatorFailure:
    """Test orchestrator behavior when ContainerValidator fails."""

    def test_container_validation_failure_fails_closed(self, orchestrator, mock_container):
        """Test that ContainerValidator failure results in FAIL assessment."""
        with patch.object(orchestrator, 'container_validator') as mock_validator:
            mock_container_validation = Mock(valid=False)
            mock_container_validation.violations = [Mock(property_name='privileged')]
            mock_validator.validate_container.return_value = mock_container_validation

            assessment = orchestrator.validate_isolation(mock_container)

            assert assessment.valid is False
            assert assessment.assessment_type == "FAIL"
            assert "container_configuration_invalid" in assessment.security_critical_failures
            assert "config_privileged" in assessment.security_critical_failures
            assert assessment.error_message is not None

    def test_container_validation_exception_fails_closed(self, orchestrator, mock_container):
        """Test that ContainerValidator exception results in ERROR assessment."""
        with patch.object(orchestrator, 'container_validator') as mock_validator:
            mock_validator.validate_container.side_effect = Exception("Validation error")

            assessment = orchestrator.validate_isolation(mock_container)

            assert assessment.valid is False
            assert assessment.assessment_type == "ERROR"
            assert "container_validation_error" in assessment.security_critical_failures
            assert assessment.error_message is not None


class TestFilesystemEvidenceFailure:
    """Test orchestrator behavior when filesystem evidence fails."""

    def test_filesystem_evidence_missing_fails_closed(self, orchestrator, mock_container):
        """Test that missing filesystem evidence results in FAIL assessment."""
        with patch.object(orchestrator, 'container_validator') as mock_validator:
            with patch.object(orchestrator, 'filesystem_probes') as mock_fs:
                # Container validation passes
                mock_container_validation = Mock(valid=True, violations=[])
                mock_validator.validate_container.return_value = mock_container_validation

                # Filesystem evidence returns empty dict
                mock_fs.run_all_probes.return_value = {}

                assessment = orchestrator.validate_isolation(mock_container)

                assert assessment.valid is False
                assert assessment.assessment_type == "FAIL"
                assert "critical_evidence_missing" in assessment.security_critical_failures
                assert "missing_rootfs_readonly" in assessment.security_critical_failures

    def test_filesystem_probe_failure_fails_closed(self, orchestrator, mock_container):
        """Test that filesystem probe failure results in FAIL assessment."""
        with patch.object(orchestrator, 'container_validator') as mock_validator:
            with patch.object(orchestrator, 'filesystem_probes') as mock_fs:
                # Container validation passes
                mock_container_validation = Mock(valid=True, violations=[])
                mock_validator.validate_container.return_value = mock_container_validation

                # Filesystem evidence includes failed probe
                mock_fs.run_all_probes.return_value = {
                    'rootfs_readonly': Mock(passed=False),
                    'tmpfs_writability': Mock(passed=True)
                }

                assessment = orchestrator.validate_isolation(mock_container)

                assert assessment.valid is False
                assert assessment.assessment_type == "FAIL"
                assert "filesystem_rootfs_readonly_failed" in assessment.security_critical_failures

    def test_filesystem_collection_exception_fails_closed(self, orchestrator, mock_container):
        """Test that filesystem collection exception results in FAIL assessment."""
        with patch.object(orchestrator, 'container_validator') as mock_validator:
            with patch.object(orchestrator, 'filesystem_probes') as mock_fs:
                # Container validation passes
                mock_container_validation = Mock(valid=True, violations=[])
                mock_validator.validate_container.return_value = mock_container_validation

                # Filesystem collection raises exception
                mock_fs.run_all_probes.side_effect = Exception("Collection error")

                assessment = orchestrator.validate_isolation(mock_container)

                assert assessment.valid is False
                assert assessment.assessment_type == "FAIL"
                assert "critical_evidence_missing" in assessment.security_critical_failures


class TestProcessEvidenceFailure:
    """Test orchestrator behavior when process evidence fails."""

    def test_process_evidence_missing_fails_closed(self, orchestrator, mock_container):
        """Test that missing process evidence results in FAIL assessment."""
        with patch.object(orchestrator, 'container_validator') as mock_validator:
            with patch.object(orchestrator, 'process_probes') as mock_proc:
                # Container validation passes
                mock_container_validation = Mock(valid=True, violations=[])
                mock_validator.validate_container.return_value = mock_container_validation

                # Process evidence returns empty dict
                mock_proc.run_all_probes.return_value = {}

                assessment = orchestrator.validate_isolation(mock_container)

                assert assessment.valid is False
                assert assessment.assessment_type == "FAIL"
                assert "critical_evidence_missing" in assessment.security_critical_failures
                assert "missing_pid_namespace_evidence" in assessment.security_critical_failures

    def test_process_probe_failure_fails_closed(self, orchestrator, mock_container):
        """Test that process probe failure results in FAIL assessment."""
        with patch.object(orchestrator, 'container_validator') as mock_validator:
            with patch.object(orchestrator, 'process_probes') as mock_proc:
                # Container validation passes
                mock_container_validation = Mock(valid=True, violations=[])
                mock_validator.validate_container.return_value = mock_container_validation

                # Process evidence includes failed probe
                mock_proc.run_all_probes.return_value = {
                    'pid_namespace_evidence': Mock(passed=False),
                    'process_visibility': Mock(passed=True)
                }

                assessment = orchestrator.validate_isolation(mock_container)

                assert assessment.valid is False
                assert assessment.assessment_type == "FAIL"
                assert "process_pid_namespace_evidence_failed" in assessment.security_critical_failures


class TestNetworkEvidenceFailure:
    """Test orchestrator behavior when network evidence fails."""

    def test_network_evidence_missing_fails_closed(self, orchestrator, mock_container):
        """Test that missing network evidence results in FAIL assessment."""
        with patch.object(orchestrator, 'container_validator') as mock_validator:
            with patch.object(orchestrator, 'network_probes') as mock_net:
                # Container validation passes
                mock_container_validation = Mock(valid=True, violations=[])
                mock_validator.validate_container.return_value = mock_container_validation

                # Network evidence returns empty dict
                mock_net.run_all_probes.return_value = {}

                assessment = orchestrator.validate_isolation(mock_container)

                assert assessment.valid is False
                assert assessment.assessment_type == "FAIL"
                assert "critical_evidence_missing" in assessment.security_critical_failures
                assert "missing_network_namespace_evidence" in assessment.security_critical_failures

    def test_network_probe_failure_fails_closed(self, orchestrator, mock_container):
        """Test that network probe failure results in FAIL assessment."""
        with patch.object(orchestrator, 'container_validator') as mock_validator:
            with patch.object(orchestrator, 'network_probes') as mock_net:
                # Container validation passes
                mock_container_validation = Mock(valid=True, violations=[])
                mock_validator.validate_container.return_value = mock_container_validation

                # Network evidence includes failed probe
                mock_net.run_all_probes.return_value = {
                    'network_namespace_evidence': Mock(passed=False),
                    'network_interface_evidence': Mock(passed=True)
                }

                assessment = orchestrator.validate_isolation(mock_container)

                assert assessment.valid is False
                assert assessment.assessment_type == "FAIL"
                assert "network_network_namespace_evidence_failed" in assessment.security_critical_failures


class TestSuccessfulAggregation:
    """Test successful evidence aggregation scenarios."""

    def test_all_validations_pass(self, orchestrator, mock_container):
        """Test that all validations passing results in PASS assessment."""
        with patch.object(orchestrator, 'container_validator') as mock_validator:
            with patch.object(orchestrator, 'filesystem_probes') as mock_fs:
                with patch.object(orchestrator, 'process_probes') as mock_proc:
                    with patch.object(orchestrator, 'network_probes') as mock_net:
                        # Container validation passes
                        mock_container_validation = Mock(valid=True, violations=[])
                        mock_validator.validate_container.return_value = mock_container_validation

                        # All probes pass
                        mock_fs.run_all_probes.return_value = {
                            'rootfs_readonly': Mock(passed=True),
                            'tmpfs_writability': Mock(passed=True),
                            'mount_evidence': Mock(passed=True),
                            'container_local_storage': Mock(passed=True)
                        }
                        mock_proc.run_all_probes.return_value = {
                            'pid_namespace_evidence': Mock(passed=True),
                            'process_visibility': Mock(passed=True),
                            'pid1_evidence': Mock(passed=True),
                            'controlled_subprocess': Mock(passed=True)
                        }
                        mock_net.run_all_probes.return_value = {
                            'network_namespace_evidence': Mock(passed=True),
                            'network_interface_evidence': Mock(passed=True),
                            'routing_table_evidence': Mock(passed=True),
                            'dns_configuration_evidence': Mock(passed=True),
                            'networkmode_verification': Mock(passed=True)
                        }

                        assessment = orchestrator.validate_isolation(mock_container)

                        assert assessment.valid is True
                        assert assessment.assessment_type == "PASS"
                        assert len(assessment.security_critical_failures) == 0
                        assert assessment.error_message is None

    def test_evidence_aggregation_succeeds(self, orchestrator, mock_container):
        """Test that evidence aggregation stores all results correctly."""
        with patch.object(orchestrator, 'container_validator') as mock_validator:
            with patch.object(orchestrator, 'filesystem_probes') as mock_fs:
                with patch.object(orchestrator, 'process_probes') as mock_proc:
                    with patch.object(orchestrator, 'network_probes') as mock_net:
                        # Container validation passes
                        mock_container_validation = Mock(valid=True, violations=[])
                        mock_validator.validate_container.return_value = mock_container_validation

                        # Provide probe results
                        mock_fs.run_all_probes.return_value = {'rootfs_readonly': Mock(passed=True)}
                        mock_proc.run_all_probes.return_value = {'pid_namespace_evidence': Mock(passed=True)}
                        mock_net.run_all_probes.return_value = {'network_namespace_evidence': Mock(passed=True)}

                        assessment = orchestrator.validate_isolation(mock_container)

                        assert assessment.evidence.container_validation == mock_container_validation
                        assert 'rootfs_readonly' in assessment.evidence.filesystem_evidence
                        assert 'pid_namespace_evidence' in assessment.evidence.process_evidence
                        assert 'network_namespace_evidence' in assessment.evidence.network_evidence


class TestConsistencyChecks:
    """Test consistency check logic."""

    def test_config_runtime_consistency_with_valid_config(self, orchestrator):
        """Test consistency check with valid configuration."""
        evidence = EvidenceAggregate(
            container_validation=Mock(valid=True, violations=[]),
            config_runtime_consistent=True
        )

        # Consistency should already be set
        assert evidence.config_runtime_consistent is True

    def test_config_runtime_inconsistency_with_invalid_config(self, orchestrator):
        """Test consistency check with invalid configuration."""
        evidence = EvidenceAggregate(
            container_validation=Mock(valid=False, violations=[]),
            config_runtime_consistent=False
        )

        # Consistency should already be set
        assert evidence.config_runtime_consistent is False

    def test_config_runtime_inconsistency_detected(self, orchestrator, mock_container):
        """Test that config-runtime inconsistency results in FAIL."""
        with patch.object(orchestrator, 'container_validator') as mock_validator:
            with patch.object(orchestrator, 'filesystem_probes') as mock_fs:
                with patch.object(orchestrator, 'process_probes') as mock_proc:
                    with patch.object(orchestrator, 'network_probes') as mock_net:
                        # Container validation passes
                        mock_container_validation = Mock(valid=True, violations=[])
                        mock_validator.validate_container.return_value = mock_container_validation

                        # All probes pass
                        mock_fs.run_all_probes.return_value = {'rootfs_readonly': Mock(passed=True)}
                        mock_proc.run_all_probes.return_value = {'pid_namespace_evidence': Mock(passed=True)}
                        mock_net.run_all_probes.return_value = {'network_namespace_evidence': Mock(passed=True)}

                        # Manually set inconsistency
                        orchestrator._check_consistency = lambda e: False

                        assessment = orchestrator.validate_isolation(mock_container)

                        assert assessment.valid is False
                        assert "config_runtime_inconsistent" in assessment.security_critical_failures


class TestFailClosedBehavior:
    """Test fail-closed behavior for security-critical failures."""

    def test_missing_critical_evidence_fails_closed(self, orchestrator, mock_container):
        """Test that missing critical evidence fails closed."""
        with patch.object(orchestrator, 'container_validator') as mock_validator:
            with patch.object(orchestrator, 'filesystem_probes') as mock_fs:
                # Container validation passes
                mock_container_validation = Mock(valid=True, violations=[])
                mock_validator.validate_container.return_value = mock_container_validation

                # Filesystem evidence missing critical probe
                mock_fs.run_all_probes.return_value = {
                    'tmpfs_writability': Mock(passed=True),
                    'mount_evidence': Mock(passed=True)
                    # Missing rootfs_readonly
                }

                assessment = orchestrator.validate_isolation(mock_container)

                assert assessment.valid is False
                assert assessment.assessment_type == "FAIL"
                assert "critical_evidence_missing" in assessment.security_critical_failures

    def test_probe_failure_fails_closed(self, orchestrator, mock_container):
        """Test that probe failure fails closed."""
        with patch.object(orchestrator, 'container_validator') as mock_validator:
            with patch.object(orchestrator, 'filesystem_probes') as mock_fs:
                # Container validation passes
                mock_container_validation = Mock(valid=True, violations=[])
                mock_validator.validate_container.return_value = mock_container_validation

                # Probe fails
                mock_fs.run_all_probes.return_value = {
                    'rootfs_readonly': Mock(passed=False),
                    'tmpfs_writability': Mock(passed=True),
                    'mount_evidence': Mock(passed=True),
                    'container_local_storage': Mock(passed=True)
                }

                assessment = orchestrator.validate_isolation(mock_container)

                assert assessment.valid is False
                assert assessment.assessment_type == "FAIL"
                assert "filesystem_rootfs_readonly_failed" in assessment.security_critical_failures


class TestViolationLogging:
    """Test violation logging behavior."""

    def test_critical_failures_logged(self, orchestrator, mock_container):
        """Test that critical failures are logged."""
        with patch.object(orchestrator, 'container_validator') as mock_validator:
            with patch.object(orchestrator, 'logger') as mock_logger:
                # Container validation fails
                mock_container_validation = Mock(valid=False)
                mock_container_validation.violations = [Mock(property_name='privileged')]
                mock_validator.validate_container.return_value = mock_container_validation

                assessment = orchestrator.validate_isolation(mock_container)

                # Verify error was logged
                assert mock_logger.error.called
                # The error call should include the container_id
                error_call_args = mock_logger.error.call_args
                assert "FAILED" in str(error_call_args)


class TestMalformedResults:
    """Test handling of malformed or unexpected results."""

    def test_malformed_probe_result_handling(self, orchestrator, mock_container):
        """Test that malformed probe results are handled gracefully."""
        with patch.object(orchestrator, 'container_validator') as mock_validator:
            with patch.object(orchestrator, 'filesystem_probes') as mock_fs:
                # Container validation passes
                mock_container_validation = Mock(valid=True, violations=[])
                mock_validator.validate_container.return_value = mock_container_validation

                # Probe returns result with failed 'passed' attribute
                malformed_result = Mock(passed=False)
                mock_fs.run_all_probes.return_value = {
                    'rootfs_readonly': malformed_result
                }

                # Should handle the malformed result
                assessment = orchestrator.validate_isolation(mock_container)

                # Should fail closed due to failed probe
                assert assessment.valid is False
                assert assessment.assessment_type == "FAIL"
                assert "filesystem_rootfs_readonly_failed" in assessment.security_critical_failures
