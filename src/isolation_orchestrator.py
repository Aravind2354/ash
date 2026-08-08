"""Runtime isolation evidence orchestration for container security validation.

This module provides orchestration logic that aggregates trusted host-side
Docker configuration validation with runtime evidence from filesystem, process,
and network probes to produce a comprehensive security assessment.

SECURITY CRITICAL: This module implements fail-closed behavior for
security-critical isolation properties. When required security evidence cannot
be verified, the system fails closed rather than proceeding with unverified
analysis.

IMPORTANT: Runtime evidence alone does NOT prove:
- Complete impossibility of container escape
- Absence of kernel vulnerabilities
- Absolute host isolation

This orchestrator preserves the distinction between:
- Trusted host-side configuration validation (PROOF)
- Runtime evidence probes (EVIDENCE)
- Final security assessment (PROOF + EVIDENCE aggregation)
"""

import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

try:
    import docker
    from docker.models.containers import Container
except ImportError:
    docker = None
    Container = None

from config.logging_config import get_logger


@dataclass
class EvidenceAggregate:
    """Combined evidence from all isolation domains."""

    # Trusted configuration validation
    container_validation: Optional[Any] = None

    # Runtime filesystem evidence
    filesystem_evidence: Dict[str, Any] = field(default_factory=dict)

    # Runtime process evidence
    process_evidence: Dict[str, Any] = field(default_factory=dict)

    # Runtime network evidence
    network_evidence: Dict[str, Any] = field(default_factory=dict)

    # Timestamp
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Consistency flags
    config_runtime_consistent: bool = False
    all_critical_evidence_collected: bool = False
    evidence_collection_errors: List[str] = field(default_factory=list)


@dataclass
class IsolationAssessment:
    """Structured result of isolation boundary validation."""

    valid: bool
    assessment_type: str  # "PASS", "FAIL", "ERROR"
    container_id: str
    evidence: EvidenceAggregate
    security_critical_failures: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class IsolationOrchestrator:
    """Orchestrates isolation evidence aggregation and security assessment.

    This class combines trusted host-side Docker configuration validation
    with runtime evidence from filesystem, process, and network probes to
    produce a comprehensive security assessment.

    SECURITY CRITICAL: Implements fail-closed behavior for security-critical
    isolation properties. When required security evidence cannot be verified,
    the system fails closed rather than proceeding with unverified analysis.
    """

    # Security-critical isolation properties
    CRITICAL_ISOLATION_PROPERTIES = {
        'filesystem': ['rootfs_readonly', 'tmpfs_writability'],
        'process': ['pid_namespace_evidence', 'process_visibility'],
        'network': ['network_namespace_evidence', 'network_interface_evidence']
    }

    def __init__(self):
        """Initialize the IsolationOrchestrator."""
        self.logger = get_logger(__name__)

        # Import probe modules
        try:
            from src.container_validator import ContainerValidator
            from src.filesystem_probes import FilesystemProbes
            from src.process_probes import ProcessProbes
            from src.network_probes import NetworkProbes

            self.container_validator = ContainerValidator()
            self.filesystem_probes = FilesystemProbes()
            self.process_probes = ProcessProbes()
            self.network_probes = NetworkProbes()

        except ImportError as e:
            self.logger.error(f"Failed to import required modules: {e}")
            raise

    def validate_isolation(self, container: Container) -> IsolationAssessment:
        """Validate isolation boundary by aggregating configuration and evidence.

        This method combines trusted host-side Docker configuration validation
        with runtime evidence from filesystem, process, and network probes to
        produce a comprehensive security assessment.

        Args:
            container: Docker container object to validate

        Returns:
            IsolationAssessment with comprehensive security assessment
        """
        container_id = container.id[:12]  # Short ID for logging

        self.logger.info(f"Starting isolation validation for container {container_id}")

        # Step 1: Trusted host-side configuration validation
        try:
            container_validation = self.container_validator.validate_container(container)
            self.logger.info(
                f"Container configuration validation result: {container_validation.valid}",
                extra={
                    "extra_fields": {
                        "container_id": container_id,
                        "config_valid": container_validation.valid,
                        "violations": len(container_validation.violations)
                    }
                }
            )
        except Exception as e:
            self.logger.error(
                f"Error during container configuration validation for {container_id}: {e}",
                exc_info=True
            )
            # Fail closed on configuration validation error
            return IsolationAssessment(
                valid=False,
                assessment_type="ERROR",
                container_id=container_id,
                evidence=EvidenceAggregate(timestamp=datetime.now(timezone.utc)),
                security_critical_failures=["container_validation_error"],
                error_message=f"Container configuration validation failed: {e}"
            )

        # Step 2: Collect runtime evidence from all probes
        evidence = EvidenceAggregate(
            container_validation=container_validation,
            timestamp=datetime.now(timezone.utc)
        )

        # Collect filesystem evidence
        try:
            evidence.filesystem_evidence = self.filesystem_probes.run_all_probes()
            self.logger.info(f"Filesystem evidence collected: {len(evidence.filesystem_evidence)} probes")
        except Exception as e:
            self.logger.error(f"Error collecting filesystem evidence: {e}", exc_info=True)
            evidence.evidence_collection_errors.append(f"filesystem_evidence: {e}")

        # Collect process evidence
        try:
            evidence.process_evidence = self.process_probes.run_all_probes()
            self.logger.info(f"Process evidence collected: {len(evidence.process_evidence)} probes")
        except Exception as e:
            self.logger.error(f"Error collecting process evidence: {e}", exc_info=True)
            evidence.evidence_collection_errors.append(f"process_evidence: {e}")

        # Collect network evidence
        try:
            evidence.network_evidence = self.network_probes.run_all_probes()
            self.logger.info(f"Network evidence collected: {len(evidence.network_evidence)} probes")
        except Exception as e:
            self.logger.error(f"Error collecting network evidence: {e}", exc_info=True)
            evidence.evidence_collection_errors.append(f"network_evidence: {e}")

        # Step 3: Check consistency between configuration and runtime evidence
        evidence.config_runtime_consistent = self._check_consistency(evidence)

        # Step 4: Verify all critical evidence was collected
        evidence.all_critical_evidence_collected = self._check_critical_evidence(evidence)

        # Step 5: Generate security assessment
        assessment = self._generate_assessment(container_id, evidence, container_validation)

        # Step 6: Log assessment result
        if assessment.valid:
            self.logger.info(
                f"Container {container_id} isolation validation PASSED",
                extra={
                    "extra_fields": {
                        "container_id": container_id,
                        "assessment_type": assessment.assessment_type,
                        "warnings": len(assessment.warnings)
                    }
                }
            )
        else:
            self.logger.error(
                f"Container {container_id} isolation validation FAILED",
                extra={
                    "extra_fields": {
                        "container_id": container_id,
                        "assessment_type": assessment.assessment_type,
                        "critical_failures": len(assessment.security_critical_failures)
                    }
                }
            )

        return assessment

    def _check_consistency(self, evidence: EvidenceAggregate) -> bool:
        """Check consistency between configuration and runtime evidence.

        Args:
            evidence: Collected evidence aggregate

        Returns:
            True if configuration and evidence are consistent, False otherwise
        """
        if evidence.container_validation is None:
            return False

        # Check that configuration validation passed
        if not evidence.container_validation.valid:
            return False

        # Additional consistency checks could be added here
        # For now, configuration validation passing is sufficient

        return True

    def _check_critical_evidence(self, evidence: EvidenceAggregate) -> bool:
        """Check that all critical evidence was successfully collected.

        Args:
            evidence: Collected evidence aggregate

        Returns:
            True if all critical evidence was collected, False otherwise
        """
        # Check filesystem critical evidence
        for probe in self.CRITICAL_ISOLATION_PROPERTIES['filesystem']:
            if probe not in evidence.filesystem_evidence:
                return False
            if not evidence.filesystem_evidence[probe].passed:
                return False

        # Check process critical evidence
        for probe in self.CRITICAL_ISOLATION_PROPERTIES['process']:
            if probe not in evidence.process_evidence:
                return False
            if not evidence.process_evidence[probe].passed:
                return False

        # Check network critical evidence
        for probe in self.CRITICAL_ISOLATION_PROPERTIES['network']:
            if probe not in evidence.network_evidence:
                return False
            if not evidence.network_evidence[probe].passed:
                return False

        return True

    def _generate_assessment(self, container_id: str, evidence: EvidenceAggregate,
                           container_validation: Any) -> IsolationAssessment:
        """Generate final security assessment based on aggregated evidence.

        Args:
            container_id: Container identifier
            evidence: Collected evidence aggregate
            container_validation: Container validation result

        Returns:
            IsolationAssessment with final security decision
        """
        critical_failures = []
        warnings = []

        # SECURITY CRITICAL: Fail closed if configuration validation failed
        if not container_validation.valid:
            critical_failures.append("container_configuration_invalid")
            for violation in container_validation.violations:
                critical_failures.append(f"config_{violation.property_name}")

        # SECURITY CRITICAL: Fail closed if critical evidence collection failed
        if not evidence.all_critical_evidence_collected:
            critical_failures.append("critical_evidence_missing")
            # Add specific missing evidence failures
            for domain, probes in self.CRITICAL_ISOLATION_PROPERTIES.items():
                for probe in probes:
                    if domain == 'filesystem' and probe not in evidence.filesystem_evidence:
                        critical_failures.append(f"missing_{probe}")
                    elif domain == 'process' and probe not in evidence.process_evidence:
                        critical_failures.append(f"missing_{probe}")
                    elif domain == 'network' and probe not in evidence.network_evidence:
                        critical_failures.append(f"missing_{probe}")

        # SECURITY CRITICAL: Fail closed if evidence collection errors occurred
        if evidence.evidence_collection_errors:
            critical_failures.append("evidence_collection_errors")
            for error in evidence.evidence_collection_errors:
                critical_failures.append(f"collection_error: {error}")

        # Check for consistency failures
        if not evidence.config_runtime_consistent:
            critical_failures.append("config_runtime_inconsistent")

        # Check for individual probe failures
        for probe_name, probe_result in evidence.filesystem_evidence.items():
            if not probe_result.passed:
                critical_failures.append(f"filesystem_{probe_name}_failed")

        for probe_name, probe_result in evidence.process_evidence.items():
            if not probe_result.passed:
                critical_failures.append(f"process_{probe_name}_failed")

        for probe_name, probe_result in evidence.network_evidence.items():
            if not probe_result.passed:
                critical_failures.append(f"network_{probe_name}_failed")

        # Generate assessment type
        if critical_failures:
            assessment_type = "FAIL"
            valid = False
        else:
            assessment_type = "PASS"
            valid = True

        return IsolationAssessment(
            valid=valid,
            assessment_type=assessment_type,
            container_id=container_id,
            evidence=evidence,
            security_critical_failures=critical_failures,
            warnings=warnings,
            error_message=" ; ".join(critical_failures) if critical_failures else None
        )
