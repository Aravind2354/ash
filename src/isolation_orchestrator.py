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
import json
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

    def __init__(
        self,
        container_validator: Optional[Any] = None,
        filesystem_probes: Optional[Any] = None,
        process_probes: Optional[Any] = None,
        network_probes: Optional[Any] = None,
        docker_client: Optional[Any] = None,
    ):
        """Initialize the IsolationOrchestrator."""
        self.logger = get_logger(__name__)

        # Import probe modules
        try:
            from src.container_validator import ContainerValidator
            from src.filesystem_probes import FilesystemProbes
            from src.process_probes import ProcessProbes
            from src.network_probes import NetworkProbes

            self.container_validator = container_validator or ContainerValidator(docker_client=docker_client)
            self.filesystem_probes = filesystem_probes or FilesystemProbes()
            self.process_probes = process_probes or ProcessProbes()
            self.network_probes = network_probes or NetworkProbes()

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

        # Step 2: Collect runtime evidence from all probes (inside container if available)
        evidence = EvidenceAggregate(
            container_validation=container_validation,
            timestamp=datetime.now(timezone.utc)
        )
        self._collect_container_evidence(container, evidence)

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

    def _collect_container_evidence(self, container: Any, evidence: EvidenceAggregate) -> None:
        """Collect runtime evidence by executing probe_runner inside the container.

        If container has `exec_run`, it executes `python -m src.probe_runner` inside
        the running container, parses the JSON evidence, and reconstructs ProbeResult objects.
        If container does not support `exec_run` (e.g., in unit tests with mock containers),
        it falls back to local probe runners to maintain test compatibility.
        """
        if hasattr(container, "exec_run") and callable(container.exec_run):
            try:
                exec_result = container.exec_run(
                    ["python", "-m", "src.probe_runner"],
                    workdir="/analysis",
                    stdout=True,
                    stderr=True,
                    demux=False
                )

                exit_code = getattr(exec_result, 'exit_code', 0)
                output_bytes = getattr(exec_result, 'output', b'')
                output_str = output_bytes.decode('utf-8', errors='replace') if isinstance(output_bytes, bytes) else str(output_bytes)

                if exit_code != 0:
                    self.logger.error(f"In-container probe runner failed with exit code {exit_code}: {output_str}")
                    evidence.evidence_collection_errors.append(f"in_container_probe_runner_exit_code_{exit_code}: {output_str}")

                from src.probe_runner import PROBE_DELIMITER_START, PROBE_DELIMITER_END
                if PROBE_DELIMITER_START in output_str and PROBE_DELIMITER_END in output_str:
                    start_idx = output_str.find(PROBE_DELIMITER_START) + len(PROBE_DELIMITER_START)
                    end_idx = output_str.find(PROBE_DELIMITER_END, start_idx)
                    json_str = output_str[start_idx:end_idx].strip()
                    payload = json.loads(json_str)

                    from src.filesystem_probes import ProbeResult as FSProbeResult
                    from src.process_probes import ProbeResult as ProcProbeResult
                    from src.network_probes import ProbeResult as NetProbeResult

                    fs_dict = payload.get("filesystem", {})
                    for k, v in fs_dict.items():
                        evidence.filesystem_evidence[k] = FSProbeResult(
                            probe_name=v.get('probe_name', k),
                            passed=bool(v.get('passed', False)),
                            observed_value=v.get('observed_value'),
                            expected_condition=v.get('expected_condition', ''),
                            error=v.get('error')
                        )

                    proc_dict = payload.get("process", {})
                    for k, v in proc_dict.items():
                        evidence.process_evidence[k] = ProcProbeResult(
                            probe_name=v.get('probe_name', k),
                            passed=bool(v.get('passed', False)),
                            observed_value=v.get('observed_value'),
                            expected_condition=v.get('expected_condition', ''),
                            error=v.get('error')
                        )

                    net_dict = payload.get("network", {})
                    for k, v in net_dict.items():
                        evidence.network_evidence[k] = NetProbeResult(
                            probe_name=v.get('probe_name', k),
                            passed=bool(v.get('passed', False)),
                            observed_value=v.get('observed_value'),
                            expected_condition=v.get('expected_condition', ''),
                            error=v.get('error')
                        )

                    self.logger.info(
                        f"In-container evidence collected: {len(evidence.filesystem_evidence)} fs, "
                        f"{len(evidence.process_evidence)} proc, {len(evidence.network_evidence)} net probes"
                    )
                    return
                else:
                    self.logger.error(f"In-container probe runner returned invalid output format: {output_str}")
                    evidence.evidence_collection_errors.append(f"invalid_probe_output_format: {output_str[:200]}")
                    return
            except Exception as e:
                self.logger.error(f"Error executing in-container probe runner: {e}", exc_info=True)
                evidence.evidence_collection_errors.append(f"in_container_exec_error: {e}")
                return

        # Fallback to local probe instances (e.g., for mock containers in unit tests)
        try:
            evidence.filesystem_evidence = self.filesystem_probes.run_all_probes()
            self.logger.info(f"Filesystem evidence collected: {len(evidence.filesystem_evidence)} probes")
        except Exception as e:
            self.logger.error(f"Error collecting filesystem evidence: {e}", exc_info=True)
            evidence.evidence_collection_errors.append(f"filesystem_evidence: {e}")

        try:
            evidence.process_evidence = self.process_probes.run_all_probes()
            self.logger.info(f"Process evidence collected: {len(evidence.process_evidence)} probes")
        except Exception as e:
            self.logger.error(f"Error collecting process evidence: {e}", exc_info=True)
            evidence.evidence_collection_errors.append(f"process_evidence: {e}")

        try:
            evidence.network_evidence = self.network_probes.run_all_probes()
            self.logger.info(f"Network evidence collected: {len(evidence.network_evidence)} probes")
        except Exception as e:
            self.logger.error(f"Error collecting network evidence: {e}", exc_info=True)
            evidence.evidence_collection_errors.append(f"network_evidence: {e}")
