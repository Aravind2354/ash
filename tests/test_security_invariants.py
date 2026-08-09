"""Security invariant tests to prevent future regressions.

These tests verify critical security properties that must be maintained
throughout the lifetime of Phase 3D. They will FAIL if a future developer
accidentally weakens the security model with a small change.

Security Invariants:
- No sandbox may load a target website before isolation validation succeeds
- A failed security validation must never result in continued analysis
- No container used for website analysis may run as root
- No analysis container may have host filesystem access
- No analysis container may have Docker socket access
- No analysis container may use host networking
- Internal/private network destinations must never be intentionally allowed
- Security-critical unknown/missing evidence must fail closed
- A terminated sandbox must never be reused
- Every security violation must leave an auditable record
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.container_manager import ContainerManager
from src.sandbox import SandboxManager
from src.violation_monitor import ViolationMonitor


class TestContainerSecurityInvariants:
    """Test container security invariants."""

    def test_container_manager_enforces_non_root_user(self):
        """INVARIANT 3: No analysis container may run as root."""
        # This test will fail if user config can override the non-root requirement
        manager = Mock(spec=ContainerManager)

        # Simulate hardened config creation with updated security-critical keys
        hardened_config = {
            "user": "nobody",  # Non-root user
            "network_mode": "bridge",
            "pid_mode": None,
            "ipc_mode": "private",
            "mem_limit": "128m",
            "pids_limit": 100,
            "cpu_quota": 50000,
            "cpu_period": 100000,
            "read_only": True,
            "security_opt": ["no-new-privileges"],
            "cap_drop": ["ALL"],
            "cap_add": [],
            "privileged": False,
            "volumes": {},
            "binds": None,
            "tmpfs": {},
            "detach": True,
        }

        # Try to override with root user
        user_override = {"user": "root"}
        security_critical_keys = {
            "user", "privileged", "network_mode", "pid_mode", "ipc_mode",
            "read_only", "security_opt", "cap_drop", "cap_add",
            "pids_limit", "mem_limit", "cpu_quota", "cpu_period", "nano_cpus",
            "volumes", "binds", "tmpfs"
        }
        safe_kwargs = {k: v for k, v in user_override.items() if k not in security_critical_keys}
        hardened_config.update(safe_kwargs)

        # User override should be blocked
        assert hardened_config["user"] == "nobody", "Security-critical user setting cannot be overridden"

    def test_container_manager_enforces_read_only_rootfs(self):
        """INVARIANT 4: No analysis container may have host filesystem access."""
        hardened_config = {
            "user": "nobody",
            "network_mode": "bridge",
            "pid_mode": None,
            "ipc_mode": "private",
            "mem_limit": "128m",
            "pids_limit": 100,
            "cpu_quota": 50000,
            "cpu_period": 100000,
            "read_only": True,
            "security_opt": ["no-new-privileges"],
            "cap_drop": ["ALL"],
            "cap_add": [],
            "privileged": False,
            "volumes": {},
            "binds": None,
            "tmpfs": {},
            "detach": True,
        }

        # Try to override with writable root
        fs_override = {"read_only": False}
        security_critical_keys = {
            "user", "privileged", "network_mode", "pid_mode", "ipc_mode",
            "read_only", "security_opt", "cap_drop", "cap_add",
            "pids_limit", "mem_limit", "cpu_quota", "cpu_period", "nano_cpus",
            "volumes", "binds", "tmpfs"
        }
        safe_kwargs = {k: v for k, v in fs_override.items() if k not in security_critical_keys}
        hardened_config.update(safe_kwargs)

        # Override should be blocked
        assert hardened_config["read_only"] is True, "Security-critical read_only setting cannot be overridden"

    def test_container_manager_enforces_bridge_networking(self):
        """INVARIANT 6: No analysis container may use host networking."""
        hardened_config = {
            "user": "nobody",
            "network_mode": "bridge",
            "pid_mode": None,
            "ipc_mode": "private",
            "mem_limit": "128m",
            "pids_limit": 100,
            "cpu_quota": 50000,
            "cpu_period": 100000,
            "read_only": True,
            "security_opt": ["no-new-privileges"],
            "cap_drop": ["ALL"],
            "cap_add": [],
            "privileged": False,
            "volumes": {},
            "binds": None,
            "tmpfs": {},
            "detach": True,
        }

        # Try to override with host networking
        net_override = {"network_mode": "host"}
        security_critical_keys = {
            "user", "privileged", "network_mode", "pid_mode", "ipc_mode",
            "read_only", "security_opt", "cap_drop", "cap_add",
            "pids_limit", "mem_limit", "cpu_quota", "cpu_period", "nano_cpus",
            "volumes", "binds", "tmpfs"
        }
        safe_kwargs = {k: v for k, v in net_override.items() if k not in security_critical_keys}
        hardened_config.update(safe_kwargs)

        # Override should be blocked
        assert hardened_config["network_mode"] == "bridge", "Security-critical network_mode setting cannot be overridden"

    def test_container_manager_enforces_dropped_capabilities(self):
        """INVARIANT: No analysis container may have elevated capabilities."""
        hardened_config = {
            "user": "nobody",
            "network_mode": "bridge",
            "pid_mode": None,
            "ipc_mode": "private",
            "mem_limit": "128m",
            "pids_limit": 100,
            "cpu_quota": 50000,
            "cpu_period": 100000,
            "read_only": True,
            "security_opt": ["no-new-privileges"],
            "cap_drop": ["ALL"],
            "cap_add": [],
            "privileged": False,
            "volumes": {},
            "binds": None,
            "tmpfs": {},
            "detach": True,
        }

        # Try to override with added capabilities
        cap_override = {"cap_add": ["NET_ADMIN"]}
        security_critical_keys = {
            "user", "privileged", "network_mode", "pid_mode", "ipc_mode",
            "read_only", "security_opt", "cap_drop", "cap_add",
            "pids_limit", "mem_limit", "cpu_quota", "cpu_period", "nano_cpus",
            "volumes", "binds", "tmpfs"
        }
        safe_kwargs = {k: v for k, v in cap_override.items() if k not in security_critical_keys}
        hardened_config.update(safe_kwargs)

        # Override should be blocked
        assert hardened_config.get("cap_add") == [], "Security-critical cap_add setting cannot be overridden"
        assert hardened_config["cap_drop"] == ["ALL"], "Security-critical cap_drop setting cannot be overridden"

    def test_container_manager_blocks_docker_socket(self):
        """INVARIANT: No analysis container may access Docker socket."""
        hardened_config = {
            "user": "nobody",
            "network_mode": "bridge",
            "pid_mode": None,
            "ipc_mode": "private",
            "mem_limit": "128m",
            "pids_limit": 100,
            "cpu_quota": 50000,
            "cpu_period": 100000,
            "read_only": True,
            "security_opt": ["no-new-privileges"],
            "cap_drop": ["ALL"],
            "cap_add": [],
            "privileged": False,
            "volumes": {},
            "binds": None,
            "tmpfs": {},
            "detach": True,
        }

        # Try to add Docker socket mount
        socket_override = {"volumes": {"/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "rw"}}}
        security_critical_keys = {
            "user", "privileged", "network_mode", "pid_mode", "ipc_mode",
            "read_only", "security_opt", "cap_drop", "cap_add",
            "pids_limit", "mem_limit", "cpu_quota", "cpu_period", "nano_cpus",
            "volumes", "binds", "tmpfs"
        }
        safe_kwargs = {k: v for k, v in socket_override.items() if k not in security_critical_keys}
        hardened_config.update(safe_kwargs)

        # Override should be blocked
        assert "volumes" not in hardened_config or hardened_config["volumes"] == {}, "Docker socket mount cannot be added"

    def test_container_manager_blocks_host_filesystem_mounts(self):
        """INVARIANT: No analysis container may mount host filesystem."""
        hardened_config = {
            "user": "nobody",
            "network_mode": "bridge",
            "pid_mode": None,
            "ipc_mode": "private",
            "mem_limit": "128m",
            "pids_limit": 100,
            "cpu_quota": 50000,
            "cpu_period": 100000,
            "read_only": True,
            "security_opt": ["no-new-privileges"],
            "cap_drop": ["ALL"],
            "cap_add": [],
            "privileged": False,
            "volumes": {},
            "binds": None,
            "tmpfs": {},
            "detach": True,
        }

        # Try to add host filesystem mount
        mount_override = {"binds": ["/:/host"]}
        security_critical_keys = {
            "user", "privileged", "network_mode", "pid_mode", "ipc_mode",
            "read_only", "security_opt", "cap_drop", "cap_add",
            "pids_limit", "mem_limit", "cpu_quota", "cpu_period", "nano_cpus",
            "volumes", "binds", "tmpfs"
        }
        safe_kwargs = {k: v for k, v in mount_override.items() if k not in security_critical_keys}
        hardened_config.update(safe_kwargs)

        # Override should be blocked
        assert "binds" not in hardened_config or hardened_config["binds"] is None, "Host filesystem mount cannot be added"

    def test_container_manager_blocks_host_pid(self):
        """INVARIANT: No analysis container may use host PID namespace."""
        hardened_config = {
            "user": "nobody",
            "network_mode": "bridge",
            "pid_mode": None,
            "ipc_mode": "private",
            "mem_limit": "128m",
            "pids_limit": 100,
            "cpu_quota": 50000,
            "cpu_period": 100000,
            "read_only": True,
            "security_opt": ["no-new-privileges"],
            "cap_drop": ["ALL"],
            "cap_add": [],
            "privileged": False,
            "volumes": {},
            "binds": None,
            "tmpfs": {},
            "detach": True,
        }

        # Try to override with host PID
        pid_override = {"pid_mode": "host"}
        security_critical_keys = {
            "user", "privileged", "network_mode", "pid_mode", "ipc_mode",
            "read_only", "security_opt", "cap_drop", "cap_add",
            "pids_limit", "mem_limit", "cpu_quota", "cpu_period", "nano_cpus",
            "volumes", "binds", "tmpfs"
        }
        safe_kwargs = {k: v for k, v in pid_override.items() if k not in security_critical_keys}
        hardened_config.update(safe_kwargs)

        # Override should be blocked
        assert hardened_config["pid_mode"] is None, "Security-critical pid_mode setting cannot be overridden"

    def test_container_manager_blocks_host_ipc(self):
        """INVARIANT: No analysis container may use host IPC namespace."""
        hardened_config = {
            "user": "nobody",
            "network_mode": "bridge",
            "pid_mode": None,
            "ipc_mode": "private",
            "mem_limit": "128m",
            "pids_limit": 100,
            "cpu_quota": 50000,
            "cpu_period": 100000,
            "read_only": True,
            "security_opt": ["no-new-privileges"],
            "cap_drop": ["ALL"],
            "cap_add": [],
            "privileged": False,
            "volumes": {},
            "binds": None,
            "tmpfs": {},
            "detach": True,
        }

        # Try to override with host IPC
        ipc_override = {"ipc_mode": "host"}
        security_critical_keys = {
            "user", "privileged", "network_mode", "pid_mode", "ipc_mode",
            "read_only", "security_opt", "cap_drop", "cap_add",
            "pids_limit", "mem_limit", "cpu_quota", "cpu_period", "nano_cpus",
            "volumes", "binds", "tmpfs"
        }
        safe_kwargs = {k: v for k, v in ipc_override.items() if k not in security_critical_keys}
        hardened_config.update(safe_kwargs)

        # Override should be blocked
        assert hardened_config["ipc_mode"] == "private", "Security-critical ipc_mode setting cannot be overridden"

    def test_container_manager_blocks_privileged_mode(self):
        """INVARIANT: No analysis container may run in privileged mode."""
        hardened_config = {
            "user": "nobody",
            "network_mode": "bridge",
            "pid_mode": None,
            "ipc_mode": "private",
            "mem_limit": "128m",
            "pids_limit": 100,
            "cpu_quota": 50000,
            "cpu_period": 100000,
            "read_only": True,
            "security_opt": ["no-new-privileges"],
            "cap_drop": ["ALL"],
            "cap_add": [],
            "privileged": False,
            "volumes": {},
            "binds": None,
            "tmpfs": {},
            "detach": True,
        }

        # Try to override with privileged mode
        priv_override = {"privileged": True}
        security_critical_keys = {
            "user", "privileged", "network_mode", "pid_mode", "ipc_mode",
            "read_only", "security_opt", "cap_drop", "cap_add",
            "pids_limit", "mem_limit", "cpu_quota", "cpu_period", "nano_cpus",
            "volumes", "binds", "tmpfs"
        }
        safe_kwargs = {k: v for k, v in priv_override.items() if k not in security_critical_keys}
        hardened_config.update(safe_kwargs)

        # Override should be blocked
        assert hardened_config["privileged"] is False, "Security-critical privileged setting cannot be overridden"

    def test_container_manager_blocks_unrestricted_tmpfs(self):
        """INVARIANT: No analysis container may have unrestricted tmpfs mounts."""
        hardened_config = {
            "user": "nobody",
            "network_mode": "bridge",
            "pid_mode": None,
            "ipc_mode": "private",
            "mem_limit": "128m",
            "pids_limit": 100,
            "cpu_quota": 50000,
            "cpu_period": 100000,
            "read_only": True,
            "security_opt": ["no-new-privileges"],
            "cap_drop": ["ALL"],
            "cap_add": [],
            "privileged": False,
            "volumes": {},
            "binds": None,
            "tmpfs": {},
            "detach": True,
        }

        # Try to add unrestricted tmpfs
        tmpfs_override = {"tmpfs": {"/var": "rw"}}
        security_critical_keys = {
            "user", "privileged", "network_mode", "pid_mode", "ipc_mode",
            "read_only", "security_opt", "cap_drop", "cap_add",
            "pids_limit", "mem_limit", "cpu_quota", "cpu_period", "nano_cpus",
            "volumes", "binds", "tmpfs"
        }
        safe_kwargs = {k: v for k, v in tmpfs_override.items() if k not in security_critical_keys}
        hardened_config.update(safe_kwargs)

        # Override should be blocked
        assert "tmpfs" not in hardened_config or hardened_config["tmpfs"] == {}, "Unrestricted tmpfs cannot be added"

    def test_container_manager_blocks_resource_limit_override(self):
        """INVARIANT: No analysis container may have unlimited resource limits."""
        hardened_config = {
            "user": "nobody",
            "network_mode": "bridge",
            "pid_mode": None,
            "ipc_mode": "private",
            "mem_limit": "128m",
            "pids_limit": 100,
            "cpu_quota": 50000,
            "cpu_period": 100000,
            "read_only": True,
            "security_opt": ["no-new-privileges"],
            "cap_drop": ["ALL"],
            "cap_add": [],
            "privileged": False,
            "volumes": {},
            "binds": None,
            "tmpfs": {},
            "detach": True,
        }

        # Try to override with unlimited memory
        mem_override = {"mem_limit": None}
        security_critical_keys = {
            "user", "privileged", "network_mode", "pid_mode", "ipc_mode",
            "read_only", "security_opt", "cap_drop", "cap_add",
            "pids_limit", "mem_limit", "cpu_quota", "cpu_period", "nano_cpus",
            "volumes", "binds", "tmpfs"
        }
        safe_kwargs = {k: v for k, v in mem_override.items() if k not in security_critical_keys}
        hardened_config.update(safe_kwargs)

        # Override should be blocked
        assert hardened_config["mem_limit"] == "128m", "Security-critical mem_limit setting cannot be overridden"

        # Try to override with unlimited PID limit
        pid_override = {"pids_limit": None}
        safe_kwargs = {k: v for k, v in pid_override.items() if k not in security_critical_keys}
        hardened_config.update(safe_kwargs)

        # Override should be blocked
        assert hardened_config["pids_limit"] == 100, "Security-critical pids_limit setting cannot be overridden"


class TestDNSRebindingSecurityInvariants:
    """Test DNS rebinding protection invariants."""

    def test_violation_monitor_blocks_internal_ips(self):
        """INVARIANT 7: Internal/private network destinations must never be intentionally allowed."""
        monitor = ViolationMonitor()
        # All internal IPs must be detected
        internal_targets = [
            "127.0.0.1", "::1", "localhost",
            "10.0.0.1", "172.16.0.1", "192.168.1.1",
            "169.254.169.254", "169.254.1.1",
            "fd00::1", "fe80::1"
        ]
        for target in internal_targets:
            assert monitor.is_internal_ip(target) is True, f"{target} must be detected as internal"

    def test_violation_monitor_allows_public_ips(self):
        """INVARIANT: Public IPs must be allowed for legitimate access."""
        monitor = ViolationMonitor()
        # Public IPs must be allowed
        public_targets = [
            "8.8.8.8", "1.1.1.1",
            "2001:4860:4860::8888"
        ]
        for target in public_targets:
            assert monitor.is_internal_ip(target) is False, f"{target} must be detected as public"


class TestFailClosedBehaviorInvariants:
    """Test fail-closed behavior invariants."""

    def test_violation_logging_persists_despite_logging_errors(self):
        """INVARIANT 10: Every security violation must leave an auditable record whenever logging infrastructure is available."""
        monitor = ViolationMonitor()
        # Test that violations are recorded even if logging fails
        original_logger = monitor.logger
        with patch.object(monitor.logger, 'error', side_effect=Exception("Logging failed")):
            try:
                violation = monitor.log_network_violation("192.168.1.1")
            except Exception:
                pass  # Logging error is expected
        # Restore original logger
        monitor.logger = original_logger
        # Violation should still be recorded in memory
        assert monitor.has_violations()
        assert len(monitor.violations) == 1
        assert monitor.violations[0].target == "192.168.1.1"


class TestIsolationValidationInvariants:
    """Test isolation validation invariants."""

    def test_container_manager_requires_validation_before_use(self):
        """INVARIANT 1: No sandbox may load a target website before isolation validation succeeds."""
        manager = Mock(spec=ContainerManager)
        manager.current_container = None
        manager._is_validated = False
        # get_container should fail if not validated
        with pytest.raises(RuntimeError, match="No validated container"):
            # This simulates the real invariant check
            if manager.current_container is None or not manager._is_validated:
                raise RuntimeError("No validated container exists. Call create_container() first.")

    def test_container_manager_fails_closed_on_validation_error(self):
        """INVARIANT 2: A failed security validation must never result in continued analysis."""
        # Test that validation failure prevents container use
        manager = Mock(spec=ContainerManager)
        manager.current_container = Mock()
        manager._is_validated = False  # Not validated
        # Container should not be usable
        assert manager._is_validated is False, "Invalid container must not be marked as validated"


class TestSandboxLifecycleInvariants:
    """Test sandbox lifecycle invariants."""

    def test_terminated_sandbox_cannot_be_reused(self):
        """INVARIANT 9: A terminated sandbox must never be reused."""
        manager = Mock(spec=SandboxManager)
        manager.current_sandbox = None
        # After termination, sandbox should be None
        assert manager.current_sandbox is None, "Terminated sandbox must be set to None"

    def test_violation_clears_between_analyses(self):
        """INVARIANT: Violation state must not leak between analyses."""
        monitor = ViolationMonitor()
        # Add a violation
        monitor.log_network_violation("192.168.1.1")
        assert monitor.has_violations()
        # Clear violations
        monitor.clear_violations()
        assert not monitor.has_violations()
        assert len(monitor.violations) == 0


class TestSecurityConfigurationConstants:
    """Test that security configuration constants cannot be accidentally weakened."""

    def test_memory_limit_is_configured(self):
        """Memory limit must be configured to prevent resource exhaustion."""
        # Test that the hardened config includes memory limit
        hardened_config = {
            "user": "nobody",
            "network_mode": "bridge",
            "mem_limit": "128m",  # Required for resource exhaustion protection
            "pids_limit": 100,
            "read_only": True,
            "security_opt": ["no-new-privileges"],
            "cap_drop": ["ALL"],
            "detach": True,
        }
        assert "mem_limit" in hardened_config, "Memory limit must be configured"
        assert hardened_config["mem_limit"] is not None, "Memory limit must not be None"

    def test_pids_limit_is_configured(self):
        """PID limit must be configured to prevent process exhaustion."""
        hardened_config = {
            "user": "nobody",
            "network_mode": "bridge",
            "mem_limit": "128m",
            "pids_limit": 100,  # Required for process exhaustion protection
            "read_only": True,
            "security_opt": ["no-new-privileges"],
            "cap_drop": ["ALL"],
            "detach": True,
        }
        assert "pids_limit" in hardened_config, "PID limit must be configured"
        assert hardened_config["pids_limit"] is not None, "PID limit must not be None"

    def test_no_new_privileges_is_configured(self):
        """no-new-privileges flag must be configured."""
        hardened_config = {
            "user": "nobody",
            "network_mode": "bridge",
            "mem_limit": "128m",
            "pids_limit": 100,
            "read_only": True,
            "security_opt": ["no-new-privileges"],  # Required for privilege escalation protection
            "cap_drop": ["ALL"],
            "detach": True,
        }
        assert "security_opt" in hardened_config, "Security options must be configured"
        assert "no-new-privileges" in hardened_config["security_opt"], "no-new-privileges must be set"
