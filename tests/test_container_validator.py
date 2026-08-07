"""Unit tests for container security configuration validation.

Tests host-side Docker container security property validation logic.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timezone

from src.container_validator import (
    ContainerValidator,
    ValidationResult,
    SecurityCheck,
)


@pytest.fixture
def mock_container():
    """Create a mock Docker container."""
    container = Mock()
    container.id = "abc123def456"
    container.reload = Mock()
    return container


@pytest.fixture
def validator():
    """Create a ContainerValidator instance with mocked Docker client."""
    with patch('src.container_validator.docker.from_env') as mock_docker:
        mock_client = Mock()
        mock_docker.return_value = mock_client
        return ContainerValidator()


class TestValidationResult:
    """Test ValidationResult dataclass."""
    
    def test_validation_result_initialization(self):
        """Test ValidationResult initializes correctly."""
        result = ValidationResult(
            valid=True,
            container_id="abc123"
        )
        
        assert result.valid is True
        assert result.container_id == "abc123"
        assert len(result.checks) == 0
        assert len(result.violations) == 0
        assert isinstance(result.timestamp, datetime)
    
    def test_add_check_passed(self):
        """Test adding a passed check."""
        result = ValidationResult(valid=True, container_id="abc123")
        check = SecurityCheck(
            property_name="test",
            passed=True,
            observed_value="good",
            expected_condition="good condition"
        )
        
        result.add_check(check)
        
        assert len(result.checks) == 1
        assert len(result.violations) == 0
        assert result.valid is True
    
    def test_add_check_failed_error(self):
        """Test adding a failed check with error severity invalidates result."""
        result = ValidationResult(valid=True, container_id="abc123")
        check = SecurityCheck(
            property_name="test",
            passed=False,
            observed_value="bad",
            expected_condition="good condition",
            severity="error"
        )
        
        result.add_check(check)
        
        assert len(result.checks) == 1
        assert len(result.violations) == 1
        assert result.valid is False
    
    def test_add_check_failed_warning(self):
        """Test adding a failed check with warning severity does not invalidate."""
        result = ValidationResult(valid=True, container_id="abc123")
        check = SecurityCheck(
            property_name="test",
            passed=False,
            observed_value="bad",
            expected_condition="good condition",
            severity="warning"
        )
        
        result.add_check(check)
        
        assert len(result.checks) == 1
        assert len(result.violations) == 0
        assert result.valid is True


class TestPrivilegedCheck:
    """Test privileged mode validation."""
    
    def test_privileged_false_passes(self, validator, mock_container):
        """Test container with privileged=false passes validation."""
        mock_container.attrs = {
            'HostConfig': {
                'Privileged': False
            }
        }
        
        result = validator.validate_container(mock_container)
        
        privileged_check = next(c for c in result.checks if c.property_name == 'privileged')
        assert privileged_check.passed is True
        assert privileged_check.observed_value is False
    
    def test_privileged_true_fails(self, validator, mock_container):
        """Test container with privileged=true fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'Privileged': True
            }
        }
        
        result = validator.validate_container(mock_container)
        
        privileged_check = next(c for c in result.checks if c.property_name == 'privileged')
        assert privileged_check.passed is False
        assert privileged_check.observed_value is True
        assert result.valid is False


class TestReadonlyRootfsCheck:
    """Test read-only root filesystem validation."""
    
    def test_readonly_rootfs_true_passes(self, validator, mock_container):
        """Test container with readonly rootfs passes validation."""
        mock_container.attrs = {
            'HostConfig': {
                'ReadonlyRootfs': True
            }
        }
        
        result = validator.validate_container(mock_container)
        
        readonly_check = next(c for c in result.checks if c.property_name == 'readonly_rootfs')
        assert readonly_check.passed is True
        assert readonly_check.observed_value is True
    
    def test_readonly_rootfs_false_fails(self, validator, mock_container):
        """Test container with writable rootfs fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'ReadonlyRootfs': False
            }
        }
        
        result = validator.validate_container(mock_container)
        
        readonly_check = next(c for c in result.checks if c.property_name == 'readonly_rootfs')
        assert readonly_check.passed is False
        assert readonly_check.observed_value is False
        assert result.valid is False


class TestTmpfsPolicyCheck:
    """Test Phase 3A tmpfs policy validation."""
    
    def test_no_mounts_passes(self, validator, mock_container):
        """Test container with no mounts passes validation."""
        mock_container.attrs = {
            'HostConfig': {
                'Binds': None,
                'Tmpfs': {}
            },
            'Mounts': []
        }
        
        result = validator.validate_container(mock_container)
        
        bind_check = next(c for c in result.checks if c.property_name == 'bind_mounts')
        assert bind_check.passed is True
    
    def test_approved_tmp_tmpfs_passes(self, validator, mock_container):
        """Test container with approved /tmp tmpfs passes validation."""
        mock_container.attrs = {
            'HostConfig': {
                'Binds': None,
                'Tmpfs': {
                    '/tmp': 'size=64m,noexec,nosuid,nodev'
                }
            },
            'Mounts': []  # Empty mounts array - validation will check HostConfig['Tmpfs'] directly
        }
        
        result = validator.validate_container(mock_container)
        
        bind_check = next(c for c in result.checks if c.property_name == 'bind_mounts')
        assert bind_check.passed is True
        assert bind_check.observed_value['approved_tmpfs_mounts'] == [
            {
                'destination': '/tmp',
                'size_mb': 64,
                'options': 'size=64m,noexec,nosuid,nodev'
            }
        ]
    
    def test_approved_analysis_temp_tmpfs_passes(self, validator, mock_container):
        """Test container with approved /analysis/temp tmpfs passes validation."""
        mock_container.attrs = {
            'HostConfig': {
                'Binds': None,
                'Tmpfs': {
                    '/analysis/temp': 'size=64m,nosuid,nodev,noexec'
                }
            },
            'Mounts': []  # Empty mounts array - validation will check HostConfig['Tmpfs'] directly
        }
        
        result = validator.validate_container(mock_container)
        
        bind_check = next(c for c in result.checks if c.property_name == 'bind_mounts')
        assert bind_check.passed is True
    
    def test_tmpfs_size_exceeds_64mb_fails(self, validator, mock_container):
        """Test container with tmpfs size > 64MB fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'Binds': None,
                'Tmpfs': {
                    '/tmp': 'size=128m,nosuid,nodev,noexec'
                }
            },
            'Mounts': []  # Empty mounts array - validation will check HostConfig['Tmpfs'] directly
        }
        
        result = validator.validate_container(mock_container)
        
        bind_check = next(c for c in result.checks if c.property_name == 'bind_mounts')
        assert bind_check.passed is False
        assert result.valid is False
        assert 'size exceeds 64MB' in bind_check.observed_value['invalid_mounts'][0]['reason']
    
    def test_arbitrary_tmpfs_destination_fails(self, validator, mock_container):
        """Test container with tmpfs at non-approved destination fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'Binds': None,
                'Tmpfs': {
                    '/var/tmp': 'size=64m,nosuid,nodev,noexec'
                }
            },
            'Mounts': []  # Empty mounts array - validation will check HostConfig['Tmpfs'] directly
        }
        
        result = validator.validate_container(mock_container)
        
        bind_check = next(c for c in result.checks if c.property_name == 'bind_mounts')
        assert bind_check.passed is False
        assert result.valid is False
        assert 'not approved' in bind_check.observed_value['invalid_mounts'][0]['reason']
    
    def test_bind_mount_fails(self, validator, mock_container):
        """Test container with host bind mount fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'Binds': ['/host/path:/container/path'],
                'Tmpfs': {}
            },
            'Mounts': [
                {
                    'Type': 'bind',
                    'Destination': '/container/path',
                    'Source': '/host/path'
                }
            ]
        }
        
        result = validator.validate_container(mock_container)
        
        bind_check = next(c for c in result.checks if c.property_name == 'bind_mounts')
        assert bind_check.passed is False
        assert result.valid is False
        assert 'Host bind mounts are prohibited' in bind_check.observed_value['invalid_mounts'][0]['reason']
    
    def test_named_volume_fails(self, validator, mock_container):
        """Test container with named Docker volume fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'Binds': None,
                'Tmpfs': {}
            },
            'Mounts': [
                {
                    'Type': 'volume',
                    'Name': 'my_volume',
                    'Destination': '/data'
                }
            ]
        }
        
        result = validator.validate_container(mock_container)
        
        bind_check = next(c for c in result.checks if c.property_name == 'bind_mounts')
        assert bind_check.passed is False
        assert result.valid is False
        assert 'Named Docker volumes are prohibited' in bind_check.observed_value['invalid_mounts'][0]['reason']
    
    def test_unknown_mount_type_fails(self, validator, mock_container):
        """Test container with unknown mount type fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'Binds': None,
                'Tmpfs': {}
            },
            'Mounts': [
                {
                    'Type': 'unknown',
                    'Destination': '/tmp'
                }
            ]
        }
        
        result = validator.validate_container(mock_container)
        
        bind_check = next(c for c in result.checks if c.property_name == 'bind_mounts')
        assert bind_check.passed is False
        assert result.valid is False
    
    def test_source_backed_tmpfs_fails(self, validator, mock_container):
        """Test container with source-backed tmpfs fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'Binds': None,
                'Tmpfs': {
                    '/tmp': 'size=64m,nosuid,nodev,noexec'
                }
            },
            'Mounts': [
                {
                    'Type': 'tmpfs',
                    'Destination': '/tmp',
                    'Source': '/host/path'  # tmpfs should not have source
                }
            ]
        }
        
        result = validator.validate_container(mock_container)
        
        bind_check = next(c for c in result.checks if c.property_name == 'bind_mounts')
        assert bind_check.passed is False
        assert result.valid is False
        assert 'should not have source path' in bind_check.observed_value['invalid_mounts'][0]['reason']
    
    def test_missing_noexec_option_fails(self, validator, mock_container):
        """Test container with missing noexec option fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'Binds': None,
                'Tmpfs': {
                    '/tmp': 'size=64m,nosuid,nodev'  # Missing noexec
                }
            },
            'Mounts': []  # Empty mounts array - validation will check HostConfig['Tmpfs'] directly
        }
        
        result = validator.validate_container(mock_container)
        
        bind_check = next(c for c in result.checks if c.property_name == 'bind_mounts')
        assert bind_check.passed is False
        assert result.valid is False
        assert 'Missing required options' in bind_check.observed_value['invalid_mounts'][0]['reason']
    
    def test_missing_required_tmpfs_options_fails(self, validator, mock_container):
        """Test container with missing required tmpfs options fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'Binds': None,
                'Tmpfs': {
                    '/tmp': 'size=64m'  # Missing nosuid, nodev, noexec
                }
            },
            'Mounts': []  # Empty mounts array - validation will check HostConfig['Tmpfs'] directly
        }
        
        result = validator.validate_container(mock_container)
        
        bind_check = next(c for c in result.checks if c.property_name == 'bind_mounts')
        assert bind_check.passed is False
        assert result.valid is False
        assert 'Missing required options' in bind_check.observed_value['invalid_mounts'][0]['reason']
    
    def test_malformed_mount_configuration_fails_closed(self, validator, mock_container):
        """Test container with malformed mount configuration fails closed."""
        mock_container.attrs = {
            'HostConfig': {
                'Binds': None,
                'Tmpfs': {}
            },
            'Mounts': [
                {
                    'Type': 'tmpfs'
                    # Missing Destination
                }
            ]
        }
        
        result = validator.validate_container(mock_container)
        
        bind_check = next(c for c in result.checks if c.property_name == 'bind_mounts')
        assert bind_check.passed is False
        assert result.valid is False
    
    def test_legacy_bind_mount_format_fails(self, validator, mock_container):
        """Test container with legacy Binds format fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'Binds': ['/host/path:/container/path:ro'],
                'Tmpfs': {}
            },
            'Mounts': []
        }
        
        result = validator.validate_container(mock_container)
        
        bind_check = next(c for c in result.checks if c.property_name == 'bind_mounts')
        assert bind_check.passed is False
        assert result.valid is False
        assert 'Legacy bind mounts format' in bind_check.observed_value['invalid_mounts'][0]['reason']


class TestIpcModeCheck:
    """Test IPC namespace mode validation."""
    
    def test_private_ipc_mode_passes(self, validator, mock_container):
        """Test container with private IPC mode passes validation."""
        mock_container.attrs = {
            'HostConfig': {
                'IpcMode': 'private'
            }
        }
        
        result = validator.validate_container(mock_container)
        
        ipc_check = next(c for c in result.checks if c.property_name == 'ipc_mode')
        assert ipc_check.passed is True
    
    def test_default_ipc_mode_passes(self, validator, mock_container):
        """Test container with default IPC mode passes validation."""
        mock_container.attrs = {
            'HostConfig': {
                'IpcMode': ''
            }
        }
        
        result = validator.validate_container(mock_container)
        
        ipc_check = next(c for c in result.checks if c.property_name == 'ipc_mode')
        assert ipc_check.passed is True
    
    def test_host_ipc_mode_fails(self, validator, mock_container):
        """Test container with host IPC mode fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'IpcMode': 'host'
            }
        }
        
        result = validator.validate_container(mock_container)
        
        ipc_check = next(c for c in result.checks if c.property_name == 'ipc_mode')
        assert ipc_check.passed is False
        assert ipc_check.observed_value == 'host'
        assert result.valid is False


class TestNetworkModeCheck:
    """Test network namespace mode validation."""
    
    def test_none_network_mode_passes(self, validator, mock_container):
        """Test container with network=none passes validation (Phase 2 requirement)."""
        mock_container.attrs = {
            'HostConfig': {
                'NetworkMode': 'none'
            }
        }
        
        result = validator.validate_container(mock_container)
        
        network_check = next(c for c in result.checks if c.property_name == 'network_mode')
        assert network_check.passed is True
    
    def test_host_network_mode_fails(self, validator, mock_container):
        """Test container with host network mode fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'NetworkMode': 'host'
            }
        }
        
        result = validator.validate_container(mock_container)
        
        network_check = next(c for c in result.checks if c.property_name == 'network_mode')
        assert network_check.passed is False
        assert network_check.observed_value == 'host'
        assert result.valid is False
    
    def test_bridge_network_mode_fails_phase2(self, validator, mock_container):
        """Test container with bridge network mode fails in Phase 2 (requires none)."""
        mock_container.attrs = {
            'HostConfig': {
                'NetworkMode': 'bridge'
            }
        }
        
        result = validator.validate_container(mock_container)
        
        network_check = next(c for c in result.checks if c.property_name == 'network_mode')
        assert network_check.passed is False
        assert result.valid is False


class TestCapabilitiesCheck:
    """Test capabilities validation."""
    
    def test_cap_drop_all_passes(self, validator, mock_container):
        """Test container with CapDrop=['ALL'] and no CapAdd passes validation."""
        mock_container.attrs = {
            'HostConfig': {
                'CapAdd': [],
                'CapDrop': ['ALL']
            }
        }
        
        result = validator.validate_container(mock_container)
        
        caps_check = next(c for c in result.checks if c.property_name == 'capabilities')
        assert caps_check.passed is True
    
    def test_cap_drop_without_all_fails(self, validator, mock_container):
        """Test container with CapDrop=['NET_RAW'] fails validation (missing ALL)."""
        mock_container.attrs = {
            'HostConfig': {
                'CapAdd': [],
                'CapDrop': ['CAP_NET_RAW']
            }
        }
        
        result = validator.validate_container(mock_container)
        
        caps_check = next(c for c in result.checks if c.property_name == 'capabilities')
        assert caps_check.passed is False
        assert result.valid is False
    
    def test_empty_cap_drop_fails(self, validator, mock_container):
        """Test container with empty CapDrop fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'CapAdd': [],
                'CapDrop': []
            }
        }
        
        result = validator.validate_container(mock_container)
        
        caps_check = next(c for c in result.checks if c.property_name == 'capabilities')
        assert caps_check.passed is False
        assert result.valid is False
    
    def test_missing_cap_drop_fails(self, validator, mock_container):
        """Test container with missing CapDrop fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'CapAdd': [],
                'CapDrop': None
            }
        }
        
        result = validator.validate_container(mock_container)
        
        caps_check = next(c for c in result.checks if c.property_name == 'capabilities')
        assert caps_check.passed is False
        assert result.valid is False
    
    def test_any_cap_add_fails(self, validator, mock_container):
        """Test container with any CapAdd entry fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'CapAdd': ['CAP_NET_BIND_SERVICE'],
                'CapDrop': ['ALL']
            }
        }
        
        result = validator.validate_container(mock_container)
        
        caps_check = next(c for c in result.checks if c.property_name == 'capabilities')
        assert caps_check.passed is False
        assert result.valid is False
    
    def test_empty_cap_add_passes(self, validator, mock_container):
        """Test container with empty CapAdd passes validation."""
        mock_container.attrs = {
            'HostConfig': {
                'CapAdd': [],
                'CapDrop': ['ALL']
            }
        }
        
        result = validator.validate_container(mock_container)
        
        caps_check = next(c for c in result.checks if c.property_name == 'capabilities')
        assert caps_check.passed is True


class TestNoNewPrivilegesCheck:
    """Test no-new-privileges validation."""
    
    def test_no_new_privileges_enabled_passes(self, validator, mock_container):
        """Test container with no-new-privileges enabled passes validation."""
        mock_container.attrs = {
            'HostConfig': {
                'SecurityOpt': ['no-new-privileges']
            }
        }
        
        result = validator.validate_container(mock_container)
        
        nnp_check = next(c for c in result.checks if c.property_name == 'no_new_privileges')
        assert nnp_check.passed is True
    
    def test_no_new_privileges_missing_fails(self, validator, mock_container):
        """Test container without no-new-privileges fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'SecurityOpt': []
            }
        }
        
        result = validator.validate_container(mock_container)
        
        nnp_check = next(c for c in result.checks if c.property_name == 'no_new_privileges')
        assert nnp_check.passed is False
        assert result.valid is False
    
    def test_no_new_privileges_none_fails(self, validator, mock_container):
        """Test container with None SecurityOpt fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'SecurityOpt': None
            }
        }
        
        result = validator.validate_container(mock_container)
        
        nnp_check = next(c for c in result.checks if c.property_name == 'no_new_privileges')
        assert nnp_check.passed is False
        assert result.valid is False


class TestMemoryLimitCheck:
    """Test memory limit validation."""
    
    def test_memory_limit_configured_passes(self, validator, mock_container):
        """Test container with memory limit passes validation."""
        mock_container.attrs = {
            'HostConfig': {
                'Memory': 536870912  # 512MB
            }
        }
        
        result = validator.validate_container(mock_container)
        
        memory_check = next(c for c in result.checks if c.property_name == 'memory_limit')
        assert memory_check.passed is True
    
    def test_memory_limit_zero_fails(self, validator, mock_container):
        """Test container with zero memory limit fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'Memory': 0
            }
        }
        
        result = validator.validate_container(mock_container)
        
        memory_check = next(c for c in result.checks if c.property_name == 'memory_limit')
        assert memory_check.passed is False
        assert result.valid is False
    
    def test_memory_limit_missing_fails(self, validator, mock_container):
        """Test container with missing memory limit fails validation."""
        mock_container.attrs = {
            'HostConfig': {}
        }
        
        result = validator.validate_container(mock_container)
        
        memory_check = next(c for c in result.checks if c.property_name == 'memory_limit')
        assert memory_check.passed is False
        assert result.valid is False


class TestPidLimitCheck:
    """Test PID limit validation."""
    
    def test_pid_limit_configured_passes(self, validator, mock_container):
        """Test container with PID limit passes validation."""
        mock_container.attrs = {
            'HostConfig': {
                'PidsLimit': 100
            }
        }
        
        result = validator.validate_container(mock_container)
        
        pid_limit_check = next(c for c in result.checks if c.property_name == 'pid_limit')
        assert pid_limit_check.passed is True
    
    def test_pid_limit_none_fails(self, validator, mock_container):
        """Test container with None PID limit fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'PidsLimit': None
            }
        }
        
        result = validator.validate_container(mock_container)
        
        pid_limit_check = next(c for c in result.checks if c.property_name == 'pid_limit')
        assert pid_limit_check.passed is False
        assert result.valid is False
    
    def test_pid_limit_missing_fails(self, validator, mock_container):
        """Test container with missing PID limit fails validation."""
        mock_container.attrs = {
            'HostConfig': {}
        }
        
        result = validator.validate_container(mock_container)
        
        pid_limit_check = next(c for c in result.checks if c.property_name == 'pid_limit')
        assert pid_limit_check.passed is False
        assert result.valid is False


class TestCpuLimitsCheck:
    """Test CPU limits validation."""
    
    def test_cpu_quota_configured_passes(self, validator, mock_container):
        """Test container with CPU quota passes validation."""
        mock_container.attrs = {
            'HostConfig': {
                'CpuQuota': 50000,
                'CpuPeriod': 100000
            }
        }
        
        result = validator.validate_container(mock_container)
        
        cpu_check = next(c for c in result.checks if c.property_name == 'cpu_limits')
        assert cpu_check.passed is True
    
    def test_cpu_shares_configured_passes(self, validator, mock_container):
        """Test container with CPU shares passes validation."""
        mock_container.attrs = {
            'HostConfig': {
                'CpuShares': 512
            }
        }
        
        result = validator.validate_container(mock_container)
        
        cpu_check = next(c for c in result.checks if c.property_name == 'cpu_limits')
        assert cpu_check.passed is True
    
    def test_cpuset_configured_passes(self, validator, mock_container):
        """Test container with CPU set passes validation."""
        mock_container.attrs = {
            'HostConfig': {
                'CpusetCpus': '0-1'
            }
        }
        
        result = validator.validate_container(mock_container)
        
        cpu_check = next(c for c in result.checks if c.property_name == 'cpu_limits')
        assert cpu_check.passed is True
    
    def test_no_cpu_limits_fails(self, validator, mock_container):
        """Test container with no CPU limits fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'CpuQuota': 0,
                'CpuPeriod': 0,
                'CpuShares': 0,
                'NanoCpus': 0,
                'CpusetCpus': ''
            }
        }
        
        result = validator.validate_container(mock_container)
        
        cpu_check = next(c for c in result.checks if c.property_name == 'cpu_limits')
        assert cpu_check.passed is False
        assert result.valid is False


class TestUserCheck:
    """Test user validation."""
    
    def test_non_root_user_passes(self, validator, mock_container):
        """Test container running as non-root user passes validation."""
        mock_container.attrs = {
            'Config': {
                'User': '1000'
            }
        }
        
        result = validator.validate_container(mock_container)
        
        user_check = next(c for c in result.checks if c.property_name == 'user')
        assert user_check.passed is True
        assert user_check.observed_value == '1000'
    
    def test_named_user_passes(self, validator, mock_container):
        """Test container running as named non-root user passes validation."""
        mock_container.attrs = {
            'Config': {
                'User': 'analyzer'
            }
        }
        
        result = validator.validate_container(mock_container)
        
        user_check = next(c for c in result.checks if c.property_name == 'user')
        assert user_check.passed is True
    
    def test_root_user_fails(self, validator, mock_container):
        """Test container running as root fails validation."""
        mock_container.attrs = {
            'Config': {
                'User': 'root'
            }
        }
        
        result = validator.validate_container(mock_container)
        
        user_check = next(c for c in result.checks if c.property_name == 'user')
        assert user_check.passed is False
        assert result.valid is False
    
    def test_uid_zero_fails(self, validator, mock_container):
        """Test container running as UID 0 fails validation."""
        mock_container.attrs = {
            'Config': {
                'User': '0'
            }
        }
        
        result = validator.validate_container(mock_container)
        
        user_check = next(c for c in result.checks if c.property_name == 'user')
        assert user_check.passed is False
        assert result.valid is False
    
    def test_default_user_fails(self, validator, mock_container):
        """Test container with default (empty) user fails validation."""
        mock_container.attrs = {
            'Config': {
                'User': ''
            }
        }
        
        result = validator.validate_container(mock_container)
        
        user_check = next(c for c in result.checks if c.property_name == 'user')
        assert user_check.passed is False
        assert user_check.observed_value == "root (default)"
        assert result.valid is False


class TestValidHardenedConfiguration:
    """Test completely valid hardened configuration."""
    
    def test_valid_hardened_configuration_passes_all_checks(self, validator, mock_container):
        """Test a fully hardened container configuration passes all validation."""
        mock_container.attrs = {
            'HostConfig': {
                'Privileged': False,
                'ReadonlyRootfs': True,
                'Binds': None,
                'PidMode': '',
                'IpcMode': 'private',
                'NetworkMode': 'none',
                'CapAdd': [],
                'CapDrop': ['ALL'],
                'SecurityOpt': ['no-new-privileges'],
                'Memory': 536870912,
                'PidsLimit': 100,
                'CpuQuota': 50000,
                'CpuPeriod': 100000
            },
            'Config': {
                'User': '1000'
            },
            'Mounts': []
        }
        
        result = validator.validate_container(mock_container)
        
        assert result.valid is True
        assert len(result.violations) == 0
        assert len(result.checks) == 12  # All security checks performed


class TestMalformedConfiguration:
    """Test malformed or missing Docker configuration fails closed."""
    
    def test_missing_host_config_fails_closed(self, validator, mock_container):
        """Test container with missing HostConfig fails validation."""
        mock_container.attrs = {}
        
        result = validator.validate_container(mock_container)
        
        assert result.valid is False
        assert len(result.violations) > 0
    
    def test_missing_config_fails_closed(self, validator, mock_container):
        """Test container with missing Config fails validation."""
        mock_container.attrs = {
            'HostConfig': {
                'Privileged': False,
                'ReadonlyRootfs': True,
                'Binds': None,
                'PidMode': '',
                'IpcMode': 'private',
                'NetworkMode': 'none',
                'CapAdd': [],
                'CapDrop': ['CAP_NET_RAW'],
                'SecurityOpt': ['no-new-privileges'],
                'Memory': 536870912,
                'PidsLimit': 100,
                'CpuQuota': 50000
            }
        }
        
        result = validator.validate_container(mock_container)
        
        assert result.valid is False
        # User check should fail
        user_check = next(c for c in result.checks if c.property_name == 'user')
        assert user_check.passed is False


class TestValidationErrorHandling:
    """Test validation error handling."""
    
    def test_container_reload_error_fails_closed(self, validator, mock_container):
        """Test container reload error fails validation closed."""
        mock_container.reload.side_effect = Exception("Reload failed")
        
        result = validator.validate_container(mock_container)
        
        assert result.valid is False
        error_check = next(c for c in result.checks if c.property_name == 'validation_error')
        assert error_check is not None
        assert error_check.passed is False
    
    def test_validation_logs_check_results(self, validator, mock_container):
        """Test validation logs check results appropriately."""
        mock_container.attrs = {
            'HostConfig': {
                'Privileged': True  # This will fail
            }
        }
        
        with patch.object(validator.logger, 'error') as mock_log_error:
            result = validator.validate_container(mock_container)
            
            # Should log error for privileged check failure
            assert mock_log_error.called
            log_calls = [str(call) for call in mock_log_error.call_args_list]
            assert any('privileged' in str(call) for call in log_calls)
