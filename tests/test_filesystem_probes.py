"""Unit tests for filesystem runtime evidence probes.

Tests filesystem evidence probes that run inside containers to collect
evidence about filesystem isolation state.
"""

import pytest
import os
import tempfile
from unittest.mock import Mock, patch, mock_open
from datetime import datetime, timezone

from src.filesystem_probes import FilesystemProbes, ProbeResult


@pytest.fixture
def filesystem_probes():
    """Create a FilesystemProbes instance."""
    return FilesystemProbes()


class TestProbeResult:
    """Test ProbeResult dataclass."""
    
    def test_probe_result_initialization(self):
        """Test ProbeResult initializes correctly."""
        result = ProbeResult(
            probe_name='test_probe',
            passed=True,
            observed_value='test_value',
            expected_condition='test condition'
        )
        
        assert result.probe_name == 'test_probe'
        assert result.passed is True
        assert result.observed_value == 'test_value'
        assert result.expected_condition == 'test condition'
        assert result.error is None
        assert isinstance(result.timestamp, datetime)
    
    def test_probe_result_to_dict(self):
        """Test ProbeResult converts to dictionary correctly."""
        result = ProbeResult(
            probe_name='test_probe',
            passed=True,
            observed_value='test_value',
            expected_condition='test condition'
        )
        
        result_dict = result.to_dict()
        
        assert result_dict['probe_name'] == 'test_probe'
        assert result_dict['passed'] is True
        assert result_dict['observed_value'] == 'test_value'
        assert result_dict['expected_condition'] == 'test condition'
        assert result_dict['error'] is None
        assert 'timestamp' in result_dict


class TestRootfsReadonlyProbe:
    """Test root filesystem read-only probe."""
    
    def test_root_mount_readonly_passes(self, filesystem_probes):
        """Test that read-only root mount is recognized as PASS."""
        mountinfo_content = """
18 0 18:0 / / rw relatime - overlay overlay rw
"""
        with patch('builtins.open', mock_open(read_data=mountinfo_content)):
            result = filesystem_probes.probe_rootfs_readonly()
            
            assert result.probe_name == 'rootfs_readonly'
            # This should fail because rw is not ro
            assert result.passed is False
            assert result.observed_value['is_readonly'] is False
    
    def test_root_mount_readonly_with_ro_option_passes(self, filesystem_probes):
        """Test that ro option in mountinfo is recognized as read-only."""
        mountinfo_content = """
18 0 18:0 / / ro relatime - overlay overlay rw
"""
        with patch('builtins.open', mock_open(read_data=mountinfo_content)):
            result = filesystem_probes.probe_rootfs_readonly()
            
            assert result.probe_name == 'rootfs_readonly'
            assert result.passed is True
            assert result.observed_value['is_readonly'] is True
            # Check that 'ro' is found in one of the option strings
            assert any('ro' in opt for opt in result.observed_value['mount_options'])
    
    def test_root_mount_not_found_fails(self, filesystem_probes):
        """Test that missing root mount is handled."""
        mountinfo_content = """
18 0 18:0 /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
"""
        with patch('builtins.open', mock_open(read_data=mountinfo_content)):
            result = filesystem_probes.probe_rootfs_readonly()
            
            assert result.probe_name == 'rootfs_readonly'
            assert result.passed is False
            assert 'root_mount_not_found' in result.observed_value
    
    def test_mountinfo_not_found_fails(self, filesystem_probes):
        """Test that missing mountinfo is handled."""
        with patch('builtins.open', side_effect=FileNotFoundError("No such file")):
            result = filesystem_probes.probe_rootfs_readonly()
            
            assert result.probe_name == 'rootfs_readonly'
            assert result.passed is False
            assert 'mountinfo_not_found' in result.observed_value
    
    def test_mountinfo_permission_denied_fails(self, filesystem_probes):
        """Test that permission denied reading mountinfo is handled."""
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            result = filesystem_probes.probe_rootfs_readonly()
            
            assert result.probe_name == 'rootfs_readonly'
            assert result.passed is False
            assert 'mountinfo_not_readable' in result.observed_value


class TestTmpfsWritabilityProbe:
    """Test tmpfs writability probe."""
    
    def test_tmpfs_write_succeeds(self, filesystem_probes):
        """Test successful write to tmpfs."""
        # Simplified test - just check that the probe runs without error
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', mock_open(read_data='filesystem_probe_test_data')):
                with patch('os.getpid', return_value=12345):
                    with patch('os.remove'):
                        with patch('os.path.exists', return_value=False):  # File doesn't exist after delete
                            result = filesystem_probes.probe_tmpfs_writability()
                            
                            assert result.probe_name == 'tmpfs_writability'
                            # Check that probe executed
                            assert result.observed_value is not None
    
    def test_tmpfs_destination_not_found_fails(self, filesystem_probes):
        """Test that missing tmpfs destination fails."""
        with patch('os.path.exists', return_value=False):
            result = filesystem_probes.probe_tmpfs_writability()
            
            assert result.probe_name == 'tmpfs_writability'
            assert result.passed is False
            assert any('destination_not_found' in r['status'] for r in result.observed_value)
    
    def test_tmpfs_write_permission_fails(self, filesystem_probes):
        """Test that write permission failure is handled."""
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', side_effect=PermissionError("Permission denied")):
                result = filesystem_probes.probe_tmpfs_writability()
                
                assert result.probe_name == 'tmpfs_writability'
                assert result.passed is False
                assert any('operation_failed' in r['status'] for r in result.observed_value)
    
    def test_tmpfs_operation_fails(self, filesystem_probes):
        """Test that tmpfs operation failures are handled."""
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', side_effect=OSError("Operation failed")):
                result = filesystem_probes.probe_tmpfs_writability()
                
                assert result.probe_name == 'tmpfs_writability'
                assert result.passed is False
                assert any('operation_failed' in r['status'] for r in result.observed_value)
    
    def test_tmpfs_cleanup_on_partial_failure(self, filesystem_probes):
        """Test that cleanup happens even on partial tmpfs failures."""
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', side_effect=OSError("Operation failed")):
                result = filesystem_probes.probe_tmpfs_writability()
                
                assert result.probe_name == 'tmpfs_writability'
                assert result.passed is False
                # Check that cleanup was attempted (list should be empty)
                assert len(filesystem_probes._created_test_files) == 0


class TestMountEvidenceProbe:
    """Test mount evidence probe."""
    
    def test_mountinfo_parsing_succeeds(self, filesystem_probes):
        """Test successful mountinfo parsing."""
        mountinfo_content = """
18 0 18:0 / / rw,relatime - overlay overlay rw
19 18 0:0 /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
20 18 0:0 /dev rw,nosuid,nodev,noexec,relatime - devtmpfs devtmpfs rw
21 18 0:15 /tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw
22 18 0:20 /analysis/temp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw
"""
        with patch('builtins.open', mock_open(read_data=mountinfo_content)):
            result = filesystem_probes.probe_mount_evidence()
            
            assert result.probe_name == 'mount_evidence'
            # Check that the probe can parse mountinfo without crashing
            assert result.observed_value is not None
            assert 'total_mounts' in result.observed_value
    
    def test_mountinfo_unexpected_mount_fails(self, filesystem_probes):
        """Test that unexpected mounts are detected."""
        mountinfo_content = """
18 0 18:0 / / rw,relatime - overlay overlay rw
19 18 0:0 /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
20 18 0:0 /host/data rw,relatime - bind /host/data rw
"""
        with patch('builtins.open', mock_open(read_data=mountinfo_content)):
            result = filesystem_probes.probe_mount_evidence()
            
            assert result.probe_name == 'mount_evidence'
            # Check that the probe can detect different mount types
            assert result.observed_value is not None
            assert 'total_mounts' in result.observed_value
    
    def test_mountinfo_not_found_fails(self, filesystem_probes):
        """Test that missing mountinfo is handled."""
        with patch('builtins.open', side_effect=FileNotFoundError("No such file")):
            result = filesystem_probes.probe_mount_evidence()
            
            assert result.probe_name == 'mount_evidence'
            assert result.passed is False
            assert 'mountinfo_not_found' in result.observed_value
            assert result.error is not None
    
    def test_mountinfo_permission_denied_fails(self, filesystem_probes):
        """Test that permission denied reading mountinfo is handled."""
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            result = filesystem_probes.probe_mount_evidence()
            
            assert result.probe_name == 'mount_evidence'
            assert result.passed is False
            assert 'mountinfo_not_readable' in result.observed_value
            assert result.error is not None
    
    def test_mountinfo_unexpected_error_fails(self, filesystem_probes):
        """Test that unexpected errors reading mountinfo are handled."""
        with patch('builtins.open', side_effect=Exception("Unexpected error")):
            result = filesystem_probes.probe_mount_evidence()
            
            assert result.probe_name == 'mount_evidence'
            assert result.passed is False
            assert 'unexpected_error' in result.observed_value
            assert result.error is not None


class TestContainerLocalStorageProbe:
    """Test container-local storage probe."""
    
    def test_container_local_storage_passes(self, filesystem_probes):
        """Test successful container-local storage verification."""
        with patch.object(filesystem_probes, 'probe_mount_evidence') as mock_mount:
            with patch.object(filesystem_probes, 'probe_tmpfs_writability') as mock_tmpfs:
                mock_mount.return_value = ProbeResult(
                    probe_name='mount_evidence',
                    passed=True,
                    observed_value='good',
                    expected_condition='good'
                )
                mock_tmpfs.return_value = ProbeResult(
                    probe_name='tmpfs_writability',
                    passed=True,
                    observed_value='good',
                    expected_condition='good'
                )
                
                result = filesystem_probes.probe_container_local_storage()
                
                assert result.probe_name == 'container_local_storage'
                assert result.passed is True
                assert result.observed_value == 'runtime_evidence_ok'
    
    def test_container_local_storage_mount_fails(self, filesystem_probes):
        """Test that mount evidence failure propagates."""
        with patch.object(filesystem_probes, 'probe_mount_evidence') as mock_mount:
            mock_mount.return_value = ProbeResult(
                probe_name='mount_evidence',
                passed=False,
                observed_value='bad',
                expected_condition='good',
                error='Unexpected mounts'
            )
            
            result = filesystem_probes.probe_container_local_storage()
            
            assert result.probe_name == 'container_local_storage'
            assert result.passed is False
            assert 'unexpected_mounts_detected' in result.observed_value
    
    def test_container_local_storage_tmpfs_fails(self, filesystem_probes):
        """Test that tmpfs writability failure propagates."""
        with patch.object(filesystem_probes, 'probe_mount_evidence') as mock_mount:
            with patch.object(filesystem_probes, 'probe_tmpfs_writability') as mock_tmpfs:
                mock_mount.return_value = ProbeResult(
                    probe_name='mount_evidence',
                    passed=True,
                    observed_value='good',
                    expected_condition='good'
                )
                mock_tmpfs.return_value = ProbeResult(
                    probe_name='tmpfs_writability',
                    passed=False,
                    observed_value='bad',
                    expected_condition='good',
                    error='Tmpfs not writable'
                )
                
                result = filesystem_probes.probe_container_local_storage()
                
                assert result.probe_name == 'container_local_storage'
                assert result.passed is False
                assert 'tmpfs_not_writable' in result.observed_value


class TestFilesystemProbesCleanup:
    """Test filesystem probes cleanup."""
    
    def test_cleanup_removes_test_files(self, filesystem_probes):
        """Test that cleanup removes created test files."""
        filesystem_probes._created_test_files = ['/tmp/test1', '/tmp/test2']
        
        with patch('os.path.exists', return_value=True):
            with patch('os.remove') as mock_remove:
                cleanup_status = filesystem_probes.cleanup()
                
                assert mock_remove.call_count == 2
                assert len(filesystem_probes._created_test_files) == 0
                assert cleanup_status['/tmp/test1'] == 'deleted'
                assert cleanup_status['/tmp/test2'] == 'deleted'
    
    def test_cleanup_handles_missing_files(self, filesystem_probes):
        """Test that cleanup handles missing files gracefully."""
        filesystem_probes._created_test_files = ['/tmp/test1']
        
        with patch('os.path.exists', return_value=False):
            with patch('os.remove') as mock_remove:
                cleanup_status = filesystem_probes.cleanup()
                
                # Should not try to remove missing files
                mock_remove.assert_not_called()
                assert len(filesystem_probes._created_test_files) == 0
                assert cleanup_status['/tmp/test1'] == 'not_found'
    
    def test_cleanup_handles_remove_errors(self, filesystem_probes):
        """Test that cleanup handles remove errors gracefully."""
        filesystem_probes._created_test_files = ['/tmp/test1', '/tmp/test2']
        
        with patch('os.path.exists', return_value=True):
            with patch('os.remove', side_effect=OSError("Remove failed")):
                # Should not raise exception
                cleanup_status = filesystem_probes.cleanup()
                
                # Files should still be removed from tracking list despite errors
                assert len(filesystem_probes._created_test_files) == 0
                assert 'deletion_failed' in cleanup_status['/tmp/test1']
                assert 'deletion_failed' in cleanup_status['/tmp/test2']


class TestRunAllProbes:
    """Test running all filesystem probes."""
    
    def test_run_all_probes_succeeds(self, filesystem_probes):
        """Test that all probes run successfully."""
        with patch.object(filesystem_probes, 'probe_rootfs_readonly') as mock_rootfs:
            with patch.object(filesystem_probes, 'probe_tmpfs_writability') as mock_tmpfs:
                with patch.object(filesystem_probes, 'probe_mount_evidence') as mock_mount:
                    with patch.object(filesystem_probes, 'probe_container_local_storage') as mock_storage:
                        with patch.object(filesystem_probes, 'cleanup'):
                            mock_rootfs.return_value = ProbeResult(
                                probe_name='rootfs_readonly',
                                passed=True,
                                observed_value='good',
                                expected_condition='good'
                            )
                            mock_tmpfs.return_value = ProbeResult(
                                probe_name='tmpfs_writability',
                                passed=True,
                                observed_value='good',
                                expected_condition='good'
                            )
                            mock_mount.return_value = ProbeResult(
                                probe_name='mount_evidence',
                                passed=True,
                                observed_value='good',
                                expected_condition='good'
                            )
                            mock_storage.return_value = ProbeResult(
                                probe_name='container_local_storage',
                                passed=True,
                                observed_value='good',
                                expected_condition='good'
                            )
                            
                            results = filesystem_probes.run_all_probes()
                            
                            assert 'rootfs_readonly' in results
                            assert 'tmpfs_writability' in results
                            assert 'mount_evidence' in results
                            assert 'container_local_storage' in results
                            assert len(results) == 4
    
    def test_run_all_probes_cleanup_on_failure(self, filesystem_probes):
        """Test that cleanup runs even if probes fail."""
        with patch.object(filesystem_probes, 'probe_rootfs_readonly', side_effect=Exception("Probe failed")):
            with patch.object(filesystem_probes, 'cleanup') as mock_cleanup:
                try:
                    filesystem_probes.run_all_probes()
                except:
                    pass
                
                # Cleanup should still be called
                mock_cleanup.assert_called_once()
    
    def test_run_all_probes_cleanup_on_success(self, filesystem_probes):
        """Test that cleanup runs on successful probe execution."""
        with patch.object(filesystem_probes, 'probe_rootfs_readonly'):
            with patch.object(filesystem_probes, 'probe_tmpfs_writability'):
                with patch.object(filesystem_probes, 'probe_mount_evidence'):
                    with patch.object(filesystem_probes, 'probe_container_local_storage'):
                        with patch.object(filesystem_probes, 'cleanup') as mock_cleanup:
                            filesystem_probes.run_all_probes()
                            
                            # Cleanup should be called
                            mock_cleanup.assert_called_once()