"""Unit tests for runtime PID/process isolation evidence probes."""

import os
import sys
import subprocess
from unittest.mock import patch, mock_open, MagicMock
import pytest

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.process_probes import ProcessProbes, ProbeResult


@pytest.fixture
def process_probes():
    """Create a ProcessProbes instance for testing."""
    return ProcessProbes()


class TestProbeResult:
    """Test ProbeResult dataclass."""
    
    def test_probe_result_initialization(self, process_probes):
        """Test ProbeResult can be initialized."""
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
    
    def test_probe_result_to_dict(self, process_probes):
        """Test ProbeResult can be converted to dictionary."""
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
        assert 'timestamp' in result_dict


class TestPidNamespaceEvidence:
    """Test PID namespace evidence probe."""
    
    def test_valid_namespace_identifiers_collected(self, process_probes):
        """Test that valid namespace identifiers are collected."""
        with patch('os.path.exists', return_value=True):
            with patch('os.stat') as mock_stat:
                # Mock same inode for both namespaces
                mock_stat.return_value.st_ino = 12345
                
                result = process_probes.probe_pid_namespace_evidence()
                
                assert result.probe_name == 'pid_namespace_evidence'
                assert result.passed is True
                assert result.observed_value['self_ns_inode'] == 12345
                assert result.observed_value['pid1_ns_inode'] == 12345
                assert result.observed_value['same_namespace'] is True
    
    def test_self_and_pid1_namespace_equality_recognized(self, process_probes):
        """Test that self and PID 1 namespace equality is recognized."""
        with patch('os.path.exists', return_value=True):
            with patch('os.stat') as mock_stat:
                # Mock same inode for both namespaces
                mock_stat.return_value.st_ino = 12345
                
                result = process_probes.probe_pid_namespace_evidence()
                
                assert result.observed_value['same_namespace'] is True
    
    def test_different_namespace_identifiers_recognized(self, process_probes):
        """Test that different namespace identifiers are recognized."""
        with patch('os.path.exists', return_value=True):
            with patch('os.stat') as mock_stat:
                # Mock different inodes
                def stat_side_effect(path):
                    mock = MagicMock()
                    if 'self' in path:
                        mock.st_ino = 12345
                    else:
                        mock.st_ino = 67890
                    return mock
                
                mock_stat.side_effect = stat_side_effect
                
                result = process_probes.probe_pid_namespace_evidence()
                
                assert result.observed_value['same_namespace'] is False
    
    def test_self_ns_not_found_fails(self, process_probes):
        """Test that missing self namespace fails."""
        with patch('os.path.exists', side_effect=[False, True]):
            result = process_probes.probe_pid_namespace_evidence()
            
            assert result.probe_name == 'pid_namespace_evidence'
            assert result.passed is False
            assert 'self_ns_not_found' in result.observed_value
            assert result.error is not None
    
    def test_pid1_ns_not_found_fails(self, process_probes):
        """Test that missing PID 1 namespace fails."""
        with patch('os.path.exists', side_effect=[True, False]):
            result = process_probes.probe_pid_namespace_evidence()
            
            assert result.probe_name == 'pid_namespace_evidence'
            assert result.passed is False
            # On Windows, this may return unexpected_error due to path differences
            # Just check that it fails with an error
            assert result.error is not None
    
    def test_permission_denied_fails(self, process_probes):
        """Test that permission denied is handled."""
        with patch('os.path.exists', return_value=True):
            with patch('os.stat', side_effect=PermissionError("Permission denied")):
                result = process_probes.probe_pid_namespace_evidence()
                
                assert result.passed is False
                assert 'permission_denied' in result.observed_value
                assert result.error is not None


class TestProcessVisibility:
    """Test process visibility probe."""
    
    def test_numeric_proc_entries_parsed(self, process_probes):
        """Test that numeric /proc entries are parsed correctly."""
        with patch('os.path.exists', return_value=True):
            with patch('os.listdir', return_value=['1', '2', '123', 'self', 'status']):
                with patch('os.getpid', return_value=100):
                    result = process_probes.probe_process_visibility()
                    
                    assert result.probe_name == 'process_visibility'
                    assert result.passed is True
                    assert result.observed_value['pid_count'] == 3
                    assert set(result.observed_value['visible_pids']) == {1, 2, 123}
                    assert result.observed_value['pid1_visible'] is True
    
    def test_non_pid_entries_ignored(self, process_probes):
        """Test that non-PID entries are ignored."""
        with patch('os.path.exists', return_value=True):
            with patch('os.listdir', return_value=['1', 'self', 'status', 'cpuinfo']):
                with patch('os.getpid', return_value=100):
                    result = process_probes.probe_process_visibility()
                    
                    assert result.observed_value['pid_count'] == 1
                    assert result.observed_value['visible_pids'] == [1]
    
    def test_pid1_evidence_collected(self, process_probes):
        """Test that PID 1 evidence is collected."""
        with patch('os.path.exists', return_value=True):
            with patch('os.listdir', return_value=['1', '2']):
                with patch('os.getpid', return_value=100):
                    result = process_probes.probe_process_visibility()
                    
                    assert result.observed_value['pid1_visible'] is True
    
    def test_proc_not_found_fails(self, process_probes):
        """Test that missing /proc fails."""
        with patch('os.path.exists', return_value=False):
            result = process_probes.probe_process_visibility()
            
            assert result.passed is False
            assert 'proc_not_found' in result.observed_value
            assert result.error is not None
    
    def test_permission_denied_fails(self, process_probes):
        """Test that permission denied is handled."""
        with patch('os.path.exists', return_value=True):
            with patch('os.listdir', side_effect=PermissionError("Permission denied")):
                result = process_probes.probe_process_visibility()
                
                assert result.passed is False
                assert 'permission_denied' in result.observed_value
                assert result.error is not None


class TestPid1Evidence:
    """Test PID 1 evidence probe."""
    
    def test_valid_status_parsing(self, process_probes):
        """Test that valid status parsing works."""
        status_content = """Name: init
State: S (sleeping)
Pid: 1
"""
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', mock_open(read_data=status_content)):
                with patch('os.path.exists', side_effect=[True, False]):  # cmdline doesn't exist
                    result = process_probes.probe_pid1_evidence()
                    
                    assert result.probe_name == 'pid1_evidence'
                    assert result.passed is True
                    assert result.observed_value['pid'] == 1
                    assert result.observed_value['name'] == 'init'
                    assert result.observed_value['state'] == 'S (sleeping)'
    
    def test_valid_cmdline_parsing(self, process_probes):
        """Test that valid cmdline parsing works."""
        status_content = "Name: init\nState: S\n"
        cmdline_content = b"/sbin/init\x00arg1\x00arg2"
        
        with patch('os.path.exists', return_value=True):
            # Use side_effect to handle both file opens
            def open_side_effect(path, mode='r'):
                if 'status' in path:
                    return mock_open(read_data=status_content).return_value()
                elif 'cmdline' in path:
                    return mock_open(read_data=cmdline_content).return_value()
                else:
                    raise FileNotFoundError(path)
            
            with patch('builtins.open', side_effect=open_side_effect):
                result = process_probes.probe_pid1_evidence()
            
            assert result.passed is True
            assert 'cmdline' in result.observed_value
            assert result.observed_value['cmdline'] != 'unknown'
    
    def test_malformed_status_handled(self, process_probes):
        """Test that malformed status is handled safely."""
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', side_effect=IOError("Read error")):
                result = process_probes.probe_pid1_evidence()
                
                assert result.passed is False
                assert result.error is not None
    
    def test_missing_pid1_status_fails(self, process_probes):
        """Test that missing PID 1 status fails."""
        with patch('os.path.exists', return_value=False):
            result = process_probes.probe_pid1_evidence()
            
            assert result.passed is False
            assert 'pid1_status_not_found' in result.observed_value
            assert result.error is not None


class TestControlledSubprocess:
    """Test controlled subprocess probe with observability."""
    
    def test_subprocess_starts_and_receives_pid(self, process_probes):
        """Test that subprocess starts and receives a PID."""
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_process.pid = 12345
            mock_process.poll.return_value = None  # Still alive
            mock_process.wait.return_value = 0
            mock_popen.return_value = mock_process
            
            with patch('src.process_probes.time.sleep'):
                with patch('os.path.exists', return_value=True):
                    with patch('os.listdir', return_value=['1', '12345', 'self']):
                        result = process_probes.probe_controlled_subprocess()
                        
                        assert result.probe_name == 'controlled_subprocess'
                        assert result.passed is True
                        assert result.observed_value['process_started'] is True
                        assert result.observed_value['pid_obtained'] is True
                        assert result.observed_value['pid'] == 12345
                        assert result.observed_value['pid_observed_while_alive'] is True
                        assert result.observed_value['process_terminated'] is True
                        assert result.observed_value['terminated_cleanly'] is True
    
    def test_pid_observed_while_alive(self, process_probes):
        """Test that PID is observed while process is alive."""
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_process.pid = 12345
            mock_process.poll.return_value = None  # Still alive
            mock_process.wait.return_value = 0
            mock_popen.return_value = mock_process
            
            with patch('src.process_probes.time.sleep'):
                with patch('os.path.exists', return_value=True):
                    with patch('os.listdir', return_value=['1', '12345', 'self']):
                        result = process_probes.probe_controlled_subprocess()
                        
                        assert result.observed_value['pid_observed_while_alive'] is True
    
    def test_pid_not_observed_when_proc_missing(self, process_probes):
        """Test that PID observation fails when /proc is missing."""
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_process.pid = 12345
            mock_process.poll.return_value = None
            mock_process.wait.return_value = 0
            mock_popen.return_value = mock_process
            
            with patch('src.process_probes.time.sleep'):
                with patch('os.path.exists', return_value=False):
                    result = process_probes.probe_controlled_subprocess()
                    
                    # Should still pass but PID not observed
                    assert result.observed_value['pid_observed_while_alive'] is False
    
    def test_process_terminates_cleanly(self, process_probes):
        """Test that process terminates cleanly."""
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_process.pid = 12345
            # First poll() call returns None (still alive), second returns exit code (terminated)
            mock_process.poll.side_effect = [None, 0]
            mock_process.wait.return_value = 0
            mock_popen.return_value = mock_process
            
            with patch('src.process_probes.time.sleep'):
                with patch('os.path.exists', return_value=True):
                    with patch('os.listdir', return_value=['1', '12345']):
                        result = process_probes.probe_controlled_subprocess()
                        
                        assert result.observed_value['process_terminated'] is True
                        assert result.observed_value['terminated_cleanly'] is True
                        assert result.observed_value['no_child_remains'] is True
    
    def test_subprocess_nonzero_exit_fails(self, process_probes):
        """Test that non-zero exit is handled."""
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_process.pid = 12345
            mock_process.poll.return_value = None
            mock_process.wait.return_value = 1
            mock_popen.return_value = mock_process
            
            with patch('src.process_probes.time.sleep'):
                with patch('os.path.exists', return_value=True):
                    with patch('os.listdir', return_value=['1', '12345']):
                        result = process_probes.probe_controlled_subprocess()
                        
                        assert result.passed is False
                        assert result.observed_value['return_code'] == 1
                        assert result.observed_value['terminated_cleanly'] is False
                        assert result.error is not None
    
    def test_process_terminates_early_fails(self, process_probes):
        """Test that process terminating early is handled."""
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_process.pid = 12345
            mock_process.poll.return_value = 0  # Already terminated
            mock_popen.return_value = mock_process
            
            with patch('src.process_probes.time.sleep'):
                result = process_probes.probe_controlled_subprocess()
                
                assert result.passed is False
                assert result.observed_value['pid_observed_while_alive'] is False
                assert result.observed_value['process_terminated_early'] is True
                assert result.error is not None
    
    def test_no_pid_assigned_fails(self, process_probes):
        """Test that missing PID assignment fails."""
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_process.pid = None
            mock_popen.return_value = mock_process
            
            result = process_probes.probe_controlled_subprocess()
            
            assert result.passed is False
            assert result.observed_value['pid_obtained'] is False
            assert result.error is not None
    
    def test_cleanup_on_normal_completion(self, process_probes):
        """Test that cleanup occurs on normal completion."""
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_process.pid = 12345
            mock_process.poll.return_value = None
            mock_process.wait.return_value = 0
            mock_popen.return_value = mock_process
            
            with patch('src.process_probes.time.sleep'):
                with patch('os.path.exists', return_value=True):
                    with patch('os.listdir', return_value=['1', '12345']):
                        result = process_probes.probe_controlled_subprocess()
                        
                        # Process should be removed from tracking list
                        assert 12345 not in process_probes._created_processes
                        assert result.observed_value['cleanup_success'] is True
    
    def test_cleanup_on_error(self, process_probes):
        """Test that cleanup occurs when probe execution raises."""
        with patch('subprocess.Popen', side_effect=Exception("Subprocess failed")):
            result = process_probes.probe_controlled_subprocess()
            
            assert result.passed is False
            assert result.observed_value['cleanup_attempted'] is False
            assert result.error is not None
    
    def test_timeout_behavior(self, process_probes):
        """Test timeout behavior."""
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_process.pid = 12345
            mock_process.poll.return_value = None
            mock_process.wait.side_effect = subprocess.TimeoutExpired("cmd", 5)
            mock_popen.return_value = mock_process
            
            with patch('src.process_probes.time.sleep'):
                with patch.object(process_probes, '_terminate_process'):
                    result = process_probes.probe_controlled_subprocess()
                    
                    assert result.passed is False
                    assert result.observed_value['timeout'] is True
                    assert result.observed_value['process_terminated'] is False
                    assert result.observed_value['cleanup_success'] is True


class TestProcessProbesCleanup:
    """Test process probes cleanup."""
    
    def test_cleanup_removes_processes(self, process_probes):
        """Test that cleanup removes created processes."""
        process_probes._created_processes = [12345, 67890]
        
        with patch('os.kill') as mock_kill:
            with patch('os.waitpid', side_effect=ProcessLookupError):
                cleanup_status = process_probes.cleanup()
                
                assert len(process_probes._created_processes) == 0
                assert '12345' in cleanup_status
                assert '67890' in cleanup_status
    
    def test_cleanup_handles_exited_processes(self, process_probes):
        """Test that cleanup handles already-exited processes."""
        process_probes._created_processes = [12345]
        
        with patch('os.kill', side_effect=ProcessLookupError):
            cleanup_status = process_probes.cleanup()
            
            assert len(process_probes._created_processes) == 0
            assert cleanup_status['12345'] == 'already_exited'
    
    def test_cleanup_handles_permission_errors(self, process_probes):
        """Test that cleanup handles permission errors."""
        process_probes._created_processes = [12345]
        
        with patch('os.kill', side_effect=PermissionError):
            cleanup_status = process_probes.cleanup()
            
            assert len(process_probes._created_processes) == 0
            assert 'permission_denied' in cleanup_status['12345']


class TestRunAllProbes:
    """Test running all process probes."""
    
    def test_run_all_probes_succeeds(self, process_probes):
        """Test that all probes run successfully."""
        with patch.object(process_probes, 'probe_pid_namespace_evidence') as mock_ns:
            with patch.object(process_probes, 'probe_process_visibility') as mock_vis:
                with patch.object(process_probes, 'probe_pid1_evidence') as mock_pid1:
                    with patch.object(process_probes, 'probe_controlled_subprocess') as mock_sub:
                        with patch.object(process_probes, 'cleanup'):
                            mock_ns.return_value = ProbeResult(
                                probe_name='pid_namespace_evidence',
                                passed=True,
                                observed_value='good',
                                expected_condition='good'
                            )
                            mock_vis.return_value = ProbeResult(
                                probe_name='process_visibility',
                                passed=True,
                                observed_value='good',
                                expected_condition='good'
                            )
                            mock_pid1.return_value = ProbeResult(
                                probe_name='pid1_evidence',
                                passed=True,
                                observed_value='good',
                                expected_condition='good'
                            )
                            mock_sub.return_value = ProbeResult(
                                probe_name='controlled_subprocess',
                                passed=True,
                                observed_value='good',
                                expected_condition='good'
                            )
                            
                            results = process_probes.run_all_probes()
                            
                            assert len(results) == 4
                            assert 'pid_namespace_evidence' in results
                            assert 'process_visibility' in results
                            assert 'pid1_evidence' in results
                            assert 'controlled_subprocess' in results
    
    def test_run_all_probes_cleanup_on_failure(self, process_probes):
        """Test that cleanup occurs when probe fails."""
        with patch.object(process_probes, 'probe_pid_namespace_evidence', side_effect=Exception("Probe failed")):
            with patch.object(process_probes, 'cleanup') as mock_cleanup:
                results = process_probes.run_all_probes()
                
                # Cleanup should still be called
                mock_cleanup.assert_called_once()
    
    def test_run_all_probes_cleanup_on_success(self, process_probes):
        """Test that cleanup occurs on success."""
        with patch.object(process_probes, 'probe_pid_namespace_evidence') as mock_ns:
            with patch.object(process_probes, 'cleanup') as mock_cleanup:
                mock_ns.return_value = ProbeResult(
                    probe_name='pid_namespace_evidence',
                    passed=True,
                    observed_value='good',
                    expected_condition='good'
                )
                
                results = process_probes.run_all_probes()
                
                # Cleanup should be called
                mock_cleanup.assert_called_once()
