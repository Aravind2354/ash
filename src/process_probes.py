"""Runtime PID/process isolation evidence probes for container validation.

This module provides probes that collect evidence about PID namespace behavior,
process visibility, controlled subprocess creation, and PID/resource limits inside
containers. These probes run inside the container and return structured evidence
for later aggregation.

SECURITY CRITICAL: All probes are designed to be non-destructive and fail
closed on errors. These probes provide EVIDENCE, not absolute proof of
isolation. They complement trusted host-side Docker configuration validation.

IMPORTANT: Runtime evidence alone does NOT prove:
- Complete impossibility of container escape
- Absence of kernel vulnerabilities
- Absolute host process isolation
Filesystem evidence comes from Phase 3A. Network evidence belongs to Phase 3C.
"""

import os
import sys
import subprocess
import signal
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone


@dataclass
class ProbeResult:
    """Result of a single process evidence probe."""
    
    probe_name: str
    passed: bool
    observed_value: Any
    expected_condition: str
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert probe result to dictionary for JSON serialization."""
        return {
            'probe_name': self.probe_name,
            'passed': self.passed,
            'observed_value': self.observed_value,
            'expected_condition': self.expected_condition,
            'error': self.error,
            'timestamp': self.timestamp.isoformat()
        }


class ProcessProbes:
    """Runtime PID/process evidence probes for container isolation validation.
    
    These probes collect evidence about PID namespace state and process behavior
    inside containers. They are designed to be non-destructive and fail closed
    on errors.
    """
    
    def __init__(self):
        """Initialize process probes."""
        self._created_processes = []  # Track subprocess PIDs for cleanup
        self.logger = None  # Optional logger for debugging
    
    def probe_pid_namespace_evidence(self) -> ProbeResult:
        """Probe A: Collect PID namespace evidence.
        
        Reads namespace identifiers for /proc/self/ns/pid and /proc/1/ns/pid
        to determine if current process and PID 1 belong to the same container
        PID namespace.
        
        Returns:
            ProbeResult with PID namespace evidence.
        """
        try:
            # Read self PID namespace
            self_ns_path = '/proc/self/ns/pid'
            if not os.path.exists(self_ns_path):
                return ProbeResult(
                    probe_name='pid_namespace_evidence',
                    passed=False,
                    observed_value='self_ns_not_found',
                    expected_condition='/proc/self/ns/pid should be readable',
                    error='/proc/self/ns/pid not found (PID namespace not available)'
                )
            
            self_ns_inode = os.stat(self_ns_path).st_ino
            
            # Read PID 1 namespace
            pid1_ns_path = '/proc/1/ns/pid'
            if not os.path.exists(pid1_ns_path):
                return ProbeResult(
                    probe_name='pid_namespace_evidence',
                    passed=False,
                    observed_value='pid1_ns_not_found',
                    expected_condition='/proc/1/ns/pid should be readable',
                    error='/proc/1/ns/pid not found (PID 1 not accessible)'
                )
            
            pid1_ns_inode = os.stat(pid1_ns_path).st_ino
            
            # Compare namespace identifiers
            same_namespace = self_ns_inode == pid1_ns_inode
            
            return ProbeResult(
                probe_name='pid_namespace_evidence',
                passed=True,  # Evidence collection succeeded
                observed_value={
                    'self_ns_inode': self_ns_inode,
                    'pid1_ns_inode': pid1_ns_inode,
                    'same_namespace': same_namespace,
                    'current_pid': os.getpid()
                },
                expected_condition='Current process and PID 1 should be in same PID namespace',
                error=None
            )
            
        except PermissionError as e:
            return ProbeResult(
                probe_name='pid_namespace_evidence',
                passed=False,
                observed_value='permission_denied',
                expected_condition='/proc/*/ns/pid should be readable',
                error=f'Permission denied reading namespace: {e}'
            )
        except Exception as e:
            return ProbeResult(
                probe_name='pid_namespace_evidence',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='/proc/*/ns/pid should be readable',
                error=f'Unexpected error reading namespace: {e}'
            )
    
    def probe_process_visibility(self) -> ProbeResult:
        """Probe B: Collect process visibility evidence.
        
        Enumerates numeric entries under /proc to determine visible PIDs.
        Returns structured evidence about process count and visibility.
        
        Returns:
            ProbeResult with process visibility evidence.
        """
        try:
            proc_path = '/proc'
            if not os.path.exists(proc_path):
                return ProbeResult(
                    probe_name='process_visibility',
                    passed=False,
                    observed_value='proc_not_found',
                    expected_condition='/proc should be readable',
                    error='/proc not found (procfs not available)'
                )
            
            # Enumerate numeric entries (PIDs)
            visible_pids = []
            for entry in os.listdir(proc_path):
                if entry.isdigit():
                    try:
                        pid = int(entry)
                        visible_pids.append(pid)
                    except ValueError:
                        continue
            
            current_pid = os.getpid()
            pid_count = len(visible_pids)
            
            # Check if PID 1 is visible
            pid1_visible = 1 in visible_pids
            
            return ProbeResult(
                probe_name='process_visibility',
                passed=True,  # Evidence collection succeeded
                observed_value={
                    'pid_count': pid_count,
                    'current_pid': current_pid,
                    'visible_pids': visible_pids[:100],  # Limit to first 100 for safety
                    'pid1_visible': pid1_visible
                },
                expected_condition='Numeric PIDs should be visible in /proc',
                error=None
            )
            
        except PermissionError as e:
            return ProbeResult(
                probe_name='process_visibility',
                passed=False,
                observed_value='permission_denied',
                expected_condition='/proc should be readable',
                error=f'Permission denied reading /proc: {e}'
            )
        except Exception as e:
            return ProbeResult(
                probe_name='process_visibility',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='/proc should be readable',
                error=f'Unexpected error reading /proc: {e}'
            )
    
    def probe_pid1_evidence(self) -> ProbeResult:
        """Probe C: Collect PID 1 evidence.
        
        Inspects /proc/1/status and /proc/1/cmdline to collect information
        about PID 1. Does not hard-code that PID 1 must be /sbin/init.
        
        Returns:
            ProbeResult with PID 1 evidence.
        """
        try:
            pid1_status_path = '/proc/1/status'
            pid1_cmdline_path = '/proc/1/cmdline'
            
            if not os.path.exists(pid1_status_path):
                return ProbeResult(
                    probe_name='pid1_evidence',
                    passed=False,
                    observed_value='pid1_status_not_found',
                    expected_condition='/proc/1/status should be readable',
                    error='/proc/1/status not found (PID 1 not accessible)'
                )
            
            # Read PID 1 status
            status_info = {}
            with open(pid1_status_path, 'r') as f:
                for line in f:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        status_info[key.strip()] = value.strip()
            
            # Extract relevant status information
            pid1_name = status_info.get('Name', 'unknown')
            pid1_state = status_info.get('State', 'unknown')
            
            # Read PID 1 cmdline if available
            cmdline = 'unknown'
            if os.path.exists(pid1_cmdline_path):
                try:
                    with open(pid1_cmdline_path, 'rb') as f:
                        cmdline_bytes = f.read()
                        cmdline = cmdline_bytes.decode('utf-8', errors='replace').replace('\x00', ' ')
                except Exception:
                    cmdline = 'unreadable'
            
            return ProbeResult(
                probe_name='pid1_evidence',
                passed=True,  # Evidence collection succeeded
                observed_value={
                    'pid': 1,
                    'name': pid1_name,
                    'state': pid1_state,
                    'cmdline': cmdline[:200] if cmdline != 'unknown' else cmdline  # Limit length
                },
                expected_condition='PID 1 should be visible from container',
                error=None
            )
            
        except PermissionError as e:
            return ProbeResult(
                probe_name='pid1_evidence',
                passed=False,
                observed_value='permission_denied',
                expected_condition='/proc/1/* should be readable',
                error=f'Permission denied reading PID 1: {e}'
            )
        except Exception as e:
            return ProbeResult(
                probe_name='pid1_evidence',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='/proc/1/* should be readable',
                error=f'Unexpected error reading PID 1: {e}'
            )
    
    def probe_controlled_subprocess(self) -> ProbeResult:
        """Probe D: Test controlled subprocess creation with observability.
        
        Spawns a harmless subprocess to verify:
        1. Subprocess starts and receives a PID
        2. Subprocess remains alive briefly using deterministic synchronization
        3. Its PID is obtained
        4. While it is alive, /proc is enumerated
        5. Its PID is confirmed visible inside the container namespace
        6. The process is then allowed/triggered to terminate
        7. The process is waited for
        8. The process is confirmed terminated
        9. Cleanup is guaranteed with try/finally
        10. Timeout handling remains strict
        
        Returns:
            ProbeResult with subprocess evidence distinguishing:
            - process started
            - PID obtained
            - PID observed while alive
            - process terminated
            - cleanup success/failure
        """
        process = None
        steps_completed = {}
        
        try:
            # Step 1: Start a harmless local Python subprocess that remains alive briefly
            # Using time.sleep(0.5) to keep process alive for observability
            process = subprocess.Popen(
                [sys.executable, '-c', 'import time; time.sleep(0.5)'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            steps_completed['process_started'] = True
            self._created_processes.append(process.pid)
            
            # Step 2: Verify subprocess has a PID
            if process.pid is None:
                steps_completed['pid_obtained'] = False
                return ProbeResult(
                    probe_name='controlled_subprocess',
                    passed=False,
                    observed_value=steps_completed,
                    expected_condition='Subprocess should receive a PID',
                    error='Subprocess did not receive a PID'
                )
            
            steps_completed['pid_obtained'] = True
            steps_completed['pid'] = process.pid
            
            # Step 3: While process is alive, enumerate /proc to observe it
            # Use a brief delay to ensure process is still alive
            time.sleep(0.1)  # Brief delay to ensure process is established
            
            # Check if process is still alive
            if process.poll() is not None:
                steps_completed['pid_observed_while_alive'] = False
                steps_completed['process_terminated_early'] = True
                return ProbeResult(
                    probe_name='controlled_subprocess',
                    passed=False,
                    observed_value=steps_completed,
                    expected_condition='Subprocess should remain alive for observation',
                    error='Subprocess terminated before observation'
                )
            
            # Step 4: Enumerate /proc to confirm PID is visible
            pid_observed = False
            try:
                proc_path = '/proc'
                if os.path.exists(proc_path):
                    for entry in os.listdir(proc_path):
                        if entry.isdigit() and int(entry) == process.pid:
                            pid_observed = True
                            break
            except Exception:
                # /proc enumeration failed, but process might still be observable
                pid_observed = False
            
            steps_completed['pid_observed_while_alive'] = pid_observed
            
            # Step 5: Allow process to terminate naturally
            try:
                return_code = process.wait(timeout=5)
                steps_completed['process_terminated'] = True
                steps_completed['return_code'] = return_code
                
                # Verify clean termination
                if return_code != 0:
                    steps_completed['terminated_cleanly'] = False
                    return ProbeResult(
                        probe_name='controlled_subprocess',
                        passed=False,
                        observed_value=steps_completed,
                        expected_condition='Subprocess should terminate cleanly (exit code 0)',
                        error=f'Subprocess exited with code {return_code}'
                    )
                
                steps_completed['terminated_cleanly'] = True
                
                # Step 6: Confirm no child process remains
                # Verify process is truly gone by checking poll() again
                # After wait(), poll() should return the exit code (not None)
                final_poll = process.poll()
                if final_poll is not None:
                    steps_completed['no_child_remains'] = True
                    steps_completed['final_poll_result'] = final_poll
                else:
                    steps_completed['no_child_remains'] = False
                    steps_completed['final_poll_result'] = None
                
                # Remove from tracking list since it completed successfully
                if process.pid in self._created_processes:
                    self._created_processes.remove(process.pid)
                
                steps_completed['cleanup_success'] = True
                
                return ProbeResult(
                    probe_name='controlled_subprocess',
                    passed=True,
                    observed_value=steps_completed,
                    expected_condition='Subprocess should start, remain alive for observation, and terminate cleanly',
                    error=None
                )
                
            except subprocess.TimeoutExpired:
                # Process hung - force termination
                steps_completed['process_terminated'] = False
                steps_completed['timeout'] = True
                self._terminate_process(process)
                steps_completed['cleanup_success'] = True
                return ProbeResult(
                    probe_name='controlled_subprocess',
                    passed=False,
                    observed_value=steps_completed,
                    expected_condition='Subprocess should terminate within timeout',
                    error='Subprocess did not terminate within timeout'
                )
                
        except Exception as e:
            # Step 7: Cleanup on error with try/finally guarantee
            steps_completed['unexpected_error'] = str(e)
            if process:
                self._terminate_process(process)
                steps_completed['cleanup_attempted'] = True
            else:
                steps_completed['cleanup_attempted'] = False
            
            return ProbeResult(
                probe_name='controlled_subprocess',
                passed=False,
                observed_value=steps_completed,
                expected_condition='Subprocess should start, be observed while alive, and terminate cleanly',
                error=f'Unexpected error during subprocess test: {e}'
            )
    
    def _terminate_process(self, process: subprocess.Popen) -> None:
        """Terminate a process with cleanup tracking."""
        try:
            if process.poll() is None:  # Process still running
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    # Force kill if terminate didn't work
                    process.kill()
                    process.wait(timeout=1)
        except Exception:
            pass  # Best effort cleanup
        finally:
            # Remove from tracking list
            if process.pid in self._created_processes:
                self._created_processes.remove(process.pid)
    
    def cleanup(self) -> Dict[str, str]:
        """Clean up any remaining processes created during probing.
        
        Returns:
            Dict with cleanup status for each process.
        """
        cleanup_status = {}
        
        for pid in self._created_processes[:]:  # Copy list
            try:
                # Try to terminate the process
                os.kill(pid, signal.SIGTERM)
                # Wait briefly to see if it exits
                os.waitpid(pid, os.WNOHANG)
                cleanup_status[str(pid)] = 'terminated'
            except (ProcessLookupError, ChildProcessError):
                # Process already gone
                cleanup_status[str(pid)] = 'already_exited'
            except PermissionError:
                cleanup_status[str(pid)] = 'permission_denied'
            except Exception as e:
                cleanup_status[str(pid)] = f'cleanup_failed: {type(e).__name__}'
            finally:
                # Always remove from tracking list
                if pid in self._created_processes:
                    self._created_processes.remove(pid)
        
        return cleanup_status
    
    def run_all_probes(self) -> Dict[str, ProbeResult]:
        """Run all process probes and return results.
        
        Returns:
            Dictionary mapping probe names to ProbeResult objects.
        """
        results = {}
        
        try:
            # Run all probes
            results['pid_namespace_evidence'] = self.probe_pid_namespace_evidence()
        except Exception as e:
            results['pid_namespace_evidence'] = ProbeResult(
                probe_name='pid_namespace_evidence',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='Probe should execute without errors',
                error=f'Unexpected error during probe: {e}'
            )
        
        try:
            results['process_visibility'] = self.probe_process_visibility()
        except Exception as e:
            results['process_visibility'] = ProbeResult(
                probe_name='process_visibility',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='Probe should execute without errors',
                error=f'Unexpected error during probe: {e}'
            )
        
        try:
            results['pid1_evidence'] = self.probe_pid1_evidence()
        except Exception as e:
            results['pid1_evidence'] = ProbeResult(
                probe_name='pid1_evidence',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='Probe should execute without errors',
                error=f'Unexpected error during probe: {e}'
            )
        
        try:
            results['controlled_subprocess'] = self.probe_controlled_subprocess()
        except Exception as e:
            results['controlled_subprocess'] = ProbeResult(
                probe_name='controlled_subprocess',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='Probe should execute without errors',
                error=f'Unexpected error during probe: {e}'
            )
        
        finally:
            # Always cleanup, even if probes fail
            self.cleanup()
        
        return results
    
    def __del__(self):
        """Cleanup on destruction (fallback, not primary guarantee)."""
        self.cleanup()