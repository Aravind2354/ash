"""Runtime filesystem evidence probes for container isolation validation.

This module provides probes that collect evidence about filesystem isolation
state inside containers. These probes run inside the container and return
structured evidence for later aggregation.

SECURITY CRITICAL: All probes are designed to be non-destructive and fail
closed on errors. These probes provide EVIDENCE, not absolute proof of
isolation.
"""

import os
import errno
import tempfile
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone


@dataclass
class ProbeResult:
    """Result of a single filesystem evidence probe."""
    
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


class FilesystemProbes:
    """Runtime filesystem evidence probes for container isolation validation.
    
    These probes collect evidence about filesystem state inside containers.
    They are designed to be non-destructive and fail closed on errors.
    """
    
    # Approved tmpfs destinations (must match ContainerValidator)
    APPROVED_TMPFS_DESTINATIONS = {'/tmp', '/analysis/temp'}
    
    # Test file names for probes (unique to avoid conflicts)
    TEST_FILE_PREFIX = 'fs_probe_'
    
    def __init__(self):
        """Initialize FilesystemProbes."""
        self._created_test_files: List[str] = []
    
    def probe_rootfs_readonly(self) -> ProbeResult:
        """Probe A: Test root filesystem is read-only using mountinfo evidence.
        
        Uses /proc/self/mountinfo to determine if root filesystem is mounted read-only.
        This provides runtime evidence that complements trusted host-side Docker configuration.
        
        Returns:
            ProbeResult with evidence about root filesystem mount state.
        """
        mountinfo_path = '/proc/self/mountinfo'
        
        try:
            with open(mountinfo_path, 'r') as f:
                mountinfo_lines = f.readlines()
            
            # Find root filesystem mount entry
            root_mount = None
            for line in mountinfo_lines:
                parts = line.split()
                if len(parts) >= 5 and parts[4] == '/':
                    # Extract mount options (field after mount point)
                    # Format: mount_id parent_id major:minor root mount_point options - fs_type source options
                    try:
                        dash_index = parts.index('-')
                        # Options are before the dash, after mount point
                        # Extract options between mount point (parts[4]) and dash
                        options_start = 5  # After mount point
                        options_end = dash_index
                        if options_end > options_start:
                            # Options may be comma-separated in mountinfo
                            options_field = ' '.join(parts[options_start:options_end])
                            root_options = options_field.split(',')
                            root_mount = {
                                'mount_point': '/',
                                'options': root_options
                            }
                            break
                    except (ValueError, IndexError):
                        continue
            
            if root_mount is None:
                return ProbeResult(
                    probe_name='rootfs_readonly',
                    passed=False,
                    observed_value='root_mount_not_found',
                    expected_condition='Root filesystem mount should be found in mountinfo',
                    error='Could not find root filesystem mount in /proc/self/mountinfo'
                )
            
            # Check for 'ro' (read-only) option
            # Options are space-separated in mountinfo, check each
            is_readonly = any('ro' in opt for opt in root_mount['options'])
            
            return ProbeResult(
                probe_name='rootfs_readonly',
                passed=is_readonly,
                observed_value={
                    'mount_options': root_mount['options'],
                    'is_readonly': is_readonly
                },
                expected_condition='Root filesystem should be mounted read-only (ro option)',
                error=None if is_readonly else 'Root filesystem is mounted read-write (security concern)'
            )
            
        except FileNotFoundError:
            return ProbeResult(
                probe_name='rootfs_readonly',
                passed=False,
                observed_value='mountinfo_not_found',
                expected_condition='/proc/self/mountinfo should be readable',
                error='/proc/self/mountinfo not found (kernel may not support procfs)'
            )
        except PermissionError:
            return ProbeResult(
                probe_name='rootfs_readonly',
                passed=False,
                observed_value='mountinfo_not_readable',
                expected_condition='/proc/self/mountinfo should be readable',
                error='Permission denied reading /proc/self/mountinfo'
            )
        except Exception as e:
            return ProbeResult(
                probe_name='rootfs_readonly',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='/proc/self/mountinfo should be readable',
                error=f'Unexpected error reading mountinfo: {e}'
            )
    
    def probe_tmpfs_writability(self) -> ProbeResult:
        """Probe B: Test approved tmpfs writability.
        
        Create uniquely named temporary probe files only inside approved tmpfs.
        Verify write/read/delete succeeds.
        Leave no probe files behind.
        
        Returns:
            ProbeResult with evidence about tmpfs writability.
        """
        results = []
        
        for destination in self.APPROVED_TMPFS_DESTINATIONS:
            # Check if destination exists
            if not os.path.exists(destination):
                results.append({
                    'destination': destination,
                    'status': 'destination_not_found',
                    'passed': False
                })
                continue
            
            # Create unique test file
            test_file = os.path.join(destination, f'{self.TEST_FILE_PREFIX}{os.getpid()}')
            test_content = 'filesystem_probe_test_data'
            
            try:
                # Write test
                with open(test_file, 'w') as f:
                    f.write(test_content)
                self._created_test_files.append(test_file)
                
                # Read test
                with open(test_file, 'r') as f:
                    read_content = f.read()
                
                # Verify content
                if read_content != test_content:
                    results.append({
                        'destination': destination,
                        'status': 'read_write_mismatch',
                        'passed': False
                    })
                    # Clean up
                    try:
                        os.remove(test_file)
                        self._created_test_files.remove(test_file)
                    except OSError:
                        pass
                    continue
                
                # Delete test
                os.remove(test_file)
                self._created_test_files.remove(test_file)
                
                # Verify deletion
                if os.path.exists(test_file):
                    results.append({
                        'destination': destination,
                        'status': 'file_not_deleted',
                        'passed': False
                    })
                else:
                    results.append({
                        'destination': destination,
                        'status': 'write_read_delete_success',
                        'passed': True
                    })
                    
            except (PermissionError, OSError) as e:
                results.append({
                    'destination': destination,
                    'status': f'operation_failed: {type(e).__name__}',
                    'passed': False
                })
            except Exception as e:
                results.append({
                    'destination': destination,
                    'status': f'unexpected_error: {type(e).__name__}',
                    'passed': False
                })
        
        # Overall probe passes if all destinations pass
        all_passed = all(r['passed'] for r in results)
        
        return ProbeResult(
            probe_name='tmpfs_writability',
            passed=all_passed,
            observed_value=results,
            expected_condition='Approved tmpfs destinations should support write/read/delete',
            error=None if all_passed else 'Some tmpfs destinations failed writability test'
        )
    
    def probe_mount_evidence(self) -> ProbeResult:
        """Probe C: Inspect /proc/self/mountinfo for mount evidence.
        
        Use mountinfo as evidence to confirm expected approved tmpfs mounts.
        Do not treat readable mountinfo itself as a violation.
        
        Returns:
            ProbeResult with mount evidence analysis.
        """
        mountinfo_path = '/proc/self/mountinfo'
        
        try:
            with open(mountinfo_path, 'r') as f:
                mountinfo_lines = f.readlines()
            
            # Parse mountinfo for evidence
            mount_entries = []
            for line in mountinfo_lines:
                parts = line.split()
                if len(parts) >= 5:
                    mount_point = parts[4]
                    mount_type = 'unknown'
                    mount_source = 'unknown'
                    
                    # Try to extract filesystem type and source
                    # Format: mount_id parent_id major:minor root mount_point options - fs_type source options
                    try:
                        dash_index = parts.index('-')
                        if dash_index + 3 < len(parts):
                            mount_type = parts[dash_index + 1]
                            mount_source = parts[dash_index + 2]
                    except ValueError:
                        # No dash found, use unknown
                        pass
                    
                    mount_entries.append({
                        'mount_point': mount_point,
                        'type': mount_type,
                        'source': mount_source
                    })
            
            # Check for approved tmpfs mounts
            approved_tmpfs_found = []
            unexpected_mounts = []
            
            for entry in mount_entries:
                if entry['mount_point'] in self.APPROVED_TMPFS_DESTINATIONS:
                    if entry['type'] == 'tmpfs':
                        approved_tmpfs_found.append(entry['mount_point'])
                    else:
                        unexpected_mounts.append({
                            'mount_point': entry['mount_point'],
                            'type': entry['type'],
                            'reason': 'Approved destination has wrong filesystem type'
                        })
                elif entry['mount_point'].startswith('/'):
                    # Check for other mounted filesystems at root level
                    # Allow expected filesystem types
                    if entry['type'] not in ('proc', 'sysfs', 'devtmpfs', 'cgroup', 'overlay', 'tmpfs'):
                        unexpected_mounts.append({
                            'mount_point': entry['mount_point'],
                            'type': entry['type'],
                            'reason': 'Unexpected root-level mount'
                        })
            
            return ProbeResult(
                probe_name='mount_evidence',
                passed=len(unexpected_mounts) == 0,
                observed_value={
                    'total_mounts': len(mount_entries),
                    'approved_tmpfs_found': approved_tmpfs_found,
                    'unexpected_mounts': unexpected_mounts if unexpected_mounts else "none"
                },
                expected_condition='Only approved tmpfs mounts at expected destinations',
                error=None if len(unexpected_mounts) == 0 else f'Found {len(unexpected_mounts)} unexpected mounts'
            )
            
        except FileNotFoundError:
            return ProbeResult(
                probe_name='mount_evidence',
                passed=False,
                observed_value='mountinfo_not_found',
                expected_condition='/proc/self/mountinfo should be readable',
                error='/proc/self/mountinfo not found (kernel may not support procfs)'
            )
        except PermissionError:
            return ProbeResult(
                probe_name='mount_evidence',
                passed=False,
                observed_value='mountinfo_not_readable',
                expected_condition='/proc/self/mountinfo should be readable',
                error='Permission denied reading /proc/self/mountinfo'
            )
        except Exception as e:
            return ProbeResult(
                probe_name='mount_evidence',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='/proc/self/mountinfo should be readable',
                error=f'Unexpected error reading mountinfo: {e}'
            )
    
    def probe_container_local_storage(self) -> ProbeResult:
        """Probe D: Establish container-local storage evidence.
        
        Uses runtime mountinfo evidence to verify:
        - No unexpected host-backed mounts are visible
        - Approved tmpfs destinations are writable
        
        Note: This provides runtime evidence only. Host-side Docker configuration
        validation by ContainerValidator is required to prove absence of host bind mounts
        and volumes. Runtime mountinfo alone cannot prove host invisibility.
        
        Returns:
            ProbeResult with runtime container-local storage evidence.
        """
        try:
            # Check mountinfo for unexpected mounts
            mountinfo_result = self.probe_mount_evidence()
            
            if not mountinfo_result.passed:
                return ProbeResult(
                    probe_name='container_local_storage',
                    passed=False,
                    observed_value='unexpected_mounts_detected',
                    expected_condition='Runtime evidence should show no unexpected mounts',
                    error='Mountinfo evidence suggests unexpected mounts present'
                )
            
            # Check that we can create and read files in tmpfs
            tmpfs_result = self.probe_tmpfs_writability()
            
            if not tmpfs_result.passed:
                return ProbeResult(
                    probe_name='container_local_storage',
                    passed=False,
                    observed_value='tmpfs_not_writable',
                    expected_condition='Approved tmpfs destinations should be writable',
                    error='Approved tmpfs destinations not writable'
                )
            
            return ProbeResult(
                probe_name='container_local_storage',
                passed=True,
                observed_value='runtime_evidence_ok',
                expected_condition='Runtime evidence should show no unexpected mounts and writable tmpfs',
                error=None
            )
            
        except Exception as e:
            return ProbeResult(
                probe_name='container_local_storage',
                passed=False,
                observed_value=f'unexpected_error: {type(e).__name__}',
                expected_condition='Runtime evidence should show no unexpected mounts and writable tmpfs',
                error=f'Unexpected error during probe: {e}'
            )
    
    def cleanup(self) -> None:
        """Clean up any test files created during probing.
        
        This should be called after all probes are complete to ensure
        no probe files are left behind.
        
        Returns:
            Dict with cleanup status for each attempted deletion.
        """
        cleanup_status = {}
        
        for test_file in self._created_test_files[:]:  # Copy list to allow modification
            try:
                if os.path.exists(test_file):
                    os.remove(test_file)
                    cleanup_status[test_file] = 'deleted'
                else:
                    cleanup_status[test_file] = 'not_found'
            except OSError as e:
                # Report cleanup failure
                cleanup_status[test_file] = f'deletion_failed: {type(e).__name__}'
            finally:
                # Always remove from tracking list, even if delete failed
                if test_file in self._created_test_files:
                    self._created_test_files.remove(test_file)
        
        return cleanup_status
    
    def run_all_probes(self) -> Dict[str, ProbeResult]:
        """Run all filesystem probes and return results.
        
        Returns:
            Dictionary mapping probe names to ProbeResult objects.
        """
        results = {}
        
        try:
            # Run all probes
            results['rootfs_readonly'] = self.probe_rootfs_readonly()
            results['tmpfs_writability'] = self.probe_tmpfs_writability()
            results['mount_evidence'] = self.probe_mount_evidence()
            results['container_local_storage'] = self.probe_container_local_storage()
            
        finally:
            # Always cleanup, even if probes fail
            self.cleanup()
        
        return results
    
    def __del__(self):
        """Cleanup on destruction."""
        self.cleanup()