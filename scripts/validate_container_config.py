"""Host-side Docker container security validation.

This script validates that a Docker container meets the required security
hardening configuration before allowing integration tests to run.

It inspects the ACTUAL Docker container configuration through the host Docker API
and performs fail-closed validation of all required security properties.

Requirements:
- Non-root user
- Read-only root filesystem
- No privileged mode
- Bridge networking
- No host PID
- Private IPC
- No Docker socket
- No host bind mounts
- Approved tmpfs only
- no-new-privileges
- CapDrop includes ALL
- Bounded memory
- Bounded CPU
- Bounded PID count
"""

import sys
import json
from typing import Tuple, Dict, List


def validate_container_config(container_id: str) -> Tuple[bool, List[str]]:
    """Validate Docker container security configuration.

    Args:
        container_id: Docker container ID to validate

    Returns:
        Tuple of (is_valid: bool, error_messages: List[str])
        - (True, []) if all validations pass
        - (False, [error1, error2, ...]) if any validation fails
    """
    try:
        import docker
    except ImportError:
        return False, ["Docker Python SDK not installed. Install with: pip install docker"]

    try:
        client = docker.from_env()
        container = client.containers.get(container_id)
        config = container.attrs
    except Exception as e:
        return False, [f"Failed to inspect container {container_id}: {e}"]

    errors = []

    # Validate non-root user
    user = config.get('Config', {}).get('User', 'root')
    if user == 'root' or user is None:
        errors.append(f"Container running as root user (User: {user})")

    # Validate read-only root filesystem
    readonly_rootfs = config.get('HostConfig', {}).get('ReadonlyRootfs', False)
    if not readonly_rootfs:
        errors.append("Root filesystem is not read-only")

    # Validate no privileged mode
    privileged = config.get('HostConfig', {}).get('Privileged', False)
    if privileged:
        errors.append("Container is running in privileged mode")

    # Validate bridge networking (not host)
    network_mode = config.get('HostConfig', {}).get('NetworkMode', '')
    if network_mode == 'host':
        errors.append("Container using host networking mode")

    # Validate no host PID
    pid_mode = config.get('HostConfig', {}).get('PidMode', '')
    if pid_mode == 'host':
        errors.append("Container using host PID namespace")

    # Validate private IPC
    ipc_mode = config.get('HostConfig', {}).get('IpcMode', '')
    if ipc_mode != 'private' and ipc_mode != '':
        errors.append(f"Container using non-private IPC mode: {ipc_mode}")

    # Validate no Docker socket mount and no host bind mounts
    binds = config.get('HostConfig', {}).get('Binds') or []
    for bind in binds:
        if 'docker.sock' in bind or '/var/run/docker.sock' in bind:
            errors.append("Container has Docker socket mounted")
            break
        # Allow tmpfs (not in binds) but reject absolute path mounts to host
        if bind.startswith('/') and '/tmp' not in bind:
            errors.append(f"Container has host bind mount: {bind}")
            break

    # Validate no-new-privileges security option
    security_opts = config.get('HostConfig', {}).get('SecurityOpt', [])
    if 'no-new-privileges' not in security_opts:
        errors.append("Container missing no-new-privileges security option")

    # Validate capabilities dropped
    cap_drop = config.get('HostConfig', {}).get('CapDrop', [])
    if 'ALL' not in cap_drop:
        errors.append(f"Container not dropping all capabilities (CapDrop: {cap_drop})")

    # Validate no additional capabilities added
    cap_add = config.get('HostConfig', {}).get('CapAdd', [])
    if cap_add:
        errors.append(f"Container has additional capabilities (CapAdd: {cap_add})")

    # Validate bounded memory
    memory_limit = config.get('HostConfig', {}).get('Memory', 0)
    if memory_limit == 0:
        errors.append("Container has no memory limit")

    # Validate bounded CPU
    cpu_quota = config.get('HostConfig', {}).get('CpuQuota', 0)
    if cpu_quota == 0:
        errors.append("Container has no CPU quota limit")

    # Validate bounded PID count
    pids_limit = config.get('HostConfig', {}).get('PidsLimit', 0)
    if pids_limit == 0:
        errors.append("Container has no PID limit")

    # Validate tmpfs configuration
    tmpfs = config.get('HostConfig', {}).get('Tmpfs', {})
    if '/tmp' not in tmpfs:
        errors.append("Container missing /tmp tmpfs mount")
    else:
        # Check tmpfs options are secure (but allow rw for test infrastructure marker file)
        tmpfs_opts = tmpfs['/tmp']
        if 'rw' not in tmpfs_opts:
            errors.append("/tmp tmpfs missing rw option for test infrastructure")
        if 'nosuid' not in tmpfs_opts:
            errors.append("/tmp tmpfs missing nosuid option")

    # Allow additional tmpfs mounts for test infrastructure
    allowed_tmpfs = ['/tmp', '/analysis/.pytest_cache', '/analysis/.hypothesis']
    for mount in tmpfs:
        if mount not in allowed_tmpfs:
            errors.append(f"Container has disallowed tmpfs mount: {mount}")
        else:
            # Check security options for all tmpfs mounts
            tmpfs_opts = tmpfs[mount]
            if 'nosuid' not in tmpfs_opts:
                errors.append(f"{mount} tmpfs missing nosuid option")

    return (len(errors) == 0, errors)


def main():
    """Main entry point for validation script."""
    if len(sys.argv) != 2:
        print("Usage: python validate_container_config.py <container_id>")
        sys.exit(1)

    container_id = sys.argv[1]
    is_valid, errors = validate_container_config(container_id)

    if is_valid:
        print(f"[PASS] Container {container_id[:12]} security validation passed")
        sys.exit(0)
    else:
        print(f"[FAIL] Container {container_id[:12]} security validation failed:")
        for error in errors:
            print(f"  - {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
