"""Diagnostic script to verify container environment and SandboxManager state.

This script checks:
1. SANDBOX_CONTAINER_ID environment variable
2. /proc/1/cgroup contents
3. /proc/self/cgroup contents
4. SandboxManager state before/after trust handoff
5. validate_isolation() result

Run this inside the Docker test container BEFORE running pytest.
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.sandbox import SandboxManager
from src.violation_monitor import ViolationMonitor


def main():
    print("=" * 80)
    print("CONTAINER ENVIRONMENT DIAGNOSTICS")
    print("=" * 80)

    # 1. Check SANDBOX_CONTAINER_ID
    print("\n[1] SANDBOX_CONTAINER_ID environment variable:")
    container_id = os.environ.get('SANDBOX_CONTAINER_ID')
    if container_id:
        print(f"    Present: YES")
        print(f"    Value: {container_id}")
    else:
        print(f"    Present: NO")
        print(f"    Value: None")

    # 2. Check /proc/1/cgroup
    print("\n[2] /proc/1/cgroup contents:")
    try:
        with open('/proc/1/cgroup', 'r') as f:
            cgroup1 = f.read()
        print(f"    {cgroup1.strip()}")
    except Exception as e:
        print(f"    ERROR: {e}")

    # 3. Check /proc/self/cgroup
    print("\n[3] /proc/self/cgroup contents:")
    try:
        with open('/proc/self/cgroup', 'r') as f:
            cgroup_self = f.read()
        print(f"    {cgroup_self.strip()}")
    except Exception as e:
        print(f"    ERROR: {e}")

    # 4. Create SandboxManager and check state
    print("\n[4] SandboxManager state BEFORE trust handoff:")
    violation_monitor = ViolationMonitor()
    manager = SandboxManager(violation_monitor=violation_monitor)
    print(f"    Manager object ID: {id(manager)}")
    print(f"    _isolation_validated: {manager._isolation_validated}")
    print(f"    _container_id: {manager._container_id}")

    # 5. Perform trust handoff if container ID exists
    print("\n[5] Trust handoff:")
    if container_id:
        print(f"    Calling set_isolation_validated('{container_id}')")
        manager.set_isolation_validated(container_id)
    else:
        print(f"    SKIPPED - No container ID available")

    # 6. Check state after handoff
    print("\n[6] SandboxManager state AFTER trust handoff:")
    print(f"    Manager object ID: {id(manager)}")
    print(f"    _isolation_validated: {manager._isolation_validated}")
    print(f"    _container_id: {manager._container_id}")

    # 7. Call validate_isolation()
    print("\n[7] validate_isolation() result:")
    try:
        is_valid, message = manager.validate_isolation()
        print(f"    is_valid: {is_valid}")
        print(f"    message: {message}")
    except Exception as e:
        print(f"    ERROR: {e}")

    print("\n" + "=" * 80)
    print("DIAGNOSTICS COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
