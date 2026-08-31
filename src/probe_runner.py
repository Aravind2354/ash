"""In-container probe runner for isolation validation.

This module is executed inside the running Docker container via `container.exec_run`
to collect runtime evidence from filesystem, process, and network probes and
return serialized JSON output to the host IsolationOrchestrator.
"""

import sys
import json
from typing import Dict, Any

from src.filesystem_probes import FilesystemProbes
from src.process_probes import ProcessProbes
from src.network_probes import NetworkProbes


PROBE_DELIMITER_START = "__PROBE_OUTPUT_START__"
PROBE_DELIMITER_END = "__PROBE_OUTPUT_END__"


def run_all_container_probes() -> Dict[str, Any]:
    """Execute all isolation probes inside the container and aggregate results."""
    fs_probes = FilesystemProbes()
    proc_probes = ProcessProbes()
    net_probes = NetworkProbes()

    fs_results = fs_probes.run_all_probes()
    proc_results = proc_probes.run_all_probes()
    net_results = net_probes.run_all_probes()

    return {
        "filesystem": {k: v.to_dict() for k, v in fs_results.items()},
        "process": {k: v.to_dict() for k, v in proc_results.items()},
        "network": {k: v.to_dict() for k, v in net_results.items()},
    }


def main():
    """Main entry point for in-container probe runner."""
    try:
        results = run_all_container_probes()
        json_output = json.dumps(results)
        sys.stdout.write(f"\n{PROBE_DELIMITER_START}\n{json_output}\n{PROBE_DELIMITER_END}\n")
        sys.stdout.flush()
        sys.exit(0)
    except Exception as e:
        error_output = json.dumps({
            "error": str(e),
            "exception_type": type(e).__name__
        })
        sys.stdout.write(f"\n{PROBE_DELIMITER_START}\n{error_output}\n{PROBE_DELIMITER_END}\n")
        sys.stdout.flush()
        sys.exit(1)


if __name__ == "__main__":
    main()
