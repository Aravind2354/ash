"""Diagnostic runner to check container environment before running tests."""

import sys
import subprocess
import time
import threading
import signal
import os
from typing import Optional


class DiagnosticOrchestrator:
    """Orchestrates Docker container diagnostic execution."""

    def __init__(self, timeout: int = 300):
        """Initialize the orchestrator.

        Args:
            timeout: Maximum time in seconds for diagnostic execution
        """
        self.timeout = timeout
        self.container_name = "website-authenticity-detector-test"
        self.image_name = "website-authenticity-detector:test"
        self.container_id = None
        self.process = None

    def verify_docker_available(self) -> bool:
        """Verify Docker is available and running."""
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                print("[FAIL] Docker command failed")
                return False

            result = subprocess.run(
                ["docker", "ps"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                print("[FAIL] Docker daemon not running")
                return False

            print("[PASS] Docker is available")
            return True
        except Exception as e:
            print(f"[FAIL] Docker verification failed: {e}")
            return False

    def build_test_image(self) -> bool:
        """Build the test Docker image."""
        print("Building test image...")
        try:
            result = subprocess.run(
                ["docker", "build", "-f", "Dockerfile.test", "-t", self.image_name, "."],
                capture_output=True,
                text=True,
                timeout=600
            )
            if result.returncode != 0:
                print(f"[FAIL] Image build failed:\n{result.stderr}")
                return False

            print("[PASS] Test image built successfully")
            return True
        except subprocess.TimeoutExpired:
            print("[FAIL] Image build timed out")
            return False
        except Exception as e:
            print(f"[FAIL] Image build failed: {e}")
            return False

    def create_hardened_container(self) -> bool:
        """Create a hardened test container with security configuration."""
        print("Creating hardened test container...")
        try:
            cmd = [
                "docker", "run", "-d",
                "--name", self.container_name,
                "--read-only",
                "--tmpfs", "/tmp:rw,nosuid,size=64m",
                "--tmpfs", "/analysis/.pytest_cache:rw,nosuid,size=32m",
                "--tmpfs", "/analysis/.hypothesis:rw,nosuid,size=32m",
                "--user", "analyzer",
                "--security-opt", "no-new-privileges",
                "--cap-drop", "ALL",
                "--memory", "128m",
                "--cpu-quota", "50000",
                "--pids-limit", "100",
                "--network", "bridge",
                self.image_name,
                "tail", "-f", "/dev/null"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                print(f"[FAIL] Container creation failed:\n{result.stderr}")
                return False

            self.container_id = result.stdout.strip()
            print(f"[PASS] Container created: {self.container_id[:12]}")
            return True
        except subprocess.TimeoutExpired:
            print("[FAIL] Container creation timed out")
            return False
        except Exception as e:
            print(f"[FAIL] Container creation failed: {e}")
            return False

    def validate_container_security(self) -> bool:
        """Validate container security configuration."""
        print("Validating container security configuration...")
        try:
            result = subprocess.run(
                ["python", "scripts/validate_container_config.py", self.container_id],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                print(f"[FAIL] Container security validation failed:\n{result.stdout}")
                return False

            print("[PASS] Container security validation passed")
            return True
        except subprocess.TimeoutExpired:
            print("[FAIL] Container validation timed out")
            return False
        except Exception as e:
            print(f"[FAIL] Container validation failed: {e}")
            return False

    def run_diagnostics(self) -> int:
        """Run diagnostic script inside the container."""
        print("Running container diagnostics...")
        try:
            cmd = [
                "docker", "exec",
                "-e", f"SANDBOX_CONTAINER_ID={self.container_id}",
                self.container_name,
                "python",
                "scripts/diagnose_container.py"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            print(result.stdout)
            if result.stderr:
                print(result.stderr)
            return result.returncode

        except subprocess.TimeoutExpired:
            print("[FAIL] Diagnostic execution timed out")
            return 1
        except Exception as e:
            print(f"[FAIL] Diagnostic execution failed: {e}")
            return 1

    def cleanup_container(self) -> None:
        """Clean up the test container."""
        print("Cleaning up container...")
        try:
            if self.process and self.process.poll() is None:
                self.process.kill()

            result = subprocess.run(
                ["docker", "rm", "-f", self.container_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                print("[PASS] Container cleaned up")
            else:
                print(f"[FAIL] Container cleanup failed: {result.stderr}")
        except Exception as e:
            print(f"[FAIL] Container cleanup failed: {e}")

    def run(self) -> int:
        """Run the complete diagnostic workflow."""
        try:
            if not self.verify_docker_available():
                return 1

            if not self.build_test_image():
                return 1

            if not self.create_hardened_container():
                self.cleanup_container()
                return 1

            if not self.validate_container_security():
                self.cleanup_container()
                return 1

            exit_code = self.run_diagnostics()
            return exit_code

        except KeyboardInterrupt:
            print("\nInterrupted by user")
            return 1
        except Exception as e:
            print(f"✗ Orchestrator failed: {e}")
            return 1
        finally:
            self.cleanup_container()


def main():
    """Main entry point."""
    orchestrator = DiagnosticOrchestrator(timeout=300)
    exit_code = orchestrator.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
