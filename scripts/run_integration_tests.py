"""Cross-platform Docker integration test orchestration script.

This script manages the complete workflow for running Docker-based integration tests:
1. Verifies Docker availability
2. Builds the test image (optional with --skip-build)
3. Creates a hardened test container
4. Validates container security configuration
5. Runs integration tests inside the container with live output streaming
6. Handles timeouts and cleanup
7. Returns pytest exit code

The container is created with hardened security settings and validated before
test execution. The trust handoff from host to container is via SANDBOX_CONTAINER_ID
environment variable (test infrastructure mechanism, not production security).

IMPORTANT: This trust handoff exists only to connect the host-side validation result
to the test process. It is not a production security mechanism.
"""

import sys
import subprocess
import threading
import os
import argparse
from typing import Optional


class IntegrationTestOrchestrator:
    """Orchestrates Docker integration test execution with security validation."""

    def __init__(self, timeout: int = 300, skip_build: bool = False):
        """Initialize the orchestrator.

        Args:
            timeout: Maximum time in seconds for the complete test job
            skip_build: Skip image build if image already exists
        """
        self.timeout = timeout
        self.skip_build = skip_build
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
        if self.skip_build:
            # Check if image already exists
            try:
                result = subprocess.run(
                    ["docker", "images", "-q", self.image_name],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.stdout.strip():
                    print("[PASS] Test image already exists, skipping build")
                    return True
                else:
                    print("Image not found, building anyway...")
            except Exception as e:
                print(f"Image check failed, building anyway: {e}")

        print("Building test image...")
        try:
            result = subprocess.run(
                ["docker", "build", "-f", "Dockerfile.test", "-t", self.image_name, "."],
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes for build
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

        # Clean up any existing container with the same name
        try:
            subprocess.run(
                ["docker", "rm", "-f", self.container_name],
                capture_output=True,
                text=True,
                timeout=30
            )
        except Exception:
            pass  # Ignore if container doesn't exist

        try:
            # Create container with hardened security settings
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
                "--memory", "256m",
                "--cpu-quota", "100000",
                "--pids-limit", "200",
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
            # Run the validation script
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

    def run_integration_tests(self) -> int:
        """Run integration tests inside the container with live output streaming."""
        print("Running integration tests...")
        try:
            # Run pytest with timeout and SANDBOX_CONTAINER_ID environment variable
            cmd = [
                "docker", "exec",
                "-e", f"SANDBOX_CONTAINER_ID={self.container_id}",
                self.container_name,
                "pytest",
                "tests/test_dns_rebinding_integration.py",
                "-v",
                "--timeout=300"
            ]

            # Start the process with live output streaming
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)

            # Timeout handler
            def timeout_handler():
                print("\n[FAIL] Test execution timed out")
                if self.process and self.process.poll() is None:
                    self.process.kill()

            # Set timeout timer
            timer = threading.Timer(self.timeout, timeout_handler)
            timer.start()

            # Stream output in real-time (cross-platform compatible)
            try:
                while True:
                    line = self.process.stdout.readline()
                    if not line:
                        break
                    print(line, end='', flush=True)
            finally:
                timer.cancel()

            # Wait for process to complete
            returncode = self.process.wait()
            return returncode

        except Exception as e:
            print(f"[FAIL] Test execution failed: {e}")
            if self.process:
                self.process.kill()
            return 1

    def cleanup_container(self) -> None:
        """Clean up the test container."""
        print("Cleaning up container...")
        try:
            # Terminate running docker exec if any
            if self.process and self.process.poll() is None:
                self.process.kill()

            # Remove container
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
        """Run the complete integration test workflow."""
        try:
            # Verify Docker
            if not self.verify_docker_available():
                return 1

            # Build image
            if not self.build_test_image():
                return 1

            # Create container
            if not self.create_hardened_container():
                self.cleanup_container()
                return 1

            # Validate security
            if not self.validate_container_security():
                self.cleanup_container()
                return 1

            # Run tests
            exit_code = self.run_integration_tests()

            return exit_code

        except KeyboardInterrupt:
            print("\nInterrupted by user")
            return 1
        except Exception as e:
            print(f"✗ Orchestrator failed: {e}")
            return 1
        finally:
            # Always cleanup
            self.cleanup_container()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Run Docker integration tests")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout in seconds (default: 300)")
    parser.add_argument("--skip-build", action="store_true", help="Skip image build if it already exists")
    args = parser.parse_args()

    orchestrator = IntegrationTestOrchestrator(timeout=args.timeout, skip_build=args.skip_build)
    exit_code = orchestrator.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
