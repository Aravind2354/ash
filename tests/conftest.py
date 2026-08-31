"""Pytest configuration and shared fixtures."""

import os
import pytest


@pytest.fixture(scope="session")
def sandbox_container_id():
    """Get the SANDBOX_CONTAINER_ID from environment or active Docker daemon."""
    env_id = os.environ.get('SANDBOX_CONTAINER_ID')
    if env_id:
        yield env_id
        return

    # Check if Docker is available
    try:
        import docker
        client = docker.from_env(timeout=2)
        client.ping()
        container = client.containers.create(
            "python:3.11-slim",
            command="tail -f /dev/null",
            user="nobody",
            network_mode="bridge",
            mem_limit="128m",
            pids_limit=100,
            read_only=True,
            security_opt=["no-new-privileges"],
            cap_drop=["ALL"],
            privileged=False,
            detach=True,
        )
        container.start()
        cid = container.id[:12]
        yield cid
        try:
            container.remove(force=True)
        except Exception:
            pass
    except Exception:
        yield None
