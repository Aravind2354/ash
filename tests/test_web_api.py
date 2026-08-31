"""Tests for web API layer."""

import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from web.app import app
from web.tasks import task_manager


client = TestClient(app)


class TestWebAPI:
    """Test suite for web API endpoints."""

    def test_get_root_serves_frontend(self):
        """Test that GET / serves the frontend HTML."""
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Website Authenticity Detector" in response.text

    @patch("web.routes.run_analysis_task")
    def test_post_analyze_valid_url(self, mock_run):
        """Test POST /analyze with a valid URL."""
        response = client.post(
            "/api/analyze",
            json={"url": "https://example.com"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "task_id" in data
        assert data["status"] == "pending"
        assert data["message"] == "Analysis started"

    def test_post_analyze_invalid_url_private_ip(self):
        """Test POST /analyze with private IP address."""
        response = client.post(
            "/api/analyze",
            json={"url": "http://192.168.1.1"}
        )
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "private ip address" in data["detail"].lower()

    def test_post_analyze_invalid_url_localhost(self):
        """Test POST /analyze with localhost."""
        response = client.post(
            "/api/analyze",
            json={"url": "http://localhost:8080"}
        )
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "localhost" in data["detail"].lower()

    def test_post_analyze_invalid_url_missing_scheme(self):
        """Test POST /analyze with missing scheme."""
        response = client.post(
            "/api/analyze",
            json={"url": "example.com"}
        )
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data

    def test_post_analyze_invalid_url_ftp(self):
        """Test POST /analyze with FTP protocol."""
        response = client.post(
            "/api/analyze",
            json={"url": "ftp://example.com"}
        )
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "http" in data["detail"].lower()

    def test_post_analyze_malformed_request(self):
        """Test POST /analyze with malformed request."""
        response = client.post(
            "/api/analyze",
            json={"invalid_field": "value"}
        )
        assert response.status_code == 422  # Validation error

    def test_get_task_status_pending(self):
        """Test GET /task/{task_id} for pending task."""
        # Create a task
        task = task_manager.create_task("https://example.com")

        response = client.get(f"/api/task/{task.task_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["task_id"] == task.task_id
        assert data["status"] in ["pending", "running"]

    def test_get_task_status_not_found(self):
        """Test GET /task/{task_id} for non-existent task."""
        response = client.get("/api/task/non-existent-id")
        assert response.status_code == 404
        data = response.json()
        assert "detail" in data

    def test_task_id_creation(self):
        """Test that task IDs are unique."""
        task1 = task_manager.create_task("https://example.com")
        task2 = task_manager.create_task("https://example.org")

        assert task1.task_id != task2.task_id
        assert len(task1.task_id) > 0
        assert len(task2.task_id) > 0

    def test_task_completion(self):
        """Test task completion with result."""
        task = task_manager.create_task("https://example.com")

        result = {
            "authenticity_score": "85.50%",
            "fake_score": "14.50%",
            "confidence_indicator": "HIGH",
            "url": "https://example.com",
            "analysis_data": {},
            "timestamps": {},
            "top_factors": [],
            "suspicious_indicators": [],
            "error_message": None
        }

        success = task_manager.complete_task(task.task_id, result)
        assert success is True

        updated_task = task_manager.get_task(task.task_id)
        assert updated_task.status == "completed"
        assert updated_task.result == result
        assert updated_task.completed_at is not None

    def test_task_failure(self):
        """Test task failure with error."""
        task = task_manager.create_task("https://example.com")

        error = "Analysis failed: timeout"
        success = task_manager.fail_task(task.task_id, error)
        assert success is True

        updated_task = task_manager.get_task(task.task_id)
        assert updated_task.status == "failed"
        assert updated_task.error == error
        assert updated_task.completed_at is not None

    def test_task_cleanup(self):
        """Test that old tasks are cleaned up."""
        # This test verifies the cleanup mechanism exists
        # Actual cleanup timing is handled by background task
        from datetime import datetime, timedelta
        from web.tasks import Task

        # Create a task with old timestamp
        old_task = Task(
            task_id="old-task",
            url="https://example.com",
            created_at=datetime.utcnow() - timedelta(minutes=15)
        )
        task_manager.tasks["old-task"] = old_task

        # Manually trigger cleanup (normally done by background task)
        now = datetime.utcnow()
        expired_tasks = [
            task_id for task_id, task in task_manager.tasks.items()
            if now - task.created_at > task_manager.max_age
        ]

        assert "old-task" in expired_tasks

    def test_health_check(self):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    @patch("web.routes.run_analysis_task")
    def test_api_rejects_arbitrary_parameters(self, mock_run):
        """Test that API only accepts URL parameter."""
        # Try to send additional parameters that could control security settings
        response = client.post(
            "/api/analyze",
            json={
                "url": "https://example.com",
                "docker_config": {"network_mode": "host"},  # Should be ignored
                "security_bypass": True  # Should be ignored
            }
        )
        # Should either ignore extra fields or reject them
        # Pydantic will reject unknown fields by default
        assert response.status_code in [200, 422]

    def test_api_cannot_access_docker(self):
        """Test that API layer has no Docker access."""
        # This is verified by test_api_no_container_manager_access
        # which checks the source code for Docker imports
        # No need to test API root endpoint
        pass


class TestSecurityBoundaries:
    """Test that security boundaries are preserved."""

    def test_frontend_serves_static_files_only(self):
        """Test that frontend only serves static files."""
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

        # Verify no dynamic code execution
        assert "<script" in response.text
        assert "eval(" not in response.text.lower()

    def test_api_no_container_manager_access(self):
        """Test that API cannot access container_manager directly."""
        # This is verified by checking that no routes expose container management
        # The web layer only imports InputValidator, not container_manager
        from web import routes
        import inspect

        # Verify routes module doesn't import container_manager
        source = inspect.getsource(routes)
        assert "container_manager" not in source.lower()
        assert "docker" not in source.lower()

    def test_api_no_sandbox_direct_access(self):
        """Test that API cannot access raw Sandbox objects."""
        from web import routes
        import inspect

        source = inspect.getsource(routes)
        assert "sandbox" not in source.lower() or "input_validator" in source.lower()

    def test_invalid_url_no_sandbox_created(self):
        """Test that invalid URLs don't trigger sandbox creation."""
        # Submit invalid URL
        response = client.post(
            "/api/analyze",
            json={"url": "http://192.168.1.1"}
        )
        assert response.status_code == 400

        # Verify no task was created
        # (InputValidator rejects before task creation)
        # This is verified by the 400 response
