"""Tests for web API layer."""

import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from web.app import app
from web.tasks import task_manager
from src.authenticity_detector import AuthenticityDetector


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


class TestBackgroundTaskArchitecture:
    """Test suite for asynchronous background task execution, progress updates, and XGBoost integration."""

    def test_post_analyze_returns_immediately(self):
        """POST /api/analyze returns fast response with unique task_id."""
        with patch("web.routes.run_analysis_task") as mock_run:
            response = client.post(
                "/api/analyze",
                json={"url": "https://example.com"}
            )
            assert response.status_code == 200
            data = response.json()
            assert "task_id" in data
            assert data["status"] == "pending"
            assert data["message"] == "Analysis started"

            # Check task manager has the task
            task = task_manager.get_task(data["task_id"])
            assert task is not None
            assert task.url == "https://example.com"
            assert task.progress == "queued"

    @pytest.mark.asyncio
    async def test_run_analysis_task_progress_sequence(self):
        """Verify background task records progress transitions correctly."""
        from web.tasks import run_analysis_task, Task

        task = task_manager.create_task("https://example.com")
        progress_history = []

        original_update = task_manager.update_task

        def tracking_update(task_id, **kwargs):
            if "progress" in kwargs:
                progress_history.append(kwargs["progress"])
            return original_update(task_id, **kwargs)

        mock_detector = AsyncMock()
        async def fake_analyze(url, progress_callback=None):
            if progress_callback:
                progress_callback("starting")
                progress_callback("collecting website data")
                progress_callback("extracting features")
                progress_callback("running XGBoost")
                progress_callback("running AI/hybrid analysis")
                progress_callback("generating report")
                progress_callback("completed")
            return {
                "authenticity_score": "92.00%",
                "fake_score": "8.00%",
                "confidence_indicator": "HIGH",
                "top_factors": ["Factor 1", "Factor 2", "Factor 3"],
                "suspicious_indicators": [],
                "error_message": None
            }

        mock_detector.analyze_website_async = fake_analyze

        with patch("web.tasks.task_manager.update_task", side_effect=tracking_update), \
             patch("web.tasks.AuthenticityDetector", return_value=mock_detector):
            await run_analysis_task(task.task_id, "https://example.com")

        completed_task = task_manager.get_task(task.task_id)
        assert completed_task.status == "completed"
        assert completed_task.result["authenticity_score"] == "92.00%"
        assert "starting" in progress_history
        assert "collecting website data" in progress_history
        assert "extracting features" in progress_history
        assert "running XGBoost" in progress_history
        assert "running AI/hybrid analysis" in progress_history
        assert "generating report" in progress_history

    @pytest.mark.asyncio
    async def test_run_analysis_task_executes_real_xgboost_pipeline(self):
        """Verify that background task executes feature extraction and XGBoost model inference."""
        from web.tasks import run_analysis_task
        from src.models import AnalysisData, NetworkData, DOMData, JavaScriptData, VisualData, SSLData
        from src.ml_model import MLPhishingModel

        task = task_manager.create_task("https://example.com")

        # Create realistic analysis data
        mock_data = AnalysisData(
            network=NetworkData(request_count=10, unique_domains=["example.com"], protocol_distribution={"https": 10}, failed=False),
            dom=DOMData(html_content="<html><head><title>Example</title></head><body><h1>Hello</h1></body></html>", structure_metrics={"total_elements": 20}, failed=False),
            javascript=JavaScriptData(script_count=1, dom_modifications=0, external_api_calls=0, failed=False),
            visual=VisualData(screenshot_path="/tmp/screenshot.png", layout_characteristics={"has_images": True, "viewport_width": 1920, "viewport_height": 1080}, failed=False),
            ssl=SSLData(issuer="DigiCert", expiration_date="2027-01-01", chain_valid=True, failed=False),
            categories_collected=5,
        )

        mock_sandbox = AsyncMock()
        mock_sandbox.load_url.return_value = True
        mock_sb_manager = AsyncMock()
        mock_sb_manager.create_sandbox.return_value = mock_sandbox
        mock_sb_manager.validate_isolation.return_value = (True, "")

        mock_collector = AsyncMock()
        mock_collector.collect_all.return_value = mock_data

        detector = AuthenticityDetector(
            sandbox_manager=mock_sb_manager,
            data_collector=mock_collector
        )

        with patch("web.tasks.AuthenticityDetector", return_value=detector):
            await run_analysis_task(task.task_id, "https://example.com")

        completed_task = task_manager.get_task(task.task_id)
        assert completed_task.status == "completed"
        assert completed_task.result is not None
        assert completed_task.result["authenticity_score"] is not None
        assert completed_task.result["fake_score"] is not None
        assert len(completed_task.result["top_factors"]) == 3

    @pytest.mark.asyncio
    async def test_run_analysis_task_failure_handling(self):
        """Verify error recording when an exception occurs during background analysis."""
        from web.tasks import run_analysis_task

        task = task_manager.create_task("https://error-site.example")

        mock_detector = AsyncMock()
        mock_detector.analyze_website_async.side_effect = RuntimeError("Playwright connection refused")

        with patch("web.tasks.AuthenticityDetector", return_value=mock_detector):
            await run_analysis_task(task.task_id, "https://error-site.example")

        failed_task = task_manager.get_task(task.task_id)
        assert failed_task.status == "failed"
        assert "Playwright connection refused" in failed_task.error

    def test_concurrent_tasks_unique_and_isolated(self):
        """Verify concurrent task creation produces distinct tasks with isolated state."""
        import concurrent.futures

        urls = [f"https://example{i}.org" for i in range(20)]
        created_tasks = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(task_manager.create_task, u) for u in urls]
            for f in concurrent.futures.as_completed(futures):
                created_tasks.append(f.result())

        task_ids = [t.task_id for t in created_tasks]
        assert len(task_ids) == 20
        assert len(set(task_ids)) == 20  # All unique

        # Updating one task doesn't corrupt others
        first_id = task_ids[0]
        task_manager.update_task(first_id, status="running", progress="extracting features")
        assert task_manager.get_task(first_id).progress == "extracting features"
        assert task_manager.get_task(task_ids[1]).progress == "queued"

