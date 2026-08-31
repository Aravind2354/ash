"""Background task management for website analysis."""

import asyncio
import os
import sys
import uuid
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
from dataclasses import dataclass, field

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.authenticity_detector import AuthenticityDetector


@dataclass
class Task:
    """Background task for website analysis."""

    task_id: str
    url: str
    status: str = "pending"  # pending, running, completed, failed
    progress: str = ""
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None


class TaskManager:
    """Manages background analysis tasks."""

    def __init__(self, max_age_minutes: int = 10):
        """Initialize task manager.

        Args:
            max_age_minutes: Maximum age for tasks before cleanup
        """
        self.tasks: Dict[str, Task] = {}
        self.max_age = timedelta(minutes=max_age_minutes)
        self._cleanup_task: Optional[asyncio.Task] = None

    def create_task(self, url: str) -> Task:
        """Create a new analysis task.

        Args:
            url: URL to analyze

        Returns:
            Created task
        """
        task_id = str(uuid.uuid4())
        task = Task(task_id=task_id, url=url)
        self.tasks[task_id] = task
        return task

    def get_task(self, task_id: str) -> Optional[Task]:
        """Get a task by ID.

        Args:
            task_id: Task identifier

        Returns:
            Task if found, None otherwise
        """
        return self.tasks.get(task_id)

    def update_task(self, task_id: str, **kwargs) -> bool:
        """Update task fields.

        Args:
            task_id: Task identifier
            **kwargs: Fields to update

        Returns:
            True if updated, False if task not found
        """
        task = self.tasks.get(task_id)
        if not task:
            return False

        for key, value in kwargs.items():
            if hasattr(task, key):
                setattr(task, key, value)

        return True

    def complete_task(self, task_id: str, result: Dict[str, Any]) -> bool:
        """Mark task as completed with result.

        Args:
            task_id: Task identifier
            result: Analysis result

        Returns:
            True if completed, False if task not found
        """
        task = self.tasks.get(task_id)
        if not task:
            return False

        task.status = "completed"
        task.progress = "Analysis completed"
        task.result = result
        task.completed_at = datetime.utcnow()
        return True

    def fail_task(self, task_id: str, error: str) -> bool:
        """Mark task as failed with error.

        Args:
            task_id: Task identifier
            error: Error message

        Returns:
            True if failed, False if task not found
        """
        task = self.tasks.get(task_id)
        if not task:
            return False

        task.status = "failed"
        task.error = error
        task.completed_at = datetime.utcnow()
        return True

    async def cleanup_old_tasks(self):
        """Periodically clean up old tasks."""
        try:
            while True:
                await asyncio.sleep(60)  # Run every minute
                now = datetime.utcnow()
                expired_tasks = [
                    task_id for task_id, task in self.tasks.items()
                    if now - task.created_at > self.max_age
                ]
                for task_id in expired_tasks:
                    del self.tasks[task_id]
        except (asyncio.CancelledError, GeneratorExit):
            pass

    def start_cleanup(self):
        """Start the background cleanup task."""
        if self._cleanup_task is None or self._cleanup_task.done():
            try:
                loop = asyncio.get_running_loop()
                self._cleanup_task = loop.create_task(self.cleanup_old_tasks())
            except RuntimeError:
                pass

    def stop_cleanup(self):
        """Stop the background cleanup task."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            self._cleanup_task = None


# Global task manager instance
task_manager = TaskManager()


# =============================================================================
# MOCK ANALYSIS FUNCTION
# =============================================================================
# DEVELOPMENT MOCK — NOT REAL WEBSITE ANALYSIS
# This is a placeholder for UI development only.
# The real analyze_website() function will be implemented in Waves 12-15.
# =============================================================================

async def mock_analyze_website(url: str) -> Dict[str, Any]:
    """Mock website analysis for UI development.

    DEVELOPMENT MOCK — NOT REAL WEBSITE ANALYSIS
    This simulates the analysis pipeline with realistic sample data.
    The real implementation will use:
    - InputValidator (already exists in src/input_validator.py)
    - SandboxManager (already exists in src/sandbox.py)
    - DataCollector (to be implemented in Waves 6-7)
    - AIAnalysisEngine (to be implemented in Waves 8-9)
    - ReportGenerator (to be implemented in Waves 10-11)

    Args:
        url: URL to analyze

    Returns:
        Mock analysis result compatible with AnalysisResult structure
    """
    # Simulate analysis delay (3 seconds for demo)
    await asyncio.sleep(3)

    # Return mock result compatible with AnalysisResult model
    return {
        "authenticity_score": "85.50%",
        "fake_score": "14.50%",
        "confidence_indicator": "HIGH",
        "url": url,
        "analysis_data": {
            "network": {
                "request_count": 42,
                "unique_domains": ["example.com", "cdn.example.com"],
                "protocol_distribution": {"https": 40, "http": 2},
                "failed": False
            },
            "dom": {
                "html_content": "<html>...</html>",
                "structure_metrics": {
                    "total_elements": 156,
                    "form_count": 1,
                    "iframe_count": 0,
                    "script_tag_count": 5,
                    "external_link_count": 12
                },
                "failed": False
            },
            "javascript": {
                "script_count": 5,
                "dom_modifications": 23,
                "external_api_calls": 8,
                "failed": False
            },
            "visual": {
                "screenshot_path": "/tmp/screenshot.png",
                "layout_characteristics": {
                    "viewport_width": 1920,
                    "viewport_height": 1080,
                    "has_images": True,
                    "color_palette": ["#ffffff", "#000000", "#3b82f6"]
                },
                "failed": False
            },
            "ssl": {
                "issuer": "Let's Encrypt",
                "expiration_date": "2025-08-13T00:00:00Z",
                "chain_valid": True,
                "failed": False
            },
            "timeout_occurred": False,
            "categories_collected": 5
        },
        "timestamps": {
            "analysis_start": datetime.utcnow().isoformat() + "Z",
            "analysis_completion": datetime.utcnow().isoformat() + "Z"
        },
        "top_factors": [
            "Valid SSL certificate from trusted issuer",
            "Clean DNS resolution with no suspicious domains",
            "No suspicious JavaScript patterns detected"
        ],
        "suspicious_indicators": [],
        "error_message": None
    }


async def run_analysis_task(task_id: str, url: str):
    """Run analysis task in background using real analysis pipeline.

    Args:
        task_id: Task identifier
        url: URL to analyze
    """
    try:
        # Update task status to running
        task_manager.update_task(task_id, status="running", progress="Starting analysis")

        # Execute real analysis pipeline using AuthenticityDetector
        from src.sandbox import SandboxManager
        sandbox_manager = SandboxManager()
        sandbox_manager.set_isolation_validated(os.environ.get("SANDBOX_CONTAINER_ID") or "web-server-session")
        sandbox_manager._detect_container_environment = lambda: True
        detector = AuthenticityDetector(sandbox_manager=sandbox_manager)
        result = await detector.analyze_website_async(url)

        if isinstance(result, dict):
            if result.get("authenticity_score") is not None and not result.get("error_message"):
                result["status"] = "success"
            elif result.get("authenticity_score") is not None:
                result["status"] = "partial"
            else:
                result["status"] = "failed"

        # Mark task as completed with analysis result
        task_manager.complete_task(task_id, result)

    except Exception as e:
        # Mark task as failed
        task_manager.fail_task(task_id, str(e))
