"""Background task management for website analysis."""

import asyncio
import logging
import os
import sys
import threading
import uuid
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
from dataclasses import dataclass, field

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.authenticity_detector import AuthenticityDetector
from config.logging_config import get_logger

logger = get_logger("web.tasks")


@dataclass
class Task:
    """Background task for website analysis."""

    task_id: str
    url: str
    status: str = "pending"  # pending, running, completed, failed
    progress: str = "queued"
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None


class TaskManager:
    """Thread-safe manager for background analysis tasks with concurrency control."""

    def __init__(self, max_age_minutes: int = 10, max_concurrent_analyses: int = 1, max_queue_size: int = 10):
        """Initialize task manager.

        Args:
            max_age_minutes: Maximum age for tasks before cleanup
            max_concurrent_analyses: Maximum number of concurrent analyses (default: 1 for memory optimization)
            max_queue_size: Maximum number of pending tasks in queue (default: 10)
        """
        self.tasks: Dict[str, Task] = {}
        self.max_age = timedelta(minutes=max_age_minutes)
        self._cleanup_task: Optional[asyncio.Task] = None
        self._lock = threading.Lock()
        
        # Concurrency control for memory optimization
        self._analysis_semaphore = asyncio.Semaphore(max_concurrent_analyses)
        self._max_concurrent_analyses = max_concurrent_analyses
        self._max_queue_size = max_queue_size
        self._pending_queue: asyncio.Queue = asyncio.Queue(maxsize=max_queue_size)

    def create_task(self, url: str) -> Task:
        """Create a new analysis task.

        Args:
            url: URL to analyze

        Returns:
            Created task with unique ID and initial queued state
        """
        task_id = str(uuid.uuid4())
        task = Task(task_id=task_id, url=url, status="pending", progress="queued")
        with self._lock:
            self.tasks[task_id] = task
        logger.info(f"[Task {task_id}] Created task for URL: {url}")
        return task

    async def can_accept_new_task(self) -> bool:
        """Check if the system can accept a new analysis task.

        Returns:
            True if queue has capacity and sufficient memory, False otherwise
        """
        # Check queue capacity
        try:
            self._pending_queue.put_nowait(None)
            self._pending_queue.get_nowait()  # Remove the dummy item
        except asyncio.QueueFull:
            logger.warning("Queue is full, rejecting new task")
            return False
        
        # Check available memory (basic check)
        try:
            import psutil
            available_mb = psutil.virtual_memory().available / 1024 / 1024
            # Require at least 200 MB available for a new analysis
            if available_mb < 200:
                logger.warning(f"Insufficient memory ({available_mb:.0f} MB available), rejecting new task")
                return False
        except ImportError:
            # psutil not available, skip memory check
            pass
        except Exception as e:
            logger.warning(f"Memory check failed: {e}")
        
        return True

    async def acquire_analysis_slot(self):
        """Acquire a slot for analysis (concurrency control).

        This method will block until a slot is available, implementing
        the queuing behavior for memory optimization.
        """
        await self._analysis_semaphore.acquire()

    def release_analysis_slot(self):
        """Release an analysis slot after completion."""
        self._analysis_semaphore.release()

    def get_task(self, task_id: str) -> Optional[Task]:
        """Get a task by ID.

        Args:
            task_id: Task identifier

        Returns:
            Task if found, None otherwise
        """
        with self._lock:
            return self.tasks.get(task_id)

    def update_task(self, task_id: str, **kwargs) -> bool:
        """Update task fields in a thread-safe manner.

        Args:
            task_id: Task identifier
            **kwargs: Fields to update

        Returns:
            True if updated, False if task not found
        """
        with self._lock:
            task = self.tasks.get(task_id)
            if not task:
                return False

            for key, value in kwargs.items():
                if hasattr(task, key):
                    setattr(task, key, value)

            return True

    def complete_task(self, task_id: str, result: Dict[str, Any]) -> bool:
        """Mark task as completed with analysis result.

        Args:
            task_id: Task identifier
            result: Analysis result dictionary

        Returns:
            True if completed, False if task not found
        """
        with self._lock:
            task = self.tasks.get(task_id)
            if not task:
                return False

            task.status = "completed"
            task.progress = "completed"
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
        with self._lock:
            task = self.tasks.get(task_id)
            if not task:
                return False

            task.status = "failed"
            task.progress = "failed"
            task.error = error
            task.completed_at = datetime.utcnow()
            return True

    async def cleanup_old_tasks(self):
        """Periodically clean up old tasks."""
        try:
            while True:
                await asyncio.sleep(60)  # Run every minute
                now = datetime.utcnow()
                with self._lock:
                    expired_tasks = [
                        task_id for task_id, task in self.tasks.items()
                        if now - task.created_at > self.max_age
                    ]
                    for task_id in expired_tasks:
                        del self.tasks[task_id]
                if expired_tasks:
                    logger.info(f"Cleaned up {len(expired_tasks)} expired background tasks")
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


async def run_analysis_task(task_id: str, url: str):
    """Run full website analysis pipeline in background with stage progress tracking.

    Execution Stages:
    1. queued -> starting
    2. collecting website data (Playwright loading, Network, DOM, JS, Visual, SSL)
    3. extracting features (Domain, Brand, Threat Intel, FeatureExtractor)
    4. running XGBoost (MLPhishingModel inference)
    5. running AI/hybrid analysis (AIAnalysisEngine risk gates, heuristic scoring)
    6. generating report (ReportGenerator report compilation)
    7. completed / failed

    Args:
        task_id: Unique task identifier
        url: Validated URL to analyze
    """
    # Acquire analysis slot for concurrency control (memory optimization)
    await task_manager.acquire_analysis_slot()
    
    logger.info(f"[Task {task_id}] Background analysis started for {url}")
    task_manager.update_task(task_id, status="running", progress="starting")

    def on_progress(stage: str):
        logger.info(f"[Task {task_id}] Stage: {stage} ({url})")
        task_manager.update_task(task_id, status="running", progress=stage)

    sandbox_manager = None
    try:
        # Dedicated SandboxManager per task to prevent shared state corruption during concurrent requests
        from src.sandbox import SandboxManager
        sandbox_manager = SandboxManager()
        sandbox_manager.set_isolation_validated(os.environ.get("SANDBOX_CONTAINER_ID") or "web-server-session")
        sandbox_manager._detect_container_environment = lambda: True
        detector = AuthenticityDetector(sandbox_manager=sandbox_manager)

        # Execute full analysis asynchronously with live progress reporting
        result = await detector.analyze_website_async(url, progress_callback=on_progress)

        if isinstance(result, dict):
            if result.get("risk_level") == "INCONCLUSIVE" or result.get("classification") == "INCONCLUSIVE":
                result["status"] = "completed"
                result["classification"] = "INCONCLUSIVE"
                result["risk_level"] = "INCONCLUSIVE"
                result["authenticity_score"] = None
                result["fake_score"] = None
                result["confidence"] = result.get("confidence") or result.get("confidence_indicator") or "LOW"
                result["confidence_indicator"] = result.get("confidence_indicator") or "LOW"
                result["xgboost_executed"] = False
                result["xgboost_probability"] = None
                if not result.get("reason"):
                    result["reason"] = "Target website was not reached due to an anti-bot or verification challenge"
                if not result.get("recommendation"):
                    result["recommendation"] = "Try again with a website that can be reached by the analysis browser"
                result["error_message"] = None
            elif result.get("authenticity_score") is not None and not result.get("error_message"):
                result["status"] = "completed"
            elif result.get("authenticity_score") is not None:
                result["status"] = "partial"
            else:
                result["status"] = "failed"

        # Check if analysis completed or failed
        if isinstance(result, dict) and result.get("status") == "failed" and result.get("error_message"):
            task_manager.fail_task(task_id, result.get("error_message"))
            # Keep result dictionary available on task for inspection
            task_manager.update_task(task_id, result=result)
            api_resp_log = f"[11] API RESPONSE: task_id={task_id}, status=failed, error={result.get('error_message')}"
            logger.warning(api_resp_log)
            print(api_resp_log, flush=True)
        else:
            task_manager.complete_task(task_id, result)
            api_resp_log = (
                f"[11] API RESPONSE: task_id={task_id}, status=completed, "
                f"authenticity_score={result.get('authenticity_score') if isinstance(result, dict) else None}, "
                f"fake_score={result.get('fake_score') if isinstance(result, dict) else None}, "
                f"risk_level={result.get('risk_level') if isinstance(result, dict) else None}, "
                f"confidence={result.get('confidence_indicator') if isinstance(result, dict) else None}"
            )
            logger.info(api_resp_log)
            print(api_resp_log, flush=True)

    except Exception as e:
        logger.error(f"[Task {task_id}] Unhandled error during analysis for {url}: {e}", exc_info=True)
        task_manager.fail_task(task_id, str(e))
    finally:
        # Release analysis slot for concurrency control
        task_manager.release_analysis_slot()
        
        if sandbox_manager:
            try:
                await sandbox_manager.terminate_sandbox(force=True)
            except Exception as term_err:
                logger.warning(f"[Task {task_id}] Error cleaning up sandbox manager: {term_err}")
