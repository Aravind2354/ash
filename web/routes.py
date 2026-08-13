"""API routes for website analysis."""

import sys
import os
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from typing import Dict

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.input_validator import InputValidator
from web.models import AnalyzeRequest, AnalyzeResponse, TaskStatusResponse
from web.tasks import task_manager, run_analysis_task

router = APIRouter()
input_validator = InputValidator()


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_website(request: AnalyzeRequest):
    """Submit a URL for analysis.

    This endpoint validates the URL and creates a background task for analysis.
    The analysis runs asynchronously; use the returned task_id to poll for results.

    Args:
        request: Analysis request with URL

    Returns:
        Task ID and status

    Raises:
        HTTPException: If URL validation fails
    """
    # Validate URL using the authoritative InputValidator
    is_valid, error_message = input_validator.validate_url(request.url)

    if not is_valid:
        raise HTTPException(status_code=400, detail=error_message)

    # Create background task
    task = task_manager.create_task(request.url)

    # Start analysis in background
    import asyncio
    asyncio.create_task(run_analysis_task(task.task_id, request.url))

    return AnalyzeResponse(
        task_id=task.task_id,
        status="pending",
        message="Analysis started"
    )


@router.get("/task/{task_id}", response_model=TaskStatusResponse)
async def get_task_status(task_id: str):
    """Get the status of an analysis task.

    Args:
        task_id: Task identifier

    Returns:
        Task status and result if completed

    Raises:
        HTTPException: If task not found
    """
    task = task_manager.get_task(task_id)

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    return TaskStatusResponse(
        task_id=task.task_id,
        status=task.status,
        progress=task.progress,
        result=task.result,
        error=task.error,
        created_at=task.created_at,
        completed_at=task.completed_at
    )
