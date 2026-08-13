"""Pydantic models for web API request/response validation."""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Dict, List, Any
from datetime import datetime


class AnalyzeRequest(BaseModel):
    """Request model for website analysis."""

    url: str = Field(..., description="URL to analyze")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "url": "https://example.com"
            }
        }
    )


class AnalyzeResponse(BaseModel):
    """Response model for analysis request submission."""

    task_id: str = Field(..., description="Unique task identifier")
    status: str = Field(..., description="Task status (pending, running, completed, failed)")
    message: str = Field(..., description="Status message")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "task_id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "pending",
                "message": "Analysis started"
            }
        }
    )


class TaskStatusResponse(BaseModel):
    """Response model for task status polling."""

    task_id: str = Field(..., description="Unique task identifier")
    status: str = Field(..., description="Task status (pending, running, completed, failed)")
    progress: Optional[str] = Field(None, description="Current progress description")
    result: Optional[Dict[str, Any]] = Field(None, description="Analysis result if completed")
    error: Optional[str] = Field(None, description="Error message if failed")
    created_at: Optional[datetime] = Field(None, description="Task creation timestamp")
    completed_at: Optional[datetime] = Field(None, description="Task completion timestamp")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "task_id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "completed",
                "progress": "Analysis completed",
                "result": {
                    "authenticity_score": "85.50%",
                    "fake_score": "14.50%",
                    "confidence_indicator": "HIGH",
                    "url": "https://example.com",
                    "analysis_data": {},
                    "timestamps": {},
                    "top_factors": [],
                    "suspicious_indicators": [],
                    "error_message": None
                },
                "error": None
            }
        }
    )
