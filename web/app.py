"""FastAPI application for Website Authenticity Detector web layer."""

import asyncio
import sys

# Playwright requires a Windows event loop that supports subprocesses.
if sys.platform == 'win32':
     asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from web.routes import router
from web.tasks import task_manager
from pathlib import Path


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan events."""
    # Startup
    task_manager.start_cleanup()
    try:
        yield
    finally:
        # Shutdown
        task_manager.stop_cleanup()


# Create FastAPI application
app = FastAPI(
    title="Website Authenticity Detector API",
    description="Web API for analyzing website authenticity",
    version="0.1.0",
    lifespan=lifespan
)

# Mount static files
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# ============================================================================
# CORS CONFIGURATION
# ============================================================================
# DEVELOPMENT CONFIGURATION - RESTRICTIVE IN PRODUCTION
# In production, restrict to specific origins that need access.
# ============================================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],  # Restrictive for development
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router, prefix="/api")


# Root route to serve frontend
@app.get("/")
async def serve_frontend():
    """Serve the frontend UI."""
    from fastapi.responses import FileResponse
    from pathlib import Path
    static_path = Path(__file__).parent / "static" / "index.html"
    return FileResponse(str(static_path))


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}
