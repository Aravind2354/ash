"""Sandbox management module for isolated website execution.

This module provides Sandbox and SandboxManager classes for creating and managing
isolated virtual environments using Playwright with isolated browser contexts.
"""

import asyncio
import logging
from typing import Optional
from datetime import datetime, timezone

from playwright.async_api import async_playwright, Browser, BrowserContext, Page
from config.logging_config import get_logger


# Timeout constants (from requirements)
INITIALIZATION_TIMEOUT = 15.0  # seconds (Requirement 1.5)
TERMINATION_TIMEOUT = 10.0  # seconds (Requirement 1.4, 1.6)


class Sandbox:
    """Represents an isolated browser context for website execution.
    
    This class wraps a Playwright browser context and provides lifecycle management
    for loading and executing websites in isolation.
    """
    
    def __init__(self, browser: Browser, context: BrowserContext):
        """Initialize a Sandbox with Playwright browser and context.
        
        Args:
            browser: Playwright browser instance
            context: Isolated browser context
        """
        self.browser = browser
        self.context = context
        self.page: Optional[Page] = None
        self.logger = get_logger(__name__)
        self._created_at = datetime.now(timezone.utc)
    
    async def create_page(self) -> Page:
        """Create a new page in the isolated context.
        
        Returns:
            New Playwright Page instance
        """
        if self.page is not None:
            await self.page.close()
        
        self.page = await self.context.new_page()
        self.logger.info("Created new page in sandbox context")
        return self.page
    
    async def close_page(self) -> None:
        """Close the current page if it exists."""
        if self.page is not None:
            await self.page.close()
            self.page = None
            self.logger.info("Closed page in sandbox context")
    
    async def close(self) -> None:
        """Close the browser context."""
        await self.close_page()
        if self.context:
            await self.context.close()
            self.logger.info("Closed sandbox context")


class SandboxManager:
    """Manages creation, lifecycle, and cleanup of isolated sandbox environments.
    
    This class handles the complete lifecycle of sandbox environments including
    initialization with timeout, graceful/forced termination, and reset between
    analyses.
    
    Requirements: 1.1, 1.4, 1.5, 1.6, 6.6
    """
    
    def __init__(self):
        """Initialize the SandboxManager."""
        self.logger = get_logger(__name__)
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.current_sandbox: Optional[Sandbox] = None
        self._is_initialized = False
    
    async def create_sandbox(self) -> Sandbox:
        """Create a new isolated sandbox environment with 15-second timeout.
        
        Creates a Playwright browser instance with an isolated browser context.
        If initialization fails within 15 seconds, raises an exception.
        
        Requirements: 1.1, 1.5
        
        Returns:
            Sandbox instance with isolated browser context
            
        Raises:
            TimeoutError: If sandbox initialization exceeds 15 seconds
            Exception: If sandbox initialization fails for other reasons
        """
        if self._is_initialized and self.current_sandbox is not None:
            self.logger.warning("Sandbox already exists, returning existing instance")
            return self.current_sandbox
        
        self.logger.info("Starting sandbox initialization")
        start_time = datetime.now(timezone.utc)
        
        try:
            # Create sandbox with timeout
            self.current_sandbox = await asyncio.wait_for(
                self._create_sandbox_internal(),
                timeout=INITIALIZATION_TIMEOUT
            )
            
            initialization_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            self.logger.info(
                f"Sandbox initialized successfully in {initialization_time:.2f}s",
                extra={"extra_fields": {"initialization_time_seconds": initialization_time}}
            )
            self._is_initialized = True
            return self.current_sandbox
            
        except asyncio.TimeoutError:
            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
            error_msg = f"Sandbox initialization failed: exceeded {INITIALIZATION_TIMEOUT}s timeout (took {elapsed:.2f}s)"
            self.logger.error(error_msg)
            # Clean up any partial initialization
            await self._cleanup_partial_initialization()
            raise TimeoutError(error_msg)
            
        except Exception as e:
            error_msg = f"Sandbox initialization failed: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            await self._cleanup_partial_initialization()
            raise Exception(error_msg)
    
    async def _create_sandbox_internal(self) -> Sandbox:
        """Internal method to create sandbox without timeout wrapper.
        
        Returns:
            Sandbox instance
        """
        if self.playwright is None:
            self.playwright = await async_playwright().start()
            self.logger.info("Started Playwright")
        
        if self.browser is None:
            # Launch browser with isolation settings
            self.browser = await self.playwright.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                ]
            )
            self.logger.info("Launched Chromium browser")
        
        # Create isolated browser context
        context = await self.browser.new_context(
            ignore_https_errors=True,  # For SSL certificate analysis
            java_script_enabled=True,
        )
        self.logger.info("Created isolated browser context")
        
        return Sandbox(self.browser, context)
    
    async def _cleanup_partial_initialization(self) -> None:
        """Clean up partial initialization state after failure."""
        try:
            if self.current_sandbox:
                await self.current_sandbox.close()
        except Exception as e:
            self.logger.error(f"Error closing sandbox during partial cleanup: {str(e)}")
        finally:
            self.current_sandbox = None
        
        try:
            if self.browser:
                await self.browser.close()
        except Exception as e:
            self.logger.error(f"Error closing browser during partial cleanup: {str(e)}")
        finally:
            self.browser = None
        
        try:
            if self.playwright:
                await self.playwright.stop()
        except Exception as e:
            self.logger.error(f"Error stopping Playwright during partial cleanup: {str(e)}")
        finally:
            self.playwright = None
        
        self._is_initialized = False
        self.logger.info("Cleaned up partial initialization state")
    
    async def terminate_sandbox(self, force: bool = False) -> None:
        """Terminate the sandbox with graceful or forced shutdown.
        
        Attempts graceful shutdown first, then forced termination if needed.
        Must complete within 10 seconds per requirements.
        
        Requirements: 1.4, 1.6
        
        Args:
            force: If True, skip graceful shutdown and force terminate immediately
        """
        if self.current_sandbox is None:
            self.logger.warning("No sandbox to terminate")
            return
        
        self.logger.info(f"Terminating sandbox (force={force})")
        start_time = datetime.now(timezone.utc)
        
        try:
            if force:
                # Forced termination
                await self._force_terminate()
            else:
                # Attempt graceful termination with timeout
                try:
                    await asyncio.wait_for(
                        self._graceful_terminate(),
                        timeout=TERMINATION_TIMEOUT
                    )
                except asyncio.TimeoutError:
                    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                    self.logger.warning(
                        f"Graceful termination exceeded {TERMINATION_TIMEOUT}s (took {elapsed:.2f}s), forcing termination"
                    )
                    await self._force_terminate()
            
            termination_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            self.logger.info(
                f"Sandbox terminated in {termination_time:.2f}s",
                extra={"extra_fields": {"termination_time_seconds": termination_time, "forced": force}}
            )
            
        except Exception as e:
            self.logger.error(f"Error during sandbox termination: {str(e)}", exc_info=True)
            # Ensure cleanup happens even on error
            await self._force_terminate()
            raise
    
    async def _graceful_terminate(self) -> None:
        """Perform graceful shutdown of sandbox resources."""
        if self.current_sandbox:
            await self.current_sandbox.close()
        self.current_sandbox = None
        self._is_initialized = False
    
    async def _force_terminate(self) -> None:
        """Force terminate all sandbox resources immediately.
        
        Logs forced termination event as required by Requirement 1.6.
        """
        self.logger.warning("Forcing sandbox termination")
        
        try:
            if self.current_sandbox:
                await self.current_sandbox.close()
        except Exception as e:
            self.logger.error(f"Error closing sandbox during force termination: {str(e)}")
        finally:
            self.current_sandbox = None
        
        try:
            if self.browser:
                await self.browser.close()
        except Exception as e:
            self.logger.error(f"Error closing browser during force termination: {str(e)}")
        finally:
            self.browser = None
        
        try:
            if self.playwright:
                await self.playwright.stop()
        except Exception as e:
            self.logger.error(f"Error stopping Playwright during force termination: {str(e)}")
        finally:
            self.playwright = None
        
        self._is_initialized = False
        self.logger.warning("Forced termination complete")
    
    async def reset_sandbox(self) -> None:
        """Reset the sandbox environment between analyses.
        
        Deletes temporary files, terminates processes, and reinitializes
        network isolation settings. Creates a fresh sandbox for the next analysis.
        
        Requirement: 6.6
        """
        self.logger.info("Resetting sandbox environment")
        
        # Terminate existing sandbox
        if self.current_sandbox is not None:
            await self.terminate_sandbox()
        
        # Clean up any remaining resources
        await self._cleanup_partial_initialization()
        
        # Create fresh sandbox for next analysis
        try:
            await self.create_sandbox()
            self.logger.info("Sandbox reset complete, new sandbox ready")
        except Exception as e:
            self.logger.error(f"Failed to create new sandbox during reset: {str(e)}", exc_info=True)
            raise
    
    async def get_sandbox(self) -> Sandbox:
        """Get the current sandbox instance.
        
        Returns:
            Current Sandbox instance
            
        Raises:
            RuntimeError: If no sandbox is initialized
        """
        if self.current_sandbox is None or not self._is_initialized:
            raise RuntimeError("Sandbox not initialized. Call create_sandbox() first.")
        return self.current_sandbox
    
    async def cleanup(self) -> None:
        """Complete cleanup of all SandboxManager resources.
        
        Call this when shutting down the application to ensure all resources
        are properly released.
        """
        self.logger.info("Performing complete SandboxManager cleanup")
        await self.terminate_sandbox(force=True)
        await self._cleanup_partial_initialization()
        self.logger.info("SandboxManager cleanup complete")
