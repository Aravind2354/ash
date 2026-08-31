"""Sandbox management module for isolated website execution.

This module provides Sandbox and SandboxManager classes for creating and managing
isolated virtual environments using Playwright with isolated browser contexts.

SECURITY WARNING: Playwright BrowserContext is NOT a host security boundary.
BrowserContext provides browser-level isolation only (cookies, localStorage, etc.)
and does NOT prevent malicious code from:
- Accessing the host file system
- Spawning processes on the host system
- Accessing internal network addresses
- Escaping the browser context

Host-level isolation MUST be implemented separately through containerization,
VMs, or OS-level sandboxing before analyzing untrusted websites.

For untrusted website analysis:
1. Use ContainerManager to create and validate a Docker container
2. Run this SandboxManager inside the validated container
3. The container provides host-level isolation (filesystem, process, network)
4. SandboxManager provides browser-level isolation (cookies, localStorage, etc.)

Current configuration uses --no-sandbox for local development compatibility.
This configuration MUST NOT be used to analyze untrusted websites until an
external containment boundary exists (Docker, VM, or OS-level sandbox).

Requirements: 1.1, 1.4, 1.5, 1.6, 6.1, 6.2, 6.6
"""
import tempfile
import asyncio
import logging
import inspect
import socket
import os
from typing import Optional, Tuple, List, Any
from datetime import datetime, timezone

from playwright.async_api import async_playwright, Browser, BrowserContext, Page
from config.logging_config import get_logger


# Timeout constants (from requirements)
INITIALIZATION_TIMEOUT = 15.0  # seconds (Requirement 1.5)
TERMINATION_TIMEOUT = 10.0  # seconds (Requirement 1.4, 1.6)
ISOLATION_FAILURE_TERMINATION_TIMEOUT = 2.0  # seconds (Requirement 6.2)
RESPONSIVENESS_TIMEOUT = 15.0  # seconds (Requirement 8.2)
REDIRECT_TIMEOUT = 10.0  # seconds per redirect (Requirement 8.5)
MAX_REDIRECTS = 5  # maximum redirects to follow (Requirement 8.6, 8.7)


class Sandbox:
    """Represents an isolated browser context for website execution.

    This class wraps a Playwright browser context and provides lifecycle management
    for loading and executing websites in isolation.

    When used for untrusted website analysis, isolation should be validated
    before loading any URLs (Requirement 6.1).
    """

    def __init__(self, browser: Browser, context: BrowserContext, sandbox_manager: 'SandboxManager', violation_monitor=None):
        """Initialize a Sandbox with Playwright browser and context.

        Args:
            browser: Playwright browser instance
            context: Isolated browser context
            sandbox_manager: Parent SandboxManager for isolation validation
            violation_monitor: Optional ViolationMonitor for runtime violation detection
        """
        self.browser = browser
        self.context = context
        self.sandbox_manager = sandbox_manager
        self.violation_monitor = violation_monitor
        self.page: Optional[Page] = None
        self.logger = get_logger(__name__)
        self._created_at = datetime.now(timezone.utc)
        self._page_lock = asyncio.Lock()  # Synchronize page creation

        # Redirect tracking (Task 4.4)
        self.redirect_chain: List[str] = []  # List of URLs in redirect chain
        self.redirect_count: int = 0  # Number of redirects followed
        self.final_url: Optional[str] = None  # Final URL reached
        self.suspicious_indicators: List[str] = []  # Suspicious indicators detected

    async def create_page(self) -> Page:
        """Create a new page in the isolated context.

        Thread-safe: Uses lock to prevent concurrent page creation races.

        Returns:
            New Playwright Page instance

        Raises:
            RuntimeError: If page creation times out or fails
        """
        async with self._page_lock:
            if self.page is not None:
                await self.page.close()

            try:
                self.page = await asyncio.wait_for(
                    self.context.new_page(),
                    timeout=INITIALIZATION_TIMEOUT
                )
                self.logger.info("Created new page in sandbox context")
                return self.page
            except asyncio.TimeoutError:
                self.logger.error(
                    f"Page creation timed out after {INITIALIZATION_TIMEOUT}s",
                    extra={
                        "extra_fields": {
                            "timeout_seconds": INITIALIZATION_TIMEOUT,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                    }
                )
                # Clean up and fail closed
                await self.close()
                raise RuntimeError(
                    f"Page creation timed out after {INITIALIZATION_TIMEOUT}s. "
                    f"Sandbox terminated per fail-closed behavior."
                )
            except Exception as e:
                self.logger.error(f"Page creation failed: {e}")
                # Clean up and fail closed
                await self.close()
                raise RuntimeError(
                    f"Page creation failed: {e}. "
                    f"Sandbox terminated per fail-closed behavior."
                )

    async def close_page(self) -> None:
        """Close the current page if it exists."""
        if self.page is not None:
            try:
                await asyncio.wait_for(self.page.close(), timeout=2.0)
            except Exception as e:
                self.logger.warning(f"Error closing page in sandbox context: {e}")
            self.page = None
            self.logger.info("Closed page in sandbox context")

    async def close(self) -> None:
        """Close the browser context."""
        await self.close_page()
        if self.context:
            try:
                await asyncio.wait_for(self.context.close(), timeout=3.0)
            except Exception as e:
                self.logger.warning(f"Error closing context: {e}")
            self.logger.info("Closed sandbox context")

    async def load_url(self, url: str, timeout: int = 30) -> bool:
        """Load a URL in the isolated browser context.

        Loads the specified URL in the sandbox with a timeout. Validates
        isolation before loading if required (Requirement 6.1).

        Monitors for runtime violations during URL loading per Requirement 6.5:
        - Network violations (internal IP connections)
        - Filesystem violations (download attempts)
        - Process violations (detected through page context)

        Follows redirects up to MAX_REDIRECTS (5) with REDIRECT_TIMEOUT (10s) per redirect
        (Requirements 8.5, 8.6, 8.7). Marks excessive redirects as suspicious.

        If isolation validation fails, the operation is blocked and the
        sandbox is terminated within 2 seconds (Requirement 6.2).

        If security-critical violations are detected, the analysis is
        terminated immediately per fail-closed behavior.

        Args:
            url: URL to load
            timeout: Maximum time to wait for page load (default 30s)

        Returns:
            True if URL loaded successfully without violations, False otherwise

        Raises:
            RuntimeError: If isolation validation fails or security-critical violation detected
        """
        self.logger.info(f"Loading URL in sandbox: {url}")

        # Reset redirect tracking for new load
        self.redirect_chain = [url]
        self.redirect_count = 0
        self.final_url = url
        self.suspicious_indicators = []

        # Validate isolation before loading (Requirement 6.1)
        is_valid, error_msg = self.sandbox_manager.validate_isolation()

        if not is_valid:
            # Isolation validation failed - terminate within 2 seconds (Requirement 6.2)
            self.logger.error(
                f"Isolation validation failed before URL loading: {error_msg}",
                extra={
                    "extra_fields": {
                        "url": url,
                        "validation_error": error_msg,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )

            # Terminate sandbox immediately
            try:
                await self.sandbox_manager.terminate_sandbox(force=True)
                self.logger.info("Sandbox terminated due to isolation validation failure")
            except Exception as e:
                self.logger.error(f"Error terminating sandbox: {e}")

            raise RuntimeError(
                f"Isolation validation failed: {error_msg}. "
                f"Cannot load URL. Sandbox terminated per Requirement 6.2."
            )

        # Create page if needed
        if self.page is None:
            await self.create_page()

        # Set up request interception for network violations (Requirement 6.5)
        # This provides DNS rebinding protection by checking resolved IP addresses
        from urllib.parse import urlparse
        import socket

        host = urlparse(url).hostname

        # Check if URL itself targets internal network (pre-emptive check)
        if self.violation_monitor and host:
            if self.violation_monitor.is_internal_ip(host):
                # Target URL is internal network - violation detected
                violation = self.violation_monitor.log_network_violation(
                    ip_address=host,
                    container_id=self.sandbox_manager._container_id,
                    details={'url': url, 'violation_stage': 'url_resolution'}
                )

                self.logger.error(
                    f"Target URL uses internal network address: {host}",
                    extra={
                        "extra_fields": {
                            "url": url,
                            "internal_ip": host,
                            "container_id": self.sandbox_manager._container_id,
                            "timestamp": violation.timestamp.isoformat()
                        }
                    }
                )

                # Terminate immediately per fail-closed behavior
                try:
                    await self.sandbox_manager.terminate_sandbox(force=True)
                except Exception as e:
                    self.logger.error(f"Error terminating sandbox: {e}")

                raise RuntimeError(
                    f"Target URL uses internal network address: {host}. "
                    f"Analysis terminated per Requirement 6.5."
                )

            # DNS rebinding protection: resolve hostname and check actual IP
            # This prevents DNS rebinding attacks where a public hostname resolves
            # to a private IP address
            try:
                # Resolve hostname to IP addresses
                # Use socket.getaddrinfo for comprehensive resolution (IPv4 and IPv6)
                addr_info = socket.getaddrinfo(host, None)
                resolved_ips = set()
                for family, _, _, _, sockaddr in addr_info:
                    resolved_ips.add(sockaddr[0])

                # Check all resolved IPs
                for resolved_ip in resolved_ips:
                    if self.violation_monitor.is_internal_ip(resolved_ip):
                        # DNS rebinding detected - public hostname resolves to private IP
                        violation = self.violation_monitor.log_network_violation(
                            ip_address=resolved_ip,
                            container_id=self.sandbox_manager._container_id,
                            details={
                                'url': url,
                                'hostname': host,
                                'resolved_ip': resolved_ip,
                                'violation_stage': 'dns_resolution',
                                'all_resolved_ips': list(resolved_ips)
                            }
                        )

                        self.logger.error(
                            f"DNS rebinding detected: {host} resolves to internal IP {resolved_ip}",
                            extra={
                                "extra_fields": {
                                    "url": url,
                                    "hostname": host,
                                    "resolved_ip": resolved_ip,
                                    "all_resolved_ips": list(resolved_ips),
                                    "container_id": self.sandbox_manager._container_id,
                                    "timestamp": violation.timestamp.isoformat()
                                }
                            }
                        )

                        # Terminate immediately per fail-closed behavior
                        try:
                            await self.sandbox_manager.terminate_sandbox(force=True)
                        except Exception as e:
                            self.logger.error(f"Error terminating sandbox: {e}")

                        raise RuntimeError(
                            f"DNS rebinding detected: {host} resolves to internal IP {resolved_ip}. "
                            f"Analysis terminated per Requirement 6.5."
                        )

                self.logger.info(
                    f"DNS resolution check passed for {host}: {resolved_ips}",
                    extra={
                        "extra_fields": {
                            "hostname": host,
                            "resolved_ips": list(resolved_ips),
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                    }
                )

            except socket.gaierror as e:
                # DNS resolution failed - fail closed for security
                self.logger.error(
                    f"DNS resolution failed for {host}: {e}",
                    extra={
                        "extra_fields": {
                            "hostname": host,
                            "error": str(e),
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                    }
                )
                raise RuntimeError(
                    f"DNS resolution failed for {host}: {e}. "
                    f"Cannot safely load URL without DNS validation."
                )
            except RuntimeError as e:
                # Re-raise RuntimeError (e.g., from DNS rebinding detection)
                raise
            except Exception as e:
                # Other resolution errors - fail closed for security
                self.logger.error(
                    f"Error during DNS resolution for {host}: {e}",
                    extra={
                        "extra_fields": {
                            "hostname": host,
                            "error": str(e),
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                    }
                )
                raise RuntimeError(
                    f"DNS resolution error for {host}: {e}. "
                    f"Cannot safely load URL without DNS validation."
                )

        # Set up request interception to block internal/private destinations at runtime
        # This provides hostname-based filtering and DNS rebinding protection for subresources.
        # Browser-level network security and container-level isolation provide
        # the primary protection against internal network access.
        if self.violation_monitor:
            async def handle_request(route, request):
                """Intercept and block requests to internal/private destinations."""
                # Get hostname from URL
                request_url = request.url
                parsed = urlparse(request_url)
                hostname = parsed.hostname

                if hostname and self.violation_monitor.is_internal_ip(hostname):
                    # Internal destination detected - block and log
                    violation = self.violation_monitor.log_network_violation(
                        ip_address=hostname,
                        container_id=self.sandbox_manager._container_id,
                        details={
                            'url': request_url,
                            'violation_stage': 'request_interception',
                            'resource_type': request.resource_type
                        }
                    )

                    self.logger.error(
                        f"Request blocked to internal destination: {hostname}",
                        extra={
                            "extra_fields": {
                                "url": request_url,
                                "internal_ip": hostname,
                                "container_id": self.sandbox_manager._container_id,
                                "timestamp": violation.timestamp.isoformat()
                            }
                        }
                    )

                    # Block the request
                    await route.abort()
                    return

                # DNS rebinding protection for subresources: resolve and check actual IP
                try:
                    addr_info = socket.getaddrinfo(hostname, None)
                    resolved_ips = set()
                    for family, _, _, _, sockaddr in addr_info:
                        resolved_ips.add(sockaddr[0])

                    # Check all resolved IPs
                    for resolved_ip in resolved_ips:
                        if self.violation_monitor.is_internal_ip(resolved_ip):
                            # DNS rebinding detected in subresource request
                            violation = self.violation_monitor.log_network_violation(
                                ip_address=resolved_ip,
                                container_id=self.sandbox_manager._container_id,
                                details={
                                    'url': request_url,
                                    'hostname': hostname,
                                    'resolved_ip': resolved_ip,
                                    'violation_stage': 'subresource_dns_resolution',
                                    'resource_type': request.resource_type,
                                    'all_resolved_ips': list(resolved_ips)
                                }
                            )

                            self.logger.error(
                                f"Subresource DNS rebinding blocked: {hostname} resolves to internal IP {resolved_ip}",
                                extra={
                                    "extra_fields": {
                                        "url": request_url,
                                        "hostname": hostname,
                                        "resolved_ip": resolved_ip,
                                        "resource_type": request.resource_type,
                                        "container_id": self.sandbox_manager._container_id,
                                        "timestamp": violation.timestamp.isoformat()
                                    }
                                }
                            )

                            # Block the request
                            await route.abort()
                            return

                except socket.gaierror as e:
                    # DNS resolution failed - block request for security
                    self.logger.error(
                        f"Subresource DNS resolution failed for {hostname}: {e}",
                        extra={
                            "extra_fields": {
                                "hostname": hostname,
                                "error": str(e),
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            }
                        }
                    )
                    # Block the request
                    await route.abort()
                    return
                except Exception as e:
                    # Other resolution errors - block request for security
                    self.logger.error(
                        f"Error during subresource DNS resolution for {hostname}: {e}",
                        extra={
                            "extra_fields": {
                                "hostname": hostname,
                                "error": str(e),
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            }
                        }
                    )
                    # Block the request
                    await route.abort()
                    return

                # Allow external requests
                await route.continue_()

            # Enable request interception (page.route is async in Playwright Python async API)
            await self.page.route('**', handle_request)

        # Disable automatic redirect following to implement manual redirect handling
        # We'll follow redirects manually to enforce per-redirect validation and limits
        try:
            # Load URL with manual redirect handling
            current_url = url
            redirect_loop_count = 0

            while redirect_loop_count <= MAX_REDIRECTS:
                # Validate current URL before loading (security check for each redirect)
                current_host = urlparse(current_url).hostname

                if self.violation_monitor and current_host:
                    # Check if URL targets internal network
                    if self.violation_monitor.is_internal_ip(current_host):
                        # Internal destination detected - violation
                        violation = self.violation_monitor.log_network_violation(
                            ip_address=current_host,
                            container_id=self.sandbox_manager._container_id,
                            details={'url': current_url, 'violation_stage': 'redirect_validation'}
                        )

                        self.logger.error(
                            f"Redirect target uses internal network address: {current_host}",
                            extra={
                                "extra_fields": {
                                    "url": current_url,
                                    "internal_ip": current_host,
                                    "container_id": self.sandbox_manager._container_id,
                                    "timestamp": violation.timestamp.isoformat()
                                }
                            }
                        )

                        # Terminate immediately per fail-closed behavior
                        try:
                            await self.sandbox_manager.terminate_sandbox(force=True)
                        except Exception as e:
                            self.logger.error(f"Error terminating sandbox: {e}")

                        raise RuntimeError(
                            f"Redirect target uses internal network address: {current_host}. "
                            f"Analysis terminated per Requirement 6.5."
                        )

                    # DNS rebinding protection for redirect target
                    try:
                        addr_info = socket.getaddrinfo(current_host, None)
                        resolved_ips = set()
                        for family, _, _, _, sockaddr in addr_info:
                            resolved_ips.add(sockaddr[0])

                        for resolved_ip in resolved_ips:
                            if self.violation_monitor.is_internal_ip(resolved_ip):
                                # DNS rebinding detected in redirect target
                                violation = self.violation_monitor.log_network_violation(
                                    ip_address=resolved_ip,
                                    container_id=self.sandbox_manager._container_id,
                                    details={
                                        'url': current_url,
                                        'hostname': current_host,
                                        'resolved_ip': resolved_ip,
                                        'violation_stage': 'redirect_dns_resolution',
                                        'all_resolved_ips': list(resolved_ips)
                                    }
                                )

                                self.logger.error(
                                    f"DNS rebinding detected in redirect: {current_host} resolves to internal IP {resolved_ip}",
                                    extra={
                                        "extra_fields": {
                                            "url": current_url,
                                            "hostname": current_host,
                                            "resolved_ip": resolved_ip,
                                            "all_resolved_ips": list(resolved_ips),
                                            "container_id": self.sandbox_manager._container_id,
                                            "timestamp": violation.timestamp.isoformat()
                                        }
                                    }
                                )

                                # Terminate immediately per fail-closed behavior
                                try:
                                    await self.sandbox_manager.terminate_sandbox(force=True)
                                except Exception as e:
                                    self.logger.error(f"Error terminating sandbox: {e}")

                                raise RuntimeError(
                                    f"DNS rebinding detected in redirect: {current_host} resolves to internal IP {resolved_ip}. "
                                    f"Analysis terminated per Requirement 6.5."
                                )

                    except socket.gaierror as e:
                        # DNS resolution failed - fail closed for security
                        self.logger.error(
                            f"DNS resolution failed for redirect target {current_host}: {e}",
                            extra={
                                "extra_fields": {
                                    "hostname": current_host,
                                    "error": str(e),
                                    "timestamp": datetime.now(timezone.utc).isoformat()
                                }
                            }
                        )
                        raise RuntimeError(
                            f"DNS resolution failed for redirect target {current_host}: {e}. "
                            f"Cannot safely follow redirect without DNS validation."
                        )
                    except RuntimeError as e:
                        # Re-raise RuntimeError (e.g., from DNS rebinding detection)
                        raise
                    except Exception as e:
                        # Other resolution errors - fail closed for security
                        self.logger.error(
                            f"Error during DNS resolution for redirect target {current_host}: {e}",
                            extra={
                                "extra_fields": {
                                    "hostname": current_host,
                                    "error": str(e),
                                    "timestamp": datetime.now(timezone.utc).isoformat()
                                }
                            }
                        )
                        raise RuntimeError(
                            f"DNS resolution error for redirect target {current_host}: {e}. "
                            f"Cannot safely follow redirect without DNS validation."
                        )

                # Load current URL with per-redirect timeout
                try:
                    # Use redirect timeout for individual loads, overall timeout for the entire operation
                    per_redirect_timeout = min(REDIRECT_TIMEOUT, timeout - (redirect_loop_count * REDIRECT_TIMEOUT))
                    if per_redirect_timeout <= 0:
                        raise asyncio.TimeoutError("Overall timeout exceeded")

                    response = await asyncio.wait_for(
                        self.page.goto(current_url, wait_until="domcontentloaded"),
                        timeout=per_redirect_timeout
                    )

                    # Check if this was a redirect
                    if response and response.status in (301, 302, 303, 307, 308):
                        redirect_url = response.headers.get('location', '')
                        if redirect_url:
                            # Normalize redirect URL (handle relative URLs)
                            if not redirect_url.startswith(('http://', 'https://')):
                                # Relative URL - resolve against current URL
                                from urllib.parse import urljoin
                                redirect_url = urljoin(current_url, redirect_url)

                            redirect_loop_count += 1
                            self.redirect_count = redirect_loop_count
                            self.redirect_chain.append(redirect_url)

                            self.logger.info(
                                f"Redirect {redirect_loop_count}: {current_url} -> {redirect_url}",
                                extra={
                                    "extra_fields": {
                                        "redirect_count": redirect_loop_count,
                                        "from_url": current_url,
                                        "to_url": redirect_url,
                                        "timestamp": datetime.now(timezone.utc).isoformat()
                                    }
                                }
                            )

                            # Check if we've reached max redirects
                            if redirect_loop_count >= MAX_REDIRECTS:
                                self.logger.warning(
                                    f"Reached maximum redirects ({MAX_REDIRECTS}), stopping redirect following",
                                    extra={
                                        "extra_fields": {
                                            "redirect_count": redirect_loop_count,
                                            "max_redirects": MAX_REDIRECTS,
                                            "final_url": current_url,
                                            "timestamp": datetime.now(timezone.utc).isoformat()
                                        }
                                    }
                                )
                                self.suspicious_indicators.append(
                                    f"Excessive redirects: {redirect_loop_count} (max {MAX_REDIRECTS})"
                                )
                                # Stop following redirects, analyze current page
                                break
                            else:
                                # Continue to next redirect
                                current_url = redirect_url
                                continue
                    else:
                        # Not a redirect or no location header - we're done
                        break

                except asyncio.TimeoutError:
                    if redirect_loop_count > 0:
                        self.logger.warning(
                            f"Redirect {redirect_loop_count} to {current_url} exceeded {REDIRECT_TIMEOUT}s timeout",
                            extra={
                                "extra_fields": {
                                    "redirect_count": redirect_loop_count,
                                    "redirect_url": current_url,
                                    "timeout_seconds": REDIRECT_TIMEOUT,
                                    "timestamp": datetime.now(timezone.utc).isoformat()
                                }
                            }
                        )
                        # Per Requirement 8.5: analyze last successfully loaded page
                        # If we haven't loaded any page yet, this is a failure
                        if redirect_loop_count == 0:
                            self.logger.error(f"Initial URL load timed out: {url}")
                            return False
                        else:
                            # We have a page loaded, break and analyze it
                            break
                    else:
                        self.logger.error(f"URL load timed out after {timeout}s: {url}")
                        return False

        except Exception as e:
            # Re-raise RuntimeError for security violations
            if isinstance(e, RuntimeError):
                raise
            self.logger.error(f"Failed to load URL {url}: {e}")
            return False

        # If we successfully loaded a page (initial or after redirects)
        self.final_url = current_url
        self.logger.info(
            f"URL loaded successfully: {url} -> {self.final_url}",
            extra={
                "extra_fields": {
                    "initial_url": url,
                    "final_url": self.final_url,
                    "redirect_count": self.redirect_count,
                    "redirect_chain": self.redirect_chain,
                    "suspicious_indicators": self.suspicious_indicators,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            }
        )
        return True

    async def is_healthy(self) -> bool:
        """Check if the browser context is still alive and usable.

        Returns:
            True if browser and context are still connected, False otherwise
        """
        try:
            # Check if browser is still connected
            if not self.browser:
                return False

            # Handle both sync and async is_connected methods
            if inspect.iscoroutinefunction(self.browser.is_connected):
                connected = await self.browser.is_connected()
            else:
                connected = self.browser.is_connected()

            if not connected:
                return False

            # Check if context is still valid by attempting to get pages
            # This will raise if the context has been closed
            pages = await self.context.pages()
            return True
        except Exception as e:
            self.logger.warning(f"Sandbox health check failed: {str(e)}")
            return False

    async def is_responsive(self) -> bool:
        """Check if the sandbox is responsive within 15 seconds.

        Verifies that the sandbox can respond to commands within the
        responsiveness requirement (Requirement 8.2). This is a more
        comprehensive check than is_healthy() as it includes timeout behavior.

        Returns:
            True if sandbox is responsive within 15 seconds, False otherwise
        """
        try:
            # Use asyncio.wait_for to enforce 15-second timeout
            return await asyncio.wait_for(
                self.is_healthy(),
                timeout=RESPONSIVENESS_TIMEOUT
            )
        except asyncio.TimeoutError:
            self.logger.warning(
                f"Sandbox responsiveness check exceeded {RESPONSIVENESS_TIMEOUT}s"
            )
            return False
        except Exception as e:
            self.logger.warning(f"Sandbox responsiveness check failed: {str(e)}")
            return False


class SandboxManager:
    """Manages creation, lifecycle, and cleanup of isolated sandbox environments.

    This class handles the complete lifecycle of sandbox environments including
    initialization with timeout, graceful/forced termination, and reset between
    analyses.

    When running inside a Docker container for untrusted website analysis:
    - ContainerManager should validate the container before SandboxManager is used
    - SandboxManager.validate_isolation() checks if running in validated container
    - If validation fails, operations are blocked per Requirement 6.2

    Requirements: 1.1, 1.4, 1.5, 1.6, 6.1, 6.2, 6.6
    """

    def __init__(self, violation_monitor=None):
        """Initialize the SandboxManager.

        Args:
            violation_monitor: Optional ViolationMonitor for runtime violation detection
        """
        self.logger = get_logger(__name__)
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.current_sandbox: Optional[Sandbox] = None
        self._is_initialized = False
        self._lifecycle_lock = asyncio.Lock()  # Synchronize lifecycle operations
        self._isolation_validated = False  # Track if isolation is validated
        self._container_id: Optional[str] = None  # Container ID if running in Docker
        self.violation_monitor = violation_monitor

    def _detect_container_environment(self) -> bool:
        """Detect if running inside a container environment.

        Checks multiple indicators to reliably detect container execution:
        1. /.dockerenv file (strong Docker evidence, present in all Docker containers)
        2. cgroup v1 markers ("docker", "kubepods") in /proc/1/cgroup
        3. For cgroup v2, requires /.dockerenv as additional evidence

        IMPORTANT: Container detection is NOT security validation.
        This only determines if we're in a container environment.
        Security validation still requires _isolation_validated and _container_id.

        Returns:
            True if running in a container, False otherwise
        """
        # Check for Docker-specific file (strongest evidence)
        try:
            if os.path.exists('/.dockerenv'):
                self.logger.debug("Detected Docker environment via /.dockerenv")
                return True
        except Exception:
            pass

        # Check cgroup for container markers (cgroup v1)
        try:
            with open('/proc/1/cgroup', 'r') as f:
                cgroup_content = f.read()
                if 'docker' in cgroup_content or 'kubepods' in cgroup_content:
                    self.logger.debug("Detected container environment via cgroup v1 markers")
                    return True
        except (FileNotFoundError, IOError):
            pass

        # Not detected as container
        return False

    def validate_isolation(self) -> Tuple[bool, str]:
        """Validate sandbox isolation boundaries.

        Checks if the sandbox is running in a properly isolated environment.
        When running inside Docker, this validates that the container has been
        validated by ContainerManager. When running locally, this performs a
        basic check to warn that isolation is not enforced.

        Requirements: 6.1, 6.2

        Returns:
            Tuple of (is_valid: bool, error_message: str)
            - (True, "") if isolation is valid
            - (False, error_message) if isolation is invalid
        """
        # Check if running inside container
        try:
            is_in_container = self._detect_container_environment()
        except Exception as e:
            # Detection failure - fail closed
            self.logger.error(f"Container detection failed: {e}")
            is_in_container = False

        if is_in_container:
            # Running in container - check if it was validated
            if self._isolation_validated and self._container_id:
                self.logger.info(
                    f"Sandbox running in validated container: {self._container_id}",
                    extra={
                        "extra_fields": {
                            "container_id": self._container_id,
                            "isolation_validated": True,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                    }
                )
                return True, ""
            else:
                error_msg = (
                    "Sandbox is running in a Docker container but isolation "
                    "has not been validated. Use ContainerManager to create "
                    "and validate the container before using SandboxManager."
                )
                self.logger.error(
                    error_msg,
                    extra={
                        "extra_fields": {
                            "isolation_validated": False,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                    }
                )
                return False, error_msg
        else:
            # Running locally - warn about lack of isolation and fail-closed
            warning_msg = (
                "Sandbox is NOT running in a Docker container. "
                "Host-level isolation is NOT enforced. "
                "This configuration is for local development only. "
                "Use ContainerManager with Docker for untrusted website analysis."
            )
            self.logger.warning(
                warning_msg,
                extra={
                    "extra_fields": {
                        "isolation_validated": False,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )
            return False, warning_msg

    def set_isolation_validated(self, container_id: str) -> None:
        """Mark that the sandbox is running in a validated container.

        This should be called by ContainerManager after successful validation.

        Args:
            container_id: Docker container ID
        """
        self._isolation_validated = True
        self._container_id = container_id
        self.logger.info(
            f"Sandbox isolation marked as validated for container: {container_id}",
            extra={
                "extra_fields": {
                    "container_id": container_id,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            }
        )

    async def create_sandbox(self) -> Sandbox:
        """Create a new isolated sandbox environment with 15-second timeout.

        Creates a Playwright browser instance with an isolated browser context.
        If initialization fails within 15 seconds, raises an exception.
        Thread-safe: Uses lock to prevent concurrent lifecycle operations.

        Requirements: 1.1, 1.5

        Returns:
            Sandbox instance with isolated browser context

        Raises:
            TimeoutError: If sandbox initialization exceeds 15 seconds
            Exception: If sandbox initialization fails for other reasons
        """
        async with self._lifecycle_lock:
            # Check if existing sandbox is healthy before reusing
            if self._is_initialized and self.current_sandbox is not None:
                if await self.current_sandbox.is_healthy():
                    self.logger.info("Existing sandbox is healthy, reusing instance")
                    return self.current_sandbox
                else:
                    self.logger.warning("Existing sandbox is unhealthy, cleaning up and recreating")
                    await self._cleanup_partial_initialization()

            self.logger.info("Starting sandbox initialization")
            start_time = datetime.now(timezone.utc)

            try:
                # Create sandbox with timeout covering both creation and validation
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

                # Validate isolation after creation (Requirement 6.1)
                # This is synchronous and fast, but must complete within the overall timeout
                is_valid, error_msg = self.validate_isolation()
                if not is_valid:
                    self.logger.error(
                        f"Isolation validation failed after sandbox creation: {error_msg}",
                        extra={
                            "extra_fields": {
                                "initialization_time_seconds": initialization_time,
                                "validation_error": error_msg,
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            }
                        }
                    )
                    # Clean up and fail closed (no lock re-entry - already holding _lifecycle_lock)
                    await self._cleanup_partial_initialization()
                    raise RuntimeError(
                        f"Isolation validation failed: {error_msg}. "
                        f"Sandbox terminated per Requirement 6.2."
                    )

                return self.current_sandbox

            except asyncio.TimeoutError:
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                error_msg = f"Sandbox initialization failed: exceeded {INITIALIZATION_TIMEOUT}s timeout (took {elapsed:.2f}s)"
                self.logger.error(error_msg)
                # Clean up any partial initialization
                await self._cleanup_partial_initialization()
                raise TimeoutError(error_msg)

            except asyncio.CancelledError:
                self.logger.warning("Sandbox initialization cancelled")
                await self._cleanup_partial_initialization()
                raise

            except RuntimeError:
                # Let RuntimeError propagate (e.g., isolation validation failures)
                raise

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
            self.logger.info("Sandbox: Playwright starting")
            try:
                self.playwright = await asyncio.wait_for(
                    async_playwright().start(),
                    timeout=INITIALIZATION_TIMEOUT
                )
                self.logger.info("Sandbox: Playwright started")
            except asyncio.TimeoutError:
                self.logger.error(
                    f"Playwright initialization timed out after {INITIALIZATION_TIMEOUT}s",
                    extra={
                        "extra_fields": {
                            "timeout_seconds": INITIALIZATION_TIMEOUT,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                    }
                )
                raise RuntimeError(
                    f"Playwright initialization timed out after {INITIALIZATION_TIMEOUT}s. "
                    "Sandbox initialization failed per fail-closed behavior."
                )
            except Exception as e:
                self.logger.error(f"Playwright initialization failed: {e}")
                raise RuntimeError(
                    f"Playwright initialization failed: {e}. "
                    "Sandbox initialization failed per fail-closed behavior."
                )

        context = None
        if self.browser is None or not (hasattr(self.browser, 'is_connected') and self.browser.is_connected()):
            self.logger.info("Sandbox: browser starting")
            try:
                context = await asyncio.wait_for(
                    self.playwright.chromium.launch_persistent_context(
                        user_data_dir=tempfile.mkdtemp(prefix='fakewebsite-chromium-'),
                        headless=True,
                        args=[
                            '--no-sandbox',
                            '--disable-setuid-sandbox',
                            '--disable-dev-shm-usage',
                            '--disable-gpu',
                            '--disable-download',
                            '--disable-background-networking',
                            '--disable-background-timer-throttling',
                            '--disable-backgrounding-occluded-windows',
                            '--disable-breakpad',
                            '--disable-component-extensions-with-background-pages',
                            '--disable-extensions',
                            '--disable-features=TranslateUI',
                            '--disable-ipc-flooding-protection',
                            '--disable-renderer-backgrounding',
                            '--disable-sync',
                            '--disable-default-apps',
                            '--no-first-run',
                            '--no-default-browser-check',
                            '--metrics-recording-only',
                            '--enable-automation',
                        ],
                        ignore_https_errors=True,
                        java_script_enabled=True,
                        accept_downloads=False,
                    ),
                    timeout=INITIALIZATION_TIMEOUT
                )
                self.browser = getattr(context, '_impl_obj', None) and getattr(context._impl_obj, '_browser', None) or context
                self.logger.info("Sandbox: browser started")
            except asyncio.TimeoutError:
                self.logger.error(f"Browser launch timed out after {INITIALIZATION_TIMEOUT}s")
                raise RuntimeError(
                    f"Browser launch timed out after {INITIALIZATION_TIMEOUT}s. "
                    "Sandbox initialization failed per fail-closed behavior."
                )
            except Exception as e:
                self.logger.error(f"Browser launch failed: {e}")
                raise RuntimeError(
                    f"Browser launch failed: {e}. "
                    "Sandbox initialization failed per fail-closed behavior."
                )
        else:
            try:
                context = await self.browser.new_context(
                    ignore_https_errors=True,
                    java_script_enabled=True,
                    accept_downloads=False,
                )
            except Exception:
                self.browser = None
                return await self._create_sandbox_internal()

        return Sandbox(self.browser, context, self, self.violation_monitor)

    async def _cleanup_partial_initialization(self) -> None:
        """Clean up partial initialization state after failure.

        Safely shuts down all resources and shields from cancellation interruptions.
        State is guaranteed to be consistent after this method returns.
        """
        self.logger.info("Sandbox: cleanup started")

        if self.current_sandbox:
            sb = self.current_sandbox
            self.current_sandbox = None
            try:
                await asyncio.shield(sb.close())
            except Exception as e:
                self.logger.warning(f"Error closing current sandbox during cleanup: {e}")

        if self.browser:
            b = self.browser
            self.browser = None
            try:
                await asyncio.shield(b.close())
            except Exception as e:
                self.logger.warning(f"Error closing browser during cleanup: {e}")

        if self.playwright:
            pw = self.playwright
            self.playwright = None
            try:
                await asyncio.shield(pw.stop())
            except Exception as e:
                self.logger.warning(f"Error stopping Playwright during cleanup: {e}")
            finally:
                # Allow Playwright transport background tasks to settle on the event loop
                try:
                    await asyncio.sleep(0.05)
                except Exception:
                    pass

        self._is_initialized = False
        self.logger.info("Sandbox: cleanup completed")

    async def terminate_sandbox(self, sandbox_or_force: Any = None, force: bool = False) -> None:
        """Terminate the sandbox with graceful or forced shutdown.

        Attempts graceful shutdown first, then forced termination if needed.
        Must complete within 10 seconds per requirements.
        Thread-safe: Uses lock to prevent concurrent lifecycle operations.

        Requirements: 1.4, 1.6

        Args:
            sandbox_or_force: Optional Sandbox instance or boolean force flag
            force: If True, skip graceful shutdown and force terminate immediately
        """
        actual_force = force
        if isinstance(sandbox_or_force, bool):
            actual_force = sandbox_or_force

        async with self._lifecycle_lock:
            if self.current_sandbox is None and self.browser is None and self.playwright is None:
                self.logger.debug("No sandbox resources to terminate")
                return

            self.logger.info(f"Terminating sandbox (force={actual_force})")
            start_time = datetime.now(timezone.utc)

            try:
                if actual_force:
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
                    extra={"extra_fields": {"termination_time_seconds": termination_time, "forced": actual_force}}
                )

            except asyncio.CancelledError:
                self.logger.warning("Sandbox termination cancelled, forcing cleanup")
                await self._force_terminate()
                raise

            except Exception as e:
                self.logger.error(f"Error during sandbox termination: {str(e)}", exc_info=True)
                # Ensure cleanup happens even on error
                await self._force_terminate()
                raise

    async def _graceful_terminate(self) -> None:
        """Perform graceful shutdown of sandbox resources."""
        try:
            if self.current_sandbox:
                await self.current_sandbox.close()
        except asyncio.CancelledError:
            self.logger.warning("Graceful termination cancelled, ensuring state consistency")
            self.current_sandbox = None
            self.browser = None
            self._is_initialized = False
            raise
        self.current_sandbox = None
        self.browser = None
        if self.playwright:
            pw = self.playwright
            self.playwright = None
            try:
                await asyncio.wait_for(asyncio.shield(pw.stop()), timeout=2.0)
            except Exception as e:
                self.logger.warning(f"Error stopping Playwright during graceful termination: {e}")
        self._is_initialized = False

    async def _force_terminate(self) -> None:
        """Force terminate all sandbox resources immediately.

        Logs forced termination event as required by Requirement 1.6.
        Handles asyncio.CancelledError to ensure cleanup completes.
        """
        self.logger.warning("Forcing sandbox termination")

        if self.current_sandbox:
            sb = self.current_sandbox
            self.current_sandbox = None
            try:
                await asyncio.shield(sb.close())
            except Exception as e:
                self.logger.warning(f"Error closing sandbox during force termination: {e}")

        if self.browser:
            b = self.browser
            self.browser = None
            try:
                await asyncio.shield(b.close())
            except Exception as e:
                self.logger.warning(f"Error closing browser during force termination: {e}")

        if self.playwright:
            pw = self.playwright
            self.playwright = None
            try:
                await asyncio.shield(pw.stop())
            except Exception as e:
                self.logger.warning(f"Error stopping Playwright during force termination: {e}")
            finally:
                # Allow Playwright transport background tasks to settle on the event loop
                try:
                    await asyncio.sleep(0.05)
                except Exception:
                    pass

        self._is_initialized = False
        self.logger.warning("Forced termination complete")

    async def reset_sandbox(self) -> None:
        """Reset the sandbox environment between analyses.

        Deletes temporary files, terminates processes, and reinitializes
        network isolation settings. Creates a fresh sandbox for the next analysis.
        Revalidates isolation before reuse (Requirement 6.6).

        Thread-safe: Uses lock to prevent concurrent lifecycle operations.

        Requirement: 6.6
        """
        async with self._lifecycle_lock:
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
            except asyncio.CancelledError:
                self.logger.warning("Sandbox reset cancelled during creation")
                raise
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
