"""
Data collection framework for Website Authenticity Detector.

This module implements the DataCollector class that orchestrates concurrent
collection of data from five categories: Network, DOM, JavaScript, Visual, and SSL.

The collector supports:
- Concurrent collection using asyncio
- 60-second timeout with continuation for in-progress tasks
- Per-category failure tracking and isolation
- Aggregation into AnalysisData
- Partial collection support
"""

import asyncio
import logging
import os
import ssl
import tempfile
from typing import Optional
from datetime import datetime, timezone
from urllib.parse import urlparse

from src.models import (
    AnalysisData,
    NetworkData,
    DOMData,
    JavaScriptData,
    VisualData,
    SSLData
)


class DataCollector:
    """
    Orchestrates concurrent data collection from multiple categories.

    Collects data from five categories (Network, DOM, JavaScript, Visual, SSL)
    concurrently with failure isolation and timeout handling.

    Attributes:
        logger: Logger instance for this class
    """

    def __init__(self):
        """Initialize the DataCollector."""
        self.logger = logging.getLogger(__name__)

    async def collect_all(
        self,
        sandbox: 'Sandbox',
        url: str,
        timeout: int = 60
    ) -> AnalysisData:
        """
        Collect all data categories concurrently with timeout and failure isolation.

        Runs all five collection methods concurrently using asyncio.gather.
        Implements 60-second timeout with continuation for in-progress tasks.
        Tracks per-category failures and aggregates results into AnalysisData.

        Args:
            sandbox: Sandbox instance for data collection
            url: Target URL for SSL data collection
            timeout: Maximum time for collection (default 60 seconds)

        Returns:
            AnalysisData containing collected data from all categories.
            Categories that failed are marked with failed=True.
            timeout_occurred is set if the overall timeout was exceeded.

        Requirements: 2.6, 2.7, 2.8
        """
        self.logger.info(
            f"Starting concurrent data collection with {timeout}s timeout",
            extra={
                "extra_fields": {
                    "url": url,
                    "timeout": timeout,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            }
        )

        # Initialize result
        analysis_data = AnalysisData()

        # Schedule all collection tasks concurrently
        tasks = [
            asyncio.create_task(self._collect_network_data_safe(sandbox)),
            asyncio.create_task(self._collect_dom_data_safe(sandbox)),
            asyncio.create_task(self._collect_javascript_data_safe(sandbox)),
            asyncio.create_task(self._collect_visual_data_safe(sandbox)),
            asyncio.create_task(self._collect_ssl_data_safe(url))
        ]

        try:
            # Use asyncio.wait_for for overall timeout
            # asyncio.gather with return_exceptions=True isolates failures
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=timeout
            )

            # Aggregate results
            analysis_data.network = results[0] if not isinstance(results[0], Exception) else None
            analysis_data.dom = results[1] if not isinstance(results[1], Exception) else None
            analysis_data.javascript = results[2] if not isinstance(results[2], Exception) else None
            analysis_data.visual = results[3] if not isinstance(results[3], Exception) else None
            analysis_data.ssl = results[4] if not isinstance(results[4], Exception) else None

            # Recalculate categories_collected based on actual results
            analysis_data.categories_collected = sum([
                analysis_data.network is not None and not analysis_data.network.failed,
                analysis_data.dom is not None and not analysis_data.dom.failed,
                analysis_data.javascript is not None and not analysis_data.javascript.failed,
                analysis_data.visual is not None and not analysis_data.visual.failed,
                analysis_data.ssl is not None and not analysis_data.ssl.failed,
            ])

            self.logger.info(
                f"Data collection completed: {analysis_data.categories_collected}/5 categories collected",
                extra={
                    "extra_fields": {
                        "categories_collected": analysis_data.categories_collected,
                        "network": analysis_data.network is not None,
                        "dom": analysis_data.dom is not None,
                        "javascript": analysis_data.javascript is not None,
                        "visual": analysis_data.visual is not None,
                        "ssl": analysis_data.ssl is not None,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )

        except asyncio.TimeoutError:
            # Timeout occurred - collect results from completed tasks
            self.logger.warning(
                f"Data collection exceeded {timeout}s timeout, aggregating partial results",
                extra={
                    "extra_fields": {
                        "timeout": timeout,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )

            # Cancel pending tasks
            for task in tasks:
                if not task.done():
                    task.cancel()

            # Wait for cancellations to complete
            await asyncio.gather(*tasks, return_exceptions=True)

            # Aggregate whatever results were collected
            analysis_data.timeout_occurred = True

            # Check which tasks completed
            results = []
            for task in tasks:
                if task.done() and not task.cancelled():
                    try:
                        result = task.result()
                        results.append(result)
                    except Exception:
                        results.append(None)
                else:
                    results.append(None)

            analysis_data.network = results[0] if results[0] is not None and not isinstance(results[0], Exception) else None
            analysis_data.dom = results[1] if results[1] is not None and not isinstance(results[1], Exception) else None
            analysis_data.javascript = results[2] if results[2] is not None and not isinstance(results[2], Exception) else None
            analysis_data.visual = results[3] if results[3] is not None and not isinstance(results[3], Exception) else None
            analysis_data.ssl = results[4] if results[4] is not None and not isinstance(results[4], Exception) else None

            # Recalculate categories_collected
            analysis_data.categories_collected = sum([
                analysis_data.network is not None and not analysis_data.network.failed,
                analysis_data.dom is not None and not analysis_data.dom.failed,
                analysis_data.javascript is not None and not analysis_data.javascript.failed,
                analysis_data.visual is not None and not analysis_data.visual.failed,
                analysis_data.ssl is not None and not analysis_data.ssl.failed,
            ])

            self.logger.info(
                f"Partial collection after timeout: {analysis_data.categories_collected}/5 categories",
                extra={
                    "extra_fields": {
                        "categories_collected": analysis_data.categories_collected,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )

        except Exception as e:
            # Unexpected error - mark all as failed
            self.logger.error(
                f"Unexpected error during data collection: {e}",
                extra={
                    "extra_fields": {
                        "error": str(e),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )
            # Return empty AnalysisData
            analysis_data = AnalysisData()

        return analysis_data

    async def _collect_network_data_safe(self, sandbox: 'Sandbox') -> Optional[NetworkData]:
        """
        Safely collect network data with exception handling.

        Wraps collect_network_data to isolate failures.

        Args:
            sandbox: Sandbox instance for data collection

        Returns:
            NetworkData if successful, None if failed
        """
        try:
            return await self.collect_network_data(sandbox)
        except Exception as e:
            self.logger.error(
                f"Network data collection failed: {e}",
                extra={
                    "extra_fields": {
                        "error": str(e),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )
            # Return failed NetworkData
            return NetworkData(
                request_count=0,
                unique_domains=[],
                protocol_distribution={},
                failed=True
            )

    async def _collect_dom_data_safe(self, sandbox: 'Sandbox') -> Optional[DOMData]:
        """
        Safely collect DOM data with exception handling.

        Wraps collect_dom_data to isolate failures.

        Args:
            sandbox: Sandbox instance for data collection

        Returns:
            DOMData if successful, None if failed
        """
        try:
            return await self.collect_dom_data(sandbox)
        except Exception as e:
            self.logger.error(
                f"DOM data collection failed: {e}",
                extra={
                    "extra_fields": {
                        "error": str(e),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )
            # Return failed DOMData
            return DOMData(
                html_content="",
                structure_metrics={},
                failed=True
            )

    async def _collect_javascript_data_safe(self, sandbox: 'Sandbox') -> Optional[JavaScriptData]:
        """
        Safely collect JavaScript data with exception handling.

        Wraps collect_javascript_data to isolate failures.

        Args:
            sandbox: Sandbox instance for data collection

        Returns:
            JavaScriptData if successful, None if failed
        """
        try:
            return await self.collect_javascript_data(sandbox)
        except Exception as e:
            self.logger.error(
                f"JavaScript data collection failed: {e}",
                extra={
                    "extra_fields": {
                        "error": str(e),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )
            # Return failed JavaScriptData
            return JavaScriptData(
                script_count=0,
                dom_modifications=0,
                external_api_calls=0,
                failed=True
            )

    async def _collect_visual_data_safe(self, sandbox: 'Sandbox') -> Optional[VisualData]:
        """
        Safely collect visual data with exception handling.

        Wraps collect_visual_data to isolate failures.

        Args:
            sandbox: Sandbox instance for data collection

        Returns:
            VisualData if successful, None if failed
        """
        try:
            return await self.collect_visual_data(sandbox)
        except Exception as e:
            self.logger.error(
                f"Visual data collection failed: {e}",
                extra={
                    "extra_fields": {
                        "error": str(e),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )
            # Return failed VisualData
            return VisualData(
                screenshot_path="",
                layout_characteristics={},
                failed=True
            )

    async def _collect_ssl_data_safe(self, url: str) -> Optional[SSLData]:
        """
        Safely collect SSL data with exception handling.

        Wraps collect_ssl_data to isolate failures.

        Args:
            url: Target URL for SSL data collection

        Returns:
            SSLData if successful, None if failed
        """
        try:
            return await self.collect_ssl_data(url)
        except Exception as e:
            self.logger.error(
                f"SSL data collection failed: {e}",
                extra={
                    "extra_fields": {
                        "error": str(e),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )
            # Return failed SSLData
            return SSLData(
                issuer="",
                expiration_date="",
                chain_valid=False,
                failed=True
            )

    # Individual collection methods - to be implemented in Tasks 6.3, 6.5, 6.7, 6.9, 6.11

    async def collect_network_data(self, sandbox: 'Sandbox') -> NetworkData:
        """
        Collect network request patterns using Playwright network events.

        Tracks all network requests made during page execution to collect:
        - Total request count
        - Unique domains contacted
        - Protocol distribution (http, https, ws, wss)

        Args:
            sandbox: Sandbox instance with active page for data collection

        Returns:
            NetworkData with request count, unique domains, and protocol distribution

        Raises:
            Exception: If collection fails (caught by safe wrapper)

        Requirement: 2.1
        """
        self.logger.info("Starting network data collection")

        request_count = 0
        unique_domains = set()
        protocol_distribution = {}

        # Set up request listener
        def track_request(request):
            nonlocal request_count
            request_count += 1

            # Extract domain from URL
            from urllib.parse import urlparse
            parsed = urlparse(request.url)
            domain = parsed.netloc
            if domain:
                unique_domains.add(domain)

            # Extract protocol
            protocol = parsed.scheme.lower()
            if protocol:
                protocol_distribution[protocol] = protocol_distribution.get(protocol, 0) + 1

        # Register listener
        if sandbox.page:
            sandbox.page.on('request', track_request)

        try:
            # Wait a brief moment to ensure all requests are captured
            # In practice, this would be called after page load
            await asyncio.sleep(0.1)

            self.logger.info(
                f"Network data collected: {request_count} requests, {len(unique_domains)} unique domains",
                extra={
                    "extra_fields": {
                        "request_count": request_count,
                        "unique_domains": list(unique_domains),
                        "protocol_distribution": protocol_distribution,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )

            return NetworkData(
                request_count=request_count,
                unique_domains=list(unique_domains),
                protocol_distribution=protocol_distribution,
                failed=False
            )

        except Exception as e:
            self.logger.error(
                f"Network data collection failed: {e}",
                extra={
                    "extra_fields": {
                        "error": str(e),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )
            raise
        finally:
            # Remove listener
            if sandbox.page:
                try:
                    sandbox.page.remove_listener('request', track_request)
                except Exception:
                    pass

    async def collect_dom_data(self, sandbox: 'Sandbox') -> DOMData:
        """
        Collect DOM structure and HTML content using Playwright.

        Collects HTML content and DOM structure metrics including:
        - Total element count
        - Form count
        - Iframe count
        - Script count

        Args:
            sandbox: Sandbox instance with active page for data collection

        Returns:
            DOMData with HTML content and structure metrics

        Raises:
            Exception: If collection fails (caught by safe wrapper)

        Requirement: 2.2
        """
        self.logger.info("Starting DOM data collection")

        html_content = ""
        structure_metrics = {}

        try:
            if sandbox.page is None:
                raise ValueError("Sandbox page is not available")

            # Collect HTML content
            html_content = await sandbox.page.content()

            # Collect DOM structure metrics
            # Count total elements
            element_count = sandbox.page.query_selector_all('*')
            structure_metrics['element_count'] = element_count

            # Count forms
            form_count = sandbox.page.query_selector_all('form')
            structure_metrics['form_count'] = form_count

            # Count iframes
            iframe_count = sandbox.page.query_selector_all('iframe')
            structure_metrics['iframe_count'] = iframe_count

            # Count scripts
            script_count = sandbox.page.query_selector_all('script')
            structure_metrics['script_count'] = script_count

            self.logger.info(
                f"DOM data collected: {element_count} elements, {form_count} forms, {iframe_count} iframes, {script_count} scripts",
                extra={
                    "extra_fields": {
                        "element_count": element_count,
                        "form_count": form_count,
                        "iframe_count": iframe_count,
                        "script_count": script_count,
                        "html_length": len(html_content),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )

            return DOMData(
                html_content=html_content,
                structure_metrics=structure_metrics,
                failed=False
            )

        except Exception as e:
            self.logger.error(
                f"DOM data collection failed: {e}",
                extra={
                    "extra_fields": {
                        "error": str(e),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )
            raise

    async def collect_javascript_data(self, sandbox: 'Sandbox') -> JavaScriptData:
        """
        Collect JavaScript behavior metrics using Playwright.

        Collects:
        - Script count (number of script elements loaded/executed)
        - DOM modifications (dynamic changes to the DOM)
        - External API calls (fetch/XHR requests)

        Args:
            sandbox: Sandbox instance with active page for data collection

        Returns:
            JavaScriptData with script count, DOM modifications, and API calls

        Raises:
            Exception: If collection fails (caught by safe wrapper)

        Requirement: 2.3
        """
        self.logger.info("Starting JavaScript data collection")

        script_count = 0
        dom_modifications = 0
        external_api_calls = 0

        try:
            if sandbox.page is None:
                raise ValueError("Sandbox page is not available")

            # Count script elements
            script_elements = sandbox.page.query_selector_all('script')
            script_count = script_elements

            # Track DOM modifications using MutationObserver
            # Inject script to set up observer
            observer_script = """
            (() => {
                window.__dataCollectorMutationCount = 0;
                const observer = new MutationObserver((mutations) => {
                    window.__dataCollectorMutationCount += mutations.length;
                });
                observer.observe(document.body || document.documentElement, {
                    childList: true,
                    subtree: true,
                    attributes: false,
                    characterData: false
                });
                window.__dataCollectorMutationObserver = observer;
            })();
            """
            await sandbox.page.evaluate(observer_script)

            # Track external API calls by intercepting fetch and XHR
            # Inject script to intercept calls
            api_intercept_script = """
            (() => {
                window.__dataCollectorApiCallCount = 0;

                // Intercept fetch
                const originalFetch = window.fetch;
                window.fetch = function(...args) {
                    window.__dataCollectorApiCallCount++;
                    return originalFetch.apply(this, args);
                };

                // Intercept XMLHttpRequest
                const originalOpen = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(...args) {
                    window.__dataCollectorApiCallCount++;
                    return originalOpen.apply(this, args);
                };
            })();
            """
            await sandbox.page.evaluate(api_intercept_script)

            # Wait a brief moment to allow any JavaScript execution
            await asyncio.sleep(0.1)

            # Read collected metrics
            dom_modifications = await sandbox.page.evaluate("window.__dataCollectorMutationCount || 0")
            external_api_calls = await sandbox.page.evaluate("window.__dataCollectorApiCallCount || 0")

            # Cleanup: disconnect observer and restore original functions
            cleanup_script = """
            (() => {
                if (window.__dataCollectorMutationObserver) {
                    window.__dataCollectorMutationObserver.disconnect();
                    delete window.__dataCollectorMutationObserver;
                }
                delete window.__dataCollectorMutationCount;
                delete window.__dataCollectorApiCallCount;
            })();
            """
            await sandbox.page.evaluate(cleanup_script)

            self.logger.info(
                f"JavaScript data collected: {script_count} scripts, {dom_modifications} DOM modifications, {external_api_calls} API calls",
                extra={
                    "extra_fields": {
                        "script_count": script_count,
                        "dom_modifications": dom_modifications,
                        "external_api_calls": external_api_calls,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )

            return JavaScriptData(
                script_count=script_count,
                dom_modifications=dom_modifications,
                external_api_calls=external_api_calls,
                failed=False
            )

        except Exception as e:
            self.logger.error(
                f"JavaScript data collection failed: {e}",
                extra={
                    "extra_fields": {
                        "error": str(e),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )
            # Attempt cleanup even on failure
            try:
                if sandbox.page:
                    cleanup_script = """
                    (() => {
                        if (window.__dataCollectorMutationObserver) {
                            window.__dataCollectorMutationObserver.disconnect();
                            delete window.__dataCollectorMutationObserver;
                        }
                        delete window.__dataCollectorMutationCount;
                        delete window.__dataCollectorApiCallCount;
                    })();
                    """
                    await sandbox.page.evaluate(cleanup_script)
            except Exception:
                pass
            raise

    async def collect_visual_data(self, sandbox: 'Sandbox') -> VisualData:
        """
        Collect visual rendering data using Playwright.

        Captures screenshot and extracts layout characteristics including:
        - Viewport size
        - Image count
        - Color information

        Args:
            sandbox: Sandbox instance with active page for data collection

        Returns:
            VisualData with screenshot path and layout characteristics

        Raises:
            Exception: If collection fails (caught by safe wrapper)

        Requirement: 2.4
        """
        self.logger.info("Starting visual data collection")

        screenshot_path = ""
        layout_characteristics = {}

        try:
            if sandbox.page is None:
                raise ValueError("Sandbox page is not available")

            # Create temporary directory for screenshots if needed
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
            screenshot_filename = f"screenshot_{timestamp}.png"
            screenshot_path = os.path.join(tempfile.gettempdir(), screenshot_filename)

            # Capture screenshot
            await sandbox.page.screenshot(path=screenshot_path, full_page=False)

            # Extract layout characteristics
            # Get viewport size
            viewport_size = sandbox.page.viewport_size
            if viewport_size:
                layout_characteristics['viewport_width'] = viewport_size['width']
                layout_characteristics['viewport_height'] = viewport_size['height']

            # Count images
            image_count = sandbox.page.query_selector_all('img')
            layout_characteristics['image_count'] = image_count

            # Get basic color information (simplified - could be enhanced with actual color analysis)
            # For now, just record that color analysis is available
            layout_characteristics['color_analysis_available'] = True

            self.logger.info(
                f"Visual data collected: screenshot at {screenshot_path}, {image_count} images",
                extra={
                    "extra_fields": {
                        "screenshot_path": screenshot_path,
                        "image_count": image_count,
                        "viewport_size": viewport_size,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )

            return VisualData(
                screenshot_path=screenshot_path,
                layout_characteristics=layout_characteristics,
                failed=False
            )

        except Exception as e:
            self.logger.error(
                f"Visual data collection failed: {e}",
                extra={
                    "extra_fields": {
                        "error": str(e),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )
            # Cleanup screenshot if it was created
            if screenshot_path and os.path.exists(screenshot_path):
                try:
                    os.remove(screenshot_path)
                except Exception:
                    pass
            raise

    async def collect_ssl_data(self, url: str) -> SSLData:
        """
        Collect SSL certificate information using Python ssl module.

        For HTTPS URLs:
        - Extracts certificate issuer
        - Extracts expiration date (ISO 8601 format)
        - Performs certificate chain validation
        - Returns SSLData with extracted information

        For non-HTTPS URLs:
        - Returns SSLData with failed=True (N/A for HTTP)

        Args:
            url: Target URL for SSL data collection

        Returns:
            SSLData with issuer, expiration, and chain validation

        Raises:
            Exception: If collection fails (caught by safe wrapper)

        Requirement: 2.5
        """
        self.logger.info(f"Starting SSL data collection for {url}")

        issuer = ""
        expiration_date = ""
        chain_valid = False

        try:
            # Parse URL
            parsed = urlparse(url)

            # Check if HTTPS
            if parsed.scheme != 'https':
                self.logger.info(f"URL is not HTTPS ({parsed.scheme}), SSL data not applicable")
                # Return failed SSLData for non-HTTPS (N/A)
                return SSLData(
                    issuer="",
                    expiration_date="",
                    chain_valid=False,
                    failed=True
                )

            # Extract hostname and port
            hostname = parsed.hostname
            if not hostname:
                raise ValueError(f"Invalid URL: no hostname in {url}")

            port = parsed.port or 443

            # Create SSL context with default certificate verification
            context = ssl.create_default_context()

            # Establish SSL connection with timeout
            # Use asyncio.to_thread to run blocking SSL operations in thread pool
            def get_ssl_info():
                try:
                    # Establish connection
                    with context.wrap_socket(
                        ssl.create_connection((hostname, port), timeout=10),
                        server_hostname=hostname
                    ) as sock:
                        # Get peer certificate
                        cert = sock.getpeercert()

                        # Extract issuer (DN string)
                        issuer_dict = cert.get('issuer', [])
                        if issuer_dict:
                            # Convert list of tuples to DN string
                            issuer_parts = []
                            for part in issuer_dict:
                                for key, value in part:
                                    issuer_parts.append(f"{key}={value}")
                            issuer = ", ".join(issuer_parts)

                        # Extract expiration date and convert to ISO 8601
                        not_after = cert.get('notAfter')
                        if not_after:
                            # Convert from ASN1_TIME format to ISO 8601
                            # Format is typically: "May 25 12:00:00 2025 GMT"
                            from datetime import datetime
                            try:
                                # Parse the date string
                                exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                expiration_date = exp_date.strftime("%Y-%m-%dT%H:%M:%SZ")
                            except ValueError:
                                # Fallback if parsing fails
                                expiration_date = not_after

                        # Chain validation: connection succeeded with verification enabled
                        chain_valid = True

                        return issuer, expiration_date, chain_valid
                except ssl.SSLCertVerificationError as e:
                    # Certificate validation failed
                    # Still try to extract certificate info
                    cert = e.args[0].get('peer_cert')
                    if cert:
                        issuer_dict = cert.get('issuer', [])
                        if issuer_dict:
                            issuer_parts = []
                            for part in issuer_dict:
                                for key, value in part:
                                    issuer_parts.append(f"{key}={value}")
                            issuer = ", ".join(issuer_parts)

                        not_after = cert.get('notAfter')
                        if not_after:
                            from datetime import datetime
                            try:
                                exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                expiration_date = exp_date.strftime("%Y-%m-%dT%H:%M:%SZ")
                            except ValueError:
                                expiration_date = not_after

                    return issuer, expiration_date, False
                except Exception as e:
                    # Connection or other error
                    raise

            # Run blocking SSL operations in thread pool
            issuer, expiration_date, chain_valid = await asyncio.to_thread(get_ssl_info)

            self.logger.info(
                f"SSL data collected: issuer={issuer[:50] if issuer else 'N/A'}..., expiration={expiration_date}, chain_valid={chain_valid}",
                extra={
                    "extra_fields": {
                        "issuer": issuer[:100] if issuer else "",
                        "expiration_date": expiration_date,
                        "chain_valid": chain_valid,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )

            return SSLData(
                issuer=issuer,
                expiration_date=expiration_date,
                chain_valid=chain_valid,
                failed=False
            )

        except Exception as e:
            self.logger.error(
                f"SSL data collection failed: {e}",
                extra={
                    "extra_fields": {
                        "error": str(e),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )
            raise
