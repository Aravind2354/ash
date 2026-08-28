"""Unit tests for SSL certificate data collection (Task 6.11).

Tests the collect_ssl_data method for:
- HTTPS certificate successfully collected
- Issuer correctly extracted
- Expiration correctly extracted
- Expiration formatted as ISO 8601
- Valid certificate chain → chain_valid=True
- Invalid/self-signed certificate → chain_valid=False
- Expired certificate → appropriate validation result
- Hostname mismatch → chain_valid=False
- Connection failure
- Timeout
- HTTP/non-HTTPS N/A behavior
- SSLData.failed behavior
- Integration with DataCollector.collect_all()
- SSL failure does not cancel other categories
- Partial AnalysisData remains available

Validates Requirement: 2.5
"""

import pytest
import asyncio
import ssl
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime, timezone

# Add src to path for imports
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.data_collector import DataCollector
from src.models import SSLData, AnalysisData


@pytest.mark.asyncio
class TestSSLDataCollection:
    """Test SSL data collection functionality."""

    @pytest.fixture
    def collector(self):
        """Create a DataCollector instance."""
        return DataCollector()

    async def test_https_certificate_success(self, collector):
        """Test successful HTTPS certificate collection."""
        url = "https://example.com"

        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = ("CN=Example CA, O=Example Inc, C=US", "2025-12-31T23:59:59Z", True)
            result = await collector.collect_ssl_data(url)

        assert isinstance(result, SSLData)
        assert result.issuer == "CN=Example CA, O=Example Inc, C=US"
        assert result.expiration_date == "2025-12-31T23:59:59Z"
        assert result.chain_valid is True
        assert result.failed is False

    async def test_issuer_extraction(self, collector):
        """Test that issuer is correctly extracted."""
        url = "https://example.com"

        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = ("CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US", "2025-12-31T23:59:59Z", True)
            result = await collector.collect_ssl_data(url)

        assert isinstance(result, SSLData)
        assert "Let's Encrypt" in result.issuer
        assert result.failed is False

    async def test_expiration_extraction(self, collector):
        """Test that expiration date is correctly extracted."""
        url = "https://example.com"

        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = ("CN=Example CA", "2025-06-30T12:00:00Z", True)
            result = await collector.collect_ssl_data(url)

        assert isinstance(result, SSLData)
        assert result.expiration_date == "2025-06-30T12:00:00Z"
        assert result.failed is False

    async def test_expiration_iso8601_format(self, collector):
        """Test that expiration is in ISO 8601 format."""
        url = "https://example.com"

        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = ("CN=Example CA", "2025-12-31T23:59:59Z", True)
            result = await collector.collect_ssl_data(url)

        assert isinstance(result, SSLData)
        # Verify ISO 8601 format (basic check)
        assert 'T' in result.expiration_date
        assert 'Z' in result.expiration_date or '+' in result.expiration_date

    async def test_valid_certificate_chain(self, collector):
        """Test that valid certificate chain sets chain_valid=True."""
        url = "https://example.com"

        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = ("CN=Example CA", "2025-12-31T23:59:59Z", True)
            result = await collector.collect_ssl_data(url)

        assert isinstance(result, SSLData)
        assert result.chain_valid is True
        assert result.failed is False

    async def test_invalid_self_signed_certificate(self, collector):
        """Test that invalid/self-signed certificate sets chain_valid=False."""
        url = "https://example.com"

        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = ("CN=Self-Signed", "2025-12-31T23:59:59Z", False)
            result = await collector.collect_ssl_data(url)

        assert isinstance(result, SSLData)
        assert result.chain_valid is False
        # Failed should still be False because we collected data, even if invalid
        assert result.failed is False

    async def test_expired_certificate(self, collector):
        """Test that expired certificate is handled correctly."""
        url = "https://example.com"

        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = ("CN=Example CA", "2020-01-01T00:00:00Z", False)
            result = await collector.collect_ssl_data(url)

        assert isinstance(result, SSLData)
        assert result.chain_valid is False
        assert result.expiration_date == "2020-01-01T00:00:00Z"

    async def test_hostname_mismatch(self, collector):
        """Test that hostname mismatch sets chain_valid=False."""
        url = "https://example.com"

        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = ("CN=Wrong Host", "2025-12-31T23:59:59Z", False)
            result = await collector.collect_ssl_data(url)

        assert isinstance(result, SSLData)
        assert result.chain_valid is False

    async def test_connection_failure(self, collector):
        """Test that connection failure is handled."""
        url = "https://example.com"

        with patch('asyncio.to_thread', side_effect=Exception("Connection refused")):
            with pytest.raises(Exception):
                await collector.collect_ssl_data(url)

    async def test_timeout(self, collector):
        """Test that timeout is handled."""
        url = "https://example.com"

        with patch('asyncio.to_thread', side_effect=asyncio.TimeoutError("Timeout")):
            with pytest.raises(Exception):
                await collector.collect_ssl_data(url)

    async def test_http_non_https_na_behavior(self, collector):
        """Test that HTTP/non-HTTPS URLs return N/A SSL data."""
        url = "http://example.com"

        result = await collector.collect_ssl_data(url)

        assert isinstance(result, SSLData)
        assert result.issuer == ""
        assert result.expiration_date == ""
        assert result.chain_valid is False
        assert result.failed is True

    async def test_failed_true_behavior(self, collector):
        """Test that failed=True is set on error through safe wrapper."""
        url = "https://example.com"

        with patch('asyncio.to_thread', side_effect=Exception("Connection failed")):
            # Call through safe wrapper
            result = await collector._collect_ssl_data_safe(url)

        assert isinstance(result, SSLData)
        assert result.failed is True
        assert result.issuer == ""
        assert result.expiration_date == ""
        assert result.chain_valid is False

    async def test_invalid_url_no_hostname(self, collector):
        """Test behavior when URL has no hostname."""
        url = "https://"

        with pytest.raises(ValueError, match="no hostname"):
            await collector.collect_ssl_data(url)

    async def test_custom_port(self, collector):
        """Test that custom port is handled."""
        url = "https://example.com:8443"

        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = ("CN=Example CA", "2025-12-31T23:59:59Z", True)
            result = await collector.collect_ssl_data(url)

        assert isinstance(result, SSLData)
        assert result.chain_valid is True


@pytest.mark.asyncio
class TestSSLDataIntegration:
    """Test SSL data collection integration with DataCollector."""

    @pytest.fixture
    def collector(self):
        """Create a DataCollector instance."""
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        """Create a mock Sandbox instance."""
        sandbox = Mock()
        sandbox.page = Mock()
        return sandbox

    async def test_compatibility_with_collect_all(self, collector, mock_sandbox):
        """Test that collect_ssl_data works with DataCollector.collect_all()."""
        # Mock other collection methods
        collector.collect_network_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_dom_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_javascript_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_visual_data = AsyncMock(
            return_value=Mock(failed=False)
        )

        # Mock SSL collection
        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = ("CN=Example CA", "2025-12-31T23:59:59Z", True)
            result = await collector.collect_all(mock_sandbox, "https://example.com")

        assert result.ssl is not None
        assert isinstance(result.ssl, SSLData)
        assert result.ssl.failed is False

    async def test_ssl_failure_does_not_cancel_other_categories(self, collector, mock_sandbox):
        """Test that SSL failure does not cancel other categories."""
        # Make SSL fail
        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.side_effect = Exception("SSL failed")

            collector.collect_network_data = AsyncMock(
                return_value=Mock(failed=False)
            )
            collector.collect_dom_data = AsyncMock(
                return_value=Mock(failed=False)
            )
            collector.collect_javascript_data = AsyncMock(
                return_value=Mock(failed=False)
            )
            collector.collect_visual_data = AsyncMock(
                return_value=Mock(failed=False)
            )

            result = await collector.collect_all(mock_sandbox, "https://example.com")

        # SSL should fail, others should succeed
        assert result.ssl.failed is True
        assert result.network.failed is False
        assert result.dom.failed is False
        assert result.javascript.failed is False
        assert result.visual.failed is False

    async def test_partial_analysis_data_remains_available(self, collector, mock_sandbox):
        """Test that partial AnalysisData is available when SSL fails."""
        # Make SSL fail
        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.side_effect = Exception("SSL failed")

            collector.collect_network_data = AsyncMock(
                return_value=Mock(failed=False)
            )
            collector.collect_dom_data = AsyncMock(
                return_value=Mock(failed=False)
            )
            collector.collect_javascript_data = AsyncMock(
                return_value=Mock(failed=False)
            )
            collector.collect_visual_data = AsyncMock(
                return_value=Mock(failed=False)
            )

            result = await collector.collect_all(mock_sandbox, "https://example.com")

        # AnalysisData should be available with partial results
        assert isinstance(result, AnalysisData)
        assert result.categories_collected == 4  # Network, DOM, JavaScript, Visual
        assert result.ssl.failed is True
        assert result.network.failed is False

    async def test_http_url_in_collect_all(self, collector, mock_sandbox):
        """Test HTTP URL handling in collect_all()."""
        collector.collect_network_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_dom_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_javascript_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_visual_data = AsyncMock(
            return_value=Mock(failed=False)
        )

        result = await collector.collect_all(mock_sandbox, "http://example.com")

        # SSL should be marked as failed (N/A for HTTP)
        assert result.ssl.failed is True
        assert result.ssl.issuer == ""
        assert result.ssl.expiration_date == ""
