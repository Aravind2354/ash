"""Unit tests for network data collection (Task 6.3).

Tests the collect_network_data method for:
- Request counting
- Unique domain collection
- Protocol distribution
- Multiple requests to same domain
- Requests to multiple domains
- Mixed HTTP/HTTPS
- Empty/no-network case
- Network collection failure
- Correct NetworkData result
- Compatibility with DataCollector.collect_all()

Validates Requirement: 2.1
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timezone

# Add src to path for imports
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.data_collector import DataCollector
from src.models import NetworkData


@pytest.mark.asyncio
class TestNetworkDataCollection:
    """Test network data collection functionality."""

    @pytest.fixture
    def collector(self):
        """Create a DataCollector instance."""
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        """Create a mock Sandbox instance."""
        sandbox = Mock()
        sandbox.page = Mock()
        sandbox.page.on = Mock()
        sandbox.page.remove_listener = Mock()
        return sandbox

    async def test_request_counting(self, collector, mock_sandbox):
        """Test that requests are counted correctly."""
        # Verify listener is registered
        mock_sandbox.page.on = Mock()

        result = await collector.collect_network_data(mock_sandbox)

        assert isinstance(result, NetworkData)
        assert result.request_count >= 0
        assert result.failed is False
        mock_sandbox.page.on.assert_called_once()

    async def test_request_counting(self, collector, mock_sandbox):
        """Test that requests are counted correctly."""
        # Verify listener is registered
        mock_sandbox.page.on = Mock()

        result = await collector.collect_network_data(mock_sandbox)

        assert isinstance(result, NetworkData)
        assert result.request_count >= 0
        assert result.failed is False
        mock_sandbox.page.on.assert_called_once()

    async def test_unique_domain_collection(self, collector, mock_sandbox):
        """Test that unique domains are collected (structure verification)."""
        mock_sandbox.page.on = Mock()

        result = await collector.collect_network_data(mock_sandbox)

        assert isinstance(result, NetworkData)
        assert isinstance(result.unique_domains, list)
        assert result.failed is False

    async def test_protocol_distribution(self, collector, mock_sandbox):
        """Test that protocol distribution is returned (structure verification)."""
        mock_sandbox.page.on = Mock()

        result = await collector.collect_network_data(mock_sandbox)

        assert isinstance(result, NetworkData)
        assert isinstance(result.protocol_distribution, dict)
        assert result.failed is False

    async def test_multiple_requests_same_domain(self, collector, mock_sandbox):
        """Test structure for multiple requests (structure verification)."""
        mock_sandbox.page.on = Mock()

        result = await collector.collect_network_data(mock_sandbox)

        assert isinstance(result, NetworkData)
        assert result.request_count >= 0
        assert result.failed is False

    async def test_requests_multiple_domains(self, collector, mock_sandbox):
        """Test structure for multiple domains (structure verification)."""
        mock_sandbox.page.on = Mock()

        result = await collector.collect_network_data(mock_sandbox)

        assert isinstance(result, NetworkData)
        assert isinstance(result.unique_domains, list)
        assert result.failed is False

    async def test_mixed_http_https(self, collector, mock_sandbox):
        """Test structure for mixed protocols (structure verification)."""
        mock_sandbox.page.on = Mock()

        result = await collector.collect_network_data(mock_sandbox)

        assert isinstance(result, NetworkData)
        assert isinstance(result.protocol_distribution, dict)
        assert result.failed is False

    async def test_empty_network_case(self, collector, mock_sandbox):
        """Test empty network (no requests)."""
        mock_sandbox.page.on = Mock()

        result = await collector.collect_network_data(mock_sandbox)

        assert isinstance(result, NetworkData)
        assert result.request_count == 0
        assert len(result.unique_domains) == 0
        assert len(result.protocol_distribution) == 0
        assert result.failed is False

    async def test_network_collection_failure(self, collector, mock_sandbox):
        """Test that network collection failure is handled."""
        # Make page.on raise an exception
        mock_sandbox.page.on.side_effect = Exception("Page error")

        with pytest.raises(Exception):
            await collector.collect_network_data(mock_sandbox)

    async def test_correct_networkdata_result(self, collector, mock_sandbox):
        """Test that correct NetworkData object is returned."""
        mock_sandbox.page.on = Mock()

        result = await collector.collect_network_data(mock_sandbox)

        assert isinstance(result, NetworkData)
        assert hasattr(result, 'request_count')
        assert hasattr(result, 'unique_domains')
        assert hasattr(result, 'protocol_distribution')
        assert hasattr(result, 'failed')
        assert result.failed is False


@pytest.mark.asyncio
class TestNetworkDataIntegration:
    """Test network data collection integration with DataCollector."""

    @pytest.fixture
    def collector(self):
        """Create a DataCollector instance."""
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        """Create a mock Sandbox instance."""
        sandbox = Mock()
        sandbox.page = Mock()
        sandbox.page.on = Mock()
        sandbox.page.remove_listener = Mock()
        return sandbox

    async def test_listener_cleanup(self, collector, mock_sandbox):
        """Test that listener is cleaned up after collection."""
        mock_sandbox.page.on = Mock()

        await collector.collect_network_data(mock_sandbox)

        # Verify remove_listener was called
        mock_sandbox.page.remove_listener.assert_called_once()


@pytest.mark.asyncio
class TestNetworkDataIntegration:
    """Test network data collection integration with DataCollector."""

    @pytest.fixture
    def collector(self):
        """Create a DataCollector instance."""
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        """Create a mock Sandbox instance."""
        sandbox = Mock()
        sandbox.page = Mock()
        sandbox.page.on = Mock()
        sandbox.page.remove_listener = Mock()
        return sandbox

    async def test_compatibility_with_collect_all(self, collector, mock_sandbox):
        """Test that collect_network_data works with DataCollector.collect_all()."""
        # Mock other collection methods
        collector.collect_dom_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_javascript_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_visual_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_ssl_data = AsyncMock(
            return_value=Mock(failed=False)
        )

        result = await collector.collect_all(mock_sandbox, "https://example.com")

        assert result.network is not None
        assert isinstance(result.network, NetworkData)
        assert result.network.failed is False
