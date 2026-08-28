"""Property-based tests for SSL Certificate Data Collection (Task 6.12).

Property 5: SSL Certificate Data Collection

*For any* HTTPS URL, the data collector SHALL extract SSL certificate
information (issuer, expiration, chain validation status) and include it
in Analysis_Data.

Validates: Requirements 2.5

Design:
-------
collect_ssl_data(url) works by:
  1. Parsing url via urllib.parse.urlparse
  2. Checking scheme:
     - If scheme != 'https', returns SSLData(issuer="", expiration_date="", chain_valid=False, failed=True)
  3. Validating hostname (raises ValueError if absent)
  4. Running blocking get_ssl_info() in thread pool via asyncio.to_thread:
     - Connects with SSL context
     - Extracts issuer DN string
     - Extracts notAfter expiration date and formats as ISO 8601 (%Y-%m-%dT%H:%M:%SZ)
     - Sets chain_valid=True for valid chains, or chain_valid=False on SSLCertVerificationError
  5. Returning SSLData(issuer, expiration_date, chain_valid, failed=False)
  6. Propagates connection/other exceptions (safe wrapper _collect_ssl_data_safe returns failed=True).

Test Strategy:
  - NO LIVE NETWORK CALLS: All thread/socket operations are deterministically mocked via patch('src.data_collector.asyncio.to_thread').
  - Generate arbitrary HTTPS URLs with diverse hostnames, ports, and paths.
  - Generate arbitrary certificate metadata (issuers with diverse DN components, expiration datetimes, chain validity).
  - Generate non-HTTPS URLs (http, ws, wss, ftp) to verify the N/A contract.
  - Verify all invariants across property-based sweeps and deterministic boundary cases.
  - Verify integration with DataCollector.collect_all() -> AnalysisData.ssl.
"""

import pytest
import asyncio
import re
from datetime import datetime
from typing import Dict, Any
from unittest.mock import Mock, AsyncMock, patch

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from hypothesis import given, strategies as st, settings, HealthCheck

from src.data_collector import DataCollector
from src.models import AnalysisData, SSLData


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_label = st.from_regex(r"[a-z]{3,8}", fullmatch=True)
_tld = st.sampled_from(["com", "org", "net", "io", "dev"])
domain_strategy = st.builds(lambda lbl, tld: f"{lbl}.{tld}", lbl=_label, tld=_tld)
port_strategy = st.sampled_from([None, 443, 8443, 9443])
path_strategy = st.sampled_from(["", "/index.html", "/api/v1", "/login", "/products"])

issuer_strategy = st.builds(
    lambda cn, o, ou, c: f"CN={cn.title()} CA, O={o.title()} Inc, OU={ou.title()}, C={c}",
    cn=_label,
    o=_label,
    ou=_label,
    c=st.sampled_from(["US", "GB", "DE", "FR", "JP", "CA"])
)

expiration_strategy = st.datetimes(
    min_value=datetime(2020, 1, 1),
    max_value=datetime(2035, 12, 31)
).map(lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ"))


@st.composite
def https_scenario_strategy(draw) -> Dict[str, Any]:
    """Generate arbitrary HTTPS URL scenarios with expected certificate metadata."""
    domain = draw(domain_strategy)
    port = draw(port_strategy)
    path = draw(path_strategy)
    url = f"https://{domain}:{port}{path}" if port else f"https://{domain}{path}"

    return {
        "url": url,
        "domain": domain,
        "port": port or 443,
        "issuer": draw(issuer_strategy),
        "expiration_date": draw(expiration_strategy),
        "chain_valid": draw(st.booleans()),
    }


@st.composite
def non_https_url_strategy(draw) -> str:
    """Generate non-HTTPS URLs across various schemes."""
    scheme = draw(st.sampled_from(["http", "ws", "wss", "ftp"]))
    domain = draw(domain_strategy)
    path = draw(path_strategy)
    return f"{scheme}://{domain}{path}"


ISO_8601_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


# ---------------------------------------------------------------------------
# Property 5 -- Primary Test Class
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestProperty5SSLDataCollection:
    """Property 5: SSL Certificate Data Collection.

    *For any* HTTPS URL, the data collector SHALL extract SSL certificate
    information (issuer, expiration, chain validation status) and include
    it in Analysis_Data.

    Validates: Requirements 2.5
    """

    @pytest.fixture
    def collector(self):
        """Create fresh DataCollector instance."""
        return DataCollector()

    @pytest.fixture
    def mock_ssl_thread(self):
        """Fixture providing patched asyncio.to_thread for deterministic SSL execution."""
        with patch('src.data_collector.asyncio.to_thread', new_callable=AsyncMock) as m:
            yield m

    # ------------------------------------------------------------------
    # Primary combined property test: HTTPS scenarios across examples
    # ------------------------------------------------------------------

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=50,
        deadline=None,
    )
    @given(scenario=https_scenario_strategy())
    async def test_property_5_https_all_invariants(self, collector, mock_ssl_thread, scenario: Dict[str, Any]):
        """Property 5: For any HTTPS URL and certificate state, verify exact issuer extraction,
        ISO 8601 expiration formatting, chain validation flag, and non-failure status.
        """
        mock_ssl_thread.return_value = (
            scenario["issuer"],
            scenario["expiration_date"],
            scenario["chain_valid"]
        )

        result = await collector.collect_ssl_data(scenario["url"])

        # Invariant 1: Result is SSLData instance
        assert isinstance(result, SSLData), f"Expected SSLData, got {type(result)}"

        # Invariant 2: failed flag is False for successfully collected HTTPS certificates
        assert result.failed is False, "failed must be False when HTTPS certificate is retrieved"

        # Invariant 3: issuer DN string preserved exactly
        assert result.issuer == scenario["issuer"], (
            f"issuer='{result.issuer}', expected='{scenario['issuer']}'"
        )

        # Invariant 4: expiration date matches and satisfies ISO 8601 format
        assert result.expiration_date == scenario["expiration_date"], (
            f"expiration_date='{result.expiration_date}', expected='{scenario['expiration_date']}'"
        )
        assert ISO_8601_PATTERN.match(result.expiration_date), (
            f"expiration_date '{result.expiration_date}' does not conform to ISO 8601 (YYYY-MM-DDTHH:MM:SSZ)"
        )

        # Invariant 5: chain_valid matches expected boolean state
        assert result.chain_valid == scenario["chain_valid"], (
            f"chain_valid={result.chain_valid}, expected={scenario['chain_valid']}"
        )

    # ------------------------------------------------------------------
    # Non-HTTPS URLs: N/A Contract Verification
    # ------------------------------------------------------------------

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=30,
        deadline=None,
    )
    @given(url=non_https_url_strategy())
    async def test_property_5_non_https_na_behavior(self, collector, mock_ssl_thread, url: str):
        """Invariant: Non-HTTPS URLs immediately return failed=True (N/A) without attempting SSL."""
        result = await collector.collect_ssl_data(url)

        # No SSL connection must be attempted for non-HTTPS schemes
        mock_ssl_thread.assert_not_called()

        assert isinstance(result, SSLData)
        assert result.issuer == ""
        assert result.expiration_date == ""
        assert result.chain_valid is False
        assert result.failed is True

    # ------------------------------------------------------------------
    # Independent Property Tests for Shrinking & Isolation
    # ------------------------------------------------------------------

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=25,
        deadline=None,
    )
    @given(scenario=https_scenario_strategy())
    async def test_property_5_issuer_preservation(self, collector, mock_ssl_thread, scenario: Dict[str, Any]):
        """Invariant: Certificate issuer Distinguished Name is preserved."""
        mock_ssl_thread.return_value = (scenario["issuer"], scenario["expiration_date"], scenario["chain_valid"])
        result = await collector.collect_ssl_data(scenario["url"])
        assert result.issuer == scenario["issuer"]

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=25,
        deadline=None,
    )
    @given(scenario=https_scenario_strategy())
    async def test_property_5_expiration_preservation_and_iso_format(self, collector, mock_ssl_thread, scenario: Dict[str, Any]):
        """Invariant: Expiration date is preserved in ISO 8601 format."""
        mock_ssl_thread.return_value = (scenario["issuer"], scenario["expiration_date"], scenario["chain_valid"])
        result = await collector.collect_ssl_data(scenario["url"])
        assert result.expiration_date == scenario["expiration_date"]
        assert ISO_8601_PATTERN.match(result.expiration_date)

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=25,
        deadline=None,
    )
    @given(scenario=https_scenario_strategy())
    async def test_property_5_chain_valid_boolean_preservation(self, collector, mock_ssl_thread, scenario: Dict[str, Any]):
        """Invariant: chain_valid reflects the verification result, while failed remains False."""
        mock_ssl_thread.return_value = (scenario["issuer"], scenario["expiration_date"], scenario["chain_valid"])
        result = await collector.collect_ssl_data(scenario["url"])
        assert result.chain_valid == scenario["chain_valid"]
        assert result.failed is False


# ---------------------------------------------------------------------------
# collect_all() Integration Property Test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestProperty5CollectAllIntegration:
    """Verify SSLData is correctly placed into AnalysisData.ssl during collect_all()."""

    @pytest.fixture
    def collector(self):
        return DataCollector()

    @pytest.fixture
    def mock_ssl_thread(self):
        with patch('src.data_collector.asyncio.to_thread', new_callable=AsyncMock) as m:
            yield m

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=25,
        deadline=None,
    )
    @given(scenario=https_scenario_strategy())
    async def test_ssl_data_in_analysis_data_https(self, collector, mock_ssl_thread, scenario: Dict[str, Any]):
        """Property 5 integration: collect_all() aggregates valid SSLData for HTTPS URLs."""
        sandbox = Mock()
        sandbox.page = Mock()

        # Mock unrelated collectors so the test focuses cleanly on SSL collection
        collector.collect_network_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_dom_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_javascript_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_visual_data = AsyncMock(return_value=Mock(failed=False))

        mock_ssl_thread.return_value = (
            scenario["issuer"],
            scenario["expiration_date"],
            scenario["chain_valid"]
        )

        result = await collector.collect_all(sandbox, scenario["url"])

        assert isinstance(result, AnalysisData)
        assert result.ssl is not None
        assert isinstance(result.ssl, SSLData)
        assert result.ssl.failed is False
        assert result.ssl.issuer == scenario["issuer"]
        assert result.ssl.expiration_date == scenario["expiration_date"]
        assert result.ssl.chain_valid == scenario["chain_valid"]

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=25,
        deadline=None,
    )
    @given(url=non_https_url_strategy())
    async def test_ssl_data_in_analysis_data_non_https(self, collector, mock_ssl_thread, url: str):
        """Property 5 integration: collect_all() marks SSLData as failed/NA for non-HTTPS URLs."""
        sandbox = Mock()
        sandbox.page = Mock()

        collector.collect_network_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_dom_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_javascript_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_visual_data = AsyncMock(return_value=Mock(failed=False))

        result = await collector.collect_all(sandbox, url)

        assert isinstance(result, AnalysisData)
        assert result.ssl is not None
        assert isinstance(result.ssl, SSLData)
        assert result.ssl.failed is True
        assert result.ssl.issuer == ""
        assert result.ssl.expiration_date == ""
        assert result.ssl.chain_valid is False


# ---------------------------------------------------------------------------
# Boundary & Failure Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestProperty5BoundaryAndFailureCases:
    """Deterministic boundary tests covering specific certificate states, error paths, and isolation."""

    @pytest.fixture
    def collector(self):
        return DataCollector()

    async def test_valid_https_certificate(self, collector):
        """Boundary 1: Standard trusted HTTPS certificate."""
        url = "https://secure.example.com"
        with patch('src.data_collector.asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = (
                "CN=DigiCert Global Root CA, O=DigiCert Inc, C=US",
                "2030-11-10T00:00:00Z",
                True
            )
            result = await collector.collect_ssl_data(url)

            assert result.issuer == "CN=DigiCert Global Root CA, O=DigiCert Inc, C=US"
            assert result.expiration_date == "2030-11-10T00:00:00Z"
            assert result.chain_valid is True
            assert result.failed is False

    async def test_self_signed_certificate_chain_invalid(self, collector):
        """Boundary 2: Self-signed certificate sets chain_valid=False with failed=False."""
        url = "https://self-signed.local"
        with patch('src.data_collector.asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = (
                "CN=localhost, O=Untrusted, C=US",
                "2026-01-01T00:00:00Z",
                False
            )
            result = await collector.collect_ssl_data(url)

            assert result.issuer == "CN=localhost, O=Untrusted, C=US"
            assert result.expiration_date == "2026-01-01T00:00:00Z"
            assert result.chain_valid is False
            assert result.failed is False

    async def test_expired_certificate_chain_invalid(self, collector):
        """Boundary 3: Expired certificate sets chain_valid=False with failed=False."""
        url = "https://expired.example.com"
        with patch('src.data_collector.asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = (
                "CN=Expired CA, O=Test, C=US",
                "2019-12-31T23:59:59Z",
                False
            )
            result = await collector.collect_ssl_data(url)

            assert result.expiration_date == "2019-12-31T23:59:59Z"
            assert result.chain_valid is False
            assert result.failed is False

    async def test_custom_port_https(self, collector):
        """Boundary 4: HTTPS on non-standard port 8443."""
        url = "https://custom-port.example.com:8443/api"
        with patch('src.data_collector.asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = ("CN=Custom Port CA", "2027-05-15T12:00:00Z", True)
            result = await collector.collect_ssl_data(url)

            assert result.chain_valid is True
            assert result.failed is False

    async def test_plain_http_url_marks_na(self, collector):
        """Boundary 5: HTTP URL marks SSL as N/A."""
        url = "http://insecure.example.com"
        result = await collector.collect_ssl_data(url)

        assert result.issuer == ""
        assert result.expiration_date == ""
        assert result.chain_valid is False
        assert result.failed is True

    async def test_missing_hostname_raises_value_error(self, collector):
        """Failure 6: URL without hostname raises ValueError in collect_ssl_data."""
        with pytest.raises(ValueError, match="no hostname"):
            await collector.collect_ssl_data("https://")

    async def test_connection_failure_raises_exception(self, collector):
        """Failure 7: Connection failure raises exception in direct collect_ssl_data."""
        with patch('src.data_collector.asyncio.to_thread', side_effect=ConnectionRefusedError("Connection refused")):
            with pytest.raises(ConnectionRefusedError, match="Connection refused"):
                await collector.collect_ssl_data("https://unreachable.example.com")

    async def test_connection_failure_handled_by_safe_wrapper(self, collector):
        """Failure 8: Connection failure returns failed=True via safe wrapper."""
        with patch('src.data_collector.asyncio.to_thread', side_effect=ConnectionRefusedError("Connection refused")):
            result = await collector._collect_ssl_data_safe("https://unreachable.example.com")

            assert isinstance(result, SSLData)
            assert result.failed is True
            assert result.issuer == ""
            assert result.expiration_date == ""
            assert result.chain_valid is False

    async def test_ssl_timeout_handled_by_safe_wrapper(self, collector):
        """Failure 9: Timeout sets failed=True via safe wrapper."""
        with patch('src.data_collector.asyncio.to_thread', side_effect=asyncio.TimeoutError("SSL handshake timed out")):
            result = await collector._collect_ssl_data_safe("https://slow.example.com")

            assert isinstance(result, SSLData)
            assert result.failed is True

    async def test_ssl_failure_does_not_cancel_other_categories(self, collector):
        """Failure 10: SSL failure during collect_all() isolates failure and preserves other 4 categories."""
        sandbox = Mock()
        sandbox.page = Mock()

        collector.collect_network_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_dom_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_javascript_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_visual_data = AsyncMock(return_value=Mock(failed=False))

        with patch('src.data_collector.asyncio.to_thread', side_effect=RuntimeError("TLS error")):
            result = await collector.collect_all(sandbox, "https://error.example.com")

            assert result.ssl.failed is True
            assert result.network.failed is False
            assert result.dom.failed is False
            assert result.javascript.failed is False
            assert result.visual.failed is False
            assert result.categories_collected == 4
