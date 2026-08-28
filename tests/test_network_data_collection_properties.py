"""Property-based tests for Network Data Collection (Task 6.4).

Property 1: Data Collection Completeness

*For any* website execution in the virtual environment, the data collector
SHALL successfully collect network patterns (request count, domains,
protocols) and aggregate them into the Analysis_Data structure.

Validates: Requirements 2.1

Design:
-------
collect_network_data() works by:
  1. Defining a synchronous `track_request(request)` callback that reads
     `request.url` and updates counters.
  2. Registering it via `sandbox.page.on("request", track_request)`.
  3. Doing `await asyncio.sleep(0.1)` to let events accumulate.
  4. Reading the counters and returning a NetworkData object.

Test strategy:
  - Use asyncio.create_task() to start the coroutine.
  - await asyncio.sleep(0) to yield control; the coroutine runs until its
    own first await (asyncio.sleep(0.1)), at which point it suspends and
    returns control here.  The listener is now registered.
  - Capture the registered callback from mock_sandbox.page.on.call_args.
  - Call it synchronously for each generated request.
  - await the task to get the result.
  - Compare against expected values independently derived from the input.
"""

import asyncio
import pytest
from typing import List, Tuple
from unittest.mock import Mock, AsyncMock
from urllib.parse import urlparse

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hypothesis import given, strategies as st, settings, HealthCheck

from src.data_collector import DataCollector
from src.models import AnalysisData, NetworkData


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

PROTOCOLS = ["http", "https", "ws", "wss"]

# Simple, safe domain labels: letter-only, 3-8 chars, fixed TLD
_label = st.from_regex(r"[a-z]{3,8}", fullmatch=True)
_domain_strategy = st.builds(lambda lbl: f"{lbl}.example.com", lbl=_label)

# Each request is a (protocol, domain) tuple
_request_tuple = st.tuples(
    st.sampled_from(PROTOCOLS),
    _domain_strategy,
)

# A list of 0..20 requests represents the "random network activity"
requests_strategy = st.lists(_request_tuple, min_size=0, max_size=20)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_request(protocol: str, domain: str) -> Mock:
    """Build a mock request object whose .url parses correctly."""
    req = Mock()
    req.url = f"{protocol}://{domain}/some/path"
    return req


def _make_fresh_sandbox() -> Mock:
    """
    Create a mock sandbox whose page.on() captures the callback.

    Returns the sandbox; use sandbox._captured_callback to get the
    registered track_request function after the collector has started.
    """
    sandbox = Mock()
    page = Mock()
    captured = {}

    def on_side_effect(event_name, callback):
        if event_name == "request":
            captured["cb"] = callback

    page.on = Mock(side_effect=on_side_effect)
    page.remove_listener = Mock()
    sandbox.page = page
    sandbox._captured = captured
    return sandbox


def _compute_expected(requests: List[Tuple[str, str]]) -> dict:
    """
    Derive expected NetworkData values independently from generated input.
    Uses urlparse (same as production) to be consistent, but does NOT
    reproduce the production counting logic -- it computes from first
    principles by iterating tuples.
    """
    unique_domains: set = set()
    protocol_counts: dict = {}

    for protocol, domain in requests:
        url = f"{protocol}://{domain}/some/path"
        parsed = urlparse(url)
        netloc = parsed.netloc        # e.g. "abc.example.com"
        scheme = parsed.scheme.lower()  # e.g. "https"

        if netloc:
            unique_domains.add(netloc)
        if scheme:
            protocol_counts[scheme] = protocol_counts.get(scheme, 0) + 1

    return {
        "request_count": len(requests),
        "unique_domains": unique_domains,
        "protocol_distribution": protocol_counts,
    }


async def _run_collection_with_requests(
    requests: List[Tuple[str, str]],
) -> Tuple[NetworkData, Mock]:
    """
    Start collect_network_data(), inject generated requests into the
    track_request callback, and return (NetworkData result, sandbox mock).

    Flow:
      1. Create fresh collector + sandbox.
      2. Schedule collect_network_data as a task.
      3. yield (sleep 0) -- task runs until its asyncio.sleep(0.1) and suspends.
         At this point sandbox.page.on has been called and the callback is stored.
      4. Fire each generated request synchronously via the captured callback.
      5. Await the task to completion.
    """
    collector = DataCollector()
    sandbox = _make_fresh_sandbox()

    # Start the coroutine as a task so we can interleave
    task = asyncio.create_task(collector.collect_network_data(sandbox))

    # Yield once -- the task runs synchronously until its first `await`
    # (which is `asyncio.sleep(0.1)`), then suspends here.
    await asyncio.sleep(0)

    # The listener should now be registered
    captured_cb = sandbox._captured.get("cb")
    assert captured_cb is not None, (
        "track_request callback was not registered via sandbox.page.on('request', ...)"
    )

    # Inject every generated request into the listener synchronously
    for protocol, domain in requests:
        mock_req = _make_mock_request(protocol, domain)
        captured_cb(mock_req)

    # Let the task finish (its asyncio.sleep(0.1) expires)
    result = await task
    return result, sandbox


# ---------------------------------------------------------------------------
# Property 1 -- primary test class
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestProperty1DataCollectionCompleteness:
    """Property 1: Data Collection Completeness.

    *For any* website execution in the virtual environment, the data collector
    SHALL successfully collect network patterns (request count, domains,
    protocols) and aggregate them into the Analysis_Data structure.

    Validates: Requirements 2.1
    """

    # ------------------------------------------------------------------
    # Primary combined property: all invariants in one example sweep
    # ------------------------------------------------------------------

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=100,
    )
    @given(requests=requests_strategy)
    async def test_property_1_all_invariants(self, requests: List[Tuple[str, str]]):
        """Property 1: For any random list of network requests, verify all
        three mandated fields and structural invariants.

        Exercises the real track_request callback injected with generated data.
        """
        expected = _compute_expected(requests)
        result, _ = await _run_collection_with_requests(requests)

        # Invariant 1: correct type
        assert isinstance(result, NetworkData), (
            f"collect_network_data must return NetworkData, got {type(result)}"
        )

        # Invariant 2: request_count == number of requests injected
        assert result.request_count == expected["request_count"], (
            f"request_count={result.request_count}, expected={expected['request_count']} "
            f"for {len(requests)} injected requests"
        )

        # Invariant 3: unique_domains matches exactly
        assert set(result.unique_domains) == expected["unique_domains"], (
            f"unique_domains={set(result.unique_domains)!r}, "
            f"expected={expected['unique_domains']!r}"
        )

        # Invariant 4: protocol_distribution exactly matches
        assert result.protocol_distribution == expected["protocol_distribution"], (
            f"protocol_distribution={result.protocol_distribution!r}, "
            f"expected={expected['protocol_distribution']!r}"
        )

        # Invariant 5: failed is False (collection succeeded)
        assert result.failed is False, (
            "failed must be False when collection succeeds"
        )

    # ------------------------------------------------------------------
    # Separate focused properties (kept independent for Hypothesis shrinking)
    # ------------------------------------------------------------------

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=80,
    )
    @given(requests=requests_strategy)
    async def test_property_1_request_count(self, requests: List[Tuple[str, str]]):
        """Invariant: request_count equals number of injected requests."""
        result, _ = await _run_collection_with_requests(requests)
        assert result.request_count == len(requests)

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=80,
    )
    @given(requests=requests_strategy)
    async def test_property_1_unique_domains(self, requests: List[Tuple[str, str]]):
        """Invariant: unique_domains contains exactly the unique netloc values."""
        expected = _compute_expected(requests)
        result, _ = await _run_collection_with_requests(requests)
        assert set(result.unique_domains) == expected["unique_domains"]

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=80,
    )
    @given(requests=requests_strategy)
    async def test_property_1_protocol_distribution(self, requests: List[Tuple[str, str]]):
        """Invariant: protocol_distribution counts each scheme correctly."""
        expected = _compute_expected(requests)
        result, _ = await _run_collection_with_requests(requests)
        assert result.protocol_distribution == expected["protocol_distribution"]

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=80,
    )
    @given(requests=requests_strategy)
    async def test_property_1_failed_flag(self, requests: List[Tuple[str, str]]):
        """Invariant: failed is always False for any valid request list."""
        result, _ = await _run_collection_with_requests(requests)
        assert result.failed is False

    # ------------------------------------------------------------------
    # Listener cleanup property
    # ------------------------------------------------------------------

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=50,
    )
    @given(requests=requests_strategy)
    async def test_property_1_listener_removed_after_collection(
        self, requests: List[Tuple[str, str]]
    ):
        """Invariant: remove_listener is called after collection completes.

        The production finally-block must remove the listener to prevent
        callback leaks between page executions.
        """
        result, sandbox = await _run_collection_with_requests(requests)
        sandbox.page.remove_listener.assert_called_once_with("request", sandbox._captured["cb"])


# ---------------------------------------------------------------------------
# collect_all() integration test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestProperty1CollectAllIntegration:
    """Verify NetworkData is correctly placed into AnalysisData.network
    when collect_all() is used.
    """

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=50,
    )
    @given(requests=requests_strategy)
    async def test_network_data_in_analysis_data(self, requests: List[Tuple[str, str]]):
        """Property 1 integration: collect_all() puts correctly collected
        NetworkData into AnalysisData.network.

        All other categories are mocked out so the test focuses on network.
        """
        expected = _compute_expected(requests)

        collector = DataCollector()
        sandbox = _make_fresh_sandbox()

        # Mock all non-network collectors so they dont interfere
        collector.collect_dom_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_javascript_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_visual_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_ssl_data = AsyncMock(return_value=Mock(failed=False))

        # collect_all() uses asyncio.create_task() for each sub-collector
        # (line 90-94 in data_collector.py).  The task scheduling depth is:
        #   sleep(0) #1: collect_all runs until await wait_for(gather(...));
        #                sub-tasks are queued but not yet started.
        #   sleep(0) #2: _collect_network_data_safe starts, awaits
        #                collect_network_data.
        #   sleep(0) #3: collect_network_data runs to sandbox.page.on()
        #                (synchronous) then hits await asyncio.sleep(0.1).
        #                Listener is now registered.
        task = asyncio.create_task(
            collector.collect_all(sandbox, "https://example.com")
        )
        # Three yields to propagate through all nested create_task layers
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        # Listener must be registered by now -- assert rather than silently skip
        captured_cb = sandbox._captured.get("cb")
        assert captured_cb is not None, (
            "track_request callback not registered after 3 sleep(0) yields; "
            "collect_all task scheduling chain may have changed"
        )
        for protocol, domain in requests:
            captured_cb(_make_mock_request(protocol, domain))

        result = await task

        assert isinstance(result, AnalysisData)
        assert result.network is not None
        assert isinstance(result.network, NetworkData)
        assert result.network.failed is False
        assert result.network.request_count == expected["request_count"]
        assert set(result.network.unique_domains) == expected["unique_domains"]
        assert result.network.protocol_distribution == expected["protocol_distribution"]


# ---------------------------------------------------------------------------
# Boundary cases -- fixed deterministic tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestProperty1BoundaryCases:
    """Explicit boundary tests complementing the Hypothesis sweep.

    Covers the exact edge cases called out in the spec:
    - zero requests
    - one request
    - duplicate domain with different protocols
    - multiple requests to same domain
    - all four protocols
    """

    async def test_zero_requests(self):
        """Boundary: no network activity -- all fields are empty/zero."""
        result, _ = await _run_collection_with_requests([])

        assert result.request_count == 0
        assert result.unique_domains == []
        assert result.protocol_distribution == {}
        assert result.failed is False

    async def test_one_https_request(self):
        """Boundary: single HTTPS request."""
        reqs = [("https", "single.example.com")]
        result, _ = await _run_collection_with_requests(reqs)

        assert result.request_count == 1
        assert set(result.unique_domains) == {"single.example.com"}
        assert result.protocol_distribution == {"https": 1}
        assert result.failed is False

    async def test_one_http_request(self):
        """Boundary: single HTTP request."""
        reqs = [("http", "insecure.example.com")]
        result, _ = await _run_collection_with_requests(reqs)

        assert result.request_count == 1
        assert set(result.unique_domains) == {"insecure.example.com"}
        assert result.protocol_distribution == {"http": 1}

    async def test_one_ws_request(self):
        """Boundary: single WebSocket (ws) request."""
        reqs = [("ws", "socket.example.com")]
        result, _ = await _run_collection_with_requests(reqs)

        assert result.request_count == 1
        assert result.protocol_distribution == {"ws": 1}

    async def test_one_wss_request(self):
        """Boundary: single secure WebSocket (wss) request."""
        reqs = [("wss", "socket.example.com")]
        result, _ = await _run_collection_with_requests(reqs)

        assert result.request_count == 1
        assert result.protocol_distribution == {"wss": 1}

    async def test_duplicate_domain_same_protocol(self):
        """Boundary: two requests to the same domain/protocol.

        unique_domains must contain only one entry.
        request_count must be 2.
        """
        reqs = [
            ("https", "dup.example.com"),
            ("https", "dup.example.com"),
        ]
        result, _ = await _run_collection_with_requests(reqs)

        assert result.request_count == 2
        assert set(result.unique_domains) == {"dup.example.com"}
        assert result.protocol_distribution == {"https": 2}

    async def test_same_domain_different_protocols(self):
        """Boundary: http + https to same domain.

        Domain counted once.
        Protocol counts are separate.
        """
        reqs = [
            ("http", "mixed.example.com"),
            ("https", "mixed.example.com"),
        ]
        result, _ = await _run_collection_with_requests(reqs)

        assert result.request_count == 2
        assert set(result.unique_domains) == {"mixed.example.com"}
        assert result.protocol_distribution == {"http": 1, "https": 1}

    async def test_multiple_requests_same_domain(self):
        """Boundary: five requests to the same domain."""
        reqs = [("https", "busy.example.com")] * 5
        result, _ = await _run_collection_with_requests(reqs)

        assert result.request_count == 5
        assert set(result.unique_domains) == {"busy.example.com"}
        assert result.protocol_distribution == {"https": 5}

    async def test_all_four_protocols(self):
        """Boundary: one request per protocol, each a different domain."""
        reqs = [
            ("http",  "http.example.com"),
            ("https", "https.example.com"),
            ("ws",    "ws.example.com"),
            ("wss",   "wss.example.com"),
        ]
        result, _ = await _run_collection_with_requests(reqs)

        assert result.request_count == 4
        assert set(result.unique_domains) == {
            "http.example.com",
            "https.example.com",
            "ws.example.com",
            "wss.example.com",
        }
        assert result.protocol_distribution == {
            "http": 1, "https": 1, "ws": 1, "wss": 1
        }

    async def test_all_four_protocols_same_domain(self):
        """Boundary: all four protocols, same domain.
        Domain appears once; all four protocols appear in distribution.
        """
        reqs = [
            ("http",  "quad.example.com"),
            ("https", "quad.example.com"),
            ("ws",    "quad.example.com"),
            ("wss",   "quad.example.com"),
        ]
        result, _ = await _run_collection_with_requests(reqs)

        assert result.request_count == 4
        assert set(result.unique_domains) == {"quad.example.com"}
        assert result.protocol_distribution == {
            "http": 1, "https": 1, "ws": 1, "wss": 1
        }

    async def test_many_different_domains(self):
        """Boundary: 10 requests to 10 distinct domains."""
        reqs = [("https", f"host{i}.example.com") for i in range(10)]
        result, _ = await _run_collection_with_requests(reqs)

        assert result.request_count == 10
        expected_domains = {f"host{i}.example.com" for i in range(10)}
        assert set(result.unique_domains) == expected_domains
        assert result.protocol_distribution == {"https": 10}

    async def test_listener_cleaned_up_after_success(self):
        """Verify remove_listener is called after successful collection."""
        sandbox = _make_fresh_sandbox()
        collector = DataCollector()

        task = asyncio.create_task(collector.collect_network_data(sandbox))
        await asyncio.sleep(0)

        captured_cb = sandbox._captured.get("cb")
        assert captured_cb is not None

        result = await task

        sandbox.page.remove_listener.assert_called_once_with("request", captured_cb)
        assert result.failed is False
