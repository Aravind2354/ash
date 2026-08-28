"""Property-based tests for DOM Data Collection (Task 6.6).

Property 2: DOM Data Collection

*For any* HTML content in the virtual environment, the data collector SHALL
extract DOM structure metrics and HTML content into Analysis_Data.

Validates: Requirements 2.2

Design:
-------
collect_dom_data() extracts:
  1. html_content via await sandbox.page.content()
  2. element_count via sandbox.page.query_selector_all('*')
  3. form_count via sandbox.page.query_selector_all('form')
  4. iframe_count via sandbox.page.query_selector_all('iframe')
  5. script_count via sandbox.page.query_selector_all('script')
  6. failed flag (False on success)

Test Strategy:
  - Use Hypothesis to generate arbitrary HTML documents with diverse combinations
    of forms, iframes, scripts, tags, whitespace, and text/unicode content.
  - Independently calculate ground-truth counts for each generated document.
  - Mock sandbox.page.content and sandbox.page.query_selector_all to return
    the generated content and counts according to the selector queried.
  - Verify all invariants across property-based sweeps and explicit boundary cases.
  - Verify integration with DataCollector.collect_all() -> AnalysisData.dom.
"""

import pytest
import asyncio
from typing import Dict, Any
from unittest.mock import Mock, AsyncMock

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from hypothesis import given, strategies as st, settings, HealthCheck

from src.data_collector import DataCollector
from src.models import AnalysisData, DOMData


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

safe_text_strategy = st.text(
    alphabet=st.characters(
        blacklist_categories=('Cs',),
        blacklist_characters=('<', '>', '"', "'", '&')
    ),
    min_size=0,
    max_size=30
)

unicode_text_strategy = st.text(
    alphabet=st.characters(
        whitelist_categories=('L', 'N', 'P', 'S', 'Z'),
        blacklist_characters=('<', '>', '"', "'", '&')
    ),
    min_size=0,
    max_size=30
)


@st.composite
def dom_document_strategy(draw) -> Dict[str, Any]:
    """Generate arbitrary structured HTML documents with independently derived metrics."""
    num_forms = draw(st.integers(min_value=0, max_value=12))
    num_iframes = draw(st.integers(min_value=0, max_value=8))
    num_scripts = draw(st.integers(min_value=0, max_value=15))
    num_divs = draw(st.integers(min_value=0, max_value=15))
    num_spans = draw(st.integers(min_value=0, max_value=10))
    text_content = draw(safe_text_strategy)

    body_elements = []

    # Generate forms (each form contains 1 form element + 1 input element = 2 elements)
    for i in range(num_forms):
        body_elements.append(f"<form id='form_{i}' action='/submit'><input type='text' name='q_{i}' value='{text_content}'/></form>")

    # Generate iframes (1 element each)
    for i in range(num_iframes):
        body_elements.append(f"<iframe src='https://embed.example.com/{i}' id='frame_{i}'></iframe>")

    # Generate scripts (1 element each)
    for i in range(num_scripts):
        body_elements.append(f"<script type='text/javascript'>var val_{i} = '{text_content}';</script>")

    # Generate divs with nested paragraphs (div + p = 2 elements each)
    for i in range(num_divs):
        body_elements.append(f"<div class='section_{i}'><p>{text_content}</p></div>")

    # Generate standalone spans (1 element each)
    for i in range(num_spans):
        body_elements.append(f"<span id='span_{i}'>{text_content}</span>")

    # Base elements: html, head, title, body = 4 elements
    html_content = (
        f"<!DOCTYPE html><html><head><title>DOM Property Test</title></head>"
        f"<body>{''.join(body_elements)}</body></html>"
    )

    # Independent calculation of total elements:
    # 4 (html, head, title, body) + forms*2 + iframes*1 + scripts*1 + divs*2 + spans*1
    total_elements = 4 + (num_forms * 2) + num_iframes + num_scripts + (num_divs * 2) + num_spans

    return {
        "html_content": html_content,
        "element_count": total_elements,
        "form_count": num_forms,
        "iframe_count": num_iframes,
        "script_count": num_scripts,
    }


def _make_mock_sandbox(dom_case: Dict[str, Any]) -> Mock:
    """Create a mock Sandbox instance configured with the generated DOM case."""
    sandbox = Mock()
    page = Mock()
    page.content = AsyncMock(return_value=dom_case["html_content"])

    def query_selector_mock(selector: str):
        if selector == '*':
            return dom_case["element_count"]
        elif selector == 'form':
            return dom_case["form_count"]
        elif selector == 'iframe':
            return dom_case["iframe_count"]
        elif selector == 'script':
            return dom_case["script_count"]
        return 0

    page.query_selector_all = Mock(side_effect=query_selector_mock)
    sandbox.page = page
    return sandbox


# ---------------------------------------------------------------------------
# Property 2 -- Primary Test Class
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestProperty2DOMDataCollection:
    """Property 2: DOM Data Collection.

    *For any* HTML content in the virtual environment, the data collector
    SHALL extract DOM structure metrics and HTML content into Analysis_Data.

    Validates: Requirements 2.2
    """

    @pytest.fixture
    def collector(self):
        """Create fresh DataCollector instance."""
        return DataCollector()

    # ------------------------------------------------------------------
    # Primary combined property test: all invariants verified across 100 examples
    # ------------------------------------------------------------------

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=100,
    )
    @given(dom_case=dom_document_strategy())
    async def test_property_2_all_invariants(self, collector, dom_case: Dict[str, Any]):
        """Property 2: For any arbitrary generated DOM, verify all required fields,
        metrics calculations, and structural invariants.
        """
        sandbox = _make_mock_sandbox(dom_case)

        result = await collector.collect_dom_data(sandbox)

        # Invariant 1: Result is DOMData instance
        assert isinstance(result, DOMData), f"Expected DOMData, got {type(result)}"

        # Invariant 2: HTML content preserved exactly without corruption
        assert result.html_content == dom_case["html_content"], (
            "HTML content was modified or corrupted during collection"
        )

        # Invariant 3: element_count matches expected total
        assert result.structure_metrics["element_count"] == dom_case["element_count"], (
            f"element_count={result.structure_metrics.get('element_count')}, "
            f"expected={dom_case['element_count']}"
        )

        # Invariant 4: form_count matches expected forms
        assert result.structure_metrics["form_count"] == dom_case["form_count"], (
            f"form_count={result.structure_metrics.get('form_count')}, "
            f"expected={dom_case['form_count']}"
        )

        # Invariant 5: iframe_count matches expected iframes
        assert result.structure_metrics["iframe_count"] == dom_case["iframe_count"], (
            f"iframe_count={result.structure_metrics.get('iframe_count')}, "
            f"expected={dom_case['iframe_count']}"
        )

        # Invariant 6: script_count matches expected scripts
        assert result.structure_metrics["script_count"] == dom_case["script_count"], (
            f"script_count={result.structure_metrics.get('script_count')}, "
            f"expected={dom_case['script_count']}"
        )

        # Invariant 7: failed is False on success
        assert result.failed is False, "failed flag must be False for successful collection"

    # ------------------------------------------------------------------
    # Independent Property Tests for Shrinking & Isolation
    # ------------------------------------------------------------------

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=80,
    )
    @given(dom_case=dom_document_strategy())
    async def test_property_2_html_content_preserved(self, collector, dom_case: Dict[str, Any]):
        """Invariant: exact HTML content string is preserved."""
        sandbox = _make_mock_sandbox(dom_case)
        result = await collector.collect_dom_data(sandbox)
        assert result.html_content == dom_case["html_content"]

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=80,
    )
    @given(dom_case=dom_document_strategy())
    async def test_property_2_structure_metrics_calculated(self, collector, dom_case: Dict[str, Any]):
        """Invariant: all 4 required structure metrics keys exist and match expected values."""
        sandbox = _make_mock_sandbox(dom_case)
        result = await collector.collect_dom_data(sandbox)

        metrics = result.structure_metrics
        assert "element_count" in metrics
        assert "form_count" in metrics
        assert "iframe_count" in metrics
        assert "script_count" in metrics

        assert metrics["element_count"] == dom_case["element_count"]
        assert metrics["form_count"] == dom_case["form_count"]
        assert metrics["iframe_count"] == dom_case["iframe_count"]
        assert metrics["script_count"] == dom_case["script_count"]

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=80,
    )
    @given(dom_case=dom_document_strategy())
    async def test_property_2_failed_flag_false(self, collector, dom_case: Dict[str, Any]):
        """Invariant: failed flag is False for all valid DOM executions."""
        sandbox = _make_mock_sandbox(dom_case)
        result = await collector.collect_dom_data(sandbox)
        assert result.failed is False


# ---------------------------------------------------------------------------
# collect_all() Integration Property Test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestProperty2CollectAllIntegration:
    """Verify DOMData is correctly placed into AnalysisData.dom during collect_all()."""

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=50,
    )
    @given(dom_case=dom_document_strategy())
    async def test_dom_data_in_analysis_data(self, dom_case: Dict[str, Any]):
        """Property 2 integration: collect_all() aggregates DOMData into AnalysisData.dom."""
        collector = DataCollector()
        sandbox = _make_mock_sandbox(dom_case)

        # Mock unrelated collectors so the test focuses cleanly on DOM collection
        collector.collect_network_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_javascript_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_visual_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_ssl_data = AsyncMock(return_value=Mock(failed=False))

        result = await collector.collect_all(sandbox, "https://example.com")

        assert isinstance(result, AnalysisData)
        assert result.dom is not None
        assert isinstance(result.dom, DOMData)
        assert result.dom.failed is False
        assert result.dom.html_content == dom_case["html_content"]
        assert result.dom.structure_metrics["element_count"] == dom_case["element_count"]
        assert result.dom.structure_metrics["form_count"] == dom_case["form_count"]
        assert result.dom.structure_metrics["iframe_count"] == dom_case["iframe_count"]
        assert result.dom.structure_metrics["script_count"] == dom_case["script_count"]


# ---------------------------------------------------------------------------
# Boundary & Failure Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestProperty2BoundaryAndFailureCases:
    """Deterministic boundary tests covering specific edge cases and failure modes."""

    @pytest.fixture
    def collector(self):
        return DataCollector()

    async def test_empty_html_string(self, collector):
        """Boundary 1: completely empty HTML."""
        dom_case = {
            "html_content": "",
            "element_count": 0,
            "form_count": 0,
            "iframe_count": 0,
            "script_count": 0,
        }
        sandbox = _make_mock_sandbox(dom_case)
        result = await collector.collect_dom_data(sandbox)

        assert result.html_content == ""
        assert result.structure_metrics["element_count"] == 0
        assert result.structure_metrics["form_count"] == 0
        assert result.structure_metrics["iframe_count"] == 0
        assert result.structure_metrics["script_count"] == 0
        assert result.failed is False

    async def test_minimal_html_document(self, collector):
        """Boundary 2: minimal HTML document with 2 elements."""
        dom_case = {
            "html_content": "<html><body></body></html>",
            "element_count": 2,
            "form_count": 0,
            "iframe_count": 0,
            "script_count": 0,
        }
        sandbox = _make_mock_sandbox(dom_case)
        result = await collector.collect_dom_data(sandbox)

        assert result.html_content == "<html><body></body></html>"
        assert result.structure_metrics["element_count"] == 2
        assert result.structure_metrics["form_count"] == 0
        assert result.structure_metrics["iframe_count"] == 0
        assert result.structure_metrics["script_count"] == 0
        assert result.failed is False

    async def test_zero_forms_zero_iframes_zero_scripts(self, collector):
        """Boundary 3: document with regular tags but zero forms, iframes, and scripts."""
        html = "<html><head><title>Test</title></head><body><div><h1>Header</h1><p>Text</p></div></body></html>"
        dom_case = {
            "html_content": html,
            "element_count": 7,
            "form_count": 0,
            "iframe_count": 0,
            "script_count": 0,
        }
        sandbox = _make_mock_sandbox(dom_case)
        result = await collector.collect_dom_data(sandbox)

        assert result.structure_metrics["element_count"] == 7
        assert result.structure_metrics["form_count"] == 0
        assert result.structure_metrics["iframe_count"] == 0
        assert result.structure_metrics["script_count"] == 0
        assert result.failed is False

    async def test_forms_only_document(self, collector):
        """Boundary 4: document containing only forms."""
        html = "<html><body><form id='f1'></form><form id='f2'></form><form id='f3'></form></body></html>"
        dom_case = {
            "html_content": html,
            "element_count": 5,
            "form_count": 3,
            "iframe_count": 0,
            "script_count": 0,
        }
        sandbox = _make_mock_sandbox(dom_case)
        result = await collector.collect_dom_data(sandbox)

        assert result.structure_metrics["element_count"] == 5
        assert result.structure_metrics["form_count"] == 3
        assert result.structure_metrics["iframe_count"] == 0
        assert result.structure_metrics["script_count"] == 0

    async def test_iframes_only_document(self, collector):
        """Boundary 5: document containing only iframes."""
        html = "<html><body><iframe src='a'></iframe><iframe src='b'></iframe></body></html>"
        dom_case = {
            "html_content": html,
            "element_count": 4,
            "form_count": 0,
            "iframe_count": 2,
            "script_count": 0,
        }
        sandbox = _make_mock_sandbox(dom_case)
        result = await collector.collect_dom_data(sandbox)

        assert result.structure_metrics["element_count"] == 4
        assert result.structure_metrics["form_count"] == 0
        assert result.structure_metrics["iframe_count"] == 2
        assert result.structure_metrics["script_count"] == 0

    async def test_scripts_only_document(self, collector):
        """Boundary 6: document containing only scripts."""
        html = "<html><head><script>1</script><script>2</script></head><body><script>3</script><script>4</script></body></html>"
        dom_case = {
            "html_content": html,
            "element_count": 7,
            "form_count": 0,
            "iframe_count": 0,
            "script_count": 4,
        }
        sandbox = _make_mock_sandbox(dom_case)
        result = await collector.collect_dom_data(sandbox)

        assert result.structure_metrics["element_count"] == 7
        assert result.structure_metrics["form_count"] == 0
        assert result.structure_metrics["iframe_count"] == 0
        assert result.structure_metrics["script_count"] == 4

    async def test_mixed_document(self, collector):
        """Boundary 7: mixed document with forms, iframes, scripts, and regular elements."""
        html = (
            "<!DOCTYPE html><html><head><title>Mix</title><script>var a=1;</script></head>"
            "<body><form><input/></form><iframe></iframe><div><p>Hello</p></div></body></html>"
        )
        dom_case = {
            "html_content": html,
            "element_count": 10,
            "form_count": 1,
            "iframe_count": 1,
            "script_count": 1,
        }
        sandbox = _make_mock_sandbox(dom_case)
        result = await collector.collect_dom_data(sandbox)

        assert result.html_content == html
        assert result.structure_metrics["element_count"] == 10
        assert result.structure_metrics["form_count"] == 1
        assert result.structure_metrics["iframe_count"] == 1
        assert result.structure_metrics["script_count"] == 1
        assert result.failed is False

    async def test_unicode_and_special_character_content(self, collector):
        """Boundary 8: Unicode, emojis, entities, and multi-language content."""
        html = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'/><title>🔒 認証 Authentication</title></head>"
            "<body><div id='content'>안녕하세요 世界! Übergrößenträger &amp; © 2026</div>"
            "<form id='auth'><input placeholder='ユーザー名'/></form></body></html>"
        )
        dom_case = {
            "html_content": html,
            "element_count": 7,
            "form_count": 1,
            "iframe_count": 0,
            "script_count": 0,
        }
        sandbox = _make_mock_sandbox(dom_case)
        result = await collector.collect_dom_data(sandbox)

        assert result.html_content == html
        assert "🔒 認証 Authentication" in result.html_content
        assert "안녕하세요 世界!" in result.html_content
        assert result.structure_metrics["form_count"] == 1
        assert result.failed is False

    async def test_page_content_failure_raises_exception(self, collector):
        """Failure 9: page.content() exception is propagated from collect_dom_data."""
        sandbox = Mock()
        sandbox.page = Mock()
        sandbox.page.content = AsyncMock(side_effect=RuntimeError("Content evaluation timed out"))

        with pytest.raises(RuntimeError, match="Content evaluation timed out"):
            await collector.collect_dom_data(sandbox)

    async def test_page_content_failure_handled_by_safe_wrapper(self, collector):
        """Failure 10: page.content() failure sets failed=True via safe wrapper."""
        sandbox = Mock()
        sandbox.page = Mock()
        sandbox.page.content = AsyncMock(side_effect=RuntimeError("Content evaluation timed out"))

        result = await collector._collect_dom_data_safe(sandbox)

        assert isinstance(result, DOMData)
        assert result.failed is True
        assert result.html_content == ""
        assert result.structure_metrics == {}

    async def test_missing_page_raises_value_error(self, collector):
        """Failure 11: sandbox.page=None raises ValueError in collect_dom_data."""
        sandbox = Mock()
        sandbox.page = None

        with pytest.raises(ValueError, match="Sandbox page is not available"):
            await collector.collect_dom_data(sandbox)

    async def test_missing_page_handled_by_safe_wrapper(self, collector):
        """Failure 12: sandbox.page=None sets failed=True via safe wrapper."""
        sandbox = Mock()
        sandbox.page = None

        result = await collector._collect_dom_data_safe(sandbox)

        assert isinstance(result, DOMData)
        assert result.failed is True
        assert result.html_content == ""
        assert result.structure_metrics == {}
