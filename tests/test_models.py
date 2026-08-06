"""
Unit tests for data models in the Website Authenticity Detector.
"""

import pytest
from hypothesis import given, strategies as st
from src.models import (
    NetworkData,
    DOMData,
    JavaScriptData,
    VisualData,
    SSLData,
    AnalysisData,
    AnalysisResult,
)


class TestNetworkData:
    """Tests for NetworkData dataclass."""
    
    def test_network_data_creation(self):
        """Test creating NetworkData with valid values."""
        data = NetworkData(
            request_count=42,
            unique_domains=["example.com", "cdn.example.com"],
            protocol_distribution={"https": 40, "http": 2},
            failed=False
        )
        assert data.request_count == 42
        assert len(data.unique_domains) == 2
        assert data.protocol_distribution["https"] == 40
        assert data.failed is False
    
    def test_network_data_failed_flag(self):
        """Test NetworkData with failed flag set."""
        data = NetworkData(
            request_count=0,
            unique_domains=[],
            protocol_distribution={},
            failed=True
        )
        assert data.failed is True
    
    def test_network_data_default_failed_value(self):
        """Test that failed defaults to False."""
        data = NetworkData(
            request_count=10,
            unique_domains=["test.com"],
            protocol_distribution={"https": 10}
        )
        assert data.failed is False


class TestDOMData:
    """Tests for DOMData dataclass."""
    
    def test_dom_data_creation(self):
        """Test creating DOMData with valid HTML content."""
        data = DOMData(
            html_content="<html><body>Test</body></html>",
            structure_metrics={
                "total_elements": 50,
                "form_count": 2,
                "iframe_count": 0
            },
            failed=False
        )
        assert "Test" in data.html_content
        assert data.structure_metrics["total_elements"] == 50
        assert data.failed is False
    
    def test_dom_data_empty_content(self):
        """Test DOMData with empty HTML content."""
        data = DOMData(
            html_content="",
            structure_metrics={"total_elements": 0},
            failed=False
        )
        assert data.html_content == ""
        assert data.structure_metrics["total_elements"] == 0


class TestJavaScriptData:
    """Tests for JavaScriptData dataclass."""
    
    def test_javascript_data_creation(self):
        """Test creating JavaScriptData with valid metrics."""
        data = JavaScriptData(
            script_count=15,
            dom_modifications=120,
            external_api_calls=5,
            failed=False
        )
        assert data.script_count == 15
        assert data.dom_modifications == 120
        assert data.external_api_calls == 5
        assert data.failed is False
    
    def test_javascript_data_zero_values(self):
        """Test JavaScriptData with zero values (static site)."""
        data = JavaScriptData(
            script_count=0,
            dom_modifications=0,
            external_api_calls=0,
            failed=False
        )
        assert data.script_count == 0
        assert data.dom_modifications == 0
        assert data.external_api_calls == 0


class TestVisualData:
    """Tests for VisualData dataclass."""
    
    def test_visual_data_creation(self):
        """Test creating VisualData with valid characteristics."""
        data = VisualData(
            screenshot_path="/tmp/screenshot.png",
            layout_characteristics={
                "viewport_width": 1920,
                "viewport_height": 1080,
                "has_images": True,
                "color_palette": ["#FFFFFF", "#000000"]
            },
            failed=False
        )
        assert data.screenshot_path == "/tmp/screenshot.png"
        assert data.layout_characteristics["viewport_width"] == 1920
        assert data.layout_characteristics["has_images"] is True
        assert data.failed is False
    
    def test_visual_data_failed(self):
        """Test VisualData when collection fails."""
        data = VisualData(
            screenshot_path="",
            layout_characteristics={},
            failed=True
        )
        assert data.failed is True


class TestSSLData:
    """Tests for SSLData dataclass."""
    
    def test_ssl_data_creation(self):
        """Test creating SSLData with valid certificate info."""
        data = SSLData(
            issuer="Let's Encrypt",
            expiration_date="2025-12-31T23:59:59Z",
            chain_valid=True,
            failed=False
        )
        assert data.issuer == "Let's Encrypt"
        assert data.expiration_date == "2025-12-31T23:59:59Z"
        assert data.chain_valid is True
        assert data.failed is False
    
    def test_ssl_data_invalid_certificate(self):
        """Test SSLData with invalid certificate chain."""
        data = SSLData(
            issuer="Self-Signed",
            expiration_date="2024-01-01T00:00:00Z",
            chain_valid=False,
            failed=False
        )
        assert data.chain_valid is False
    
    def test_ssl_data_http_site(self):
        """Test SSLData when collection fails (HTTP site)."""
        data = SSLData(
            issuer="",
            expiration_date="",
            chain_valid=False,
            failed=True
        )
        assert data.failed is True


class TestAnalysisData:
    """Tests for AnalysisData container class."""
    
    def test_analysis_data_all_categories_collected(self):
        """Test AnalysisData with all 5 categories successfully collected."""
        network = NetworkData(10, ["test.com"], {"https": 10})
        dom = DOMData("<html></html>", {"total_elements": 5})
        javascript = JavaScriptData(3, 10, 2)
        visual = VisualData("/tmp/screen.png", {"viewport_width": 1920})
        ssl = SSLData("Let's Encrypt", "2025-12-31T23:59:59Z", True)
        
        data = AnalysisData(
            network=network,
            dom=dom,
            javascript=javascript,
            visual=visual,
            ssl=ssl
        )
        
        assert data.categories_collected == 5
        assert data.timeout_occurred is False
    
    def test_analysis_data_partial_collection(self):
        """Test AnalysisData with only 3 categories collected."""
        network = NetworkData(10, ["test.com"], {"https": 10})
        javascript = JavaScriptData(3, 10, 2)
        ssl = SSLData("Let's Encrypt", "2025-12-31T23:59:59Z", True)
        
        data = AnalysisData(
            network=network,
            dom=None,
            javascript=javascript,
            visual=None,
            ssl=ssl
        )
        
        assert data.categories_collected == 3
        assert data.dom is None
        assert data.visual is None
    
    def test_analysis_data_with_failed_categories(self):
        """Test AnalysisData where some categories have failed flag set."""
        network = NetworkData(10, ["test.com"], {"https": 10}, failed=False)
        dom = DOMData("", {}, failed=True)
        javascript = JavaScriptData(0, 0, 0, failed=True)
        visual = VisualData("", {}, failed=False)
        ssl = SSLData("", "", False, failed=True)
        
        data = AnalysisData(
            network=network,
            dom=dom,
            javascript=javascript,
            visual=visual,
            ssl=ssl
        )
        
        # Only network and visual should count (not failed)
        assert data.categories_collected == 2
    
    def test_analysis_data_timeout_flag(self):
        """Test AnalysisData with timeout flag set."""
        data = AnalysisData(
            network=NetworkData(5, ["test.com"], {"https": 5}),
            timeout_occurred=True
        )
        
        assert data.timeout_occurred is True
        assert data.categories_collected == 1
    
    def test_analysis_data_empty(self):
        """Test AnalysisData with no categories collected."""
        data = AnalysisData()
        
        assert data.categories_collected == 0
        assert data.network is None
        assert data.dom is None
        assert data.javascript is None
        assert data.visual is None
        assert data.ssl is None
    
    def test_analysis_data_categories_collected_recalculation(self):
        """Test that categories_collected is calculated in __post_init__."""
        network = NetworkData(10, ["test.com"], {"https": 10})
        dom = DOMData("<html></html>", {"total_elements": 5})
        
        # Create with wrong initial count
        data = AnalysisData(
            network=network,
            dom=dom,
            categories_collected=99  # Wrong value, should be recalculated
        )
        
        # Should be recalculated to 2
        assert data.categories_collected == 2


class TestAnalysisResult:
    """Tests for AnalysisResult dataclass."""
    
    def test_analysis_result_creation(self):
        """Test creating AnalysisResult with complete data."""
        analysis_data = AnalysisData(
            network=NetworkData(10, ["test.com"], {"https": 10})
        )
        
        result = AnalysisResult(
            authenticity_score=0.85,
            fake_score=0.15,
            confidence_indicator="HIGH",
            url="https://example.com",
            analysis_data=analysis_data,
            timestamps={
                "analysis_start": "2024-01-15T10:00:00Z",
                "analysis_completion": "2024-01-15T10:00:30Z"
            },
            top_factors=["Valid SSL", "Low redirect count", "Known domain"],
            suspicious_indicators=[]
        )
        
        assert result.authenticity_score == 0.85
        assert result.fake_score == 0.15
        assert result.confidence_indicator == "HIGH"
        assert result.url == "https://example.com"
        assert result.error_message is None
        assert len(result.top_factors) == 3
        assert len(result.suspicious_indicators) == 0
    
    def test_analysis_result_with_error(self):
        """Test AnalysisResult with error message."""
        analysis_data = AnalysisData()
        
        result = AnalysisResult(
            authenticity_score=0.0,
            fake_score=0.0,
            confidence_indicator="LOW",
            url="https://example.com",
            analysis_data=analysis_data,
            timestamps={
                "analysis_start": "2024-01-15T10:00:00Z",
                "analysis_completion": "2024-01-15T10:00:30Z"
            },
            top_factors=[],
            suspicious_indicators=[],
            error_message="Insufficient data: only 0 of 5 categories collected"
        )
        
        assert result.error_message is not None
        assert "Insufficient data" in result.error_message
    
    def test_analysis_result_with_suspicious_indicators(self):
        """Test AnalysisResult with suspicious indicators (Fake_Score > 0.5)."""
        analysis_data = AnalysisData(
            network=NetworkData(150, ["suspicious.com"], {"http": 150})
        )
        
        result = AnalysisResult(
            authenticity_score=0.25,
            fake_score=0.75,
            confidence_indicator="MEDIUM",
            url="https://phishing-example.com",
            analysis_data=analysis_data,
            timestamps={
                "analysis_start": "2024-01-15T10:00:00Z",
                "analysis_completion": "2024-01-15T10:00:30Z"
            },
            top_factors=["Multiple redirects", "No SSL", "Unusual domain"],
            suspicious_indicators=["HTTP only", "Excessive requests", "Unknown domain"]
        )
        
        assert result.fake_score > 0.5
        assert len(result.suspicious_indicators) == 3
        assert "HTTP only" in result.suspicious_indicators
    
    def test_analysis_result_score_boundaries(self):
        """Test AnalysisResult with boundary score values."""
        analysis_data = AnalysisData()
        
        # Test with 0.0 and 1.0 scores
        result = AnalysisResult(
            authenticity_score=1.0,
            fake_score=0.0,
            confidence_indicator="HIGH",
            url="https://trusted.com",
            analysis_data=analysis_data,
            timestamps={
                "analysis_start": "2024-01-15T10:00:00Z",
                "analysis_completion": "2024-01-15T10:00:30Z"
            },
            top_factors=["Official site", "Valid SSL", "Verified domain"],
            suspicious_indicators=[]
        )
        
        assert result.authenticity_score == 1.0
        assert result.fake_score == 0.0
        assert result.authenticity_score + result.fake_score == 1.0



# ============================================================================
# Property-Based Tests
# ============================================================================


class TestAnalysisDataAggregationProperty:
    """
    Property-based tests for Analysis Data Aggregation.
    
    **Validates: Requirements 2.6**
    """
    
    # Helper strategies for generating data categories
    @staticmethod
    def network_data_strategy():
        """Generate NetworkData with random failed flag."""
        return st.builds(
            NetworkData,
            request_count=st.integers(min_value=0, max_value=1000),
            unique_domains=st.lists(st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='.-')), min_size=0, max_size=10),
            protocol_distribution=st.dictionaries(
                st.sampled_from(['http', 'https', 'ws', 'wss']),
                st.integers(min_value=0, max_value=500),
                min_size=0,
                max_size=4
            ),
            failed=st.booleans()
        )
    
    @staticmethod
    def dom_data_strategy():
        """Generate DOMData with random failed flag."""
        return st.builds(
            DOMData,
            html_content=st.text(min_size=0, max_size=500),
            structure_metrics=st.dictionaries(
                st.sampled_from(['total_elements', 'form_count', 'iframe_count', 'script_tag_count']),
                st.integers(min_value=0, max_value=100),
                min_size=0,
                max_size=4
            ),
            failed=st.booleans()
        )
    
    @staticmethod
    def javascript_data_strategy():
        """Generate JavaScriptData with random failed flag."""
        return st.builds(
            JavaScriptData,
            script_count=st.integers(min_value=0, max_value=100),
            dom_modifications=st.integers(min_value=0, max_value=500),
            external_api_calls=st.integers(min_value=0, max_value=50),
            failed=st.booleans()
        )
    
    @staticmethod
    def visual_data_strategy():
        """Generate VisualData with random failed flag."""
        return st.builds(
            VisualData,
            screenshot_path=st.text(min_size=0, max_size=100),
            layout_characteristics=st.dictionaries(
                st.sampled_from(['viewport_width', 'viewport_height', 'has_images']),
                st.one_of(st.integers(min_value=0, max_value=4000), st.booleans()),
                min_size=0,
                max_size=3
            ),
            failed=st.booleans()
        )
    
    @staticmethod
    def ssl_data_strategy():
        """Generate SSLData with random failed flag."""
        return st.builds(
            SSLData,
            issuer=st.text(min_size=0, max_size=100),
            expiration_date=st.text(min_size=0, max_size=50),
            chain_valid=st.booleans(),
            failed=st.booleans()
        )
    
    @given(
        network=st.one_of(st.none(), network_data_strategy.__func__()),
        dom=st.one_of(st.none(), dom_data_strategy.__func__()),
        javascript=st.one_of(st.none(), javascript_data_strategy.__func__()),
        visual=st.one_of(st.none(), visual_data_strategy.__func__()),
        ssl=st.one_of(st.none(), ssl_data_strategy.__func__()),
        timeout_occurred=st.booleans()
    )
    def test_property_analysis_data_aggregation(
        self, network, dom, javascript, visual, ssl, timeout_occurred
    ):
        """
        Property 6: Analysis Data Aggregation
        
        **Validates: Requirements 2.6**
        
        For any combination of collected data categories (some present, some absent),
        the aggregation logic SHALL produce a valid Analysis_Data structure with
        correct category counts and appropriate failure flags.
        
        This property test verifies:
        1. Categories_collected count matches the number of successfully collected categories
        2. Successfully collected = category is not None AND failed flag is False
        3. The Analysis_Data structure is valid and contains all provided categories
        4. Timeout flag is properly preserved
        """
        # Create AnalysisData with random combination of categories
        analysis_data = AnalysisData(
            network=network,
            dom=dom,
            javascript=javascript,
            visual=visual,
            ssl=ssl,
            timeout_occurred=timeout_occurred
        )
        
        # Manually calculate expected categories_collected
        expected_count = 0
        if network is not None and not network.failed:
            expected_count += 1
        if dom is not None and not dom.failed:
            expected_count += 1
        if javascript is not None and not javascript.failed:
            expected_count += 1
        if visual is not None and not visual.failed:
            expected_count += 1
        if ssl is not None and not ssl.failed:
            expected_count += 1
        
        # Property assertion 1: categories_collected must match expected count
        assert analysis_data.categories_collected == expected_count, \
            f"Expected {expected_count} categories collected, but got {analysis_data.categories_collected}"
        
        # Property assertion 2: categories_collected must be in valid range [0, 5]
        assert 0 <= analysis_data.categories_collected <= 5, \
            f"categories_collected must be between 0 and 5, got {analysis_data.categories_collected}"
        
        # Property assertion 3: All provided categories are present in structure
        assert analysis_data.network == network
        assert analysis_data.dom == dom
        assert analysis_data.javascript == javascript
        assert analysis_data.visual == visual
        assert analysis_data.ssl == ssl
        
        # Property assertion 4: Timeout flag is preserved
        assert analysis_data.timeout_occurred == timeout_occurred
        
        # Property assertion 5: Failed categories don't contribute to count
        if network is not None and network.failed:
            # Network exists but failed, so shouldn't count
            categories_without_network = sum([
                dom is not None and not dom.failed,
                javascript is not None and not javascript.failed,
                visual is not None and not visual.failed,
                ssl is not None and not ssl.failed,
            ])
            assert analysis_data.categories_collected == categories_without_network
        
        # Property assertion 6: None categories don't contribute to count
        if network is None:
            categories_without_network = sum([
                dom is not None and not dom.failed,
                javascript is not None and not javascript.failed,
                visual is not None and not visual.failed,
                ssl is not None and not ssl.failed,
            ])
            assert analysis_data.categories_collected == categories_without_network
