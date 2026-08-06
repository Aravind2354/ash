"""Property-based tests for InputValidator class.

These tests use Hypothesis to generate random test cases and verify
universal properties of URL validation logic.

Tests validate:
- Property 30: URL Structure Validation
- Property 31: Protocol Validation
- Property 33: Private IP Rejection
- Property 34: URL Length Validation
- Property 35: Special Character Sanitization

**Validates: Requirements 9.1, 9.2, 9.4, 9.5, 9.6**
"""

import ipaddress
import pytest
from hypothesis import given, strategies as st, assume, settings
from urllib.parse import urlparse, quote
from src.input_validator import InputValidator


# ============================================================================
# Test Strategies (Smart Generators)
# ============================================================================

@st.composite
def valid_url_structure(draw):
    """Generate URLs with valid structure (scheme + host + optional components).
    
    **Property 30: URL Structure Validation**
    """
    # Valid protocols
    scheme = draw(st.sampled_from(['http', 'https']))
    
    # Valid host (domain name or public IP)
    host_strategy = st.one_of(
        # Domain names
        st.from_regex(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$', fullmatch=True),
        # Public IPv4 addresses (simplified - just use common public ranges)
        st.from_regex(r'^(8\.\d{1,3}\.\d{1,3}\.\d{1,3})$', fullmatch=True),
    )
    host = draw(host_strategy)
    
    # Optional port
    port = draw(st.one_of(st.none(), st.integers(min_value=1, max_value=65535)))
    
    # Optional path
    path = draw(st.one_of(
        st.none(),
        st.from_regex(r'^/[a-zA-Z0-9/_\-\.]*$', fullmatch=True)
    ))
    
    # Optional query
    query = draw(st.one_of(
        st.none(),
        st.from_regex(r'^[a-zA-Z0-9=_\-]*$', fullmatch=True)
    ))
    
    # Optional fragment
    fragment = draw(st.one_of(
        st.none(),
        st.from_regex(r'^[a-zA-Z0-9_\-]*$', fullmatch=True)
    ))
    
    # Construct URL
    url = f"{scheme}://{host}"
    if port:
        url += f":{port}"
    if path:
        url += path
    if query:
        url += f"?{query}"
    if fragment:
        url += f"#{fragment}"
    
    # Ensure URL is not too long
    assume(len(url) <= 2048)
    
    return url


@st.composite
def invalid_url_structure(draw):
    """Generate URLs with invalid structure (missing scheme or host).
    
    **Property 30: URL Structure Validation**
    """
    choice = draw(st.integers(min_value=1, max_value=3))
    
    if choice == 1:
        # Missing scheme
        host = draw(st.from_regex(r'^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?\.[a-z]{2,6}$', fullmatch=True))
        return f"{host}/path"
    elif choice == 2:
        # Missing host
        scheme = draw(st.sampled_from(['http', 'https']))
        return f"{scheme}://"
    else:
        # Just a path
        path = draw(st.from_regex(r'^[a-z0-9/_\-\.]+$', fullmatch=True))
        return f"/{path}"


@st.composite
def invalid_protocol_url(draw):
    """Generate URLs with invalid protocols (not HTTP/HTTPS).
    
    **Property 31: Protocol Validation**
    """
    # Invalid protocols
    scheme = draw(st.sampled_from(['ftp', 'file', 'javascript', 'data', 'ssh', 'telnet', 'ws', 'wss']))
    host = draw(st.from_regex(r'^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?\.[a-z]{2,6}$', fullmatch=True))
    path = draw(st.one_of(st.none(), st.from_regex(r'^/[a-z0-9/_\-]*$', fullmatch=True)))
    
    url = f"{scheme}://{host}"
    if path:
        url += path
    
    return url


@st.composite
def private_ip_url(draw):
    """Generate URLs with private IP addresses.
    
    **Property 33: Private IP Rejection**
    """
    scheme = draw(st.sampled_from(['http', 'https']))
    
    # Choose a private IP range
    ip_type = draw(st.integers(min_value=1, max_value=6))
    
    if ip_type == 1:
        # Localhost 127.0.0.0/8
        ip = f"127.{draw(st.integers(0, 255))}.{draw(st.integers(0, 255))}.{draw(st.integers(0, 255))}"
    elif ip_type == 2:
        # 10.0.0.0/8
        ip = f"10.{draw(st.integers(0, 255))}.{draw(st.integers(0, 255))}.{draw(st.integers(0, 255))}"
    elif ip_type == 3:
        # 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
        ip = f"172.{draw(st.integers(16, 31))}.{draw(st.integers(0, 255))}.{draw(st.integers(0, 255))}"
    elif ip_type == 4:
        # 192.168.0.0/16
        ip = f"192.168.{draw(st.integers(0, 255))}.{draw(st.integers(0, 255))}"
    elif ip_type == 5:
        # IPv6 localhost ::1
        ip = "[::1]"
    else:
        # IPv6 ULA fc00::/7
        # Generate a simple ULA address
        hex_part = draw(st.from_regex(r'^[0-9a-f]{1,4}$', fullmatch=True))
        ip = f"[fc00::{hex_part}]"
    
    path = draw(st.one_of(st.none(), st.from_regex(r'^/[a-z0-9/_\-]*$', fullmatch=True)))
    
    url = f"{scheme}://{ip}"
    if path:
        url += path
    
    return url


@st.composite
def public_ip_url(draw):
    """Generate URLs with public IP addresses.
    
    **Property 33: Private IP Rejection** (should be accepted)
    """
    scheme = draw(st.sampled_from(['http', 'https']))
    
    # Generate public IPs from well-known ranges
    # Using Google DNS, Cloudflare DNS, and other public services
    ip = draw(st.sampled_from([
        '8.8.8.8',      # Google DNS
        '8.8.4.4',      # Google DNS
        '1.1.1.1',      # Cloudflare DNS
        '1.0.0.1',      # Cloudflare DNS
        '208.67.222.222', # OpenDNS
        '9.9.9.9',      # Quad9 DNS
    ]))
    
    path = draw(st.one_of(st.none(), st.from_regex(r'^/[a-z0-9/_\-]*$', fullmatch=True)))
    
    url = f"{scheme}://{ip}"
    if path:
        url += path
    
    return url


@st.composite
def url_with_length(draw, min_length=0, max_length=3000):
    """Generate URLs with specific length constraints.
    
    **Property 34: URL Length Validation**
    """
    scheme = draw(st.sampled_from(['http', 'https']))
    host = "example.com"
    base = f"{scheme}://{host}/"
    
    # Calculate remaining length for path
    remaining = draw(st.integers(min_value=min_length - len(base), max_value=max_length - len(base)))
    remaining = max(0, remaining)
    
    # Generate path to reach desired length
    path = 'a' * remaining
    
    url = base + path
    return url


@st.composite
def url_with_special_chars(draw):
    """Generate URLs containing special characters that need sanitization.
    
    **Property 35: Special Character Sanitization**
    """
    scheme = draw(st.sampled_from(['http', 'https']))
    host = draw(st.from_regex(r'^[a-z0-9]([a-z0-9-]{0,20}[a-z0-9])?\.[a-z]{2,6}$', fullmatch=True))
    
    # Special characters that should be encoded
    special_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'", '\\', '\n', '\r', '\t']
    
    # Generate path with some special characters
    num_special = draw(st.integers(min_value=1, max_value=5))
    chars_to_include = draw(st.lists(st.sampled_from(special_chars), min_size=num_special, max_size=num_special))
    
    # Build path with special characters interspersed
    path_parts = [draw(st.from_regex(r'^[a-z0-9]+$', fullmatch=True)) for _ in range(num_special + 1)]
    path = "/".join([path_parts[i] + char for i, char in enumerate(chars_to_include)]) + path_parts[-1]
    
    url = f"{scheme}://{host}/{path}"
    
    # Ensure URL is not too long
    assume(len(url) <= 2048)
    
    return url, chars_to_include


# ============================================================================
# Property Tests
# ============================================================================

class TestURLStructureValidation:
    """Property tests for URL structure validation.
    
    **Property 30: URL Structure Validation**
    **Validates: Requirements 9.1**
    """
    
    @given(valid_url_structure())
    @settings(max_examples=100)
    def test_property_30_valid_structure_accepted(self, url):
        """Property: URLs with valid structure (scheme + host) are accepted."""
        validator = InputValidator()
        is_valid, error = validator.validate_url(url)
        
        # Should be valid since it has scheme and host
        assert is_valid is True, f"Valid URL structure rejected: {url}, error: {error}"
        assert error is None
    
    @given(invalid_url_structure())
    @settings(max_examples=100)
    def test_property_30_invalid_structure_rejected(self, url):
        """Property: URLs missing scheme or host are rejected."""
        validator = InputValidator()
        is_valid, error = validator.validate_url(url)
        
        # Should be invalid due to missing components
        assert is_valid is False, f"Invalid URL structure accepted: {url}"
        assert error is not None
        assert any(keyword in error.lower() for keyword in ['missing', 'scheme', 'host', 'http'])


class TestProtocolValidation:
    """Property tests for protocol validation.
    
    **Property 31: Protocol Validation**
    **Validates: Requirements 9.2**
    """
    
    @given(st.from_regex(r'^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?\.[a-z]{2,6}$', fullmatch=True))
    @settings(max_examples=50)
    def test_property_31_http_protocol_accepted(self, host):
        """Property: URLs with HTTP protocol are accepted."""
        validator = InputValidator()
        url = f"http://{host}"
        is_valid, error = validator.validate_url(url)
        
        assert is_valid is True, f"HTTP URL rejected: {url}, error: {error}"
        assert error is None
    
    @given(st.from_regex(r'^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?\.[a-z]{2,6}$', fullmatch=True))
    @settings(max_examples=50)
    def test_property_31_https_protocol_accepted(self, host):
        """Property: URLs with HTTPS protocol are accepted."""
        validator = InputValidator()
        url = f"https://{host}"
        is_valid, error = validator.validate_url(url)
        
        assert is_valid is True, f"HTTPS URL rejected: {url}, error: {error}"
        assert error is None
    
    @given(invalid_protocol_url())
    @settings(max_examples=100)
    def test_property_31_non_http_protocols_rejected(self, url):
        """Property: URLs with protocols other than HTTP/HTTPS are rejected."""
        validator = InputValidator()
        is_valid, error = validator.validate_url(url)
        
        assert is_valid is False, f"Non-HTTP/HTTPS URL accepted: {url}"
        assert error is not None
        assert "scheme must be http or https" in error.lower()


class TestPrivateIPRejection:
    """Property tests for private IP rejection.
    
    **Property 33: Private IP Rejection**
    **Validates: Requirements 9.4**
    """
    
    @given(private_ip_url())
    @settings(max_examples=100)
    def test_property_33_private_ips_rejected(self, url):
        """Property: URLs with private IP addresses are rejected."""
        validator = InputValidator()
        is_valid, error = validator.validate_url(url)
        
        assert is_valid is False, f"Private IP URL accepted: {url}"
        assert error is not None
        assert any(keyword in error.lower() for keyword in ['private', 'localhost', 'not allowed'])
    
    @given(public_ip_url())
    @settings(max_examples=50)
    def test_property_33_public_ips_accepted(self, url):
        """Property: URLs with public IP addresses are accepted."""
        validator = InputValidator()
        is_valid, error = validator.validate_url(url)
        
        assert is_valid is True, f"Public IP URL rejected: {url}, error: {error}"
        assert error is None
    
    @given(st.sampled_from(['http', 'https']), st.sampled_from(['localhost', 'LOCALHOST', 'Localhost', 'localhost.localdomain']))
    @settings(max_examples=20)
    def test_property_33_localhost_names_rejected(self, scheme, localhost_name):
        """Property: URLs with localhost by name are rejected (case-insensitive)."""
        validator = InputValidator()
        url = f"{scheme}://{localhost_name}/test"
        is_valid, error = validator.validate_url(url)
        
        assert is_valid is False, f"Localhost URL accepted: {url}"
        assert error is not None
        assert "localhost" in error.lower()


class TestURLLengthValidation:
    """Property tests for URL length validation.
    
    **Property 34: URL Length Validation**
    **Validates: Requirements 9.5**
    """
    
    @given(url_with_length(min_length=1, max_length=2048))
    @settings(max_examples=100)
    def test_property_34_urls_within_limit_accepted(self, url):
        """Property: URLs with length <= 2048 characters are accepted."""
        validator = InputValidator()
        
        # Verify our assumption
        assume(len(url) <= 2048)
        
        is_valid, error = validator.validate_url(url)
        
        assert is_valid is True, f"Valid length URL rejected: length={len(url)}, url={url[:100]}..., error: {error}"
        assert error is None
    
    @given(url_with_length(min_length=2049, max_length=3000))
    @settings(max_examples=100)
    def test_property_34_urls_over_limit_rejected(self, url):
        """Property: URLs with length > 2048 characters are rejected."""
        validator = InputValidator()
        
        # Verify our assumption
        assume(len(url) > 2048)
        
        is_valid, error = validator.validate_url(url)
        
        assert is_valid is False, f"Over-length URL accepted: length={len(url)}"
        assert error is not None
        assert "2048" in error
        assert "maximum length" in error.lower()
    
    @given(st.integers(min_value=2048, max_value=2048))
    @settings(max_examples=10)
    def test_property_34_boundary_length_2048_accepted(self, target_length):
        """Property: URLs with exactly 2048 characters are accepted (boundary test)."""
        validator = InputValidator()
        
        # Construct URL with exact length
        base = "https://example.com/"
        padding = "a" * (target_length - len(base))
        url = base + padding
        
        assert len(url) == 2048
        
        is_valid, error = validator.validate_url(url)
        
        assert is_valid is True, f"Boundary length URL rejected: length={len(url)}, error: {error}"
        assert error is None


class TestSpecialCharacterSanitization:
    """Property tests for special character sanitization.
    
    **Property 35: Special Character Sanitization**
    **Validates: Requirements 9.6**
    """
    
    @given(url_with_special_chars())
    @settings(max_examples=100)
    def test_property_35_special_chars_encoded(self, url_and_chars):
        """Property: Special characters in URLs are percent-encoded."""
        url, special_chars = url_and_chars
        validator = InputValidator()
        
        sanitized = validator.sanitize_url(url)
        
        # Verify that special characters are encoded
        # The sanitized URL should not contain the raw special characters
        for char in special_chars:
            # Skip checking & in query strings (valid usage)
            if char == '&' and '?' in url:
                continue
            
            # For visible characters, check they're not in sanitized version
            if char not in ['\n', '\r', '\t']:
                # Count occurrences - there should be fewer (or zero) after sanitization
                # Note: Some characters might appear in scheme/host which we don't sanitize
                scheme_and_host = sanitized.split('//', 1)[0] + '//' + sanitized.split('//', 1)[1].split('/', 1)[0] if '//' in sanitized else ''
                path_and_beyond = sanitized[len(scheme_and_host):] if scheme_and_host else sanitized
                
                # The path portion should not contain unencoded special chars
                assert char not in path_and_beyond or path_and_beyond.count(char) < url.count(char), \
                    f"Special character '{char}' not encoded in path: {sanitized}"
    
    @given(st.sampled_from(['http', 'https']),
           st.from_regex(r'^[a-z0-9]([a-z0-9-]{0,20}[a-z0-9])?\.[a-z]{2,6}$', fullmatch=True),
           st.sampled_from([';', '|', '`', '$', '(', ')']))
    @settings(max_examples=50)
    def test_property_35_specific_char_sanitization(self, scheme, host, special_char):
        """Property: Specific special characters are percent-encoded correctly."""
        validator = InputValidator()
        url = f"{scheme}://{host}/path{special_char}value"
        
        sanitized = validator.sanitize_url(url)
        
        # Check the character is encoded in the path
        path_part = sanitized.split(host, 1)[1] if host in sanitized else sanitized
        
        # Mapping of characters to their percent-encoded equivalents
        encodings = {
            ';': '%3B',
            '&': '%26',
            '|': '%7C',
            '`': '%60',
            '$': '%24',
            '(': '%28',
            ')': '%29',
            '<': '%3C',
            '>': '%3E',
            '"': '%22',
            "'": '%27',
            '\\': '%5C',
        }
        
        if special_char in encodings:
            assert encodings[special_char] in sanitized, \
                f"Character '{special_char}' not encoded to '{encodings[special_char]}' in: {sanitized}"
    
    @given(valid_url_structure())
    @settings(max_examples=50)
    def test_property_35_valid_chars_preserved(self, url):
        """Property: Valid URL characters are preserved during sanitization."""
        validator = InputValidator()
        
        # Parse original URL
        parsed = urlparse(url)
        
        sanitized = validator.sanitize_url(url)
        parsed_sanitized = urlparse(sanitized)
        
        # Scheme and host should be identical
        assert parsed.scheme == parsed_sanitized.scheme, "Scheme changed during sanitization"
        assert parsed.netloc == parsed_sanitized.netloc, "Host changed during sanitization"
    
    @given(st.sampled_from(['http', 'https']),
           st.from_regex(r'^[a-z0-9]([a-z0-9-]{0,20}[a-z0-9])?\.[a-z]{2,6}$', fullmatch=True))
    @settings(max_examples=30)
    def test_property_35_sanitize_whitespace_control_chars(self, scheme, host):
        """Property: Whitespace and control characters (newline, tab, etc.) are encoded."""
        validator = InputValidator()
        url = f"{scheme}://{host}/path\nvalue\r\twith\tcontrols"
        
        sanitized = validator.sanitize_url(url)
        
        # Check control characters are encoded
        assert '\n' not in sanitized, "Newline not encoded"
        assert '\r' not in sanitized, "Carriage return not encoded"
        assert '\t' not in sanitized, "Tab not encoded"
        
        # Check they're encoded as percent-encoded values
        assert '%0A' in sanitized or '%0D' in sanitized or '%09' in sanitized, \
            "Control characters not percent-encoded"


# ============================================================================
# Combined Property Tests
# ============================================================================

class TestCombinedValidationProperties:
    """Property tests that combine multiple validation aspects."""
    
    @given(valid_url_structure())
    @settings(max_examples=100)
    def test_combined_valid_url_passes_all_checks(self, url):
        """Property: URLs that pass structure and protocol checks are accepted."""
        validator = InputValidator()
        
        # Only test if URL is not too long
        assume(len(url) <= 2048)
        
        is_valid, error = validator.validate_url(url)
        
        # Should pass all validation checks
        assert is_valid is True, f"Valid URL rejected: {url}, error: {error}"
        assert error is None
    
    @given(valid_url_structure())
    @settings(max_examples=50)
    def test_combined_validate_and_sanitize_consistency(self, url):
        """Property: validate_and_sanitize returns consistent results."""
        validator = InputValidator()
        
        # Only test if URL is not too long
        assume(len(url) <= 2048)
        
        # Validate separately
        is_valid_separate, error_separate = validator.validate_url(url)
        
        # Validate and sanitize together
        is_valid_combined, error_combined, sanitized = validator.validate_and_sanitize(url)
        
        # Results should be consistent
        assert is_valid_separate == is_valid_combined, \
            "Validation results differ between separate and combined methods"
        assert error_separate == error_combined, \
            "Error messages differ between separate and combined methods"
        
        # Sanitized URL should also be valid if original was valid
        if is_valid_combined:
            is_valid_sanitized, _ = validator.validate_url(sanitized)
            assert is_valid_sanitized is True, \
                f"Sanitized URL is invalid: {sanitized} (original: {url})"
