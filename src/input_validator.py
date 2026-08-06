"""Input validation module for URL validation and sanitization.

This module provides the InputValidator class for validating URLs before
analysis, including protocol checks, private IP rejection, length validation,
and special character sanitization.
"""

import re
import ipaddress
from typing import Tuple, Optional
from urllib.parse import urlparse, quote


class InputValidator:
    """Validates and sanitizes URLs for website authenticity analysis.
    
    This class enforces security constraints on input URLs including:
    - Protocol validation (HTTP/HTTPS only)
    - Private IP address rejection
    - URL length limits
    - Special character sanitization
    """
    
    # Maximum allowed URL length (Requirement 9.5)
    MAX_URL_LENGTH = 2048
    
    # Private IP ranges to reject (Requirement 9.4)
    PRIVATE_IPV4_RANGES = [
        ipaddress.IPv4Network('127.0.0.0/8'),    # Localhost
        ipaddress.IPv4Network('10.0.0.0/8'),     # Private network
        ipaddress.IPv4Network('172.16.0.0/12'),  # Private network
        ipaddress.IPv4Network('192.168.0.0/16'), # Private network
    ]
    
    PRIVATE_IPV6_RANGES = [
        ipaddress.IPv6Network('fc00::/7'),  # Unique Local Address (ULA)
        ipaddress.IPv6Network('::1/128'),    # Localhost
    ]
    
    # Special characters that need percent-encoding to prevent injection (Requirement 9.6)
    SPECIAL_CHARS = [';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'", '\\', '\n', '\r', '\t']
    
    def __init__(self):
        """Initialize the InputValidator."""
        pass
    
    def validate_url(self, url: str) -> Tuple[bool, Optional[str]]:
        """Validate a URL against all security constraints.
        
        Validates: Requirements 9.1, 9.2, 9.3, 9.4, 9.5
        
        Args:
            url: The URL string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
            - is_valid: True if URL passes all validations, False otherwise
            - error_message: None if valid, descriptive error string if invalid
        """
        # Validate URL length first (9.5)
        if not self._validate_length(url):
            return False, f"URL exceeds maximum length of {self.MAX_URL_LENGTH} characters"
        
        # Validate protocol first (9.2) - check this before structure for clearer error messages
        is_valid_protocol, error = self._validate_protocol(url)
        if not is_valid_protocol:
            return False, error
        
        # Validate URL structure (9.1)
        is_valid_structure, error = self._validate_structure(url)
        if not is_valid_structure:
            return False, error
        
        # Validate against private IPs (9.4)
        is_valid_host, error = self._validate_host(url)
        if not is_valid_host:
            return False, error
        
        return True, None
    
    def _validate_structure(self, url: str) -> Tuple[bool, Optional[str]]:
        """Validate URL structure contains required components.
        
        Validates: Requirement 9.1
        
        Args:
            url: The URL string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            parsed = urlparse(url)
            
            # Must have scheme and host (netloc)
            if not parsed.scheme:
                return False, "URL validation failed: missing scheme component"
            
            if not parsed.netloc:
                return False, "URL validation failed: missing host component"
            
            # Path, query, and fragment are optional
            return True, None
            
        except Exception as e:
            return False, f"URL validation failed: invalid URL structure - {str(e)}"
    
    def _validate_protocol(self, url: str) -> Tuple[bool, Optional[str]]:
        """Validate URL uses HTTP or HTTPS protocol only.
        
        Validates: Requirement 9.2
        
        Args:
            url: The URL string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            
            if scheme not in ['http', 'https']:
                return False, f"URL validation failed: scheme must be http or https, got {scheme}"
            
            return True, None
            
        except Exception as e:
            return False, f"URL validation failed: cannot parse protocol - {str(e)}"
    
    def _validate_host(self, url: str) -> Tuple[bool, Optional[str]]:
        """Validate host is not a private IP address.
        
        Validates: Requirement 9.4
        Rejects: localhost, 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 
                 192.168.0.0/16, fc00::/7
        
        Args:
            url: The URL string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            
            if not host:
                return False, "URL validation failed: cannot extract hostname"
            
            # Check for localhost by name
            if host.lower() in ['localhost', 'localhost.localdomain']:
                return False, "URL validation failed: localhost addresses are not allowed"
            
            # Try to parse as IP address
            try:
                ip = ipaddress.ip_address(host)
                
                # Check against private IPv4 ranges
                if isinstance(ip, ipaddress.IPv4Address):
                    for private_range in self.PRIVATE_IPV4_RANGES:
                        if ip in private_range:
                            return False, f"URL validation failed: private IP address {host} is not allowed"
                
                # Check against private IPv6 ranges
                if isinstance(ip, ipaddress.IPv6Address):
                    for private_range in self.PRIVATE_IPV6_RANGES:
                        if ip in private_range:
                            return False, f"URL validation failed: private IP address {host} is not allowed"
                
            except ValueError:
                # Not an IP address, it's a hostname - that's fine
                pass
            
            return True, None
            
        except Exception as e:
            return False, f"URL validation failed: cannot validate host - {str(e)}"
    
    def _validate_length(self, url: str) -> bool:
        """Validate URL length does not exceed maximum.
        
        Validates: Requirement 9.5
        
        Args:
            url: The URL string to validate
            
        Returns:
            True if length is acceptable, False otherwise
        """
        return len(url) <= self.MAX_URL_LENGTH
    
    def sanitize_url(self, url: str) -> str:
        """Sanitize URL by percent-encoding special characters.
        
        Validates: Requirement 9.6
        Encodes: semicolons, ampersands, pipes, backticks, shell metacharacters
        
        Args:
            url: The URL string to sanitize
            
        Returns:
            Sanitized URL with special characters percent-encoded
        """
        # First, sanitize the full URL to encode control characters before parsing
        # urlparse() removes control characters, so we must encode them first
        pre_sanitized = self._sanitize_component(url)
        
        # Parse the pre-sanitized URL to handle each component separately
        try:
            parsed = urlparse(pre_sanitized)
            
            # urlparse separates path and params (separated by ;)
            # We need to combine them and sanitize together
            full_path = parsed.path
            if parsed.params:
                full_path += ';' + parsed.params
            
            # Reconstruct URL with sanitized components
            sanitized_path = self._sanitize_component(full_path) if full_path else ''
            sanitized_query = self._sanitize_component(parsed.query) if parsed.query else ''
            sanitized_fragment = self._sanitize_component(parsed.fragment) if parsed.fragment else ''
            
            # Reconstruct the URL
            result = f"{parsed.scheme}://{parsed.netloc}{sanitized_path}"
            if sanitized_query:
                result += f"?{sanitized_query}"
            if sanitized_fragment:
                result += f"#{sanitized_fragment}"
            
            return result
            
        except Exception:
            # If parsing fails, return the pre-sanitized URL
            return pre_sanitized
    
    def _sanitize_component(self, component: str) -> str:
        """Sanitize a URL component by encoding special characters.
        
        Args:
            component: URL component to sanitize
            
        Returns:
            Sanitized component with special characters encoded
        """
        result = component
        # Define percent-encoded equivalents for special characters
        char_encodings = {
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
            '\n': '%0A',
            '\r': '%0D',
            '\t': '%09',
        }
        
        for char, encoded in char_encodings.items():
            result = result.replace(char, encoded)
        
        return result
    
    def validate_and_sanitize(self, url: str) -> Tuple[bool, Optional[str], str]:
        """Validate and sanitize a URL in one operation.
        
        This is a convenience method that performs both validation and sanitization.
        
        Args:
            url: The URL string to validate and sanitize
            
        Returns:
            Tuple of (is_valid, error_message, sanitized_url)
            - is_valid: True if URL passes all validations
            - error_message: None if valid, descriptive error string if invalid
            - sanitized_url: The sanitized version of the URL
        """
        # Validate first
        is_valid, error = self.validate_url(url)
        
        # Sanitize regardless of validation result (for logging/reporting)
        sanitized = self.sanitize_url(url) if is_valid else url
        
        return is_valid, error, sanitized
