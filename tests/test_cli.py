"""Tests for the Command Line Interface (CLI) module."""

import json
import pytest
from unittest.mock import patch, MagicMock

from src.cli import build_parser, parse_fake_percentage, main


class TestCLIParsing:
    """Test CLI argument parsing and helper functions."""

    def test_build_parser_defaults(self):
        """Test parser with required URL argument."""
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"
        assert args.json_output is False
        assert args.output is None
        assert args.quiet is False

    def test_build_parser_options(self):
        """Test parser with optional flags."""
        parser = build_parser()
        args = parser.parse_args([
            "https://example.com",
            "--json",
            "-o", "out.json",
            "-q",
        ])
        assert args.url == "https://example.com"
        assert args.json_output is True
        assert args.output == "out.json"
        assert args.quiet is True

    def test_parse_fake_percentage_valid(self):
        """Test parsing percentage string to float."""
        assert parse_fake_percentage("14.50%") == 14.50
        assert parse_fake_percentage("85.00%") == 85.00
        assert parse_fake_percentage("0.00%") == 0.0
        assert parse_fake_percentage("100.00%") == 100.0

    def test_parse_fake_percentage_edge_cases(self):
        """Test parsing None or invalid percentage values."""
        assert parse_fake_percentage(None) == 0.0
        assert parse_fake_percentage("") == 0.0
        assert parse_fake_percentage("invalid") == 0.0


class TestCLIExecution:
    """Test CLI execution flows and return codes."""

    def test_cli_invalid_url_returns_code_2(self, capsys):
        """Test CLI with invalid URL returns exit code 2."""
        code = main(["not-a-valid-url"])
        assert code == 2
        captured = capsys.readouterr()
        assert "Invalid URL" in captured.err or "URL validation failed" in captured.err

    def test_cli_invalid_url_json_flag(self, capsys):
        """Test CLI with invalid URL and --json flag prints JSON error."""
        code = main(["ftp://example.com", "--json"])
        assert code == 2
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["authenticity_score"] is None
        assert "error_message" in data

    @patch("src.cli.analyze_website")
    def test_cli_authentic_site_returns_code_0(self, mock_analyze, capsys):
        """Test authentic website (fake_score <= 50%) returns exit code 0."""
        mock_analyze.return_value = {
            "url": "https://example.com",
            "authenticity_score": "92.00%",
            "fake_score": "8.00%",
            "confidence_indicator": "HIGH",
            "top_factors": ["Valid SSL certificate", "Trusted DNS"],
            "suspicious_indicators": [],
            "error_message": None,
        }

        code = main(["https://example.com", "--quiet"])
        assert code == 0
        captured = capsys.readouterr()
        assert "92.00%" in captured.out
        assert "8.00%" in captured.out

    @patch("src.cli.analyze_website")
    def test_cli_suspicious_site_returns_code_1(self, mock_analyze, capsys):
        """Test suspicious website (fake_score > 50%) returns exit code 1."""
        mock_analyze.return_value = {
            "url": "https://phishing-site.example",
            "authenticity_score": "25.00%",
            "fake_score": "75.00%",
            "confidence_indicator": "HIGH",
            "top_factors": [],
            "suspicious_indicators": ["Expired SSL certificate", "Brand mismatch"],
            "error_message": None,
        }

        code = main(["https://phishing-site.example", "--quiet"])
        assert code == 1
        captured = capsys.readouterr()
        assert "75.00%" in captured.out
        assert "Brand mismatch" in captured.out

    @patch("src.cli.analyze_website")
    def test_cli_json_output_mode(self, mock_analyze, capsys):
        """Test --json flag produces valid JSON on stdout."""
        sample_report = {
            "url": "https://example.com",
            "authenticity_score": "90.00%",
            "fake_score": "10.00%",
            "confidence_indicator": "HIGH",
            "top_factors": ["SSL valid"],
            "suspicious_indicators": [],
            "error_message": None,
        }
        mock_analyze.return_value = sample_report

        code = main(["https://example.com", "--json"])
        assert code == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed == sample_report

    @patch("src.cli.analyze_website")
    def test_cli_file_output_saving(self, mock_analyze, tmp_path):
        """Test saving report to file with -o / --output."""
        sample_report = {
            "url": "https://example.com",
            "authenticity_score": "90.00%",
            "fake_score": "10.00%",
            "confidence_indicator": "HIGH",
            "top_factors": ["SSL valid"],
            "suspicious_indicators": [],
            "error_message": None,
        }
        mock_analyze.return_value = sample_report

        out_file = tmp_path / "output_report.json"
        code = main(["https://example.com", "--json", "-o", str(out_file), "-q"])
        assert code == 0
        assert out_file.exists()
        with open(out_file, "r", encoding="utf-8") as f:
            content = json.load(f)
        assert content == sample_report
