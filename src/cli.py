"""Command Line Interface (CLI) for Website Authenticity Detector.

Provides terminal commands to analyze websites, inspect authenticity scores,
and export structured security reports.

Usage:
    python -m src <url> [options]
    python -m src.cli <url> [options]

Examples:
    python -m src https://www.google.com
    python -m src https://suspicious-login.example.com --json
    python -m src https://example.com --output report.json
"""

import argparse
import json
import sys
from typing import List, Optional

from src.analyzer import analyze_website, InputValidator, ReportGenerator


def build_parser() -> argparse.ArgumentParser:
    """Build argument parser for the CLI."""
    parser = argparse.ArgumentParser(
        prog="python -m src",
        description="AI-Powered Website Authenticity & Phishing Detector",
    )
    parser.add_argument(
        "url",
        type=str,
        help="Target website URL to analyze (e.g. https://example.com)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output the analysis report in raw JSON format to stdout",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        metavar="FILE",
        help="Save the analysis report to a file (JSON or text depending on format)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress non-essential banner and progress output",
    )
    return parser


def parse_fake_percentage(fake_str: Optional[str]) -> float:
    """Parse percentage string like '14.50%' into a float (14.50)."""
    if not fake_str:
        return 0.0
    try:
        return float(str(fake_str).replace("%", "").strip())
    except (ValueError, TypeError):
        return 0.0


def main(args: Optional[List[str]] = None) -> int:
    """CLI entry point.

    Returns:
        Exit code:
        - 0: Authentic / Low Risk (fake score <= 50%)
        - 1: Suspicious / High Risk (fake score > 50%)
        - 2: Invalid input URL or critical analysis error
    """
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    url = parsed_args.url

    # Pre-validate input URL
    validator = InputValidator()
    is_valid, validation_error = validator.validate_url(url)
    if not is_valid:
        if parsed_args.json_output:
            err_dict = {
                "url": url,
                "authenticity_score": None,
                "fake_score": None,
                "confidence_indicator": "LOW",
                "error_message": validation_error,
            }
            print(json.dumps(err_dict, indent=2))
        else:
            print(f"Error: Invalid URL '{url}' - {validation_error}", file=sys.stderr)
        return 2

    if not parsed_args.quiet and not parsed_args.json_output:
        print(f"[*] Analyzing website: {url} ...")

    # Run analysis
    report = analyze_website(url)

    # Format output
    if parsed_args.json_output:
        output_str = json.dumps(report, indent=2)
    else:
        output_str = ReportGenerator.format_text_summary(report)

    # Output to stdout
    print(output_str)

    # Save to file if requested
    if parsed_args.output:
        try:
            with open(parsed_args.output, "w", encoding="utf-8") as f:
                f.write(output_str)
            if not parsed_args.quiet and not parsed_args.json_output:
                print(f"[+] Report saved to {parsed_args.output}")
        except Exception as e:
            print(f"Warning: Failed to save output to {parsed_args.output}: {e}", file=sys.stderr)

    # Determine exit code based on analysis result
    err = report.get("error_message")
    if err and (report.get("authenticity_score") is None or "Invalid" in str(err) or "Critical" in str(err)):
        return 2

    fake_pct = parse_fake_percentage(report.get("fake_score"))
    if fake_pct > 50.0:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
