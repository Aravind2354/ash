"""Website Authenticity Detector - Main Package."""

__version__ = "0.1.0"


def __getattr__(name: str):
    """Lazy load heavy dependencies only when accessed (PEP 562)."""
    if name == "analyze_website":
        from src.authenticity_detector import analyze_website
        return analyze_website
    if name == "AuthenticityDetector":
        from src.authenticity_detector import AuthenticityDetector
        return AuthenticityDetector
    if name == "AnalysisResult":
        from src.models import AnalysisResult
        return AnalysisResult
    if name == "AnalysisData":
        from src.models import AnalysisData
        return AnalysisData
    if name == "InputValidator":
        from src.input_validator import InputValidator
        return InputValidator
    if name == "ReportGenerator":
        from src.report_generator import ReportGenerator
        return ReportGenerator
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


__all__ = [
    "__version__",
    "analyze_website",
    "AuthenticityDetector",
    "AnalysisResult",
    "AnalysisData",
    "InputValidator",
    "ReportGenerator",
]
