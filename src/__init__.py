"""Website Authenticity Detector - Main Package."""

from src.authenticity_detector import AuthenticityDetector, analyze_website
from src.models import AnalysisResult, AnalysisData
from src.input_validator import InputValidator
from src.report_generator import ReportGenerator

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "analyze_website",
    "AuthenticityDetector",
    "AnalysisResult",
    "AnalysisData",
    "InputValidator",
    "ReportGenerator",
]
