# Website Authenticity Detector

An AI-powered security tool that analyzes websites to determine if they are genuine or potentially fraudulent. The system loads target websites in an isolated virtual environment (sandbox), collects behavioral and structural data, and uses AI-powered analysis to generate authenticity probability scores.

## Features

- **Security First**: Complete isolation between the analysis environment and host system
- **Comprehensive Analysis**: Multi-dimensional data collection covering:
  - Network behavior patterns
  - DOM structure analysis
  - JavaScript execution monitoring
  - Visual characteristics
  - SSL certificate validation
- **AI-Powered Detection**: Machine learning-based analysis to identify patterns indicative of fraudulent websites
- **Robust Error Handling**: Graceful degradation with partial results when data collection is incomplete
- **Clear Reporting**: Probability scores with confidence indicators and detailed analysis reports

## Requirements

- Python 3.8 or higher (below 4.0)
- Virtual environment for dependency isolation

## Installation

1. Create a virtual environment:
```bash
python -m venv venv
```

2. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - Linux/Mac: `source venv/bin/activate`

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install Playwright browsers:
```bash
playwright install
```

## Project Structure

```
.
├── src/                    # Source code
├── tests/                  # Test suite
├── config/                 # Configuration files
├── requirements.txt        # Python dependencies
├── pyproject.toml         # Project configuration
└── README.md              # This file
```

## Usage

```python
from src.analyzer import analyze_website

# Analyze a website
result = analyze_website("https://example.com")

print(f"Authenticity Score: {result['authenticity_score']}")
print(f"Fake Score: {result['fake_score']}")
print(f"Confidence: {result['confidence_indicator']}")
```

## Development

### Running Tests

```bash
pytest
```

### Running Property-Based Tests

```bash
pytest -v tests/
```

## Architecture

The system consists of four primary components:

1. **Sandbox Manager**: Creates, manages, and destroys isolated virtual environments
2. **Data Collector**: Gathers behavioral and structural data from websites executing in the sandbox
3. **AI Analysis Engine**: Processes collected data to generate authenticity scores
4. **Report Generator**: Formats analysis results and generates structured reports

## Security

- All website analysis occurs in isolated virtual environments
- Complete prevention of file system writes to host
- No process creation on host system from sandbox
- Internal network scanning prevention
- URL validation and sanitization

## License

MIT

## Contributing

Contributions are welcome! Please ensure all tests pass before submitting pull requests.
