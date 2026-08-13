// Website Authenticity Detector - Frontend JavaScript

const API_BASE_URL = '/api';

// DOM elements
const form = document.getElementById('analyze-form');
const urlInput = document.getElementById('url-input');
const analyzeButton = document.getElementById('analyze-button');
const statusSection = document.getElementById('status-section');
const statusText = document.getElementById('status-text');
const errorSection = document.getElementById('error-section');
const errorText = document.getElementById('error-text');
const resultSection = document.getElementById('result-section');
const resultUrl = document.getElementById('result-url');
const authenticityScore = document.getElementById('authenticity-score');
const fakeScore = document.getElementById('fake-score');
const confidenceIndicator = document.getElementById('confidence-indicator');
const topFactorsList = document.getElementById('top-factors-list');
const suspiciousSection = document.getElementById('suspicious-section');
const suspiciousList = document.getElementById('suspicious-list');
const analysisDataJson = document.getElementById('analysis-data-json');

let pollingInterval = null;

// Form submission handler
form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const url = urlInput.value.trim();
    if (!url) {
        showError('Please enter a URL');
        return;
    }

    // Disable button and show loading state
    analyzeButton.disabled = true;
    hideError();
    hideResult();
    showStatus('Analysis started...');

    try {
        // Submit analysis request
        const response = await fetch(`${API_BASE_URL}/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url }),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to start analysis');
        }

        const data = await response.json();

        // Start polling for results
        pollTaskStatus(data.task_id);

    } catch (error) {
        showError(error.message);
        hideStatus();
        analyzeButton.disabled = false;
    }
});

// Poll task status
async function pollTaskStatus(taskId) {
    pollingInterval = setInterval(async () => {
        try {
            const response = await fetch(`${API_BASE_URL}/task/${taskId}`);

            if (!response.ok) {
                throw new Error('Failed to get task status');
            }

            const data = await response.json();

            // Update status text
            if (data.progress) {
                showStatus(data.progress);
            }

            // Check if task is completed
            if (data.status === 'completed') {
                clearInterval(pollingInterval);
                hideStatus();
                showResult(data.result);
                analyzeButton.disabled = false;
            }

            // Check if task failed
            if (data.status === 'failed') {
                clearInterval(pollingInterval);
                hideStatus();
                showError(data.error || 'Analysis failed');
                analyzeButton.disabled = false;
            }

        } catch (error) {
            clearInterval(pollingInterval);
            hideStatus();
            showError(error.message);
            analyzeButton.disabled = false;
        }
    }, 2000); // Poll every 2 seconds
}

// Show status section
function showStatus(message) {
    statusSection.classList.remove('hidden');
    statusText.textContent = message;
}

// Hide status section
function hideStatus() {
    statusSection.classList.add('hidden');
}

// Show error section
function showError(message) {
    errorSection.classList.remove('hidden');
    errorText.textContent = message;
}

// Hide error section
function hideError() {
    errorSection.classList.add('hidden');
}

// Show result section
function showResult(result) {
    resultSection.classList.remove('hidden');

    // Display URL
    resultUrl.textContent = result.url;

    // Display scores
    authenticityScore.textContent = result.authenticity_score;
    fakeScore.textContent = result.fake_score;

    // Display confidence
    confidenceIndicator.textContent = result.confidence_indicator;
    confidenceIndicator.className = `confidence-badge ${result.confidence_indicator.toLowerCase()}`;

    // Display top factors
    topFactorsList.innerHTML = '';
    result.top_factors.forEach(factor => {
        const li = document.createElement('li');
        li.textContent = factor;
        topFactorsList.appendChild(li);
    });

    // Display suspicious indicators if any
    if (result.suspicious_indicators && result.suspicious_indicators.length > 0) {
        suspiciousSection.classList.remove('hidden');
        suspiciousList.innerHTML = '';
        result.suspicious_indicators.forEach(indicator => {
            const li = document.createElement('li');
            li.textContent = indicator;
            suspiciousList.appendChild(li);
        });
    } else {
        suspiciousSection.classList.add('hidden');
    }

    // Display analysis data
    analysisDataJson.textContent = JSON.stringify(result.analysis_data, null, 2);
}

// Hide result section
function hideResult() {
    resultSection.classList.add('hidden');
}
