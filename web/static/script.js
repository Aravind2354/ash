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
const alertSection = document.getElementById('security-alert-section');
const alertIcon = document.getElementById('alert-icon');
const alertTitle = document.getElementById('alert-title');
const alertDescription = document.getElementById('alert-description');

let pollingInterval = null;

/**
 * Format numeric score (0.0 - 1.0) or percentage string ("89.00%") safely.
 * Returns formatted percentage string (e.g. "89.00%") or "N/A" for null/undefined/invalid values.
 *
 * @param {number|string|null|undefined} score
 * @returns {string}
 */
function formatScore(score) {
    if (score === null || score === undefined || score === '' || (typeof score === 'number' && isNaN(score))) {
        return 'N/A';
    }

    if (typeof score === 'string') {
        const trimmed = score.trim();
        if (trimmed === '' || trimmed.toUpperCase() === 'N/A' || trimmed.toUpperCase() === 'NAN') {
            return 'N/A';
        }
        if (trimmed.endsWith('%')) {
            const num = parseFloat(trimmed.slice(0, -1));
            if (!isNaN(num)) {
                return `${num.toFixed(2)}%`;
            }
            return trimmed;
        }
        const num = parseFloat(trimmed);
        if (!isNaN(num)) {
            if (num >= 0 && num <= 1.0) {
                return `${(num * 100).toFixed(2)}%`;
            }
            return `${num.toFixed(2)}%`;
        }
        return score;
    }

    if (typeof score === 'number') {
        if (score >= 0 && score <= 1.0) {
            return `${(score * 100).toFixed(2)}%`;
        }
        return `${score.toFixed(2)}%`;
    }

    return String(score);
}

// Form submission
form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const url = urlInput.value.trim();

    if (!url) {
        showError('Please enter a URL');
        return;
    }

    console.log('Starting analysis for:', url);

    analyzeButton.disabled = true;
    hideError();
    hideResult();
    showStatus('Analysis started...');

    try {
        const response = await fetch(`${API_BASE_URL}/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url })
        });

        console.log('Analyze response status:', response.status);

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to start analysis');
        }

        const data = await response.json();

        console.log('Task response:', data);

        if (data.status === 'completed') {
            console.log('Actual analysis result:', data.result);
            showResult(data.result);
            hideStatus();
            analyzeButton.disabled = false;
            return;
        }

        if (!data.task_id) {
            throw new Error('Server did not return a task ID');
        }

        // Start polling the task
        pollTaskStatus(data.task_id);

    } catch (error) {
        console.error('Analysis start error:', error);

        showError(error.message);
        hideStatus();
        analyzeButton.disabled = false;
    }
});


// Poll task status
async function pollTaskStatus(taskId) {

    console.log('Polling task:', taskId);

    // Stop previous polling if any
    if (pollingInterval) {
        clearInterval(pollingInterval);
    }

    // Check immediately
    await checkTaskStatus(taskId);

    // Then check every 2 seconds
    pollingInterval = setInterval(() => {
        checkTaskStatus(taskId);
    }, 2000);
}


// Check task status
async function checkTaskStatus(taskId) {

    try {

        const response = await fetch(
            `${API_BASE_URL}/task/${taskId}`
        );

        console.log('Task response status:', response.status);

        if (!response.ok) {
            throw new Error('Failed to get task status');
        }

        const data = await response.json();

        console.log('Task data:', data);

        // Update progress
        if (data.progress) {
            showStatus(data.progress);
        }

        // Completed
        if (data.status === 'completed') {

            console.log('TASK COMPLETED');
            console.log('RAW API RESPONSE:', data);

            if (data.result) {
                console.log('AUTHENTICITY:', data.result.authenticity_score);
                console.log('FAKE:', data.result.fake_score);
                console.log('CONFIDENCE:', data.result.confidence_indicator);
            }

            clearInterval(pollingInterval);
            pollingInterval = null;

            hideStatus();

            if (!data.result) {
                throw new Error('Task completed but no result was returned');
            }

            showResult(data.result);

            analyzeButton.disabled = false;
        }

        // Failed
        else if (data.status === 'failed') {

            console.error('TASK FAILED:', data.error);

            clearInterval(pollingInterval);
            pollingInterval = null;

            hideStatus();

            showError(
                data.error || 'Analysis failed'
            );

            analyzeButton.disabled = false;
        }

    } catch (error) {

        console.error('Task polling error:', error);

        if (pollingInterval) {
            clearInterval(pollingInterval);
            pollingInterval = null;
        }

        hideStatus();
        showError(error.message);

        analyzeButton.disabled = false;
    }
}


// Show status
function showStatus(message) {
    statusSection.classList.remove('hidden');
    statusText.textContent = message;
}


// Hide status
function hideStatus() {
    statusSection.classList.add('hidden');
}


// Show error
function showError(message) {
    errorSection.classList.remove('hidden');
    errorText.textContent = message;
}


// Hide error
function hideError() {
    errorSection.classList.add('hidden');
}


// Show result
function showResult(result) {

    console.log('Displaying result:', result);

    resultSection.classList.remove('hidden');

    // URL
    resultUrl.textContent =
        result.url || (urlInput ? urlInput.value.trim() : '') || 'Unknown URL';

    // Scores (robust numeric or percentage string formatting)
    authenticityScore.textContent =
        formatScore(result.authenticity_score);

    fakeScore.textContent =
        formatScore(result.fake_score);

    // Confidence
    const rawConfidence = result.confidence_indicator;
    const confidence =
        (rawConfidence && typeof rawConfidence === 'string')
            ? rawConfidence.toUpperCase()
            : 'LOW';

    confidenceIndicator.textContent =
        confidence;

    confidenceIndicator.className =
        `confidence-badge ${confidence.toLowerCase()}`;

    // Update Security Alert / Risk Verdict Banner (Phase 10 & 14)
    let fakeScoreNum = null;
    if (typeof result.fake_score === 'number') {
        fakeScoreNum = result.fake_score > 1.0 ? result.fake_score / 100 : result.fake_score;
    } else if (typeof result.fake_score === 'string') {
        const cleaned = result.fake_score.replace('%', '').trim();
        const parsed = parseFloat(cleaned);
        if (!isNaN(parsed)) {
            fakeScoreNum = parsed > 1.0 ? parsed / 100 : parsed;
        }
    }

    const riskLevel = (result.risk_level || '').toUpperCase();

    if (alertSection && alertIcon && alertTitle && alertDescription) {
        if (result.status === 'failed' || (result.authenticity_score == null && result.fake_score == null)) {
            alertSection.className = 'security-alert-card failed';
            alertIcon.textContent = '❌';
            alertTitle.textContent = 'ANALYSIS FAILED / INCONCLUSIVE';
            alertDescription.textContent = 'Analysis could not be completed reliably. Do not treat this result as SAFE.' + (result.error_message ? ` (Error: ${result.error_message})` : '');
        } else if (riskLevel === 'PHISHING' || (fakeScoreNum !== null && fakeScoreNum >= 0.80 && Array.isArray(result.critical_indicators) && result.critical_indicators.length > 0)) {
            alertSection.className = 'security-alert-card phishing';
            alertIcon.textContent = '🛑';
            alertTitle.textContent = 'PHISHING / MALICIOUS WEBSITE DETECTED';
            alertDescription.textContent = '⚠️ DO NOT ENTER PASSWORDS, OTPs, CARD DETAILS OR OTHER SENSITIVE INFORMATION. This website exhibits strong brand impersonation or credential harvesting patterns.';
        } else if (riskLevel === 'HIGH_RISK' || (fakeScoreNum !== null && fakeScoreNum >= 0.70)) {
            alertSection.className = 'security-alert-card high-risk';
            alertIcon.textContent = '🚨';
            alertTitle.textContent = 'HIGH RISK / DECEPTIVE DOMAIN';
            alertDescription.textContent = '⚠️ WARNING: This website exhibits multiple high-risk indicators commonly associated with deceptive or unauthorized domains. Exercise extreme caution.';
        } else if (riskLevel === 'SUSPICIOUS' || (fakeScoreNum !== null && (fakeScoreNum >= 0.45 || (Array.isArray(result.suspicious_indicators) && result.suspicious_indicators.length > 0)))) {
            alertSection.className = 'security-alert-card suspicious';
            alertIcon.textContent = '⚠️';
            alertTitle.textContent = 'POTENTIALLY SUSPICIOUS WEBSITE';
            alertDescription.textContent = confidence === 'LOW'
                ? 'This website contains potential anomalies, but available evidence is limited (LOW confidence). Proceed with caution.'
                : 'This website contains indicators commonly associated with deceptive or suspicious websites. Verify the URL before interacting.';
        } else if (result.status === 'partial' || result.error_message) {
            alertSection.className = 'security-alert-card partial';
            alertIcon.textContent = '⚠️';
            alertTitle.textContent = 'PARTIAL ANALYSIS WARNING';
            alertDescription.textContent = `Partial evidence collected. Do not treat as definitive. ${result.error_message || 'Some data categories could not be retrieved.'}`;
        } else {
            alertSection.className = 'security-alert-card safe';
            alertIcon.textContent = '🛡️';
            alertTitle.textContent = 'SAFE / LOW RISK';
            alertDescription.textContent = 'This website exhibits authentic domain identity with no significant deception or phishing indicators detected.';
        }
    }


    // Top factors
    topFactorsList.innerHTML = '';

    if (Array.isArray(result.top_factors) && result.top_factors.length > 0) {

        result.top_factors.forEach(factor => {

            const li = document.createElement('li');

            li.textContent = factor;

            topFactorsList.appendChild(li);
        });

    } else if (result.error_message) {

        const li = document.createElement('li');
        li.textContent = 'No factors available due to incomplete analysis';
        li.style.color = '#888';
        li.style.fontStyle = 'italic';
        topFactorsList.appendChild(li);
    }


    // Suspicious indicators
    suspiciousList.innerHTML = '';

    if (
        Array.isArray(result.suspicious_indicators) &&
        result.suspicious_indicators.length > 0
    ) {

        suspiciousSection.classList.remove('hidden');

        result.suspicious_indicators.forEach(indicator => {

            const li = document.createElement('li');

            li.textContent = indicator;

            suspiciousList.appendChild(li);
        });

    } else {

        suspiciousSection.classList.add('hidden');
    }


    // If partial report with error_message, inform the user
    if (result.error_message) {
        showError(result.error_message);
    } else {
        hideError();
    }


    // Analysis data
    analysisDataJson.textContent =
        JSON.stringify(
            result.analysis_data || {},
            null,
            2
        );

    // Scroll to result
    resultSection.scrollIntoView({
        behavior: 'smooth',
        block: 'start'
    });

    console.log('Result displayed successfully');
}


// Hide result
function hideResult() {
    resultSection.classList.add('hidden');
}