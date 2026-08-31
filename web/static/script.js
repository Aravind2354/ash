/**
 * Website Authenticity Detector - Cybersecurity Dashboard Frontend Engine
 * Handles URL validation, asynchronous API polling, live pipeline stepper tracking,
 * and multi-layer threat telemetry rendering.
 */

// API Configuration
const API_BASE_URL = '/api';

// DOM Elements
const form = document.getElementById('analyze-form');
const urlInput = document.getElementById('url-input');
const clearBtn = document.getElementById('clear-btn');
const analyzeButton = document.getElementById('analyze-button');
const urlErrorMsg = document.getElementById('url-error-msg');

// Progress Elements
const statusSection = document.getElementById('status-section');
const statusTargetUrl = document.getElementById('status-target-url');
const statusBadge = document.getElementById('status-badge');
const progressBarFill = document.getElementById('progress-bar-fill');
const statusText = document.getElementById('status-text');
const stepperGrid = document.getElementById('stepper-grid');

// Error Elements
const errorSection = document.getElementById('error-section');
const errorText = document.getElementById('error-text');
const tryAgainBtn = document.getElementById('try-again-btn');

// Result Elements
const resultSection = document.getElementById('result-section');
const securityAlertSection = document.getElementById('security-alert-section');
const alertIcon = document.getElementById('alert-icon');
const alertTitle = document.getElementById('alert-title');
const alertDescription = document.getElementById('alert-description');
const resultUrl = document.getElementById('result-url');
const confidenceIndicator = document.getElementById('confidence-indicator');

// Inconclusive Panel Elements
const inconclusivePanel = document.getElementById('inconclusive-panel');
const incReason = document.getElementById('inc-reason');
const incRecommendation = document.getElementById('inc-recommendation');
const tryAnotherBtn = document.getElementById('try-another-btn');

// Scores & Engine Status Elements
const authenticityScore = document.getElementById('authenticity-score');
const fakeScore = document.getElementById('fake-score');
const authMeterFill = document.getElementById('auth-meter-fill');
const fakeMeterFill = document.getElementById('fake-meter-fill');
const xgboostStatusBadge = document.getElementById('xgboost-status-badge');
const hybridStatusBadge = document.getElementById('hybrid-status-badge');
const riskLevelBadge = document.getElementById('risk-level-badge');

// Telemetry Elements
const telHostname = document.getElementById('tel-hostname');
const telBrand = document.getElementById('tel-brand');
const telBrandMatch = document.getElementById('tel-brand-match');
const telSslChain = document.getElementById('tel-ssl-chain');
const telSslSelf = document.getElementById('tel-ssl-self');
const telSslCa = document.getElementById('tel-ssl-ca');
const telDomPwd = document.getElementById('tel-dom-pwd');
const telDomHidden = document.getElementById('tel-dom-hidden');
const telDomCross = document.getElementById('tel-dom-cross');
const telNetReqs = document.getElementById('tel-net-reqs');
const telNetHttps = document.getElementById('tel-net-https');
const telThreatIntel = document.getElementById('tel-threat-intel');

// Factors & Indicators
const topFactorsList = document.getElementById('top-factors-list');
const suspiciousSection = document.getElementById('suspicious-section');
const suspiciousList = document.getElementById('suspicious-list');
const analysisDataJson = document.getElementById('analysis-data-json');

// Actions & Modal
const copyReportBtn = document.getElementById('copy-report-btn');
const downloadJsonBtn = document.getElementById('download-json-btn');
const analyzeAnotherBtn = document.getElementById('analyze-another-btn');
const loginBtn = document.getElementById('login-btn');
const loginModal = document.getElementById('login-modal');
const modalCloseBtn = document.getElementById('modal-close-btn');
const modalCancelBtn = document.getElementById('modal-cancel-btn');
const modalSubmitBtn = document.getElementById('modal-submit-btn');
const toastContainer = document.getElementById('toast-container');

// State Variables
let pollingInterval = null;
let currentActiveTaskId = null;
let currentResultData = null;

// Pipeline Stage Definitions
const STAGES = [
    { id: 'step-connect', key: 'connecting', name: 'Connecting to website', weight: 15 },
    { id: 'step-collect', key: 'collecting', name: 'Collecting website data', weight: 35 },
    { id: 'step-extract', key: 'extracting', name: 'Extracting features', weight: 55 },
    { id: 'step-xgboost', key: 'xgboost', name: 'Running XGBoost', weight: 75 },
    { id: 'step-hybrid', key: 'hybrid', name: 'Running hybrid analysis', weight: 90 },
    { id: 'step-report', key: 'report', name: 'Generating report', weight: 98 }
];

/* --------------------------------------------------------------------------
   Initialization & Event Listeners
   -------------------------------------------------------------------------- */
document.addEventListener('DOMContentLoaded', () => {
    initInputControls();
    initPresets();
    initModalControls();
    initActionButtons();
});

function initInputControls() {
    if (urlInput) {
        urlInput.addEventListener('input', () => {
            hideFieldError();
            if (clearBtn) {
                if (urlInput.value.length > 0) {
                    clearBtn.classList.remove('hidden');
                } else {
                    clearBtn.classList.add('hidden');
                }
            }
        });
    }

    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            urlInput.value = '';
            clearBtn.classList.add('hidden');
            hideFieldError();
            urlInput.focus();
        });
    }

    if (form) {
        form.addEventListener('submit', handleFormSubmit);
    }

    if (tryAgainBtn) {
        tryAgainBtn.addEventListener('click', () => {
            hideError();
            if (urlInput.value.trim()) {
                handleFormSubmit(new Event('submit'));
            } else {
                urlInput.focus();
            }
        });
    }

    if (tryAnotherBtn) {
        tryAnotherBtn.addEventListener('click', resetAndFocusInput);
    }

    if (analyzeAnotherBtn) {
        analyzeAnotherBtn.addEventListener('click', resetAndFocusInput);
    }
}

function initPresets() {
    const presetButtons = document.querySelectorAll('.preset-pill');
    presetButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            const sampleUrl = btn.getAttribute('data-url');
            if (sampleUrl && urlInput) {
                urlInput.value = sampleUrl;
                if (clearBtn) clearBtn.classList.remove('hidden');
                hideFieldError();
                urlInput.focus();
            }
        });
    });
}

function initModalControls() {
    if (loginBtn && loginModal) {
        loginBtn.addEventListener('click', () => {
            loginModal.classList.remove('hidden');
        });
    }

    const closeModal = () => {
        if (loginModal) loginModal.classList.add('hidden');
    };

    if (modalCloseBtn) modalCloseBtn.addEventListener('click', closeModal);
    if (modalCancelBtn) modalCancelBtn.addEventListener('click', closeModal);

    if (loginModal) {
        loginModal.addEventListener('click', (e) => {
            if (e.target === loginModal) closeModal();
        });
    }

    if (modalSubmitBtn) {
        modalSubmitBtn.addEventListener('click', () => {
            showToast('Authenticated as Administrator (Demo Session)');
            closeModal();
        });
    }
}

function initActionButtons() {
    if (copyReportBtn) {
        copyReportBtn.addEventListener('click', () => {
            if (!currentResultData) return;
            const summaryText = buildReportSummaryText(currentResultData);
            navigator.clipboard.writeText(summaryText)
                .then(() => showToast('Report summary copied to clipboard'))
                .catch(() => showToast('Could not copy report to clipboard'));
        });
    }

    if (downloadJsonBtn) {
        downloadJsonBtn.addEventListener('click', () => {
            if (!currentResultData) return;
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentResultData, null, 2));
            const downloadAnchor = document.createElement('a');
            downloadAnchor.setAttribute("href", dataStr);
            const safeDomain = (currentResultData.domain || 'website').replace(/[^a-z0-9]/gi, '_');
            downloadAnchor.setAttribute("download", `authenticity_report_${safeDomain}.json`);
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
            showToast('Downloaded JSON analysis report');
        });
    }
}

function resetAndFocusInput() {
    hideResult();
    hideStatus();
    hideError();
    if (urlInput) {
        urlInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
        urlInput.focus();
    }
}

/* --------------------------------------------------------------------------
   Input Validation
   -------------------------------------------------------------------------- */
function validateUrlInput(rawUrl) {
    const trimmed = (rawUrl || '').trim();
    if (!trimmed) {
        return { isValid: false, message: 'Please enter a website URL' };
    }

    if (!/^https?:\/\//i.test(trimmed)) {
        return { isValid: false, message: 'URL must start with http:// or https://' };
    }

    try {
        const parsed = new URL(trimmed);
        if (!parsed.hostname || parsed.hostname.indexOf('.') === -1 && parsed.hostname !== 'localhost') {
            return { isValid: false, message: 'Please enter a valid domain name (e.g., https://example.com)' };
        }
    } catch (err) {
        return { isValid: false, message: 'Invalid URL structure' };
    }

    return { isValid: true, url: trimmed };
}

function showFieldError(msg) {
    if (urlErrorMsg) {
        urlErrorMsg.textContent = msg;
        urlErrorMsg.classList.remove('hidden');
    }
}

function hideFieldError() {
    if (urlErrorMsg) {
        urlErrorMsg.classList.add('hidden');
        urlErrorMsg.textContent = '';
    }
}

/* --------------------------------------------------------------------------
   Form Submission & API Polling
   -------------------------------------------------------------------------- */
async function handleFormSubmit(e) {
    if (e && e.preventDefault) e.preventDefault();

    const rawUrl = urlInput ? urlInput.value : '';
    const validation = validateUrlInput(rawUrl);

    if (!validation.isValid) {
        showFieldError(validation.message);
        if (urlInput) urlInput.focus();
        return;
    }

    hideFieldError();
    hideError();
    hideResult();

    const targetUrl = validation.url;
    console.log('[Analysis] Starting request for URL:', targetUrl);

    // Disable button & show initial progress state
    if (analyzeButton) analyzeButton.disabled = true;
    showStatus(targetUrl);
    updatePipelineStepper('connecting', 'Connecting to website...');

    try {
        const response = await fetch(`${API_BASE_URL}/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: targetUrl })
        });

        if (!response.ok) {
            let errorDetail = 'Failed to initialize website analysis';
            try {
                const errData = await response.json();
                if (errData.detail) errorDetail = errData.detail;
            } catch (_) {}
            throw new Error(errorDetail);
        }

        const data = await response.json();
        console.log('[Analysis] Initial API Response:', data);

        // If returned immediately as completed
        if (data.status === 'completed' && data.result) {
            handleAnalysisCompletion(data.result);
            return;
        }

        if (!data.task_id) {
            throw new Error('Analysis engine did not assign a valid task identifier');
        }

        currentActiveTaskId = data.task_id;
        pollTaskProgress(data.task_id);

    } catch (error) {
        console.error('[Analysis Error]:', error);
        hideStatus();
        showUserFriendlyError(error.message || 'Something prevented the website from being analyzed.');
        if (analyzeButton) analyzeButton.disabled = false;
    }
}

function pollTaskProgress(taskId) {
    if (pollingInterval) {
        clearInterval(pollingInterval);
    }

    checkTaskStatus(taskId);

    pollingInterval = setInterval(() => {
        checkTaskStatus(taskId);
    }, 1000);
}

async function checkTaskStatus(taskId) {
    try {
        const response = await fetch(`${API_BASE_URL}/task/${taskId}`);
        if (!response.ok) {
            throw new Error('Failed to retrieve pipeline telemetry');
        }

        const data = await response.json();
        console.log(`[Task ${taskId}] Status:`, data.status, '| Progress:', data.progress);

        if (data.progress) {
            updatePipelineStepper(data.progress, formatProgressLabel(data.progress));
        }

        if (data.status === 'completed') {
            clearInterval(pollingInterval);
            pollingInterval = null;
            currentActiveTaskId = null;

            if (!data.result) {
                throw new Error('Analysis completed without generating a result payload');
            }

            handleAnalysisCompletion(data.result);
        } else if (data.status === 'failed') {
            clearInterval(pollingInterval);
            pollingInterval = null;
            currentActiveTaskId = null;

            hideStatus();
            const failureReason = data.error || 'The analysis pipeline encountered an unexpected error.';
            showUserFriendlyError(failureReason);
            if (analyzeButton) analyzeButton.disabled = false;
        }

    } catch (err) {
        console.error('[Polling Error]:', err);
        if (pollingInterval) {
            clearInterval(pollingInterval);
            pollingInterval = null;
        }
        hideStatus();
        showUserFriendlyError(err.message || 'Lost connection to analysis server. Please try again.');
        if (analyzeButton) analyzeButton.disabled = false;
    }
}

function handleAnalysisCompletion(result) {
    console.log('[Analysis Complete] Result Payload:', result);
    currentResultData = result;

    // Complete all stepper items
    STAGES.forEach(s => {
        const el = document.getElementById(s.id);
        if (el) {
            el.className = 'step-item completed';
            const statusEl = el.querySelector('.step-status');
            if (statusEl) statusEl.textContent = 'Completed';
        }
    });
    if (progressBarFill) progressBarFill.style.width = '100%';

    setTimeout(() => {
        hideStatus();
        renderResultView(result);
        if (analyzeButton) analyzeButton.disabled = false;
    }, 400);
}

/* --------------------------------------------------------------------------
   Live Pipeline Stepper Controller
   -------------------------------------------------------------------------- */
const PROGRESS_MAP = {
    'queued': { stageIndex: 0, label: 'Analysis queued in sandbox...' },
    'starting': { stageIndex: 0, label: 'Starting isolated sandbox instance...' },
    'connecting': { stageIndex: 0, label: 'Connecting to target website...' },
    'collecting website data': { stageIndex: 1, label: 'Collecting DOM, network, JS & SSL data...' },
    'extracting features': { stageIndex: 2, label: 'Extracting 48 security feature vectors...' },
    'running xgboost': { stageIndex: 3, label: 'Evaluating XGBoost ML classification model...' },
    'running ai/hybrid analysis': { stageIndex: 4, label: 'Evaluating heuristic risk gates & brand identity...' },
    'generating report': { stageIndex: 5, label: 'Compiling final authenticity intelligence report...' },
    'completed': { stageIndex: 6, label: 'Analysis completed successfully.' }
};

function formatProgressLabel(rawProgress) {
    if (!rawProgress) return 'Processing website...';
    const key = String(rawProgress).trim().toLowerCase();
    if (PROGRESS_MAP[key]) return PROGRESS_MAP[key].label;
    return rawProgress;
}

function updatePipelineStepper(rawProgress, displayText) {
    const key = String(rawProgress || '').trim().toLowerCase();
    let currentIdx = 0;

    if (PROGRESS_MAP[key]) {
        currentIdx = PROGRESS_MAP[key].stageIndex;
    } else {
        if (key.includes('collect')) currentIdx = 1;
        else if (key.includes('extract')) currentIdx = 2;
        else if (key.includes('xgboost')) currentIdx = 3;
        else if (key.includes('hybrid') || key.includes('ai')) currentIdx = 4;
        else if (key.includes('report')) currentIdx = 5;
        else if (key.includes('complete')) currentIdx = 6;
    }

    if (statusText) statusText.textContent = displayText || 'Processing website...';

    // Update progress bar
    if (progressBarFill && currentIdx < STAGES.length) {
        const targetPercent = STAGES[currentIdx].weight;
        progressBarFill.style.width = `${targetPercent}%`;
    }

    // Update each step item
    STAGES.forEach((stage, idx) => {
        const itemEl = document.getElementById(stage.id);
        if (!itemEl) return;

        const statusEl = itemEl.querySelector('.step-status');

        if (idx < currentIdx) {
            itemEl.className = 'step-item completed';
            if (statusEl) statusEl.textContent = '✓ Completed';
        } else if (idx === currentIdx) {
            itemEl.className = 'step-item active';
            if (statusEl) statusEl.textContent = 'Processing...';
        } else {
            itemEl.className = 'step-item';
            if (statusEl) statusEl.textContent = 'Pending';
        }
    });
}

/* --------------------------------------------------------------------------
   UI State Show / Hide Utilities
   -------------------------------------------------------------------------- */
function showStatus(targetUrl) {
    if (statusSection) {
        statusSection.classList.remove('hidden');
        if (statusTargetUrl) statusTargetUrl.textContent = `Target: ${targetUrl}`;
        if (statusBadge) statusBadge.textContent = 'In Progress';
        if (progressBarFill) progressBarFill.style.width = '10%';
        statusSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
}

function hideStatus() {
    if (statusSection) statusSection.classList.add('hidden');
}

function showUserFriendlyError(message) {
    if (errorSection) {
        errorSection.classList.remove('hidden');
        if (errorText) {
            errorText.textContent = message || 'Something prevented the website from being analyzed.';
        }
        errorSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
}

function hideError() {
    if (errorSection) errorSection.classList.add('hidden');
}

function hideResult() {
    if (resultSection) resultSection.classList.add('hidden');
}

/* --------------------------------------------------------------------------
   Score Formatting Utility
   -------------------------------------------------------------------------- */
function parseNumericScore(rawScore) {
    if (rawScore === null || rawScore === undefined || rawScore === '' || rawScore === 'N/A' || rawScore === 'NaN') {
        return null;
    }
    if (typeof rawScore === 'number') {
        if (isNaN(rawScore)) return null;
        return rawScore > 1.0 ? rawScore : rawScore * 100;
    }
    if (typeof rawScore === 'string') {
        const clean = rawScore.replace('%', '').trim();
        const num = parseFloat(clean);
        if (isNaN(num)) return null;
        return num > 1.0 ? num : num * 100;
    }
    return null;
}

function formatPercentageDisplay(scoreVal) {
    if (scoreVal === null || scoreVal === undefined) return 'N/A';
    return `${scoreVal.toFixed(1)}%`;
}

/* --------------------------------------------------------------------------
   Result Rendering Engine (Safe / Phishing / Inconclusive)
   -------------------------------------------------------------------------- */
function renderResultView(result) {
    if (!resultSection) return;
    resultSection.classList.remove('hidden');

    const authNum = parseNumericScore(result.authenticity_score);
    const fakeNum = parseNumericScore(result.fake_score);

    const classification = (result.classification || '').toUpperCase();
    const riskLevel = (result.risk_level || '').toUpperCase();
    const taskStatus = (result.status || '').toLowerCase();
    const confidence = (result.confidence_indicator || result.confidence || 'LOW').toUpperCase();

    // Check for INCONCLUSIVE / Anti-bot state
    const isInconclusive = classification === 'INCONCLUSIVE' || riskLevel === 'INCONCLUSIVE' || taskStatus === 'inconclusive';

    // Check for explicit Phishing
    const isPhishing = riskLevel === 'PHISHING' || (fakeNum !== null && fakeNum >= 75) ||
        (Array.isArray(result.critical_indicators) && result.critical_indicators.length > 0);

    const isHighRisk = riskLevel === 'HIGH_RISK' || (fakeNum !== null && fakeNum >= 60 && !isPhishing);
    const isSuspicious = riskLevel === 'SUSPICIOUS' || (fakeNum !== null && fakeNum >= 40 && !isPhishing && !isHighRisk);

    // 1. Analyzed URL
    const displayUrl = result.normalized_url || result.url || (urlInput ? urlInput.value.trim() : '') || 'https://example.com';
    if (resultUrl) {
        resultUrl.textContent = displayUrl;
        resultUrl.href = displayUrl;
    }

    // 2. Configure Verdict Banner & Inconclusive Panel
    if (isInconclusive) {
        renderInconclusiveState(result, confidence);
    } else if (isPhishing) {
        renderPhishingState(result, authNum, fakeNum, confidence);
    } else if (isHighRisk || isSuspicious) {
        renderSuspiciousState(result, authNum, fakeNum, confidence, isHighRisk);
    } else {
        renderSafeState(result, authNum, fakeNum, confidence);
    }

    // 3. Populate Telemetry Cards
    populateTelemetryGrid(result);

    // 4. Populate Factors & Indicators
    populateFactorsAndIndicators(result, isInconclusive);

    // 5. Populate Raw JSON Inspector
    if (analysisDataJson) {
        analysisDataJson.textContent = JSON.stringify(result, null, 2);
    }

    // Smooth scroll to results
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* --------------------------------------------------------------------------
   Individual Verdict State Handlers
   -------------------------------------------------------------------------- */
function renderInconclusiveState(result, confidence) {
    if (securityAlertSection) {
        securityAlertSection.className = 'security-verdict-banner inconclusive';
    }
    if (alertIcon) alertIcon.textContent = '⚠️';
    if (alertTitle) alertTitle.textContent = 'ANALYSIS INCONCLUSIVE — TARGET NOT REACHED';
    if (alertDescription) {
        alertDescription.textContent = 'The website presented an anti-bot or verification challenge, so the actual webpage could not be analyzed.';
    }

    if (confidenceIndicator) {
        confidenceIndicator.textContent = `${confidence} CONFIDENCE`;
        confidenceIndicator.className = 'confidence-badge low';
    }

    // Show Inconclusive Detail Panel
    if (inconclusivePanel) {
        inconclusivePanel.classList.remove('hidden');
        if (incReason) incReason.textContent = result.reason || 'Website content unavailable';
        if (incRecommendation) {
            incRecommendation.textContent = result.recommendation || 'Try again with a website that can be reached by the analysis browser.';
        }
    }

    // Scores display N/A
    if (authenticityScore) authenticityScore.textContent = 'N/A';
    if (fakeScore) fakeScore.textContent = 'N/A';
    if (authMeterFill) authMeterFill.style.width = '0%';
    if (fakeMeterFill) fakeMeterFill.style.width = '0%';

    // Engine Status
    if (xgboostStatusBadge) {
        xgboostStatusBadge.textContent = 'Not Executed';
        xgboostStatusBadge.className = 'engine-badge-tag warning';
    }
    if (hybridStatusBadge) {
        hybridStatusBadge.textContent = 'Intercepted';
        hybridStatusBadge.className = 'engine-badge-tag warning';
    }
    if (riskLevelBadge) {
        riskLevelBadge.textContent = 'INCONCLUSIVE';
        riskLevelBadge.className = 'engine-badge-tag warning';
    }
}

function renderPhishingState(result, authNum, fakeNum, confidence) {
    if (inconclusivePanel) inconclusivePanel.classList.add('hidden');

    if (securityAlertSection) {
        securityAlertSection.className = 'security-verdict-banner phishing';
    }
    if (alertIcon) alertIcon.textContent = '🛑';
    if (alertTitle) alertTitle.textContent = 'PHISHING / MALICIOUS WEBSITE DETECTED';
    if (alertDescription) {
        alertDescription.textContent = '⚠️ Do not enter passwords, OTPs, card details or other sensitive information. This website exhibits strong brand impersonation or credential harvesting patterns.';
    }

    if (confidenceIndicator) {
        confidenceIndicator.textContent = `${confidence} CONFIDENCE`;
        confidenceIndicator.className = `confidence-badge ${confidence.toLowerCase()}`;
    }

    // Scores
    const finalAuth = authNum !== null ? authNum : 5.0;
    const finalFake = fakeNum !== null ? fakeNum : 95.0;

    if (authenticityScore) authenticityScore.textContent = formatPercentageDisplay(finalAuth);
    if (fakeScore) fakeScore.textContent = formatPercentageDisplay(finalFake);
    if (authMeterFill) authMeterFill.style.width = `${Math.min(100, Math.max(0, finalAuth))}%`;
    if (fakeMeterFill) fakeMeterFill.style.width = `${Math.min(100, Math.max(0, finalFake))}%`;

    // Engine Status
    if (xgboostStatusBadge) {
        xgboostStatusBadge.textContent = result.xgboost_executed === false ? 'Bypassed (Security Warning)' : '✓ Executed';
        xgboostStatusBadge.className = 'engine-badge-tag danger';
    }
    if (hybridStatusBadge) {
        hybridStatusBadge.textContent = '✓ Completed';
        hybridStatusBadge.className = 'engine-badge-tag danger';
    }
    if (riskLevelBadge) {
        riskLevelBadge.textContent = 'PHISHING';
        riskLevelBadge.className = 'engine-badge-tag danger';
    }
}

function renderSuspiciousState(result, authNum, fakeNum, confidence, isHighRisk) {
    if (inconclusivePanel) inconclusivePanel.classList.add('hidden');

    if (securityAlertSection) {
        securityAlertSection.className = isHighRisk ? 'security-verdict-banner high-risk' : 'security-verdict-banner suspicious';
    }
    if (alertIcon) alertIcon.textContent = isHighRisk ? '🚨' : '⚠️';
    if (alertTitle) alertTitle.textContent = isHighRisk ? 'HIGH RISK / DECEPTIVE DOMAIN' : 'POTENTIALLY SUSPICIOUS WEBSITE';
    if (alertDescription) {
        alertDescription.textContent = isHighRisk
            ? '⚠️ WARNING: Multiple high-risk indicators commonly associated with deceptive or unauthorized domains detected.'
            : 'This website contains anomalies or suspicious signals. Verify domain ownership before interacting.';
    }

    if (confidenceIndicator) {
        confidenceIndicator.textContent = `${confidence} CONFIDENCE`;
        confidenceIndicator.className = `confidence-badge ${confidence.toLowerCase()}`;
    }

    const finalAuth = authNum !== null ? authNum : 35.0;
    const finalFake = fakeNum !== null ? fakeNum : 65.0;

    if (authenticityScore) authenticityScore.textContent = formatPercentageDisplay(finalAuth);
    if (fakeScore) fakeScore.textContent = formatPercentageDisplay(finalFake);
    if (authMeterFill) authMeterFill.style.width = `${Math.min(100, Math.max(0, finalAuth))}%`;
    if (fakeMeterFill) fakeMeterFill.style.width = `${Math.min(100, Math.max(0, finalFake))}%`;

    if (xgboostStatusBadge) {
        xgboostStatusBadge.textContent = '✓ Executed';
        xgboostStatusBadge.className = 'engine-badge-tag warning';
    }
    if (hybridStatusBadge) {
        hybridStatusBadge.textContent = '✓ Completed';
        hybridStatusBadge.className = 'engine-badge-tag warning';
    }
    if (riskLevelBadge) {
        riskLevelBadge.textContent = isHighRisk ? 'HIGH RISK' : 'SUSPICIOUS';
        riskLevelBadge.className = 'engine-badge-tag warning';
    }
}

function renderSafeState(result, authNum, fakeNum, confidence) {
    if (inconclusivePanel) inconclusivePanel.classList.add('hidden');

    if (securityAlertSection) {
        securityAlertSection.className = 'security-verdict-banner safe';
    }
    if (alertIcon) alertIcon.textContent = '🟢';
    if (alertTitle) alertTitle.textContent = 'WEBSITE APPEARS SAFE';
    if (alertDescription) {
        alertDescription.textContent = 'This website exhibits authentic domain identity with no significant deception or phishing indicators detected.';
    }

    if (confidenceIndicator) {
        confidenceIndicator.textContent = `${confidence} CONFIDENCE`;
        confidenceIndicator.className = 'confidence-badge high';
    }

    const finalAuth = authNum !== null ? authNum : 94.0;
    const finalFake = fakeNum !== null ? fakeNum : 6.0;

    if (authenticityScore) authenticityScore.textContent = formatPercentageDisplay(finalAuth);
    if (fakeScore) fakeScore.textContent = formatPercentageDisplay(finalFake);
    if (authMeterFill) authMeterFill.style.width = `${Math.min(100, Math.max(0, finalAuth))}%`;
    if (fakeMeterFill) fakeMeterFill.style.width = `${Math.min(100, Math.max(0, finalFake))}%`;

    if (xgboostStatusBadge) {
        xgboostStatusBadge.textContent = '✓ Executed';
        xgboostStatusBadge.className = 'engine-badge-tag success';
    }
    if (hybridStatusBadge) {
        hybridStatusBadge.textContent = '✓ Completed';
        hybridStatusBadge.className = 'engine-badge-tag success';
    }
    if (riskLevelBadge) {
        riskLevelBadge.textContent = 'SAFE';
        riskLevelBadge.className = 'engine-badge-tag risk-safe';
    }
}

/* --------------------------------------------------------------------------
   Telemetry Cards Population
   -------------------------------------------------------------------------- */
function populateTelemetryGrid(result) {
    const analysisData = result.analysis_data || {};
    const dom = analysisData.dom || {};
    const ssl = analysisData.ssl || {};
    const net = analysisData.network || {};

    // Domain & Brand
    if (telHostname) {
        telHostname.textContent = result.domain || result.registrable_domain || extractHostname(result.url) || '--';
    }
    if (telBrand) {
        telBrand.textContent = result.brand_detected || 'None';
    }
    if (telBrandMatch) {
        if (result.brand_detected) {
            telBrandMatch.textContent = result.brand_domain_match ? '✓ Matched' : '⚠️ MISMATCH';
            telBrandMatch.style.color = result.brand_domain_match ? 'var(--status-safe)' : 'var(--status-phish)';
        } else {
            telBrandMatch.textContent = 'N/A';
            telBrandMatch.style.color = 'var(--text-primary)';
        }
    }

    // SSL / TLS
    if (telSslChain) {
        const valid = ssl.chain_valid ?? ssl.ssl_chain_valid;
        telSslChain.textContent = valid === true ? '✓ Valid' : (valid === false ? '❌ Invalid' : 'N/A');
    }
    if (telSslSelf) {
        const selfSigned = ssl.self_signed ?? ssl.ssl_self_signed;
        telSslSelf.textContent = selfSigned === true ? '⚠️ Yes' : (selfSigned === false ? 'No' : 'N/A');
    }
    if (telSslCa) {
        const recognized = ssl.recognized_ca ?? ssl.ssl_recognized_ca;
        telSslCa.textContent = recognized === true ? '✓ Trusted' : (recognized === false ? 'Untrusted' : 'N/A');
    }

    // DOM & Forms
    if (telDomPwd) {
        const pwdCount = dom.password_inputs_count ?? dom.password_input_count ?? 0;
        telDomPwd.textContent = `${pwdCount} field(s)`;
    }
    if (telDomHidden) {
        const hiddenCount = dom.hidden_inputs_count ?? dom.hidden_input_count ?? 0;
        telDomHidden.textContent = `${hiddenCount} field(s)`;
    }
    if (telDomCross) {
        const crossDomain = dom.cross_domain_forms_count ?? dom.cross_domain_form_action_count ?? 0;
        telDomCross.textContent = crossDomain > 0 ? `⚠️ ${crossDomain}` : '0';
    }

    // Network & Threat Intel
    if (telNetReqs) {
        const reqCount = net.request_count ?? net.network_request_count ?? 0;
        telNetReqs.textContent = `${reqCount}`;
    }
    if (telNetHttps) {
        const httpsRatio = net.https_ratio ?? net.network_https_ratio;
        telNetHttps.textContent = typeof httpsRatio === 'number' ? `${(httpsRatio * 100).toFixed(0)}%` : '--';
    }
    if (telThreatIntel) {
        const flagged = result.threat_intelligence_flag || (result.reputation && result.reputation.is_malicious);
        telThreatIntel.textContent = flagged ? '🚨 Flagged' : '✓ Clean';
        telThreatIntel.style.color = flagged ? 'var(--status-phish)' : 'var(--status-safe)';
    }
}

function extractHostname(urlStr) {
    try {
        if (!urlStr) return '';
        const parsed = new URL(urlStr.startsWith('http') ? urlStr : `https://${urlStr}`);
        return parsed.hostname;
    } catch (_) {
        return '';
    }
}

/* --------------------------------------------------------------------------
   Factors & Threat Indicators Lists
   -------------------------------------------------------------------------- */
function populateFactorsAndIndicators(result, isInconclusive) {
    // Top Factors List
    if (topFactorsList) {
        topFactorsList.innerHTML = '';
        const factors = Array.isArray(result.top_factors) ? result.top_factors : [];

        if (factors.length > 0) {
            factors.forEach(f => {
                const li = document.createElement('li');
                li.textContent = f;
                topFactorsList.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.textContent = isInconclusive
                ? 'Target website intercepted before full feature analysis.'
                : 'No specific authenticity anomalies registered.';
            li.style.color = 'var(--text-muted)';
            topFactorsList.appendChild(li);
        }
    }

    // Suspicious / Critical Indicators List
    const criticalList = Array.isArray(result.critical_indicators) ? result.critical_indicators : [];
    const suspiciousItems = Array.isArray(result.suspicious_indicators) ? result.suspicious_indicators : [];
    const combinedThreats = [...criticalList, ...suspiciousItems];

    if (suspiciousSection && suspiciousList) {
        suspiciousList.innerHTML = '';

        if (combinedThreats.length > 0) {
            suspiciousSection.classList.remove('hidden');
            combinedThreats.forEach(item => {
                const li = document.createElement('li');
                li.textContent = item;
                suspiciousList.appendChild(li);
            });
        } else {
            suspiciousSection.classList.add('hidden');
        }
    }
}

/* --------------------------------------------------------------------------
   Report Summary Markdown Generator
   -------------------------------------------------------------------------- */
function buildReportSummaryText(result) {
    const risk = (result.risk_level || result.classification || 'UNKNOWN').toUpperCase();
    const url = result.normalized_url || result.url || 'Unknown URL';
    const auth = result.authenticity_score || 'N/A';
    const fake = result.fake_score || 'N/A';
    const confidence = result.confidence_indicator || result.confidence || 'LOW';

    let summary = `==================================================\n`;
    summary += `WEBSITE AUTHENTICITY INTELLIGENCE REPORT\n`;
    summary += `==================================================\n\n`;
    summary += `Target URL:           ${url}\n`;
    summary += `Security Verdict:     ${risk}\n`;
    summary += `Authenticity Score:   ${auth}\n`;
    summary += `Phishing Probability: ${fake}\n`;
    summary += `Confidence Level:     ${confidence}\n`;
    summary += `Timestamp:            ${new Date().toISOString()}\n\n`;

    if (result.top_factors && result.top_factors.length > 0) {
        summary += `--- Top Authenticity Factors ---\n`;
        result.top_factors.forEach((f, i) => {
            summary += `${i + 1}. ${f}\n`;
        });
        summary += `\n`;
    }

    const threats = [...(result.critical_indicators || []), ...(result.suspicious_indicators || [])];
    if (threats.length > 0) {
        summary += `--- Detected Security Threats & Indicators ---\n`;
        threats.forEach((t, i) => {
            summary += `• ${t}\n`;
        });
        summary += `\n`;
    }

    summary += `==================================================\n`;
    summary += `Generated by Website Authenticity Detector (AI + XGBoost)\n`;
    return summary;
}

/* --------------------------------------------------------------------------
   Toast Notification Helper
   -------------------------------------------------------------------------- */
function showToast(message) {
    if (!toastContainer) return;
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="20 6 9 17 4 12"/>
        </svg>
        <span>${message}</span>
    `;
    toastContainer.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 2800);
}