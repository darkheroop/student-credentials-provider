/**
 * Student Credentials Provider (SCP)
 * Frontend Application Module
 *
 * Educational student record analysis and credential verification platform.
 * This application does not persist submitted lookup inputs or recovered records.
 */

'use strict';

// ============================================
// APPLICATION STATE
// ============================================
const AppState = {
  isLoading: false,
  currentMode: 'demo', // Updated dynamically from health check
  lastResult: null,
};

// ============================================
// CONFIGURATION
// ============================================
const CONFIG = {
  API_BASE: '', // Same origin
  ENDPOINTS: {
    HEALTH: '/api/health',
    LOOKUP: '/api/student-lookup',
    DEMO_LOOKUP: '/api/demo-student-lookup',
  },
  ALGORITHMS: {
    md5: { name: 'MD5', length: 32 },
    sha1: { name: 'SHA-1', length: 40 },
    sha256: { name: 'SHA-256', length: 64 },
    sha384: { name: 'SHA-384', length: 96 },
    sha512: { name: 'SHA-512', length: 128 },
    ntlm: { name: 'NTLM', length: 32 },
  },
  MAX_INPUT_LENGTH: 256,
};

// ============================================
// DOM ELEMENT REFERENCES
// ============================================
let DOM = {};

/**
 * Cache all DOM element references by ID with dual-support for
 * both student-oriented and legacy identifiers.
 */
const cacheDOMElements = () => {
  DOM = {
    // Navigation
    navToggle: document.getElementById('nav-toggle') || document.getElementById('hamburger'),
    navMenu: document.getElementById('nav-menu') || document.getElementById('nav-links'),

    // Demo banner
    demoBanner: document.getElementById('demo-mode-banner') || document.getElementById('demo-banner'),

    // Form elements
    lookupInput: document.getElementById('lookup-input') || document.getElementById('hash-input'),
    hashInput: document.getElementById('lookup-input') || document.getElementById('hash-input'),
    algorithmSelect: document.getElementById('algorithm-select'),
    submitBtn: document.getElementById('submit-btn'),
    clearBtn: document.getElementById('clear-btn'),
    charCount: document.getElementById('char-count'),
    formatInfo: document.getElementById('lookup-format-info') || document.getElementById('hash-format-info'),

    // Validation & loading
    validationMessage: document.getElementById('validation-message'),
    loadingIndicator: document.getElementById('loading-indicator'),

    // Results panel
    resultContainer: document.getElementById('result-container'),
    resultCard: document.getElementById('lookup-result') || document.getElementById('result-card'),
    idleState: document.getElementById('result-idle') || document.getElementById('idle-state'),
    statusBadge: document.getElementById('result-status-badge') || document.getElementById('status-badge'),
    modeIndicator: document.getElementById('result-mode') || document.getElementById('mode-indicator'),
    resultAlgorithm: document.getElementById('result-algorithm'),
    resultLookupInput: document.getElementById('result-lookup-input') || document.getElementById('result-hash'),
    resultHash: document.getElementById('result-lookup-input') || document.getElementById('result-hash'),
    resultMatch: document.getElementById('result-match'),
    plaintextRow: document.getElementById('plaintext-row') || document.getElementById('plaintext-section'),
    plaintextValue: document.getElementById('result-plaintext') || document.getElementById('plaintext-value'),
    resultDuration: document.getElementById('result-duration'),
    resultExplanation: document.getElementById('result-explanation'),
    retryBtn: document.getElementById('retry-btn'),
    copyBtn: document.getElementById('copy-lookup-btn') || document.getElementById('copy-hash-btn'),

    // Accessibility
    statusAnnouncer: document.getElementById('status-announcer'),

    // Footer
    currentYear: document.getElementById('current-year'),
  };
};

// ============================================
// INITIALIZATION
// ============================================

document.addEventListener('DOMContentLoaded', () => {
  cacheDOMElements();
  setupEventListeners();
  initializeUI();
});

/**
 * Set up all event listeners across the application.
 */
const setupEventListeners = () => {
  // Mobile Navigation toggle
  if (DOM.navToggle) {
    DOM.navToggle.addEventListener('click', toggleMobileMenu);
  }

  // Close mobile menu when nav links are clicked
  if (DOM.navMenu) {
    DOM.navMenu.querySelectorAll('a').forEach((link) => {
      link.addEventListener('click', () => {
        closeMobileMenu();
        handleSmoothScroll(link);
      });
    });
  }

  // Lookup Input live character count & auto-resize
  if (DOM.lookupInput) {
    DOM.lookupInput.addEventListener('input', () => {
      updateCharCount();
      hideValidationError();
    });
    DOM.lookupInput.addEventListener('keydown', handleInputKeydown);
  }

  // Algorithm select format changes
  if (DOM.algorithmSelect) {
    DOM.algorithmSelect.addEventListener('change', () => {
      updateFormatInfo();
      hideValidationError();
    });
  }

  // Clear button
  if (DOM.clearBtn) {
    DOM.clearBtn.addEventListener('click', clearLookupForm);
  }

  // Submit button
  if (DOM.submitBtn) {
    DOM.submitBtn.addEventListener('click', handleStudentLookup);
  }

  // Copy button
  if (DOM.copyBtn) {
    DOM.copyBtn.addEventListener('click', handleCopyLookupValue);
  }

  // Retry button
  if (DOM.retryBtn) {
    DOM.retryBtn.addEventListener('click', () => {
      if (DOM.lookupInput) {
        DOM.lookupInput.focus();
        DOM.lookupInput.select();
      }
    });
  }

  // Global keyboard shortcuts (Escape clears result)
  document.addEventListener('keydown', handleGlobalKeydown);
};

/**
 * Initialize interface states and dynamic data.
 */
const initializeUI = () => {
  // 1. Current year in footer
  if (DOM.currentYear) {
    DOM.currentYear.textContent = new Date().getFullYear();
  }

  // 2. Fetch API health status
  fetchHealthStatus();

  // 3. Set initial format info
  updateFormatInfo();
  updateCharCount();
};

// ============================================
// NAVIGATION
// ============================================

const toggleMobileMenu = () => {
  if (!DOM.navMenu || !DOM.navToggle) return;
  const isExpanded = DOM.navToggle.getAttribute('aria-expanded') === 'true';
  DOM.navToggle.setAttribute('aria-expanded', String(!isExpanded));
  DOM.navMenu.classList.toggle('active');
};

const closeMobileMenu = () => {
  if (!DOM.navMenu || !DOM.navToggle) return;
  DOM.navToggle.setAttribute('aria-expanded', 'false');
  DOM.navMenu.classList.remove('active');
};

const handleSmoothScroll = (link) => {
  const href = link.getAttribute('href');
  if (!href) return;

  if (href.startsWith('#') || href.startsWith('/#')) {
    const targetId = href.replace(/^\/#?/, '');
    const targetElement = document.getElementById(targetId);
    if (targetElement) {
      targetElement.scrollIntoView({ behavior: 'smooth' });
    }
  }
};

// ============================================
// HEALTH CHECK
// ============================================

const fetchHealthStatus = async () => {
  try {
    const response = await fetch(`${CONFIG.API_BASE}${CONFIG.ENDPOINTS.HEALTH}`);
    if (response.ok) {
      const data = await response.json();
      AppState.currentMode = data.mode || 'demo';
      updateModeBanner();
    } else {
      AppState.currentMode = 'demo';
      updateModeBanner();
    }
  } catch (err) {
    AppState.currentMode = 'demo';
    updateModeBanner();
  }
};

const updateModeBanner = () => {
  if (!DOM.demoBanner) return;
  if (AppState.currentMode === 'live') {
    DOM.demoBanner.classList.add('live-banner');
    DOM.demoBanner.innerHTML = '<strong>Live Mode</strong> — Connected to external verification provider.';
  } else {
    DOM.demoBanner.classList.remove('live-banner');
    DOM.demoBanner.innerHTML = '<strong>Demo Mode</strong> — Using synthetic student test records. No external API calls.';
  }
};

// ============================================
// INPUT CONTROLS
// ============================================

const updateCharCount = () => {
  if (!DOM.charCount || !DOM.lookupInput) return;
  const count = DOM.lookupInput.value.length;
  DOM.charCount.textContent = `${count} character${count === 1 ? '' : 's'}`;
};

const updateFormatInfo = () => {
  if (!DOM.formatInfo || !DOM.algorithmSelect) return;
  const selectedAlgo = DOM.algorithmSelect.value;
  const algoConfig = CONFIG.ALGORITHMS[selectedAlgo];
  if (algoConfig) {
    DOM.formatInfo.innerHTML = `Expected length: <strong>${algoConfig.length}</strong> hexadecimal characters (${algoConfig.name})`;
  }
};

const clearLookupForm = () => {
  if (DOM.lookupInput) {
    DOM.lookupInput.value = '';
    DOM.lookupInput.focus();
  }
  updateCharCount();
  hideValidationError();
  showIdleState();
  hideResultCard();
};

// ============================================
// CLIENT-SIDE VALIDATION
// ============================================

const validateLookupInput = (lookupValue, algorithm) => {
  if (!lookupValue || lookupValue.trim() === '') {
    return {
      valid: false,
      message: 'Please enter a lookup value to verify.',
    };
  }

  if (lookupValue.length > CONFIG.MAX_INPUT_LENGTH) {
    return {
      valid: false,
      message: `Input exceeds maximum length of ${CONFIG.MAX_INPUT_LENGTH} characters.`,
    };
  }

  const algoConfig = CONFIG.ALGORITHMS[algorithm];
  if (!algoConfig) {
    return {
      valid: false,
      message: 'Unsupported algorithm selected.',
    };
  }

  const hexRegex = /^[0-9a-fA-F]+$/;
  if (!hexRegex.test(lookupValue)) {
    return {
      valid: false,
      message: 'Lookup value contains invalid characters. Expected hexadecimal (0-9, a-f).',
    };
  }

  if (lookupValue.length !== algoConfig.length) {
    return {
      valid: false,
      message: `Expected ${algoConfig.length} characters for ${algoConfig.name}, got ${lookupValue.length}.`,
    };
  }

  return { valid: true };
};

const validateInput = validateLookupInput; // Alias

// ============================================
// STUDENT LOOKUP SUBMISSION
// ============================================

const handleStudentLookup = async () => {
  if (AppState.isLoading) return;

  const lookupValue = DOM.lookupInput ? DOM.lookupInput.value.trim() : '';
  const algorithm = DOM.algorithmSelect ? DOM.algorithmSelect.value : '';

  const validation = validateLookupInput(lookupValue, algorithm);
  if (!validation.valid) {
    showValidationError(validation.message);
    return;
  }

  hideValidationError();
  setLoading(true);

  const endpoint =
    AppState.currentMode === 'demo'
      ? CONFIG.ENDPOINTS.DEMO_LOOKUP
      : CONFIG.ENDPOINTS.LOOKUP;

  try {
    if (typeof navigator.onLine !== 'undefined' && !navigator.onLine) {
      showError(
        'Network Unavailable',
        'You appear to be offline. Please verify connectivity and try again.'
      );
      return;
    }

    // Payload provides both student-oriented terms and compatibility fields
    const payload = {
      lookup_input: lookupValue,
      hash: lookupValue,
      algorithm_type: algorithm,
      algorithm: algorithm,
    };

    const response = await fetch(`${CONFIG.API_BASE}${endpoint}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    const data = await response.json();

    if (response.ok) {
      displayResult(data);
    } else if (response.status === 429) {
      showError(
        'Rate Limit Exceeded',
        data.message || 'Request limit exceeded. Please wait a moment before trying again.'
      );
    } else if (response.status === 400) {
      showValidationError(data.message || 'Invalid input. Please check the value and try again.');
    } else if (response.status === 401 || response.status === 403) {
      showError(
        'Authentication Error',
        data.message || 'Lookup provider authorization failed.'
      );
    } else if (response.status >= 500) {
      showError(
        'Server Error',
        data.message || 'The server encountered an error while processing the request.'
      );
    } else {
      showError(
        'Unexpected Error',
        data.message || `The server returned status ${response.status}.`
      );
    }
  } catch (err) {
    showError(
      'Network Error',
      'Unable to connect to the lookup service. Please check your connection.'
    );
  } finally {
    setLoading(false);
  }
};

const handleSubmit = handleStudentLookup; // Alias

const handleInputKeydown = (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    handleStudentLookup();
  }
};

const handleGlobalKeydown = (e) => {
  if (e.key === 'Escape') {
    hideResultCard();
    showIdleState();
    hideValidationError();
  }
};

// ============================================
// LOADING STATE MANAGEMENT
// ============================================

const setLoading = (isLoading) => {
  AppState.isLoading = isLoading;

  if (DOM.loadingIndicator) {
    if (isLoading) {
      DOM.loadingIndicator.removeAttribute('hidden');
      DOM.loadingIndicator.setAttribute('aria-hidden', 'false');
    } else {
      DOM.loadingIndicator.setAttribute('hidden', '');
      DOM.loadingIndicator.setAttribute('aria-hidden', 'true');
    }
  }

  if (DOM.submitBtn) {
    DOM.submitBtn.disabled = isLoading;
    DOM.submitBtn.innerHTML = isLoading
      ? '<span aria-hidden="true">&#x23F3;</span> Searching...'
      : '<span aria-hidden="true">&#x1F50D;</span> Search';
  }

  if (isLoading) {
    announce('Processing student lookup request, please wait.');
  } else {
    announce('Lookup complete.');
  }
};

// ============================================
// RESULT RENDERING
// ============================================

const STATUS_CONFIG = {
  match_found: {
    label: '\u2713 Match Found',
    className: 'status-found',
  },
  not_found: {
    label: '\u2014 No Match',
    className: 'status-not-found',
  },
  invalid_input: {
    label: '\u26A0 Invalid Input',
    className: 'status-error',
  },
  api_error: {
    label: '\u26A0 Provider Error',
    className: 'status-error',
  },
  auth_error: {
    label: '\u26A0 Auth Error',
    className: 'status-error',
  },
  rate_limited: {
    label: '\u26A0 Rate Limited',
    className: 'status-error',
  },
  timeout: {
    label: '\u26A0 Timeout',
    className: 'status-error',
  },
  service_unavailable: {
    label: '\u26A0 Service Unavailable',
    className: 'status-error',
  },
};

const displayResult = (data) => {
  AppState.lastResult = data;

  hideIdleState();
  showResultCard();

  // 1. Status badge
  if (DOM.statusBadge) {
    const statusInfo = STATUS_CONFIG[data.status] || {
      label: '\u26A0 Result Received',
      className: 'status-error',
    };
    DOM.statusBadge.textContent = statusInfo.label;
    DOM.statusBadge.className = 'status-badge';
    DOM.statusBadge.classList.add(statusInfo.className);
  }

  // 2. Mode indicator
  if (DOM.modeIndicator) {
    const isLive = AppState.currentMode === 'live' || data.mode === 'live';
    DOM.modeIndicator.textContent = isLive ? 'LIVE' : 'DEMO';
    DOM.modeIndicator.className = 'mode-indicator';
    DOM.modeIndicator.classList.add(isLive ? 'mode-live' : 'mode-demo');
  }

  // 3. Algorithm
  if (DOM.resultAlgorithm) {
    const algoKey = data.algorithm_type || data.algorithm || '';
    const algoConfig = CONFIG.ALGORITHMS[algoKey];
    DOM.resultAlgorithm.textContent = algoConfig ? algoConfig.name : algoKey.toUpperCase();
  }

  // 4. Input value display
  const effectiveInput = data.lookup_input || data.hash || '';
  if (DOM.resultLookupInput) {
    const maxLen = 64;
    if (effectiveInput.length > maxLen) {
      DOM.resultLookupInput.textContent = effectiveInput.substring(0, maxLen) + '\u2026';
      DOM.resultLookupInput.setAttribute('title', effectiveInput);
    } else {
      DOM.resultLookupInput.textContent = effectiveInput;
      DOM.resultLookupInput.removeAttribute('title');
    }
  }

  // 5. Match result text
  if (DOM.resultMatch) {
    DOM.resultMatch.textContent = data.found ? 'Matching Record Found' : 'No Matching Record';
  }

  // 6. Plaintext section
  if (DOM.plaintextRow && DOM.plaintextValue) {
    if (data.found && data.plaintext) {
      DOM.plaintextRow.removeAttribute('hidden');
      DOM.plaintextValue.textContent = data.plaintext;
    } else {
      DOM.plaintextRow.setAttribute('hidden', '');
      DOM.plaintextValue.textContent = '';
    }
  }

  // 7. Duration
  if (DOM.resultDuration) {
    if (data.duration !== undefined && data.duration !== null) {
      DOM.resultDuration.textContent = `${data.duration}s`;
    } else {
      DOM.resultDuration.textContent = '';
    }
  }

  // 8. Explanation
  if (DOM.resultExplanation) {
    let explanation = '';
    if (data.status === 'match_found') {
      explanation =
        'A matching student record was returned by the lookup service. ' +
        'A lookup result does not independently verify student identity or account ownership.';
    } else if (data.status === 'not_found') {
      explanation =
        'No matching entry was returned by the lookup service. ' +
        'This does not prove that the credential is invalid or unrecoverable.';
    } else {
      explanation = data.message || 'Lookup complete.';
    }
    DOM.resultExplanation.textContent = explanation;
  }

  // 9. Retry button
  if (DOM.retryBtn) {
    DOM.retryBtn.classList.remove('hidden');
  }

  // Announce to screen reader
  const statusLabel = STATUS_CONFIG[data.status]?.label || 'Lookup complete';
  announce(`Lookup Status: ${statusLabel}`);
};

// ============================================
// VISUAL STATE HELPERS
// ============================================

const showIdleState = () => {
  if (DOM.idleState) DOM.idleState.removeAttribute('hidden');
};

const hideIdleState = () => {
  if (DOM.idleState) DOM.idleState.setAttribute('hidden', '');
};

const showResultCard = () => {
  if (DOM.resultCard) {
    DOM.resultCard.removeAttribute('hidden');
    DOM.resultCard.classList.remove('fadeIn');
    void DOM.resultCard.offsetWidth;
    DOM.resultCard.classList.add('fadeIn');
  }
};

const hideResultCard = () => {
  if (DOM.resultCard) DOM.resultCard.setAttribute('hidden', '');
};

const showValidationError = (message) => {
  if (!DOM.validationMessage) return;
  DOM.validationMessage.textContent = message;
  DOM.validationMessage.removeAttribute('hidden');
  announce(`Validation Error: ${message}`);
};

const hideValidationError = () => {
  if (!DOM.validationMessage) return;
  DOM.validationMessage.setAttribute('hidden', '');
  DOM.validationMessage.textContent = '';
};

const showError = (title, message) => {
  hideIdleState();
  showResultCard();

  if (DOM.statusBadge) {
    DOM.statusBadge.textContent = `\u26A0 ${title}`;
    DOM.statusBadge.className = 'status-badge status-error';
  }

  if (DOM.resultExplanation) {
    DOM.resultExplanation.textContent = message;
  }

  if (DOM.plaintextRow) {
    DOM.plaintextRow.setAttribute('hidden', '');
  }

  if (DOM.resultMatch) {
    DOM.resultMatch.textContent = 'Error Encountered';
  }

  announce(`Error: ${title}. ${message}`);
};

const announce = (message) => {
  if (!DOM.statusAnnouncer) return;
  DOM.statusAnnouncer.textContent = '';
  requestAnimationFrame(() => {
    DOM.statusAnnouncer.textContent = message;
  });
};

const handleCopyLookupValue = async () => {
  const valueToCopy =
    AppState.lastResult?.lookup_input ||
    AppState.lastResult?.hash ||
    (DOM.lookupInput ? DOM.lookupInput.value : '');

  if (!valueToCopy) return;

  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(valueToCopy);
    } else {
      const textarea = document.createElement('textarea');
      textarea.value = valueToCopy;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
    }

    if (DOM.copyBtn) {
      const originalText = DOM.copyBtn.innerHTML;
      DOM.copyBtn.innerHTML = '&#x2714; Copied';
      setTimeout(() => {
        DOM.copyBtn.innerHTML = originalText;
      }, 1500);
    }
  } catch (err) {
    // Non-critical clipboard failure
  }
};
