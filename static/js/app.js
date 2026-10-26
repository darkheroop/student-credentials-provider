/**
 * Student Credentials Provider — Minimal Client
 */

document.addEventListener('DOMContentLoaded', () => {
  const lookupForm = document.getElementById('lookupForm');
  const lookupInput = document.getElementById('lookupInput');
  const submitBtn = document.getElementById('submitBtn');
  const resultArea = document.getElementById('resultArea');

  if (!lookupForm || !lookupInput || !submitBtn || !resultArea) {
    return;
  }

  // Exactly 32 hexadecimal characters (case-insensitive)
  const MD5_REGEX = /^[0-9a-fA-F]{32}$/;

  // Store the active plaintext result for copy operations
  let currentPlaintextResult = '';

  // Minimal SVG icons (16x16, vector line style matching the UI)
  const COPY_ICON_SVG = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
    </svg>
  `.trim();

  const CHECK_ICON_SVG = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <polyline points="20 6 9 17 4 12"></polyline>
    </svg>
  `.trim();

  /**
   * Copy plaintext value to clipboard using the Clipboard API with legacy fallback.
   */
  async function copyToClipboard(text) {
    if (!text) return false;

    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch {
        // Fall back to execCommand below
      }
    }

    try {
      const textArea = document.createElement('textarea');
      textArea.value = text;
      textArea.style.position = 'fixed';
      textArea.style.top = '-9999px';
      textArea.style.left = '-9999px';
      textArea.style.opacity = '0';
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      const successful = document.execCommand('copy');
      document.body.removeChild(textArea);
      return successful;
    } catch {
      return false;
    }
  }

  /**
   * Render successful plaintext result without any "Result:" prefix,
   * accompanied by a small copy icon.
   */
  function renderSuccessResult(plaintext) {
    currentPlaintextResult = plaintext;
    resultArea.textContent = '';
    resultArea.className = 'result-area result-success';

    // Plaintext value (safe DOM rendering via textContent)
    const textSpan = document.createElement('span');
    textSpan.className = 'result-text';
    textSpan.textContent = plaintext;

    // Small copy button
    const copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.className = 'copy-result-btn';
    copyBtn.setAttribute('aria-label', 'Copy result');
    copyBtn.setAttribute('title', 'Copy result');
    copyBtn.innerHTML = COPY_ICON_SVG;

    let resetTimeout = null;

    copyBtn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const copied = await copyToClipboard(currentPlaintextResult);
      if (copied) {
        copyBtn.innerHTML = CHECK_ICON_SVG;
        copyBtn.classList.add('copied');
        copyBtn.setAttribute('aria-label', 'Copied');
        copyBtn.setAttribute('title', 'Copied');

        if (resetTimeout) clearTimeout(resetTimeout);
        resetTimeout = setTimeout(() => {
          copyBtn.innerHTML = COPY_ICON_SVG;
          copyBtn.classList.remove('copied');
          copyBtn.setAttribute('aria-label', 'Copy result');
          copyBtn.setAttribute('title', 'Copy result');
        }, 1500);
      }
    });

    resultArea.appendChild(textSpan);
    resultArea.appendChild(copyBtn);
  }

  /**
   * Render an error or not-found status message (no copy icon).
   * Uses safe DOM textContent exclusively to prevent XSS.
   */
  function showStatusMessage(message, type = 'error') {
    currentPlaintextResult = '';
    resultArea.textContent = message;
    resultArea.className = 'result-area';

    if (type === 'error') {
      resultArea.classList.add('result-error');
    } else {
      resultArea.classList.add('result-not-found');
    }
  }

  /**
   * Hide and clear the result area.
   */
  function hideResult() {
    currentPlaintextResult = '';
    resultArea.className = 'result-area hidden';
    resultArea.textContent = '';
  }

  /**
   * Update the Submit button state during request processing.
   */
  function setLoading(isLoading) {
    if (isLoading) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'Processing...';
      submitBtn.setAttribute('aria-busy', 'true');
    } else {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Submit';
      submitBtn.removeAttribute('aria-busy');
    }
  }

  /**
   * Handle form submission.
   */
  lookupForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const trimmedInput = lookupInput.value.trim();

    // Frontend validation: require exactly 32 hexadecimal characters
    if (!MD5_REGEX.test(trimmedInput)) {
      showStatusMessage('Please enter a valid 32-character MD5 hash.', 'error');
      return;
    }

    // Begin submission: clear any old/stale result and show loading state
    setLoading(true);
    hideResult();

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);

    try {
      const response = await fetch('/api/student-lookup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          lookup_input: trimmedInput,
          algorithm_type: 'md5',
          hash: trimmedInput,
          algorithm: 'md5',
        }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      let data;
      try {
        data = await response.json();
      } catch {
        showStatusMessage('Unable to process your request. Please try again.', 'error');
        return;
      }

      if (response.ok && data.found) {
        const plaintext = data.plaintext || data.lookup_result;
        if (plaintext) {
          renderSuccessResult(plaintext);
        } else {
          showStatusMessage('No matching entry found.', 'not-found');
        }
      } else if (response.ok && data.found === false) {
        showStatusMessage('No matching entry found.', 'not-found');
      } else if (response.status === 400 && data.status === 'invalid_input') {
        showStatusMessage('Please enter a valid 32-character MD5 hash.', 'error');
      } else {
        showStatusMessage('Unable to process your request. Please try again.', 'error');
      }
    } catch {
      showStatusMessage('Unable to process your request. Please try again.', 'error');
    } finally {
      clearTimeout(timeoutId);
      setLoading(false);
    }
  });
});
