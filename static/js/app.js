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

  /**
   * Render a result message in the result area.
   * Uses safe DOM textContent exclusively to prevent XSS.
   */
  function showResult(message, type = 'neutral') {
    resultArea.textContent = message;
    resultArea.className = 'result-area';

    if (type === 'success') {
      resultArea.classList.add('result-success');
    } else if (type === 'error') {
      resultArea.classList.add('result-error');
    } else {
      resultArea.classList.add('result-not-found');
    }
  }

  /**
   * Hide the result area.
   */
  function hideResult() {
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
      showResult('Please enter a valid 32-character MD5 hash.', 'error');
      return;
    }

    // Begin submission
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
        showResult('Unable to process your request. Please try again.', 'error');
        return;
      }

      if (response.ok && data.found) {
        const plaintext = data.plaintext;
        if (plaintext) {
          showResult(`Result: ${plaintext}`, 'success');
        } else {
          showResult('No matching entry found.', 'not-found');
        }
      } else if (response.ok && data.found === false) {
        showResult('No matching entry found.', 'not-found');
      } else if (response.status === 400 && data.status === 'invalid_input') {
        showResult('Please enter a valid 32-character MD5 hash.', 'error');
      } else {
        showResult('Unable to process your request. Please try again.', 'error');
      }
    } catch {
      showResult('Unable to process your request. Please try again.', 'error');
    } finally {
      clearTimeout(timeoutId);
      setLoading(false);
    }
  });
});
