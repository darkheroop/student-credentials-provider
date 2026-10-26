/**
 * Dynamic API Management Client Script
 */

document.addEventListener('DOMContentLoaded', () => {
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
  const alertBox = document.getElementById('alertBox');
  const configsList = document.getElementById('configsList');
  const refreshBtn = document.getElementById('refreshBtn');

  // Metrics
  const metricTotal = document.getElementById('metricTotal');
  const metricActive = document.getElementById('metricActive');
  const metricPaused = document.getElementById('metricPaused');
  const metricDisabled = document.getElementById('metricDisabled');

  // Form elements
  const apiForm = document.getElementById('apiForm');
  const formTitle = document.getElementById('formTitle');
  const formMode = document.getElementById('formMode');
  const formConfigId = document.getElementById('formConfigId');
  const displayNameInput = document.getElementById('displayName');
  const providerNameSelect = document.getElementById('providerName');
  const priorityInput = document.getElementById('priority');
  const endpointInput = document.getElementById('endpoint');
  const credentialInput = document.getElementById('credential');
  const credentialLabel = document.getElementById('credentialLabel');
  const credentialHint = document.getElementById('credentialHint');
  const notesInput = document.getElementById('notes');
  const saveBtn = document.getElementById('saveBtn');
  const cancelEditBtn = document.getElementById('cancelEditBtn');

  let currentConfigs = [];

  function showAlert(message, type = 'success') {
    if (!alertBox) return;
    alertBox.textContent = message;
    alertBox.className = `alert-box alert-${type}`;
    alertBox.classList.remove('hidden');

    setTimeout(() => {
      alertBox.classList.add('hidden');
    }, 6000);
  }

  async function apiFetch(url, options = {}) {
    const defaultHeaders = {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken,
    };
    options.headers = { ...defaultHeaders, ...(options.headers || {}) };
    return fetch(url, options);
  }

  async function loadConfigs() {
    try {
      configsList.innerHTML = '<p class="empty-state">Loading configured API providers...</p>';
      const res = await apiFetch('/admin/api/configs');
      if (!res.ok) {
        throw new Error(`Failed to load: HTTP ${res.status}`);
      }
      const data = await res.json();
      currentConfigs = data.configs || [];
      renderMetrics(currentConfigs);
      renderConfigsList(currentConfigs);
    } catch (err) {
      configsList.innerHTML = `<p class="empty-state">Error loading configurations: ${err.message}</p>`;
      showAlert(err.message, 'error');
    }
  }

  function renderMetrics(configs) {
    let total = configs.length;
    let active = 0;
    let paused = 0;
    let disabled = 0;

    configs.forEach((c) => {
      if (!c.enabled) {
        disabled++;
      } else if (c.health_status === 'active') {
        active++;
      } else {
        paused++;
      }
    });

    if (metricTotal) metricTotal.textContent = total;
    if (metricActive) metricActive.textContent = active;
    if (metricPaused) metricPaused.textContent = paused;
    if (metricDisabled) metricDisabled.textContent = disabled;
  }

  function renderConfigsList(configs) {
    if (!configsList) return;
    configsList.innerHTML = '';

    if (configs.length === 0) {
      configsList.innerHTML = '<p class="empty-state">No API providers configured yet. Use the form to add one.</p>';
      return;
    }

    configs.forEach((cfg) => {
      const item = document.createElement('div');
      item.className = 'config-item';

      let statusDisplay = cfg.health_status;
      if (!cfg.enabled) {
        statusDisplay = 'disabled';
      }

      // Format date helper
      const formatDate = (val) => {
        if (!val) return 'Never';
        try {
          return new Date(val).toLocaleString();
        } catch {
          return val;
        }
      };

      const header = document.createElement('div');
      header.className = 'config-item-header';

      const title = document.createElement('div');
      title.className = 'config-item-title';
      title.textContent = `${cfg.display_name} (${cfg.provider_name.toUpperCase()})`;

      const badge = document.createElement('span');
      badge.className = `status-badge status-${statusDisplay}`;
      badge.textContent = statusDisplay.replace('_', ' ');
      title.appendChild(badge);
      header.appendChild(title);

      const details = document.createElement('div');
      details.className = 'config-item-details';

      details.innerHTML = `
        <div class="detail-line"><strong>Priority:</strong> ${cfg.priority}</div>
        <div class="detail-line"><strong>Key:</strong> <code>${cfg.masked_credential}</code></div>
        <div class="detail-line"><strong>Endpoint:</strong> <code>${cfg.endpoint}</code></div>
        <div class="detail-line"><strong>Last Success:</strong> ${formatDate(cfg.last_success_at)}</div>
        <div class="detail-line"><strong>Last Error:</strong> ${cfg.last_error_category || 'None'}</div>
        ${cfg.paused_until ? `<div class="detail-line"><strong>Paused Until:</strong> ${formatDate(cfg.paused_until)}</div>` : ''}
        ${cfg.notes ? `<div class="detail-line"><strong>Notes:</strong> ${cfg.notes}</div>` : ''}
      `;

      const actions = document.createElement('div');
      actions.className = 'config-item-actions';

      // Test Connection Button
      const testBtn = document.createElement('button');
      testBtn.className = 'btn btn-sm btn-outline';
      testBtn.textContent = 'Test Connection';
      testBtn.onclick = () => testConnection(cfg.id, testBtn);
      actions.appendChild(testBtn);

      // Reactivate button (if paused)
      if (cfg.health_status !== 'active' && cfg.enabled) {
        const reactivateBtn = document.createElement('button');
        reactivateBtn.className = 'btn btn-sm btn-outline';
        reactivateBtn.textContent = 'Reactivate';
        reactivateBtn.onclick = () => reactivateConfig(cfg.id);
        actions.appendChild(reactivateBtn);
      }

      // Enable/Disable Toggle
      const toggleBtn = document.createElement('button');
      toggleBtn.className = 'btn btn-sm btn-outline';
      toggleBtn.textContent = cfg.enabled ? 'Disable' : 'Enable';
      toggleBtn.onclick = () => toggleConfig(cfg.id);
      actions.appendChild(toggleBtn);

      // Edit Button
      const editBtn = document.createElement('button');
      editBtn.className = 'btn btn-sm btn-secondary';
      editBtn.textContent = 'Edit';
      editBtn.onclick = () => startEditConfig(cfg);
      actions.appendChild(editBtn);

      // Delete Button
      const deleteBtn = document.createElement('button');
      deleteBtn.className = 'btn btn-sm btn-danger';
      deleteBtn.textContent = 'Delete';
      deleteBtn.onclick = () => deleteConfig(cfg.id, cfg.display_name);
      actions.appendChild(deleteBtn);

      item.appendChild(header);
      item.appendChild(details);
      item.appendChild(actions);
      configsList.appendChild(item);
    });
  }

  // ── Actions ─────────────────────────────────────────────────────────

  async function testConnection(configId, btn) {
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Testing...';

    try {
      const res = await apiFetch(`/admin/api/configs/${configId}/test`, { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        showAlert(data.message, 'success');
      } else {
        showAlert(data.message || 'Connection test failed.', 'error');
      }
      loadConfigs();
    } catch (err) {
      showAlert(`Test error: ${err.message}`, 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = originalText;
    }
  }

  async function reactivateConfig(configId) {
    try {
      const res = await apiFetch(`/admin/api/configs/${configId}/reactivate`, { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        showAlert('Provider reactivated successfully.', 'success');
        loadConfigs();
      } else {
        showAlert(data.error || 'Failed to reactivate.', 'error');
      }
    } catch (err) {
      showAlert(`Error: ${err.message}`, 'error');
    }
  }

  async function toggleConfig(configId) {
    try {
      const res = await apiFetch(`/admin/api/configs/${configId}/toggle`, { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        showAlert(data.message, 'success');
        loadConfigs();
      } else {
        showAlert(data.error || 'Toggle failed.', 'error');
      }
    } catch (err) {
      showAlert(`Error: ${err.message}`, 'error');
    }
  }

  async function deleteConfig(configId, name) {
    if (!confirm(`Are you sure you want to delete the configuration "${name}"? This will remove its stored credentials.`)) {
      return;
    }

    try {
      const res = await apiFetch(`/admin/api/configs/${configId}`, { method: 'DELETE' });
      const data = await res.json();
      if (data.success) {
        showAlert('Configuration deleted successfully.', 'success');
        loadConfigs();
      } else {
        showAlert(data.error || 'Failed to delete.', 'error');
      }
    } catch (err) {
      showAlert(`Error: ${err.message}`, 'error');
    }
  }

  function startEditConfig(cfg) {
    formMode.value = 'edit';
    formConfigId.value = cfg.id;
    formTitle.textContent = `Edit Configuration: ${cfg.display_name}`;
    displayNameInput.value = cfg.display_name;
    providerNameSelect.value = cfg.provider_name;
    priorityInput.value = cfg.priority;
    endpointInput.value = cfg.endpoint;
    credentialInput.value = '';
    credentialLabel.textContent = 'Replace Credential (Leave blank to keep current)';
    credentialHint.textContent = `Current key is stored securely (${cfg.masked_credential}). Enter new key only to replace.`;
    notesInput.value = cfg.notes || '';
    saveBtn.textContent = 'Update Configuration';
    cancelEditBtn.classList.remove('hidden');

    // Scroll smoothly to form
    apiForm.scrollIntoView({ behavior: 'smooth' });
  }

  function resetForm() {
    formMode.value = 'create';
    formConfigId.value = '';
    formTitle.textContent = 'Add API Configuration';
    apiForm.reset();
    priorityInput.value = '10';
    endpointInput.value = 'https://api.md5decrypt.net/';
    credentialLabel.textContent = 'API Key / Credential *';
    credentialHint.textContent = 'Key is encrypted at rest using HMAC-SHA256 authenticated encryption.';
    saveBtn.textContent = 'Save Configuration';
    cancelEditBtn.classList.add('hidden');
  }

  cancelEditBtn?.addEventListener('click', resetForm);
  refreshBtn?.addEventListener('click', loadConfigs);

  // ── Form Submission (Create or Edit) ─────────────────────────────────
  apiForm?.addEventListener('submit', async (e) => {
    e.preventDefault();

    const mode = formMode.value;
    const configId = formConfigId.value;
    const displayName = displayNameInput.value.trim();
    const providerName = providerNameSelect.value.trim();
    const priority = parseInt(priorityInput.value, 10) || 10;
    const endpoint = endpointInput.value.trim();
    const credential = credentialInput.value.trim();
    const notes = notesInput.value.trim();

    if (!displayName) {
      showAlert('Display name is required.', 'error');
      return;
    }

    if (!endpoint) {
      showAlert('Endpoint URL is required.', 'error');
      return;
    }

    if (mode === 'create' && !credential) {
      showAlert('API key / credential is required for new configurations.', 'error');
      return;
    }

    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving...';

    try {
      let res;
      if (mode === 'create') {
        res = await apiFetch('/admin/api/configs', {
          method: 'POST',
          body: JSON.stringify({
            display_name: displayName,
            provider_name: providerName,
            priority,
            endpoint,
            credential,
            notes,
          }),
        });
      } else {
        const payload = {
          display_name: displayName,
          provider_name: providerName,
          priority,
          endpoint,
          notes,
        };
        if (credential) {
          payload.credential = credential;
        }

        res = await apiFetch(`/admin/api/configs/${configId}`, {
          method: 'PUT',
          body: JSON.stringify(payload),
        });
      }

      const data = await res.json();
      if (data.success) {
        showAlert(data.message, 'success');
        resetForm();
        loadConfigs();
      } else {
        showAlert(data.error || 'Failed to save configuration.', 'error');
      }
    } catch (err) {
      showAlert(`Error: ${err.message}`, 'error');
    } finally {
      saveBtn.disabled = false;
      saveBtn.textContent = mode === 'edit' ? 'Update Configuration' : 'Save Configuration';
    }
  });

  // Initial load
  loadConfigs();
});
