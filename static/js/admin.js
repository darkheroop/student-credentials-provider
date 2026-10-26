/**
 * Dynamic API Management & Admin Dashboard Client Script
 */

document.addEventListener('DOMContentLoaded', () => {
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
  const userRole = document.querySelector('meta[name="user-role"]')?.getAttribute('content') || 'subadmin';
  const alertBox = document.getElementById('alertBox');
  const headerUsername = document.getElementById('headerUsername');

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

  // ── Tab Navigation ──────────────────────────────────────────────────
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');

  tabButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      const tabTarget = btn.getAttribute('data-tab');

      tabButtons.forEach((b) => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      tabPanes.forEach((p) => p.classList.remove('active'));

      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');

      const targetPane = document.getElementById(`tab-pane-${tabTarget}`);
      if (targetPane) {
        targetPane.classList.add('active');
      }

      if (tabTarget === 'subadmins') {
        loadSubadmins();
      }
      if (tabTarget === 'reference') {
        loadClientKeys();
        updateCodeSnippets();
      }
    });
  });

  // ════════════════════════════════════════════════════════════════════
  // 1. API PROVIDERS MANAGEMENT
  // ════════════════════════════════════════════════════════════════════
  const configsList = document.getElementById('configsList');
  const refreshBtn = document.getElementById('refreshBtn');

  // Metrics
  const metricTotal = document.getElementById('metricTotal');
  const metricActive = document.getElementById('metricActive');
  const metricPaused = document.getElementById('metricPaused');
  const metricDisabled = document.getElementById('metricDisabled');

  // API Form elements
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

  async function loadConfigs() {
    if (!configsList) return;
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
      let statusLabel = 'Active';
      let statusClass = 'status-active';

      if (!cfg.enabled) {
        statusDisplay = 'disabled';
        statusLabel = 'Manually Disabled';
        statusClass = 'status-disabled';
      } else if (cfg.health_status === 'quota_exhausted') {
        statusLabel = 'Quota Exhausted';
        statusClass = 'status-quota_exhausted';
      } else if (cfg.health_status === 'rate_limited') {
        statusLabel = 'Rate Limited (HTTP 429)';
        statusClass = 'status-rate_limited';
      } else if (cfg.health_status === 'config_error' || cfg.health_status === 'auth_failed') {
        statusLabel = 'Configuration Error (Review Required)';
        statusClass = 'status-config_error';
      } else if (cfg.health_status === 'degraded' || cfg.health_status === 'temporarily_unavailable' || cfg.health_status === 'unhealthy') {
        statusLabel = 'Temporarily Unavailable';
        statusClass = 'status-temporarily_unavailable';
      } else {
        statusLabel = 'Active';
        statusClass = 'status-active';
      }

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

      // Priority pill indicator (Priority 1 = Highest)
      const priPill = document.createElement('span');
      priPill.className = `priority-pill ${cfg.priority === 1 ? 'priority-pill-primary' : ''}`;
      priPill.textContent = cfg.priority === 1 ? 'Priority 1 (Highest)' : `Priority ${cfg.priority}`;
      title.appendChild(priPill);

      const nameSpan = document.createElement('span');
      nameSpan.textContent = `${cfg.display_name} (${cfg.provider_name.toUpperCase()})`;
      title.appendChild(nameSpan);

      const badge = document.createElement('span');
      badge.className = `status-badge ${statusClass}`;
      badge.textContent = statusLabel;
      title.appendChild(badge);
      header.appendChild(title);

      // Reorder buttons (Move Up / Down & Direct Priority Selector)
      const reorderGroup = document.createElement('div');
      reorderGroup.style.display = 'flex';
      reorderGroup.style.gap = '6px';
      reorderGroup.style.alignItems = 'center';

      // Priority selector dropdown
      const priSelect = document.createElement('select');
      priSelect.className = 'priority-select';
      priSelect.title = `Change priority of ${cfg.display_name} (Current: #${cfg.priority})`;
      for (let p = 1; p <= configs.length; p++) {
        const opt = document.createElement('option');
        opt.value = p;
        opt.textContent = `#${p}`;
        if (p === cfg.priority) {
          opt.selected = true;
        }
        priSelect.appendChild(opt);
      }

      const upBtn = document.createElement('button');
      upBtn.className = 'btn-icon-sm';
      upBtn.title = 'Move Up (Higher Priority)';
      upBtn.innerHTML = '&#9650;';
      upBtn.disabled = (cfg.priority === 1 || configs.indexOf(cfg) === 0);

      const downBtn = document.createElement('button');
      downBtn.className = 'btn-icon-sm';
      downBtn.title = 'Move Down (Lower Priority)';
      downBtn.innerHTML = '&#9660;';
      downBtn.disabled = (configs.indexOf(cfg) === configs.length - 1);

      upBtn.onclick = () => moveConfig(cfg.id, 'up', [upBtn, downBtn, priSelect], priPill);
      downBtn.onclick = () => moveConfig(cfg.id, 'down', [upBtn, downBtn, priSelect], priPill);

      priSelect.onchange = () => {
        const targetPri = parseInt(priSelect.value, 10);
        if (targetPri !== cfg.priority) {
          changeConfigPriority(cfg.id, targetPri, priSelect, [upBtn, downBtn], priPill);
        }
      };

      reorderGroup.appendChild(priSelect);
      reorderGroup.appendChild(upBtn);
      reorderGroup.appendChild(downBtn);

      header.appendChild(reorderGroup);

      const details = document.createElement('div');
      details.className = 'config-item-details';

      details.innerHTML = `
        <div class="detail-line"><strong>Priority:</strong> #${cfg.priority}</div>
        <div class="detail-line"><strong>Key:</strong> <code>${cfg.masked_credential}</code></div>
        <div class="detail-line"><strong>Endpoint:</strong> <code>${cfg.endpoint}</code></div>
        <div class="detail-line"><strong>Last Success:</strong> ${formatDate(cfg.last_success_at)}</div>
        <div class="detail-line"><strong>Failures:</strong> ${cfg.consecutive_failures || 0} consecutive</div>
        <div class="detail-line"><strong>Last Error:</strong> ${cfg.last_error_category || 'None'}</div>
        ${cfg.last_failure_reason ? `<div class="detail-line" style="grid-column: 1 / -1;"><strong>Failure Reason:</strong> ${cfg.last_failure_reason}</div>` : ''}
        ${cfg.paused_until ? `<div class="detail-line"><strong>Cooldown Until:</strong> ${formatDate(cfg.paused_until)}</div>` : ''}
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

      // Reactivate button (if paused, exhausted, or in error)
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

  async function changeConfigPriority(configId, newPriority, selectElem, siblingBtns, pillElem) {
    if (selectElem) selectElem.disabled = true;
    if (siblingBtns) siblingBtns.forEach((b) => { if (b) b.disabled = true; });
    if (pillElem) pillElem.textContent = 'Updating...';

    try {
      const res = await apiFetch(`/admin/api/configs/${configId}/priority`, {
        method: 'POST',
        body: JSON.stringify({ priority: newPriority }),
      });
      const data = await res.json();
      if (data.success) {
        showAlert(data.message || 'Priority updated successfully.', 'success');
        loadConfigs();
      } else {
        showAlert(data.error || 'Failed to update priority.', 'error');
        loadConfigs();
      }
    } catch (err) {
      showAlert(`Priority update error: ${err.message}`, 'error');
      loadConfigs();
    }
  }

  async function moveConfig(configId, direction, siblingBtns, pillElem) {
    if (siblingBtns) siblingBtns.forEach((b) => { if (b) b.disabled = true; });
    if (pillElem) pillElem.textContent = 'Updating...';

    try {
      const res = await apiFetch(`/admin/api/configs/${configId}/move`, {
        method: 'POST',
        body: JSON.stringify({ direction }),
      });
      const data = await res.json();
      if (data.success) {
        loadConfigs();
      } else {
        showAlert(data.error || 'Failed to move configuration.', 'error');
        loadConfigs();
      }
    } catch (err) {
      showAlert(`Error: ${err.message}`, 'error');
      loadConfigs();
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

    apiForm.scrollIntoView({ behavior: 'smooth' });
  }

  function resetForm() {
    formMode.value = 'create';
    formConfigId.value = '';
    formTitle.textContent = 'Add API Configuration';
    apiForm.reset();
    priorityInput.value = '';
    endpointInput.value = 'https://api.md5decrypt.net/';
    credentialLabel.textContent = 'API Key / Credential *';
    credentialHint.textContent = 'Key is encrypted at rest using HMAC-SHA256 authenticated encryption.';
    saveBtn.textContent = 'Save Configuration';
    cancelEditBtn.classList.add('hidden');
  }

  cancelEditBtn?.addEventListener('click', resetForm);
  refreshBtn?.addEventListener('click', loadConfigs);

  const normalizePrioritiesBtn = document.getElementById('normalizePrioritiesBtn');
  normalizePrioritiesBtn?.addEventListener('click', async () => {
    try {
      const res = await apiFetch('/admin/api/configs/normalize', { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        showAlert('Priorities normalized to consecutive sequence (1, 2, 3...).', 'success');
        loadConfigs();
      } else {
        showAlert(data.error || 'Failed to normalize priorities.', 'error');
      }
    } catch (err) {
      showAlert(`Error: ${err.message}`, 'error');
    }
  });

  apiForm?.addEventListener('submit', async (e) => {
    e.preventDefault();

    const mode = formMode.value;
    const configId = formConfigId.value;
    const displayName = displayNameInput.value.trim();
    const providerName = providerNameSelect.value.trim();
    const priorityVal = priorityInput.value.trim();
    const priority = priorityVal ? parseInt(priorityVal, 10) : null;
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

  // ════════════════════════════════════════════════════════════════════
  // 2. SUBADMIN MANAGEMENT (MAIN ADMIN ONLY)
  // ════════════════════════════════════════════════════════════════════
  const createSubadminForm = document.getElementById('createSubadminForm');
  const subadminUsername = document.getElementById('subadminUsername');
  const subadminPassword = document.getElementById('subadminPassword');
  const createSubadminBtn = document.getElementById('createSubadminBtn');
  const subadminsList = document.getElementById('subadminsList');
  const refreshSubadminsBtn = document.getElementById('refreshSubadminsBtn');

  async function loadSubadmins() {
    if (!subadminsList || userRole !== 'main_admin') return;

    try {
      subadminsList.innerHTML = '<p class="empty-state">Loading subadmin accounts...</p>';
      const res = await apiFetch('/admin/api/subadmins');
      if (!res.ok) {
        throw new Error(`Failed to load subadmins: HTTP ${res.status}`);
      }
      const data = await res.json();
      renderSubadminsList(data.subadmins || []);

      // Check database engine status
      try {
        const pRes = await apiFetch('/admin/api/persistence-info');
        const pData = await pRes.json();
        const noticeTitle = document.querySelector('#persistenceNotice .notice-title');
        const noticeDesc = document.querySelector('#persistenceNotice .notice-desc');
        const envBox = document.querySelector('#persistenceNotice .env-code-box');
        if (pData.success && pData.is_postgres) {
          if (noticeTitle) noticeTitle.innerHTML = '🟢 Connected to Neon PostgreSQL (Permanent Storage)';
          if (noticeDesc) noticeDesc.innerHTML = 'Your application is connected to <strong>Neon PostgreSQL</strong>. Subadmin accounts, API keys, and failover state persist automatically and permanently across all Vercel serverless cold restarts and deployments.';
          if (envBox) envBox.style.display = 'none';
        }
      } catch (_) {}
    } catch (err) {
      subadminsList.innerHTML = `<p class="empty-state">Error loading subadmins: ${err.message}</p>`;
      showAlert(err.message, 'error');
    }
  }

  function renderSubadminsList(subadmins) {
    if (!subadminsList) return;
    subadminsList.innerHTML = '';

    if (subadmins.length === 0) {
      subadminsList.innerHTML = '<p class="empty-state">No subadmins created yet. Use the form to assign a new subadmin.</p>';
      return;
    }

    subadmins.forEach((sub) => {
      const item = document.createElement('div');
      item.className = 'subadmin-item';

      const info = document.createElement('div');
      info.className = 'subadmin-info';

      const nameLine = document.createElement('div');
      nameLine.className = 'subadmin-name';
      nameLine.textContent = sub.username;

      const roleBadge = document.createElement('span');
      roleBadge.className = 'header-badge';
      roleBadge.textContent = 'Subadmin';
      nameLine.appendChild(roleBadge);

      const statusBadge = document.createElement('span');
      statusBadge.className = `status-badge ${sub.is_active ? 'status-active' : 'status-disabled'}`;
      statusBadge.textContent = sub.is_active ? 'Active' : 'Disabled';
      nameLine.appendChild(statusBadge);

      info.appendChild(nameLine);

      const meta = document.createElement('div');
      meta.className = 'subadmin-meta';
      meta.textContent = `Created: ${sub.created_at ? new Date(sub.created_at).toLocaleString() : 'N/A'}`;
      info.appendChild(meta);

      const actions = document.createElement('div');
      actions.className = 'subadmin-actions';

      // Toggle status button
      const toggleBtn = document.createElement('button');
      toggleBtn.className = 'btn btn-sm btn-outline';
      toggleBtn.textContent = sub.is_active ? 'Disable' : 'Enable';
      toggleBtn.onclick = () => toggleSubadmin(sub.id, sub.username);
      actions.appendChild(toggleBtn);

      // Reset password button
      const resetBtn = document.createElement('button');
      resetBtn.className = 'btn btn-sm btn-secondary';
      resetBtn.textContent = 'Reset Password';
      resetBtn.onclick = () => resetSubadminPassword(sub.id, sub.username);
      actions.appendChild(resetBtn);

      // Delete button
      const deleteBtn = document.createElement('button');
      deleteBtn.className = 'btn btn-sm btn-danger';
      deleteBtn.textContent = 'Delete';
      deleteBtn.onclick = () => deleteSubadmin(sub.id, sub.username);
      actions.appendChild(deleteBtn);

      item.appendChild(info);
      item.appendChild(actions);
      subadminsList.appendChild(item);
    });

    // Update suggested SUBADMIN_USERS environment string
    const subadminEnvCode = document.getElementById('subadminEnvCode');
    if (subadminEnvCode) {
      if (subadmins.length > 0) {
        const pairs = subadmins.map((s) => `${s.username}:YOUR_PASSWORD`).join(',');
        subadminEnvCode.textContent = `SUBADMIN_USERS=${pairs}`;
      } else {
        subadminEnvCode.textContent = 'SUBADMIN_USERS=username:password';
      }
    }
  }

  async function toggleSubadmin(subId, name) {
    try {
      const res = await apiFetch(`/admin/api/subadmins/${subId}/toggle`, { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        showAlert(data.message, 'success');
        loadSubadmins();
      } else {
        showAlert(data.error || 'Failed to update subadmin status.', 'error');
      }
    } catch (err) {
      showAlert(`Error: ${err.message}`, 'error');
    }
  }

  async function resetSubadminPassword(subId, name) {
    const newPassword = prompt(`Enter new password for subadmin "${name}" (minimum 6 characters):`);
    if (newPassword === null) return; // user cancelled

    if (newPassword.trim().length < 6) {
      showAlert('New password must be at least 6 characters long.', 'error');
      return;
    }

    try {
      const res = await apiFetch(`/admin/api/subadmins/${subId}/reset-password`, {
        method: 'POST',
        body: JSON.stringify({ new_password: newPassword.trim() }),
      });
      const data = await res.json();
      if (data.success) {
        showAlert(data.message, 'success');
      } else {
        showAlert(data.error || 'Failed to reset password.', 'error');
      }
    } catch (err) {
      showAlert(`Error: ${err.message}`, 'error');
    }
  }

  async function deleteSubadmin(subId, name) {
    if (!confirm(`Are you sure you want to permanently delete the subadmin account "${name}"?`)) {
      return;
    }

    try {
      const res = await apiFetch(`/admin/api/subadmins/${subId}`, { method: 'DELETE' });
      const data = await res.json();
      if (data.success) {
        showAlert(data.message, 'success');
        loadSubadmins();
      } else {
        showAlert(data.error || 'Failed to delete subadmin.', 'error');
      }
    } catch (err) {
      showAlert(`Error: ${err.message}`, 'error');
    }
  }

  createSubadminForm?.addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = subadminUsername.value.trim();
    const password = subadminPassword.value.trim();

    if (!username) {
      showAlert('Username is required.', 'error');
      return;
    }

    if (username.length < 3) {
      showAlert('Username must be at least 3 characters long.', 'error');
      return;
    }

    if (!password || password.length < 6) {
      showAlert('Password must be at least 6 characters long.', 'error');
      return;
    }

    createSubadminBtn.disabled = true;
    createSubadminBtn.textContent = 'Creating...';

    try {
      const res = await apiFetch('/admin/api/subadmins', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (data.success) {
        showAlert(data.message, 'success');
        createSubadminForm.reset();
        loadSubadmins();
      } else {
        showAlert(data.error || 'Failed to create subadmin.', 'error');
      }
    } catch (err) {
      showAlert(`Error: ${err.message}`, 'error');
    } finally {
      createSubadminBtn.disabled = false;
      createSubadminBtn.textContent = 'Create Subadmin';
    }
  });

  refreshSubadminsBtn?.addEventListener('click', loadSubadmins);

  // ── Backup Export / Restore & Persistence ───────────────────────────
  const exportBackupBtn = document.getElementById('exportBackupBtn');
  const importBackupTriggerBtn = document.getElementById('importBackupTriggerBtn');
  const backupFileInput = document.getElementById('backupFileInput');
  const copyEnvCodeBtn = document.getElementById('copyEnvCodeBtn');

  exportBackupBtn?.addEventListener('click', async () => {
    try {
      const res = await apiFetch('/admin/api/backup/export');
      const data = await res.json();
      if (data.success) {
        const blob = new Blob([JSON.stringify(data.backup, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scp_state_backup_${new Date().toISOString().slice(0, 10)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showAlert('Backup exported and downloaded successfully.', 'success');
      } else {
        showAlert('Failed to export backup.', 'error');
      }
    } catch (err) {
      showAlert(`Export error: ${err.message}`, 'error');
    }
  });

  importBackupTriggerBtn?.addEventListener('click', () => {
    backupFileInput?.click();
  });

  backupFileInput?.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const text = await file.text();
      const backupJson = JSON.parse(text);

      const res = await apiFetch('/admin/api/backup/import', {
        method: 'POST',
        body: JSON.stringify({ backup: backupJson }),
      });
      const data = await res.json();
      if (data.success) {
        showAlert(data.message, 'success');
        loadSubadmins();
        loadConfigs();
        loadClientKeys();
      } else {
        showAlert(data.error || 'Failed to import backup.', 'error');
      }
    } catch (err) {
      showAlert(`Import error: ${err.message}`, 'error');
    } finally {
      backupFileInput.value = '';
    }
  });

  copyEnvCodeBtn?.addEventListener('click', () => {
    const code = document.getElementById('subadminEnvCode')?.textContent || '';
    navigator.clipboard.writeText(code).then(() => {
      showAlert('SUBADMIN_USERS string copied to clipboard! Paste into Vercel Project Settings > Environment Variables to make subadmins permanent.', 'success');
    });
  });

  // ════════════════════════════════════════════════════════════════════
  // 3. MY ACCOUNT (CHANGE USERNAME AND PASSWORD AFTER LOGIN)
  // ════════════════════════════════════════════════════════════════════
  const accountForm = document.getElementById('accountForm');
  const accCurrentPassword = document.getElementById('accCurrentPassword');
  const accNewUsername = document.getElementById('accNewUsername');
  const accNewPassword = document.getElementById('accNewPassword');
  const accConfirmPassword = document.getElementById('accConfirmPassword');
  const saveAccountBtn = document.getElementById('saveAccountBtn');

  accountForm?.addEventListener('submit', async (e) => {
    e.preventDefault();

    const currentPassword = accCurrentPassword.value.trim();
    const newUsername = accNewUsername.value.trim();
    const newPassword = accNewPassword.value.trim();
    const confirmPassword = accConfirmPassword.value.trim();

    if (!currentPassword) {
      showAlert('Current password is required to save account changes.', 'error');
      return;
    }

    if (newPassword) {
      if (newPassword.length < 6) {
        showAlert('New password must be at least 6 characters long.', 'error');
        return;
      }
      if (newPassword !== confirmPassword) {
        showAlert('New password and confirmation do not match.', 'error');
        return;
      }
    }

    saveAccountBtn.disabled = true;
    saveAccountBtn.textContent = 'Updating...';

    try {
      const payload = {
        current_password: currentPassword,
      };

      if (newUsername) {
        payload.new_username = newUsername;
      }
      if (newPassword) {
        payload.new_password = newPassword;
      }

      const res = await apiFetch('/admin/api/account/update', {
        method: 'POST',
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (data.success) {
        showAlert(data.message, 'success');
        if (data.username && headerUsername) {
          headerUsername.textContent = data.username;
        }
        accCurrentPassword.value = '';
        accNewPassword.value = '';
        accConfirmPassword.value = '';
      } else {
        showAlert(data.error || 'Failed to update credentials.', 'error');
      }
    } catch (err) {
      showAlert(`Error: ${err.message}`, 'error');
    } finally {
      saveAccountBtn.disabled = false;
      saveAccountBtn.textContent = 'Update Account Credentials';
    }
  });

  // ════════════════════════════════════════════════════════════════════
  // 4. EXTERNAL CLIENT API KEYS & CODE EXAMPLES
  // ════════════════════════════════════════════════════════════════════
  const clientKeysList = document.getElementById('clientKeysList');
  const refreshClientKeysBtn = document.getElementById('refreshClientKeysBtn');
  const createClientKeyForm = document.getElementById('createClientKeyForm');
  const clientKeyName = document.getElementById('clientKeyName');
  const clientKeyRateLimit = document.getElementById('clientKeyRateLimit');
  const createClientKeyBtn = document.getElementById('createClientKeyBtn');
  const apiBaseUrlDisplay = document.getElementById('apiBaseUrlDisplay');
  const snippetCode = document.getElementById('snippetCode');
  const copySnippetBtn = document.getElementById('copySnippetBtn');
  const snippetTabButtons = document.querySelectorAll('.snippet-tab-btn');

  let activeClientKeys = [];
  let currentSnippetLanguage = 'curl';

  if (apiBaseUrlDisplay) {
    apiBaseUrlDisplay.textContent = window.location.origin;
  }

  async function loadClientKeys() {
    if (!clientKeysList || userRole !== 'main_admin') return;

    try {
      clientKeysList.innerHTML = '<p class="empty-state">Loading client API keys...</p>';
      const res = await apiFetch('/admin/api/client-keys');
      if (!res.ok) {
        throw new Error(`Failed to load keys: HTTP ${res.status}`);
      }
      const data = await res.json();
      activeClientKeys = data.keys || [];
      renderClientKeys(activeClientKeys);
      updateCodeSnippets();
    } catch (err) {
      clientKeysList.innerHTML = `<p class="empty-state">Error loading keys: ${err.message}</p>`;
      showAlert(err.message, 'error');
    }
  }

  function renderClientKeys(keys) {
    if (!clientKeysList) return;
    clientKeysList.innerHTML = '';

    if (keys.length === 0) {
      clientKeysList.innerHTML = '<p class="empty-state">No client API keys created yet. Generate one above to allow another project to use this API.</p>';
      return;
    }

    keys.forEach((key) => {
      const item = document.createElement('div');
      item.className = 'subadmin-item';

      const info = document.createElement('div');
      info.className = 'subadmin-info';

      const nameLine = document.createElement('div');
      nameLine.className = 'subadmin-name';
      nameLine.textContent = key.name;

      const statusBadge = document.createElement('span');
      statusBadge.className = `status-badge ${key.is_active ? 'status-active' : 'status-disabled'}`;
      statusBadge.textContent = key.is_active ? 'Active' : 'Revoked';
      nameLine.appendChild(statusBadge);

      info.appendChild(nameLine);

      const keyDisplay = document.createElement('div');
      keyDisplay.style.margin = '4px 0';
      keyDisplay.innerHTML = `
        <span class="key-token-box">
          <code>${key.api_key}</code>
          <button type="button" class="btn-copy-inline" title="Copy API Key" onclick="navigator.clipboard.writeText('${key.api_key}'); alert('API Key copied to clipboard!');">Copy</button>
        </span>
      `;
      info.appendChild(keyDisplay);

      const meta = document.createElement('div');
      meta.className = 'subadmin-meta';
      meta.innerHTML = `
        <span><strong>Rate Limit:</strong> ${key.rate_limit_per_minute} req/min</span> &bull;
        <span><strong>Usage:</strong> ${key.requests_count} calls</span> &bull;
        <span><strong>Last Used:</strong> ${key.last_used_at ? new Date(key.last_used_at).toLocaleString() : 'Never'}</span>
      `;
      info.appendChild(meta);

      const actions = document.createElement('div');
      actions.className = 'subadmin-actions';

      // Toggle status button
      const toggleBtn = document.createElement('button');
      toggleBtn.className = 'btn btn-sm btn-outline';
      toggleBtn.textContent = key.is_active ? 'Revoke' : 'Activate';
      toggleBtn.onclick = () => toggleClientKey(key.id, key.name);
      actions.appendChild(toggleBtn);

      // Delete button
      const deleteBtn = document.createElement('button');
      deleteBtn.className = 'btn btn-sm btn-danger';
      deleteBtn.textContent = 'Delete';
      deleteBtn.onclick = () => deleteClientKey(key.id, key.name);
      actions.appendChild(deleteBtn);

      item.appendChild(info);
      item.appendChild(actions);
      clientKeysList.appendChild(item);
    });
  }

  async function toggleClientKey(keyId, name) {
    try {
      const res = await apiFetch(`/admin/api/client-keys/${keyId}/toggle`, { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        showAlert(data.message, 'success');
        loadClientKeys();
      } else {
        showAlert(data.error || 'Failed to update key status.', 'error');
      }
    } catch (err) {
      showAlert(`Error: ${err.message}`, 'error');
    }
  }

  async function deleteClientKey(keyId, name) {
    if (!confirm(`Are you sure you want to permanently delete the API key for "${name}"? External requests using this key will immediately be rejected.`)) {
      return;
    }

    try {
      const res = await apiFetch(`/admin/api/client-keys/${keyId}`, { method: 'DELETE' });
      const data = await res.json();
      if (data.success) {
        showAlert(data.message, 'success');
        loadClientKeys();
      } else {
        showAlert(data.error || 'Failed to delete key.', 'error');
      }
    } catch (err) {
      showAlert(`Error: ${err.message}`, 'error');
    }
  }

  createClientKeyForm?.addEventListener('submit', async (e) => {
    e.preventDefault();

    const name = clientKeyName.value.trim();
    const rateLimit = parseInt(clientKeyRateLimit.value, 10) || 60;

    if (!name) {
      showAlert('Application or client name is required.', 'error');
      return;
    }

    createClientKeyBtn.disabled = true;
    createClientKeyBtn.textContent = 'Generating...';

    try {
      const res = await apiFetch('/admin/api/client-keys', {
        method: 'POST',
        body: JSON.stringify({ name, rate_limit_per_minute: rateLimit }),
      });
      const data = await res.json();
      if (data.success) {
        showAlert(data.message, 'success');
        createClientKeyForm.reset();
        clientKeyRateLimit.value = '60';
        loadClientKeys();
      } else {
        showAlert(data.error || 'Failed to generate key.', 'error');
      }
    } catch (err) {
      showAlert(`Error: ${err.message}`, 'error');
    } finally {
      createClientKeyBtn.disabled = false;
      createClientKeyBtn.textContent = 'Generate API Key';
    }
  });

  refreshClientKeysBtn?.addEventListener('click', loadClientKeys);

  // ── Code Snippets Generation ────────────────────────────────────────
  function getSampleApiKey() {
    const active = activeClientKeys.find((k) => k.is_active);
    return active ? active.api_key : 'scp_live_your_api_key_here';
  }

  function updateCodeSnippets() {
    if (!snippetCode) return;

    const origin = window.location.origin || 'https://student-credentials-provider.vercel.app';
    const apiKey = getSampleApiKey();

    const snippets = {
      curl: `curl -X POST "${origin}/api/v1/lookup" \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: ${apiKey}" \\
  -d '{
    "lookup_input": "098f6bcd4621d373cade4e832627b4f6",
    "algorithm_type": "md5"
  }'`,

      python: `import requests

url = "${origin}/api/v1/lookup"
headers = {
    "Content-Type": "application/json",
    "X-API-Key": "${apiKey}"
}
payload = {
    "lookup_input": "098f6bcd4621d373cade4e832627b4f6",
    "algorithm_type": "md5"
}

response = requests.post(url, json=payload, headers=headers)
data = response.json()

if data.get("success") and data.get("status") == "match_found":
    print("Found credential:", data.get("lookup_result"))
else:
    print("Lookup status:", data.get("status"))`,

      javascript: `// Modern Browser or Node.js 18+ (Fetch API)
async function lookupStudentHash(hash) {
  const response = await fetch('${origin}/api/v1/lookup', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': '${apiKey}'
    },
    body: JSON.stringify({
      lookup_input: hash,
      algorithm_type: 'md5'
    })
  });

  const data = await response.json();
  if (data.success && data.status === 'match_found') {
    console.log('Result:', data.lookup_result);
  } else {
    console.log('Not found or error:', data.status);
  }
  return data;
}

// Example usage:
lookupStudentHash('098f6bcd4621d373cade4e832627b4f6');`,

      nodejs: `// Node.js with Axios
const axios = require('axios');

async function lookupCredential(hash) {
  try {
    const response = await axios.post('${origin}/api/v1/lookup', {
      lookup_input: hash,
      algorithm_type: 'md5'
    }, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': '${apiKey}'
      }
    });

    return response.data;
  } catch (error) {
    console.error('Request failed:', error.response?.data || error.message);
    throw error;
  }
}

lookupCredential('098f6bcd4621d373cade4e832627b4f6')
  .then(res => console.log('Response:', res));`,

      php: `<?php
// PHP cURL Integration Example
$url = "${origin}/api/v1/lookup";
$apiKey = "${apiKey}";

$data = [
    "lookup_input" => "098f6bcd4621d373cade4e832627b4f6",
    "algorithm_type" => "md5"
];

$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "Content-Type: application/json",
    "X-API-Key: " . $apiKey
]);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

$result = json_decode($response, true);
if ($httpCode === 200 && ($result['status'] ?? '') === 'match_found') {
    echo "Found credential: " . $result['lookup_result'] . "\\n";
} else {
    echo "Lookup completed with status: " . ($result['status'] ?? 'unknown') . "\\n";
}
?>`,
    };

    snippetCode.textContent = snippets[currentSnippetLanguage] || snippets.curl;
  }

  snippetTabButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      snippetTabButtons.forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      currentSnippetLanguage = btn.getAttribute('data-snippet') || 'curl';
      updateCodeSnippets();
    });
  });

  copySnippetBtn?.addEventListener('click', () => {
    if (!snippetCode) return;
    navigator.clipboard.writeText(snippetCode.textContent).then(() => {
      const originalText = copySnippetBtn.textContent;
      copySnippetBtn.textContent = 'Copied!';
      setTimeout(() => {
        copySnippetBtn.textContent = originalText;
      }, 2000);
    });
  });

  // Initial load
  loadConfigs();
  if (userRole === 'main_admin') {
    loadSubadmins();
    loadClientKeys();
  }
  updateCodeSnippets();
});
