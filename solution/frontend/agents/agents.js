const API_BASE = window.location.origin;

const state = {
  agents: [],
  selectedAgentId: null,
  agentCache: new Map(),
};

window.addEventListener('DOMContentLoaded', () => {
  initialise();
});

function getStatusLabel(status = '') {
  const normalised = status.toLowerCase();
  if (normalised === 'active') return 'Active';
  if (normalised === 'inactive') return 'Inactive';
  if (normalised === 'deleted') return 'Deleted';
  if (['warning', 'degraded'].includes(normalised)) return 'Warning';
  if (normalised === 'external') return 'External';
  return 'Unknown';
}

function formatDateTime(value) {
  if (!value) return '생성 시각 미확인';
  try {
    return `생성 시간: ${new Date(value).toLocaleString()}`;
  } catch (error) {
    return '생성 시각 미확인';
  }
}

async function initialise() {
  await loadAgents();
  bindSearch();
  setupAddAgentModal();
}

function bindSearch() {
  const searchInput = document.getElementById('agent-search');
  if (!searchInput) return;

  searchInput.addEventListener('input', (event) => {
    renderAgentList(event.target.value.trim().toLowerCase());
  });
}

function getSearchTerm() {
  const searchInput = document.getElementById('agent-search');
  return (searchInput?.value || '').trim().toLowerCase();
}

async function loadAgents() {
  try {
    const response = await fetch(`${API_BASE}/api/agents`);
    if (!response.ok) throw new Error('에이전트를 불러오지 못했습니다');
    const agents = await response.json();

    state.agents = (Array.isArray(agents) ? agents : []).filter(
      (agent) => (agent.status || '').toLowerCase() !== 'deleted'
    );
    renderAgentList(getSearchTerm());
  } catch (error) {
    console.error('에이전트 목록을 불러오지 못했습니다', error);
    const list = document.getElementById('agent-list');
    if (list) {
      list.innerHTML = '<li class="empty-state">에이전트 목록을 불러올 수 없습니다.</li>';
    }
  }
}

function renderAgentList(filter = '') {
  const list = document.getElementById('agent-list');
  const template = document.getElementById('agent-item-template');
  if (!list || !template) return;

  list.innerHTML = '';

  const filteredAgents = state.agents.filter((agent) => {
    if ((agent.status || '').toLowerCase() === 'deleted') return false;
    if (!filter) return true;
    return (
      agent.agent_id?.toLowerCase().includes(filter) ||
      agent.name?.toLowerCase().includes(filter) ||
      agent.description?.toLowerCase().includes(filter)
    );
  });

  if (filteredAgents.length === 0) {
    list.innerHTML = '<li class="empty-state">검색 조건과 일치하는 에이전트가 없습니다.</li>';
    return;
  }

  filteredAgents
    .sort((a, b) => (a.name || a.agent_id).localeCompare(b.name || b.agent_id))
    .forEach((agent) => {
      const clone = template.content.cloneNode(true);
      const element = clone.querySelector('.agent-item');
      const name = clone.querySelector('.agent-name');
      const description = clone.querySelector('.agent-description');
      const statusChip = clone.querySelector('.status-chip');

      if (name) {
        name.textContent = agent.name || agent.agent_id;
      }
      if (description) {
        description.textContent = agent.description || '';
      }
      if (statusChip) {
        statusChip.classList.add(getStatusClass(agent.status));
        statusChip.textContent = getStatusLabel(agent.status || '');
      }

      element.dataset.agentId = agent.agent_id;
      element.addEventListener('click', () => selectAgent(agent.agent_id));

      if (agent.agent_id === state.selectedAgentId) {
        element.classList.add('active');
      }

      list.appendChild(clone);
    });
}

function getStatusClass(status = '') {
  const normalised = status.toLowerCase();
  if (normalised === 'active') return 'status-active';
  if (normalised === 'inactive' || normalised === 'deleted') return 'status-inactive';
  return 'status-warning';
}

async function selectAgent(agentId) {
  state.selectedAgentId = agentId;
  highlightSelectedAgent();

  const details = await fetchAgentDetails(agentId);
  if (details) {
    renderAgentDetails(details);
  }
}

function highlightSelectedAgent() {
  document.querySelectorAll('.agent-item').forEach((item) => {
    if (item.dataset.agentId === state.selectedAgentId) {
      item.classList.add('active');
    } else {
      item.classList.remove('active');
    }
  });
}

async function fetchAgentDetails(agentId) {
  if (state.agentCache.has(agentId)) {
    return state.agentCache.get(agentId);
  }

  try {
    const response = await fetch(
      `${API_BASE}/api/agents/${encodeURIComponent(agentId)}`
    );
    if (!response.ok) throw new Error('에이전트 정보를 가져오지 못했습니다');
    const agent = await response.json();

    state.agentCache.set(agentId, agent);
    return agent;
  } catch (error) {
    console.error('에이전트 상세 정보를 불러오지 못했습니다', error);
    const container = document.getElementById('agent-details');
    if (container) {
      container.innerHTML = '<div class="agent-error">에이전트 정보를 불러올 수 없습니다.</div>';
    }
    return null;
  }
}

function renderAgentDetails(agent) {
  const container = document.getElementById('agent-details');
  const template = document.getElementById('agent-details-template');
  if (!container || !template) return;

  container.innerHTML = '';
  const node = template.content.cloneNode(true);

  const title = node.querySelector('.agent-title');
  const subtitle = node.querySelector('.agent-subtitle');
  const statusChip = node.querySelector('.overview-meta .status-chip');
  const created = node.querySelector('[data-role="created"]');
  const deleteButton = node.querySelector('#delete-agent-btn');
  const actionStatus = node.querySelector('#agent-action-status');
  const infoGrid = node.querySelector('#agent-info-grid');

  if (title) {
    title.textContent = agent.name || agent.agent_id;
  }
  if (subtitle) {
    subtitle.textContent = agent.description || '';
  }
  if (statusChip) {
    statusChip.classList.add(getStatusClass(agent.status));
    statusChip.textContent = getStatusLabel(agent.status || '');
  }
  if (created) {
    created.textContent = formatDateTime(agent.created_at);
  }
  
  // 에이전트 상세 정보 렌더링
  if (infoGrid) {
    renderAgentInfo(infoGrid, agent);
  }
  
  // 에이전트 기능 (Tools) 렌더링
  const toolsList = node.querySelector('#tools-list');
  if (toolsList) {
    renderAgentTools(toolsList, agent);
  }

  if (deleteButton) {
    const isDeleted = (agent.status || '').toLowerCase() === 'deleted';
    deleteButton.disabled = isDeleted;
    if (isDeleted && actionStatus) {
      setAgentActionStatus(actionStatus, '이미 삭제된 에이전트입니다.', true);
    } else {
      deleteButton.addEventListener('click', async () => {
        await deleteAgent(agent, deleteButton, actionStatus);
      });
    }
  }

  container.appendChild(node);
}

function renderAgentInfo(container, agent) {
  const infoItems = [];
  
  // ID
  if (agent.agent_id) {
    infoItems.push({ label: 'ID', value: agent.agent_id });
  }
  
  // URL
  if (agent.url) {
    infoItems.push({ 
      label: 'URL', 
      value: `<a href="${agent.url}" target="_blank">${agent.url}</a>` 
    });
  }
  
  // 버전
  if (agent.version) {
    infoItems.push({ label: '버전', value: agent.version });
  }
  
  // 프로토콜 버전
  if (agent.protocolVersion) {
    infoItems.push({ label: '프로토콜', value: `v${agent.protocolVersion}` });
  }
  
  // 테넌트
  if (agent.tenants && agent.tenants.length > 0) {
    infoItems.push({ label: '테넌트', value: agent.tenants.join(', ') });
  }
  
  // 업데이트 시간
  if (agent.updated_at) {
    infoItems.push({ 
      label: '마지막 수정', 
      value: new Date(agent.updated_at).toLocaleString() 
    });
  }
  
  container.innerHTML = infoItems.map(item => `
    <span class="info-label">${item.label}</span>
    <span class="info-value">${item.value}</span>
  `).join('');
}

function renderAgentTools(listElement, agent) {
  listElement.innerHTML = '';
  
  // capabilities.extensions에서 도구 추출
  const tools = [];
  const extensions = agent.capabilities?.extensions || [];
  
  extensions.forEach(ext => {
    const extTools = ext.params?.tools || [];
    extTools.forEach(tool => {
      tools.push({
        id: tool.tool_id || tool.name || '도구',
        description: tool.description || '',
        skill: tool.skill || ''
      });
    });
  });
  
  // 기존 plugins도 확인
  const plugins = agent.plugins || [];
  plugins.forEach(plugin => {
    const p = typeof plugin === 'string' ? { name: plugin } : plugin;
    if (!tools.find(t => t.id === p.name)) {
      tools.push({
        id: p.name || '기능',
        description: '',
        skill: p.type || ''
      });
    }
  });
  
  if (tools.length === 0) {
    listElement.innerHTML = '<li class="empty-state">등록된 기능이 없습니다.</li>';
    return;
  }
  
  tools.forEach(tool => {
    const item = document.createElement('li');
    item.className = 'tool-item';
    item.innerHTML = `
      <div class="tool-header">
        <span class="tool-icon material-symbols-outlined">function</span>
        <strong class="tool-name">${tool.id}</strong>
        ${tool.skill ? `<span class="tool-skill-badge">${tool.skill}</span>` : ''}
      </div>
      ${tool.description ? `<p class="tool-description">${tool.description}</p>` : ''}
    `;
    listElement.appendChild(item);
  });
}

function renderPluginList(listElement, plugins = []) {
  listElement.innerHTML = '';
  if (!plugins || plugins.length === 0) {
    listElement.innerHTML = '<li class="empty-state">등록된 플러그인이 없습니다.</li>';
    return;
  }

  plugins
    .map((plugin) => (typeof plugin === 'string' ? { name: plugin } : plugin))
    .forEach((plugin) => {
      const item = document.createElement('li');
      item.className = 'plugin-item';
      item.innerHTML = `
        <div>
          <strong>${plugin.name || '플러그인'}</strong>
          ${plugin.type ? `<span class="pill">${plugin.type}</span>` : ''}
        </div>
        <span class="status-chip ${getStatusClass(plugin.status || 'active')}">
          ${getStatusLabel(plugin.status || 'active')}
        </span>
      `;
      listElement.appendChild(item);
    });
}

function setAgentActionStatus(element, message, isError = false) {
  if (!element) return;
  element.textContent = message || '';
  element.classList.toggle('error', Boolean(isError));
}

function showAgentPlaceholder(message) {
  const container = document.getElementById('agent-details');
  if (!container) return;
  const title = message || '에이전트를 선택해주세요';
  container.innerHTML = `
    <div class="agent-details-placeholder">
      <h3>${title}</h3>
      <p>
        왼쪽 목록에서 에이전트를 선택하면 플러그인 연결 현황을 확인할 수 있습니다.
      </p>
    </div>
  `;
}

async function deleteAgent(agent, triggerButton, statusElement) {
  if (!agent || !agent.agent_id) return;

  if (!verifiedToken) {
    setAgentActionStatus(statusElement, '관리자 JWT를 먼저 확인해주세요.', true);
    openAdminTokenModal('delete');
    return;
  }

  const label = agent.name || agent.agent_id;
  if (!confirm(`에이전트 ${label}을(를) 삭제할까요?`)) return;

  const originalLabel = triggerButton?.textContent;
  if (triggerButton) {
    triggerButton.disabled = true;
    triggerButton.textContent = '삭제 중...';
  }
  setAgentActionStatus(statusElement, '삭제 중...');

  try {
    const response = await fetch(`${API_BASE}/api/agents/${encodeURIComponent(agent.agent_id)}`, {
      method: 'DELETE',
      headers: { Authorization: verifiedToken },
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.message || err.error || '에이전트 삭제에 실패했습니다.');
    }

    setAgentActionStatus(statusElement, '삭제 완료. 목록을 갱신합니다.');
    state.agentCache.delete(agent.agent_id);
    state.selectedAgentId = null;
    await loadAgents();
    showAgentPlaceholder('에이전트를 삭제했습니다. 다른 에이전트를 선택하세요.');
  } catch (error) {
    console.error('에이전트 삭제 실패', error);
    setAgentActionStatus(statusElement, error.message || '에이전트를 삭제하지 못했습니다.', true);
  } finally {
    if (triggerButton) {
      triggerButton.disabled = false;
      triggerButton.textContent = originalLabel || '삭제';
    }
  }
}

let tokenPurpose = null; // 'add' | 'delete' | null

function openAdminTokenModal(purpose = 'add') {
  tokenPurpose = purpose;
  const tokenModal = document.getElementById('token-modal');
  if (!tokenModal) return;

  tokenModal.classList.remove('hidden');
  const input = tokenModal.querySelector('#token-input');
  const status = tokenModal.querySelector('#token-status');
  if (status) {
    status.textContent = '';
    status.classList.remove('error');
  }
  if (input) {
    input.value = '';
    input.focus();
    if (typeof input.select === 'function') {
      input.select();
    }
  }
}

function setupAddAgentModal() {
  const modal = document.getElementById('add-agent-modal');
  const closeButton = document.getElementById('close-add-agent-modal');
  const form = document.getElementById('add-agent-form');
  const openButton = document.getElementById('open-add-agent-btn');
  const tokenModal = document.getElementById('token-modal');
  const tokenClose = document.getElementById('token-modal-close');
  const tokenForm = document.getElementById('token-form');

  openButton?.addEventListener('click', () => openAdminTokenModal('add'));

  tokenClose?.addEventListener('click', () => {
    tokenModal?.classList.add('hidden');
  });

  tokenModal?.addEventListener('click', (event) => {
    if (event.target === tokenModal) {
      tokenModal.classList.add('hidden');
    }
  });

  tokenForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const input = tokenForm.querySelector('#token-input');
    const status = tokenForm.querySelector('#token-status');
    if (!input || !status) return;
    const rawToken = input.value.trim();
    if (!rawToken) {
      status.textContent = '토큰을 입력해야 합니다.';
      status.classList.add('error');
      return;
    }
    status.textContent = '토큰 확인 중...';
    status.classList.remove('error');
    await verifyAdminToken(rawToken, tokenModal);
  });

  closeButton?.addEventListener('click', () => closeAddAgentModal());
  modal?.addEventListener('click', (event) => {
    if (event.target === modal) {
      closeAddAgentModal();
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      const overlay = document.getElementById('add-agent-modal');
      if (overlay && !overlay.classList.contains('hidden')) {
        closeAddAgentModal();
      }
    }
  });

  form?.addEventListener('submit', async (event) => {
    event.preventDefault();
    await submitAddAgent(form);
  });
}

function showAddAgentModal() {
  const modal = document.getElementById('add-agent-modal');
  if (modal) {
    modal.classList.remove('hidden');
    const textarea = modal.querySelector('#add-agent-body');
    textarea?.focus();
    textarea?.select();
  }
}

function closeAddAgentModal() {
  const modal = document.getElementById('add-agent-modal');
  if (modal) {
    modal.classList.add('hidden');
    const form = modal.querySelector('#add-agent-form');
    form?.reset();
    const status = modal.querySelector('#add-agent-status');
    if (status) {
      status.textContent = '';
      status.classList.remove('error');
    }
  }
}

async function submitAddAgent(form) {
  const textarea = form.querySelector('#add-agent-body');
  const status = document.getElementById('add-agent-status');
  if (!textarea || !status) {
    return;
  }

  let payload;
  try {
    payload = JSON.parse(textarea.value);
  } catch (error) {
    updateModalStatus(status, '잘못된 JSON입니다.', true);
    return;
  }

  const requestBody =
    payload && typeof payload === 'object'
      ? payload.card && typeof payload.card === 'object'
        ? payload
        : { card: payload }
      : {};

  const tenants = Array.from(form.querySelectorAll('input[name="tenant"]:checked')).map(
    (input) => input.value
  );
  if (tenants.length > 0) {
    requestBody.tenants = tenants;
  }

  if (!verifiedToken) {
    updateModalStatus(status, '관리자 JWT 토큰을 먼저 확인하세요.', true);
    return;
  }

  updateModalStatus(status, '등록 중…');

  try {
    const headers = {
      'Content-Type': 'application/json',
      Authorization: verifiedToken,
    };

    const response = await fetch(`${API_BASE}/api/create-agent`, {
      method: 'POST',
      headers,
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || '에이전트를 생성하지 못했습니다');
    }

    updateModalStatus(status, '에이전트를 생성했습니다.');
    setTimeout(() => {
      closeAddAgentModal();
      loadAgents();
    }, 600);
  } catch (error) {
    console.error('에이전트 생성 실패', error);
    updateModalStatus(status, error.message || '에이전트를 생성하지 못했습니다.', true);
  }
}

function updateModalStatus(element, message, isError = false) {
  if (!element) return;
  element.textContent = message;
  element.classList.toggle('error', Boolean(isError));
}

let verifiedToken = null;

async function verifyAdminToken(rawToken, tokenModal) {
  const tokenValue = rawToken.toLowerCase().startsWith('bearer ')
    ? rawToken
    : `Bearer ${rawToken}`;

  try {
    const response = await fetch(`${API_BASE}/api/verify-admin`, {
      method: 'GET',
      headers: { Authorization: tokenValue },
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || '관리자 토큰이 유효하지 않습니다.');
    }
    verifiedToken = tokenValue;
    tokenModal?.classList.add('hidden');
    if (tokenPurpose === 'add') {
      showAddAgentModal();
    }
    tokenPurpose = null;
  } catch (error) {
    const status = tokenModal?.querySelector('#token-status');
    if (status) {
      status.textContent = error.message || '토큰 확인에 실패했습니다.';
      status.classList.add('error');
    }
  }
}
