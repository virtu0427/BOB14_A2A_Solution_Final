const API_BASE = window.location.origin;
const REFRESH_INTERVAL = 30000;

let eventsChart;
let entityChart;
let cachedAgents = [];
let cachedRulesets = [];
let cachedLogs = [];
let entitySummaryData = [];
let entityDetailKey = 'agents';

window.addEventListener('DOMContentLoaded', () => {
  setupControls();
  loadAll();
  setInterval(loadAll, REFRESH_INTERVAL);
});

function setupControls() {
  const refreshFlowButton = document.getElementById('refresh-flow');
  if (refreshFlowButton) {
    refreshFlowButton.addEventListener('click', () => loadAgentFlow(true));
  }

  const refreshDashboardButton = document.getElementById('refresh-dashboard');
  if (refreshDashboardButton) {
    refreshDashboardButton.addEventListener('click', () => loadAll(true));
  }
}

function translateStatus(status = '') {
  const normalised = (status || '').toLowerCase();
  if (normalised === 'active') return '활성';
  if (normalised === 'inactive') return '중지';
  if (normalised === 'external') return '외부';
  if (['warning', 'degraded'].includes(normalised)) return '주의';
  return '미확인';
}

function translateVerdict(verdict = '') {
  const normalised = (verdict || '').toLowerCase();
  if (normalised === 'pass') return '통과';
  if (['violation', 'blocked'].includes(normalised)) return '위반';
  if (normalised === 'allow') return '허용';
  if (normalised === 'deny') return '거부';
  return verdict || '미확인';
}

function translateRulesetType(type = '') {
  const normalised = (type || '').toLowerCase();
  if (normalised === 'prompt_validation') return '프롬프트 검증';
  if (normalised === 'tool_validation') return '툴 검증';
  if (normalised === 'response_filtering') return '응답 필터링';
  return type || '미확인';
}

function translateEnabled(enabled) {
  return enabled ? '사용 중' : '중지';
}

function loadAll(manual = false) {
  loadDashboardStats();
  loadEntitySummary();
  loadRecentLogs();
  loadAgentFlow(manual);
}

async function loadEntitySummary() {
  let agents = [];
  let rules = [];

  try {
    const response = await fetch(`${API_BASE}/api/agents`);
    if (response.ok) {
      const data = await response.json();
      agents = Array.isArray(data) ? data : [];
    } else {
      throw new Error('에이전트 정보를 불러오지 못했습니다');
    }
  } catch (error) {
    console.error('에이전트 정보를 불러오지 못했습니다', error);
  }

  try {
    const response = await fetch(`${API_BASE}/api/rulesets`);
    if (response.ok) {
      const data = await response.json();
      rules = Array.isArray(data) ? data : [];
    } else {
      throw new Error('룰셋 정보를 불러오지 못했습니다');
    }
  } catch (error) {
    console.error('룰셋 정보를 불러오지 못했습니다', error);
  }

  cachedAgents = agents;
  cachedRulesets = rules;
  renderEntityChart();
}

async function loadDashboardStats() {
  try {
    const response = await fetch(`${API_BASE}/api/stats`);
    if (!response.ok) throw new Error('통계 정보를 불러오지 못했습니다');
    const stats = await response.json();

    updateStatCard('total-agents', stats.total_agents ?? 0);
    updateStatCard('total-rulesets', stats.total_rulesets ?? 0);
    updateStatCard('total-violations', stats.recent_violations ?? 0);
    updateStatCard('total-events', stats.total_events ?? 0);

    updateRiskIndicator(stats);
  } catch (error) {
    console.error('대시보드 통계를 불러오지 못했습니다', error);
  }
}

function updateStatCard(id, value) {
  const element = document.getElementById(id);
  if (element) {
    element.textContent = Number.isFinite(value) ? value : '--';
  }
}

function updateRiskIndicator(stats) {
  const violations = stats.recent_violations ?? 0;
  const total = stats.total_events ?? 0;
  const riskScore = total === 0 ? 0 : Math.min(100, Math.round((violations / total) * 100));

  const scoreElement = document.getElementById('risk-score');
  const barElement = document.getElementById('risk-bar-fill');

  if (scoreElement) {
    scoreElement.textContent = `${riskScore}`;
  }

  if (barElement) {
    barElement.style.width = `${riskScore}%`;
  }
}

async function loadRecentLogs() {
  try {
    const response = await fetch(`${API_BASE}/api/logs?limit=120`);
    if (!response.ok) throw new Error('로그를 불러오지 못했습니다');
    const logs = await response.json();

    cachedLogs = Array.isArray(logs) ? logs : [];
    renderRecentLogs(cachedLogs.slice(0, 12));
    updateEventsChart(cachedLogs);
    renderEntityChart();
  } catch (error) {
    console.error('최근 로그를 불러오지 못했습니다', error);
  }
}

function renderRecentLogs(logs) {
  const container = document.getElementById('dashboard-log-list');
  if (!container) return;

  container.innerHTML = '';
  container.scrollTop = 0;

  if (!logs || logs.length === 0) {
    container.innerHTML = '<div class="empty-state">최근 활동이 없습니다</div>';
    return;
  }

  logs.forEach((log) => {
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    if (['VIOLATION', 'BLOCKED'].includes((log.verdict || '').toUpperCase())) {
      entry.classList.add('violation');
    }

    const timestamp = log.timestamp ? new Date(log.timestamp) : null;
    const formattedTime = timestamp ? timestamp.toLocaleString() : 'N/A';

    entry.innerHTML = `
      <div class="log-header">
        <div>
          <strong>${log.agent_id || '알 수 없는 에이전트'}</strong>
          <span class="pill" style="margin-left: 0.5rem;">${log.policy_type || '정책'}</span>
        </div>
        <span class="status-chip ${log.verdict && log.verdict.toUpperCase() === 'VIOLATION' ? 'status-inactive' : 'status-active'}">
          ${translateVerdict(log.verdict)}
        </span>
      </div>
      <div class="log-message">${log.message || log.action || '메시지가 제공되지 않았습니다'}</div>
      <div class="log-meta">
        <span>${formattedTime}</span>
        ${log.target_agent ? `<span>→ ${log.target_agent}</span>` : ''}
      </div>
    `;

    container.appendChild(entry);
  });
}

function updateEventsChart(logs) {
  const canvas = document.getElementById('events-chart');
  if (!canvas) return;

  const now = new Date();
  const buckets = [];

  for (let i = 59; i >= 0; i -= 1) {
    const bucketTime = new Date(now.getTime() - i * 60 * 1000);
    const label = `${bucketTime.getHours().toString().padStart(2, '0')}:${bucketTime
      .getMinutes()
      .toString()
      .padStart(2, '0')}`;

    buckets.push({
      label,
      start: bucketTime,
      end: new Date(bucketTime.getTime() + 60 * 1000),
      events: 0,
      violations: 0,
    });
  }

  logs.forEach((log) => {
    if (!log.timestamp) return;
    const ts = new Date(log.timestamp).getTime();
    for (const bucket of buckets) {
      if (ts >= bucket.start.getTime() && ts < bucket.end.getTime()) {
        bucket.events += 1;
        if (['VIOLATION', 'BLOCKED'].includes((log.verdict || '').toUpperCase())) {
          bucket.violations += 1;
        }
        break;
      }
    }
  });

  const labels = buckets.map((bucket) => bucket.label);
  const eventSeries = buckets.map((bucket) => bucket.events);
  const violationSeries = buckets.map((bucket) => bucket.violations);

  const chartRange = document.getElementById('chart-range');
  if (chartRange) {
    chartRange.textContent = `최근 ${buckets.length}분`;
  }

  if (!eventsChart) {
    eventsChart = new Chart(canvas.getContext('2d'), {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: '이벤트',
            data: eventSeries,
            borderColor: 'rgba(109, 211, 255, 0.85)',
            backgroundColor: 'rgba(109, 211, 255, 0.1)',
            tension: 0.35,
            fill: true,
          },
          {
            label: '위반',
            data: violationSeries,
            borderColor: 'rgba(255, 77, 79, 0.9)',
            backgroundColor: 'rgba(255, 77, 79, 0.15)',
            tension: 0.35,
            fill: true,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            ticks: { color: 'rgba(255, 255, 255, 0.6)', maxTicksLimit: 8 },
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
          },
          y: {
            beginAtZero: true,
            ticks: { color: 'rgba(255, 255, 255, 0.6)' },
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
          },
        },
        plugins: {
          legend: {
            labels: { color: 'rgba(255, 255, 255, 0.75)' },
          },
          tooltip: {
            mode: 'index',
            intersect: false,
          },
        },
      },
    });
  } else {
    eventsChart.data.labels = labels;
    eventsChart.data.datasets[0].data = eventSeries;
    eventsChart.data.datasets[1].data = violationSeries;
    eventsChart.update('none');
  }
}

async function loadAgentFlow(manual = false) {
  const statusPill = document.getElementById('flow-status');
  if (statusPill && manual) {
    statusPill.textContent = '수동 새로고침 중…';
  }

  try {
    const response = await fetch(`${API_BASE}/api/graph/agent-flow?limit=200`);
    if (!response.ok) throw new Error('에이전트 흐름을 불러오지 못했습니다');
    const flow = await response.json();

    renderAgentFlowGraph(flow);
    renderAgentStatusList(flow.nodes);

    if (statusPill) {
      const updatedAt = flow.meta?.generated_at
        ? new Date(flow.meta.generated_at).toLocaleTimeString()
        : new Date().toLocaleTimeString();
      statusPill.textContent = `${updatedAt} 갱신`;
    }
  } catch (error) {
    console.error('에이전트 흐름을 불러오지 못했습니다', error);
    if (statusPill) {
      statusPill.textContent = '동기화 실패';
    }
  }
}

function renderAgentStatusList(nodes = []) {
  const list = document.getElementById('agent-status-list');
  if (!list) return;

  const knownAgents = nodes.filter((node) => node.status !== 'external' && node.id !== 'unknown');
  knownAgents.sort((a, b) => (b.metrics?.events || 0) - (a.metrics?.events || 0));

  list.innerHTML = '';

  if (knownAgents.length === 0) {
    list.innerHTML = `<li style="color: var(--text-secondary);">에이전트 데이터가 없습니다.</li>`;
    return;
  }

  knownAgents.forEach((node) => {
    const item = document.createElement('li');
    item.className = 'agent-status-item';

    const status = (node.status || 'unknown').toLowerCase();
    const statusClass = status === 'active' ? 'status-active' : status === 'inactive' ? 'status-inactive' : 'status-warning';

    const plugins = Array.isArray(node.plugins)
      ? node.plugins
          .map((plugin) => (typeof plugin === 'string' ? plugin : plugin.name))
          .filter(Boolean)
          .join(', ')
      : '';

    const metrics = node.metrics || { events: 0, violations: 0 };

    item.innerHTML = `
      <div class="agent-meta">
        <span class="name">${node.name || node.id}</span>
        <span class="plugins">${plugins || '등록된 플러그인이 없습니다'}</span>
      </div>
      <div class="agent-metrics">
        <span class="status-chip ${statusClass}">${translateStatus(status)}</span>
        <span class="pill">이벤트 ${metrics.events || 0}</span>
        <span class="pill">위반 ${metrics.violations || 0}</span>
      </div>
    `;

    list.appendChild(item);
  });
}

function renderEntityChart() {
  const canvas = document.getElementById('entity-chart');
  const pill = document.getElementById('entity-selected');
  if (!canvas || !pill) return;

  const violations = cachedLogs.filter((log) =>
    ['violation', 'blocked'].includes((log.verdict || '').toLowerCase())
  );

  entitySummaryData = [
    {
      key: 'agents',
      label: '에이전트',
      value: cachedAgents.length,
      border: 'rgba(109, 211, 255, 0.95)',
      background: 'rgba(109, 211, 255, 0.2)',
    },
    {
      key: 'rulesets',
      label: '룰셋',
      value: cachedRulesets.length,
      border: 'rgba(78, 246, 178, 0.95)',
      background: 'rgba(78, 246, 178, 0.2)',
    },
    {
      key: 'violations',
      label: '위반 로그',
      value: violations.length,
      border: 'rgba(255, 170, 51, 0.95)',
      background: 'rgba(255, 170, 51, 0.22)',
    },
  ];

  if (!entitySummaryData.some((entry) => entry.key === entityDetailKey)) {
    entityDetailKey = 'agents';
  }

  const labels = entitySummaryData.map((entry) => entry.label);
  const values = entitySummaryData.map((entry) => entry.value);
  const backgroundColors = entitySummaryData.map((entry) => entry.background);
  const borderColors = entitySummaryData.map((entry) => entry.border);

  if (!entityChart) {
    entityChart = new Chart(canvas.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels,
        datasets: [
          {
            data: values,
            backgroundColor: backgroundColors,
            borderColor: borderColors,
            borderWidth: 1.5,
            hoverOffset: 8,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '58%',
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label(context) {
                const item = entitySummaryData[context.dataIndex];
                const value = context.parsed;
                return `${item.label}: ${value.toLocaleString()}`;
              },
            },
          },
        },
      },
    });

    canvas.addEventListener('click', (event) => {
      const points = entityChart.getElementsAtEventForMode(
        event,
        'nearest',
        { intersect: true },
        true
      );

      if (!points.length) return;
      const selectedIndex = points[0].index;
      const selected = entitySummaryData[selectedIndex];
      if (selected) {
        entityDetailKey = selected.key;
        updateEntityDetails();
      }
    });
  } else {
    entityChart.data.labels = labels;
    entityChart.data.datasets[0].data = values;
    entityChart.data.datasets[0].backgroundColor = backgroundColors;
    entityChart.data.datasets[0].borderColor = borderColors;
    entityChart.update('none');
  }

  updateEntityDetails();
}

function updateEntityDetails() {
  const detailList = document.getElementById('entity-detail-list');
  const detailTitle = document.getElementById('entity-detail-title');
  const pill = document.getElementById('entity-selected');
  if (!detailList || !detailTitle || !pill) return;

  const target =
    entitySummaryData.find((entry) => entry.key === entityDetailKey && entry.value > 0) ||
    entitySummaryData.find((entry) => entry.value > 0) ||
    entitySummaryData[0];

  if (!target) {
    detailList.innerHTML = '';
    return;
  }

  entityDetailKey = target.key;
  pill.textContent = `${target.label} ${target.value.toLocaleString()}`;
  detailTitle.textContent = `${target.label} 상세`;

  const builders = {
    agents: getAgentSummaryItems,
    rulesets: getRulesetSummaryItems,
    violations: getViolationSummaryItems,
  };

  const items = builders[target.key]?.() || [];

  detailList.innerHTML = '';
  if (items.length === 0) {
    const empty = document.createElement('li');
    empty.className = 'entity-details__empty';
    empty.textContent = `${target.label} 데이터가 없습니다.`;
    detailList.appendChild(empty);
    return;
  }

  items.forEach((item) => {
    const listItem = document.createElement('li');
    listItem.className = 'entity-details__item';

    const info = document.createElement('div');
    info.className = 'entity-details__info';

    const title = document.createElement('strong');
    title.textContent = item.title;
    info.appendChild(title);

    if (item.note) {
      const note = document.createElement('span');
      note.className = 'entity-details__note';
      note.textContent = item.note;
      info.appendChild(note);
    }

    const meta = document.createElement('span');
    meta.className = 'entity-details__meta';
    meta.textContent = item.meta || '';

    listItem.appendChild(info);
    listItem.appendChild(meta);
    detailList.appendChild(listItem);
  });
}

function getAgentSummaryItems() {
  if (!Array.isArray(cachedAgents) || cachedAgents.length === 0) return [];

  const statusPriority = {
    active: 0,
    warning: 1,
    degraded: 1,
    external: 2,
    inactive: 3,
  };

  return cachedAgents
    .slice()
    .sort((a, b) => {
      const statusA = statusPriority[(a.status || '').toLowerCase()] ?? 4;
      const statusB = statusPriority[(b.status || '').toLowerCase()] ?? 4;
      if (statusA !== statusB) return statusA - statusB;
      return (a.name || a.agent_id || '').localeCompare(b.name || b.agent_id || '');
    })
    .slice(0, 6)
    .map((agent) => {
      const pluginCount = Array.isArray(agent.plugins) ? agent.plugins.length : 0;
      const pluginLabel = pluginCount > 0 ? `플러그인 ${pluginCount}` : '플러그인 없음';
      return {
        title: agent.name || agent.agent_id || '알 수 없는 에이전트',
        note: truncateText(agent.description, 54),
        meta: `${translateStatus(agent.status)} · ${pluginLabel}`,
      };
    });
}

function getRulesetSummaryItems() {
  if (!Array.isArray(cachedRulesets) || cachedRulesets.length === 0) return [];

  return cachedRulesets
    .slice()
    .sort((a, b) => {
      const aTime = a.updated_at ? new Date(a.updated_at).getTime() : 0;
      const bTime = b.updated_at ? new Date(b.updated_at).getTime() : 0;
      return bTime - aTime;
    })
    .slice(0, 6)
    .map((ruleset) => ({
      title: ruleset.name || ruleset.ruleset_id || '룰셋',
      note: `${translateRulesetType(ruleset.type)} · ${translateEnabled(ruleset.enabled)}`,
      meta: formatDateTime(ruleset.updated_at || ruleset.created_at),
    }));
}

function getViolationSummaryItems() {
  const violations = cachedLogs.filter((log) =>
    ['violation', 'blocked'].includes((log.verdict || '').toLowerCase())
  );
  if (violations.length === 0) return [];

  return violations
    .slice()
    .sort((a, b) => {
      const aTime = a.timestamp ? new Date(a.timestamp).getTime() : 0;
      const bTime = b.timestamp ? new Date(b.timestamp).getTime() : 0;
      return bTime - aTime;
    })
    .slice(0, 6)
    .map((log) => ({
      title: log.agent_id || '알 수 없는 에이전트',
      note: `${log.policy_type || '정책 미지정'} · ${truncateText(log.message || log.action, 60) || '메시지 없음'}`,
      meta: formatTime(log.timestamp),
    }));
}

function truncateText(text, maxLength = 48) {
  if (!text) return '';
  const trimmed = text.trim();
  return trimmed.length > maxLength ? `${trimmed.slice(0, maxLength)}…` : trimmed;
}

function formatDateTime(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleDateString();
}

function formatTime(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function renderAgentFlowGraph(flow) {
  const svgElement = document.getElementById('agent-flow-graph');
  const tooltip = document.getElementById('graph-tooltip');
  if (!svgElement || !tooltip) return;

  const svg = d3.select(svgElement);
  svg.selectAll('*').remove();

  const container = svgElement.parentElement;
  const width = container?.clientWidth || 720;
  const height = container?.clientHeight || 480;

  svg.attr('viewBox', `0 0 ${width} ${height}`);

  const nodes = flow.nodes?.map((node) => ({ ...node })) || [];
  const links = flow.edges?.map((edge) => ({ ...edge })) || [];

  const simulation = d3
    .forceSimulation(nodes)
    .force(
      'link',
      d3
        .forceLink(links)
        .id((d) => d.id)
        .distance((d) => 140 - Math.min(d.count || 0, 60))
        .strength(0.4)
    )
    .force('charge', d3.forceManyBody().strength(-260))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide().radius(60));

  const link = svg
    .append('g')
    .attr('stroke', 'rgba(109, 211, 255, 0.3)')
    .attr('stroke-width', 1.5)
    .selectAll('line')
    .data(links)
    .enter()
    .append('line')
    .attr('class', 'flow-link')
    .attr('stroke-width', (d) => Math.max(1.5, Math.log(d.count + 1) * 2));

  const nodeGroup = svg
    .append('g')
    .selectAll('g')
    .data(nodes)
    .enter()
    .append('g')
    .attr('class', 'flow-node')
    .call(
      d3
        .drag()
        .on('start', (event, d) => {
          if (!event.active) simulation.alphaTarget(0.3).restart();
          d.fx = d.x;
          d.fy = d.y;
        })
        .on('drag', (event, d) => {
          d.fx = event.x;
          d.fy = event.y;
        })
        .on('end', (event, d) => {
          if (!event.active) simulation.alphaTarget(0);
          d.fx = null;
          d.fy = null;
        })
    );

  nodeGroup
    .append('circle')
    .attr('r', (d) => 26 + Math.min(12, Math.log((d.metrics?.events || 0) + 1) * 6))
    .attr('class', (d) => `node-circle status-${(d.status || 'unknown').toLowerCase()}`)
    .on('mouseover', (event, d) => showTooltip(event, d))
    .on('mousemove', (event, d) => showTooltip(event, d))
    .on('mouseout', hideTooltip);

  nodeGroup
    .append('text')
    .attr('dy', 4)
    .attr('text-anchor', 'middle')
    .attr('class', 'node-label')
    .text((d) => (d.name || d.id).split(' ')[0]);

  simulation.on('tick', () => {
    link
      .attr('x1', (d) => clampPosition(d.source.x, width))
      .attr('y1', (d) => clampPosition(d.source.y, height))
      .attr('x2', (d) => clampPosition(d.target.x, width))
      .attr('y2', (d) => clampPosition(d.target.y, height));

    nodeGroup.attr('transform', (d) => `translate(${clampPosition(d.x, width)}, ${clampPosition(d.y, height)})`);
  });

  function showTooltip(event, node) {
    if (!tooltip) return;
    tooltip.classList.remove('hidden');
    tooltip.style.left = `${event.offsetX}px`;
    tooltip.style.top = `${event.offsetY}px`;

    const metrics = node.metrics || { events: 0, violations: 0 };
    const plugins = Array.isArray(node.plugins)
      ? node.plugins
          .map((plugin) => (typeof plugin === 'string' ? plugin : plugin.name))
          .filter(Boolean)
      : [];

    tooltip.innerHTML = `
      <div class="tooltip-title">${node.name || node.id}</div>
      <div class="tooltip-meta">${translateStatus(node.status)}</div>
      <ul>
        <li><strong>${metrics.events || 0}</strong>건의 최근 이벤트</li>
        <li><strong>${metrics.violations || 0}</strong>건의 위반</li>
        <li><strong>${plugins.length}</strong>개의 플러그인</li>
      </ul>
    `;
  }

  function hideTooltip() {
    if (!tooltip) return;
    tooltip.classList.add('hidden');
  }
}

function clampPosition(value, max) {
  return Math.max(40, Math.min(max - 40, value || 0));
}