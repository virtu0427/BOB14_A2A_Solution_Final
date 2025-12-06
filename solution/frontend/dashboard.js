const API_BASE = window.location.origin;
const REFRESH_INTERVAL = 30000;      // 전체 데이터 갱신 주기 (30초)
const LOG_REFRESH_INTERVAL = 3000;   // 로그 갱신 주기 (3초)

let eventsChart;
let cachedAgents = [];
let cachedRulesets = [];
let cachedLogs = [];
let isLoadingLogs = false;  // 중복 요청 방지

window.addEventListener('DOMContentLoaded', () => {
  setupControls();
  loadAll();
  
  // 전체 데이터 갱신 (30초)
  setInterval(loadAll, REFRESH_INTERVAL);
  
  // 로그만 실시간 갱신 (3초)
  setInterval(loadRecentLogsAsync, LOG_REFRESH_INTERVAL);
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
  if (normalised === 'pass' || normalised === 'safe' || normalised === 'allowed') return '통과';
  if (['violation', 'blocked', 'denied'].includes(normalised)) return '위반';
  if (normalised === 'allow') return '허용';
  if (normalised === 'deny') return '거부';
  return verdict || '미확인';
}

function getPolicyLabel(policyType) {
  const labels = {
    'prompt_validation': '프롬프트 검증',
    'tool_validation': '툴 접근',
    'replay_protection': '리플레이 방지',
    'agent_access': '에이전트 접근',
  };
  return labels[policyType] || policyType || '-';
}

function loadAll(manual = false) {
  loadDashboardStats();
  loadEntitySummary();
  loadRecentLogs();
  loadAgentFlow(manual);
}

async function loadEntitySummary() {
  try {
    const response = await fetch(`${API_BASE}/api/agents`);
    if (response.ok) {
      const data = await response.json();
      cachedAgents = Array.isArray(data) ? data : [];
    }
  } catch (error) {
    console.error('에이전트 정보를 불러오지 못했습니다', error);
  }

  try {
    const response = await fetch(`${API_BASE}/api/rulesets`);
    if (response.ok) {
      const data = await response.json();
      cachedRulesets = Array.isArray(data) ? data : [];
    }
  } catch (error) {
    console.error('룰셋 정보를 불러오지 못했습니다', error);
  }
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
    if (Number.isFinite(value)) {
      element.textContent = value >= 1000 ? `${(value / 1000).toFixed(1)}k` : value;
    } else {
      element.textContent = '--';
    }
  }
}

function updateRiskIndicator(stats) {
  const violations = stats.recent_violations ?? 0;
  const total = stats.total_events ?? 0;
  const riskScore = total === 0 ? 0 : Math.min(100, Math.round((violations / total) * 100));

  const scoreElement = document.getElementById('risk-score');
  const barElement = document.getElementById('risk-bar-fill');

  if (scoreElement) {
    if (riskScore < 20) {
      scoreElement.textContent = '정상';
      scoreElement.className = 'risk-score';
    } else if (riskScore < 50) {
      scoreElement.textContent = '주의';
      scoreElement.className = 'risk-score warning';
    } else {
      scoreElement.textContent = '위험';
      scoreElement.className = 'risk-score danger';
    }
  }

  if (barElement) {
    barElement.style.width = `${Math.max(5, riskScore)}%`;
  }
}

async function loadRecentLogs() {
  try {
    const response = await fetch(`${API_BASE}/api/logs?limit=200`);
    if (!response.ok) throw new Error('로그를 불러오지 못했습니다');
    const logs = await response.json();

    cachedLogs = Array.isArray(logs) ? logs : [];
    // 에이전트 + 레지스트리 로그 모두 표시, 시간순 정렬
    const sortedLogs = cachedLogs.sort((a, b) => 
      new Date(b.timestamp) - new Date(a.timestamp)
    );
    renderRecentLogs(sortedLogs.slice(0, 50));
    updateEventsChart(cachedLogs);
  } catch (error) {
    console.error('최근 로그를 불러오지 못했습니다', error);
  }
}

// 실시간 로그 갱신 (중복 요청 방지)
async function loadRecentLogsAsync() {
  if (isLoadingLogs) return;  // 이미 로딩 중이면 스킵
  
  isLoadingLogs = true;
  try {
    const response = await fetch(`${API_BASE}/api/logs?limit=200`);
    if (!response.ok) throw new Error('로그를 불러오지 못했습니다');
    const logs = await response.json();

    const newLogs = Array.isArray(logs) ? logs : [];
    
    // 새 로그가 있는지 확인 (첫 번째 로그의 timestamp 비교)
    const hasNewLogs = newLogs.length > 0 && (
      cachedLogs.length === 0 || 
      newLogs[0]?.timestamp !== cachedLogs[0]?.timestamp ||
      newLogs.length !== cachedLogs.length
    );
    
    if (hasNewLogs) {
      cachedLogs = newLogs;
      const sortedLogs = cachedLogs.sort((a, b) => 
        new Date(b.timestamp) - new Date(a.timestamp)
      );
      renderRecentLogs(sortedLogs.slice(0, 50));
      
      // 새 로그 표시 애니메이션
      highlightNewLogs();
    }
  } catch (error) {
    // 실시간 갱신 실패는 조용히 무시 (다음 주기에 재시도)
    console.debug('로그 실시간 갱신 실패:', error);
  } finally {
    isLoadingLogs = false;
  }
}

// 새 로그 하이라이트 효과
function highlightNewLogs() {
  const tbody = document.getElementById('dashboard-log-list');
  if (!tbody) return;
  
  const firstRow = tbody.querySelector('tr');
  if (firstRow) {
    firstRow.classList.add('new-log');
    setTimeout(() => {
      firstRow.classList.remove('new-log');
    }, 1000);
  }
}

function renderRecentLogs(logs) {
  const tbody = document.getElementById('dashboard-log-list');
  const countEl = document.getElementById('log-count');
  if (!tbody) return;

  tbody.innerHTML = '';
  
  if (countEl) {
    countEl.textContent = `${logs.length}건`;
  }

  if (!logs || logs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 1rem; color: #94a3b8;">최근 활동이 없습니다</td></tr>';
    return;
  }

  logs.forEach((log) => {
    const tr = document.createElement('tr');
    
    const isAgent = !log.source || log.source === 'agent';
    const isRegistry = log.source === 'registry';
    
    // violation 스타일링
    if (isAgent) {
      const verdict = (log.verdict || '').toUpperCase();
      if (['VIOLATION', 'BLOCKED', 'DENIED'].includes(verdict)) {
        tr.classList.add('violation');
      }
    } else if (isRegistry) {
      const status = log.status;
      if (status && status !== 200 && status !== 291) {
        tr.classList.add('violation');
      }
    }

    // 시간 포맷
    const formattedTime = log.timestamp ? log.timestamp.replace('T', ' ').substring(11, 19) : '-';

    // 유형 배지
    const typeBadge = isRegistry 
      ? '<span class="type-badge registry">REG</span>'
      : '<span class="type-badge agent">AGT</span>';

    // 에이전트/요청자
    let actorText = '';
    if (isRegistry) {
      actorText = log.actor || '-';
    } else {
      if (log.tool_name) {
        actorText = `${log.agent_id || '-'}/${log.tool_name}`;
      } else if (log.target_agent) {
        actorText = `${log.agent_id || '-'}→${log.target_agent}`;
      } else {
        actorText = log.agent_id || '-';
      }
    }

    // 정책/동작
    let policyText = '';
    if (isRegistry) {
      policyText = log.method || '-';
    } else {
      policyText = getPolicyLabel(log.policy_type);
    }

    // 메시지
    const message = log.message || '-';

    // 결과
    let resultBadge = '';
    if (isRegistry) {
      resultBadge = getStatusBadge(log.status);
    } else {
      resultBadge = getVerdictBadge(log.verdict);
    }

    tr.innerHTML = `
      <td class="col-time">${formattedTime}</td>
      <td class="col-type">${typeBadge}</td>
      <td class="col-agent" title="${actorText}">${truncateText(actorText, 18)}</td>
      <td class="col-policy">${policyText}</td>
      <td class="col-msg" title="${message}">${message}</td>
      <td class="col-result">${resultBadge}</td>
    `;

    tbody.appendChild(tr);
  });
}

// 텍스트 자르기
function truncateText(text, maxLen) {
  if (!text) return '-';
  return text.length > maxLen ? text.substring(0, maxLen) + '…' : text;
}

// verdict를 배지로 변환
function getVerdictBadge(verdict) {
  if (!verdict) return '<span class="verdict-badge other">-</span>';
  const upper = verdict.toUpperCase();
  if (upper === 'PASS' || upper === 'SAFE' || upper === 'ALLOWED') {
    return '<span class="verdict-badge pass">PASS</span>';
  } else if (upper === 'VIOLATION' || upper === 'BLOCKED' || upper === 'DENIED') {
    return '<span class="verdict-badge blocked">BLOCK</span>';
  }
  return `<span class="verdict-badge other">${verdict}</span>`;
}

// 상태코드를 배지로 변환
function getStatusBadge(status) {
  if (!status) return '<span class="verdict-badge other">-</span>';
  if (status === 200 || status === 291) {
    return `<span class="verdict-badge pass">${status}</span>`;
  } else if (status === 401 || status === 403 || status === 409) {
    return `<span class="verdict-badge blocked">${status}</span>`;
  }
  return `<span class="verdict-badge other">${status}</span>`;
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
            borderColor: 'rgba(101, 209, 255, 0.9)',
            backgroundColor: 'rgba(101, 209, 255, 0.1)',
            tension: 0.35,
            fill: true,
            borderWidth: 2,
          },
          {
            label: '위반',
            data: violationSeries,
            borderColor: 'rgba(255, 102, 102, 0.9)',
            backgroundColor: 'rgba(255, 102, 102, 0.1)',
            tension: 0.35,
            fill: true,
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          mode: 'index',
          intersect: false,
        },
        scales: {
          x: {
            ticks: { 
              color: 'rgba(147, 164, 196, 0.7)', 
              maxTicksLimit: 8,
              font: { size: 9 }
            },
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
          },
          y: {
            beginAtZero: true,
            ticks: { 
              color: 'rgba(147, 164, 196, 0.7)',
              font: { size: 9 }
            },
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
          },
        },
        plugins: {
          legend: {
            display: true,
            position: 'top',
            labels: { 
              color: 'rgba(147, 164, 196, 0.9)',
              boxWidth: 12,
              padding: 8,
              font: { size: 10 }
            },
          },
          tooltip: {
            backgroundColor: 'rgba(8, 14, 28, 0.95)',
            borderColor: 'rgba(99, 187, 255, 0.3)',
            borderWidth: 1,
            titleColor: '#f2f6ff',
            bodyColor: '#93a4c4',
            padding: 10,
            cornerRadius: 6,
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
    statusPill.textContent = '● 수동 새로고침 중…';
  }

  try {
    const response = await fetch(`${API_BASE}/api/graph/agent-flow?limit=200`);
    if (!response.ok) throw new Error('에이전트 흐름을 불러오지 못했습니다');
    const flow = await response.json();

    renderAgentFlowGraph(flow);

    if (statusPill) {
      const updatedAt = flow.meta?.generated_at
        ? new Date(flow.meta.generated_at).toLocaleTimeString()
        : new Date().toLocaleTimeString();
      statusPill.textContent = `● ${updatedAt} 갱신`;
      statusPill.className = 'pill pill-live';
    }
  } catch (error) {
    console.error('에이전트 흐름을 불러오지 못했습니다', error);
    if (statusPill) {
      statusPill.textContent = '● 동기화 실패';
      statusPill.className = 'pill';
      statusPill.style.color = '#ff6666';
      statusPill.style.borderColor = 'rgba(255, 102, 102, 0.3)';
    }
  }
}

function getNodeColor(status) {
  const normalised = (status || 'unknown').toLowerCase();
  switch (normalised) {
    case 'inactive': return '#ff6666';
    case 'warning':
    case 'degraded': return '#ffaa33';
    case 'active': return '#4ef6b2';
    case 'external': return '#8b5cf6';
    default: return '#65d1ff';
  }
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
    .attr('stroke', 'rgba(101, 209, 255, 0.25)')
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

  // Outer glow circle
  nodeGroup
    .append('circle')
    .attr('r', (d) => 26 + Math.min(12, Math.log((d.metrics?.events || 0) + 1) * 6))
    .attr('fill', (d) => getNodeColor(d.status))
    .attr('opacity', 0.2)
    .attr('class', (d) => `node-circle status-${(d.status || 'unknown').toLowerCase()}`);

  // Core circle
  nodeGroup
    .append('circle')
    .attr('r', (d) => 12 + Math.min(6, Math.log((d.metrics?.events || 0) + 1) * 3))
    .attr('fill', (d) => getNodeColor(d.status))
    .attr('stroke', '#fff')
    .attr('stroke-width', 1.5)
    .style('cursor', 'pointer')
    .on('mouseover', (event, d) => showTooltip(event, d))
    .on('mousemove', (event, d) => showTooltip(event, d))
    .on('mouseout', hideTooltip);

  // Labels
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
