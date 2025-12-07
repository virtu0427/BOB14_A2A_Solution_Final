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
  
  // 그래프 실시간 동기화 시작 (10초)
  startGraphSync();
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
            backgroundColor: 'transparent',
            tension: 0.35,
            fill: false,  // 선만 표시
            borderWidth: 2,
            pointBackgroundColor: 'rgba(101, 209, 255, 0.8)',
            pointBorderColor: 'rgba(101, 209, 255, 1)',
            pointRadius: (ctx) => ctx.parsed?.y === 0 ? 0 : 2,
            pointHoverRadius: (ctx) => ctx.parsed?.y === 0 ? 0 : 4,
            order: 1,  // 앞에 그려짐
          },
          {
            label: '위반',
            data: violationSeries,
            borderColor: 'rgba(255, 102, 102, 1)',
            backgroundColor: 'rgba(255, 102, 102, 0.15)',
            tension: 0.35,
            fill: true,  // 영역 채우기
            borderWidth: 2.5,
            pointBackgroundColor: 'rgba(255, 102, 102, 1)',
            pointBorderColor: 'rgba(255, 102, 102, 1)',
            pointRadius: (ctx) => ctx.parsed?.y === 0 ? 0 : 3,
            pointHoverRadius: (ctx) => ctx.parsed?.y === 0 ? 0 : 5,
            order: 2,  // 뒤에 그려짐 (위반이 항상 위에)
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
    // 에이전트와 로그 데이터를 동시에 가져옴
    const [agentsRes, logsRes] = await Promise.all([
      fetch(`${API_BASE}/api/agents`),
      fetch(`${API_BASE}/api/logs?limit=500`)
    ]);

    if (!agentsRes.ok) {
      throw new Error(`에이전트 API 오류: ${agentsRes.status} ${agentsRes.statusText}`);
    }

    const agents = await agentsRes.json();

    let logs = [];
    if (logsRes.ok) {
      const logsData = await logsRes.json();
      logs = Array.isArray(logsData) ? logsData : (logsData.logs || []);
    }

    // 그래프 데이터 구성
    const flow = buildGraphFromData(agents, logs);
    renderAgentFlowGraph(flow);

    if (statusPill) {
      const updatedAt = new Date().toLocaleTimeString();
      statusPill.textContent = `● ${updatedAt} 갱신`;
      statusPill.className = 'pill pill-live';
      statusPill.style.color = '';
      statusPill.style.borderColor = '';
    }
  } catch (error) {
    console.error('에이전트 흐름을 불러오지 못했습니다:', error);
    if (statusPill) {
      statusPill.textContent = '● 동기화 실패';
      statusPill.className = 'pill';
      statusPill.style.color = '#ff6666';
      statusPill.style.borderColor = 'rgba(255, 102, 102, 0.3)';
    }
  }
}

// 에이전트와 로그 데이터로부터 그래프 구성
function buildGraphFromData(agents, logs) {
  const nodes = [];
  const edges = [];
  const nodeMap = new Map();
  const edgeMap = new Map();

  // 레지스트리 노드 추가 (중심 노드)
  const registryNode = {
    id: 'registry',
    name: 'Registry',
    status: 'active',
    type: 'registry',
    metrics: { events: 0, violations: 0 }
  };
  nodes.push(registryNode);
  nodeMap.set('registry', registryNode);

  // 에이전트 노드 추가
  const agentNameToId = new Map();  // 이름 -> ID 매핑
  (Array.isArray(agents) ? agents : []).forEach(agent => {
    const agentId = agent.agent_id || agent.id;
    if (!agentId || nodeMap.has(agentId)) return;

    const agentName = agent.name || agent.display_name || agentId;
    const node = {
      id: agentId,
      name: agentName,
      status: agent.status || 'unknown',
      type: 'agent',
      plugins: agent.plugins || [],
      metrics: { events: 0, violations: 0 }
    };
    nodes.push(node);
    nodeMap.set(agentId, node);
    
    // 이름으로도 찾을 수 있도록 매핑 추가
    agentNameToId.set(agentName.toLowerCase(), agentId);
    // ID에서 에이전트 이름 추출 (예: "oneth.ai#agent:DeliveryAgent.v1.0.0" -> "deliveryagent")
    const idParts = agentId.match(/[:#]([^.:#]+)/g);
    if (idParts) {
      idParts.forEach(part => {
        const cleanPart = part.replace(/[:#]/g, '').toLowerCase();
        if (cleanPart && cleanPart.length > 2) {
          agentNameToId.set(cleanPart, agentId);
        }
      });
    }
  });
  
  // 이름으로 에이전트 ID 찾는 헬퍼 함수
  function findAgentId(name) {
    if (!name) return null;
    const nameLower = name.toLowerCase().replace(/\s+/g, '');
    
    // 정확히 일치하는 ID가 있으면 반환
    if (nodeMap.has(name)) return name;
    
    // 이름 매핑에서 찾기
    if (agentNameToId.has(nameLower)) return agentNameToId.get(nameLower);
    
    // 부분 일치로 찾기
    for (const [key, id] of agentNameToId.entries()) {
      if (key.includes(nameLower) || nameLower.includes(key)) {
        return id;
      }
    }
    
    return null;
  }

  // 로그에서 연결 관계와 메트릭 추출
  (Array.isArray(logs) ? logs : []).forEach(log => {
    const rawAgentId = log.agent_id || log.agentId;
    // 에이전트 ID 매칭 (짧은 이름 -> 전체 ID)
    const agentId = rawAgentId ? (findAgentId(rawAgentId) || rawAgentId) : null;
    const source = log.source;
    // verdict/status가 문자열이 아닐 수 있으므로 안전하게 처리
    const rawVerdict = log.verdict || log.status || '';
    const verdict = (typeof rawVerdict === 'string' ? rawVerdict : String(rawVerdict || '')).toLowerCase();
    const isViolation = ['violation', 'blocked', 'denied'].includes(verdict);

    // 에이전트 메트릭 업데이트
    if (agentId && nodeMap.has(agentId)) {
      const node = nodeMap.get(agentId);
      node.metrics.events++;
      if (isViolation) node.metrics.violations++;
    }

    // 레지스트리 메트릭 업데이트
    if (source === 'registry') {
      registryNode.metrics.events++;
      if (isViolation) registryNode.metrics.violations++;
    }

    // 에이전트-레지스트리 연결 (로그가 있으면 통신이 있다고 간주)
    if (agentId && nodeMap.has(agentId)) {
      const edgeKey = `${agentId}->registry`;
      if (!edgeMap.has(edgeKey)) {
        edgeMap.set(edgeKey, {
          source: agentId,
          target: 'registry',
          count: 0,
          violations: 0,
          type: 'normal'
        });
      }
      const edge = edgeMap.get(edgeKey);
      edge.count++;
      if (isViolation) {
        edge.violations++;
        edge.type = 'violation';
      }
    }

    // 에이전트 간 통신 (caller-callee 관계가 있는 경우)
    const rawCalleeId = log.callee_id || log.target_agent;
    if (agentId && rawCalleeId && agentId !== rawCalleeId) {
      // 먼저 기존 에이전트에서 찾기 (이름 매칭)
      let calleeId = findAgentId(rawCalleeId) || rawCalleeId;
      
      // 매칭된 ID가 소스와 같으면 스킵 (자기 자신 호출)
      if (calleeId === agentId) return;
      
      // callee 노드가 없으면 외부 노드로 추가
      if (!nodeMap.has(calleeId)) {
        const calleeNode = {
          id: calleeId,
          name: rawCalleeId,  // 원래 이름 표시
          status: 'external',
          type: 'external',
          metrics: { events: 0, violations: 0 }
        };
        nodes.push(calleeNode);
        nodeMap.set(calleeId, calleeNode);
      }

      const edgeKey = `${agentId}->${calleeId}`;
      if (!edgeMap.has(edgeKey)) {
        edgeMap.set(edgeKey, {
          source: agentId,
          target: calleeId,
          count: 0,
          violations: 0,
          type: 'normal'
        });
      }
      const edge = edgeMap.get(edgeKey);
      edge.count++;
      if (isViolation) {
        edge.violations++;
        edge.type = 'violation';
      }
    }
  });

  // 연결이 없는 에이전트도 레지스트리와 연결
  nodes.forEach(node => {
    if (node.type === 'agent') {
      const edgeKey = `${node.id}->registry`;
      if (!edgeMap.has(edgeKey)) {
        edgeMap.set(edgeKey, {
          source: node.id,
          target: 'registry',
          count: 0,
          type: 'inactive'
        });
      }
    }
  });

  // 에지 필터링: source와 target 노드가 모두 존재하는 에지만 포함
  const validEdges = Array.from(edgeMap.values()).filter(edge => {
    return nodeMap.has(edge.source) && nodeMap.has(edge.target);
  });

  return {
    nodes,
    edges: validEdges
  };
}

function getNodeColor(status, type) {
  // Registry is special
  if (type === 'registry') return '#65d1ff';
  
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

// Global graph state for zoom/pan
let graphZoom = null;
let graphSvg = null;
let graphContainer = null;
let currentSimulation = null;
let currentTransform = null;  // 현재 zoom/pan 상태 저장
let nodePositions = new Map();  // 노드 위치 저장

function renderAgentFlowGraph(flow) {
  try {
    const svgElement = document.getElementById('agent-flow-graph');
    const tooltip = document.getElementById('graph-tooltip');
    if (!svgElement || !tooltip) {
      console.error('[Graph] SVG 또는 tooltip 요소를 찾을 수 없음');
      return;
    }

    const svg = d3.select(svgElement);
    
    // 현재 transform 저장 (있으면)
    if (graphSvg && graphZoom) {
      const currentZoomTransform = d3.zoomTransform(graphSvg.node());
      if (currentZoomTransform && (currentZoomTransform.k !== 1 || currentZoomTransform.x !== 0 || currentZoomTransform.y !== 0)) {
        currentTransform = currentZoomTransform;
      }
    }
    
    svg.selectAll('*').remove();

  const container = svgElement.parentElement;
  const width = container?.clientWidth || 720;
  const height = container?.clientHeight || 480;

  svg.attr('viewBox', `0 0 ${width} ${height}`)
     .attr('width', '100%')
     .attr('height', '100%');

  graphSvg = svg;

  // 노드 생성 시 저장된 위치 복원 (위치가 있으면 고정)
  const nodes = flow.nodes?.map((node) => {
    const savedPos = nodePositions.get(node.id);
    if (savedPos && savedPos.x !== undefined && savedPos.y !== undefined) {
      // 저장된 위치가 있으면 해당 위치로 고정
      return { 
        ...node, 
        x: savedPos.x, 
        y: savedPos.y, 
        fx: savedPos.x,  // 고정 위치 설정
        fy: savedPos.y 
      };
    }
    return { ...node };
  }) || [];
  const links = flow.edges?.map((edge) => ({ ...edge })) || [];

  // Create main container for all graph elements FIRST
  graphContainer = svg.append('g').attr('class', 'graph-main');

  // Create zoom behavior
  graphZoom = d3.zoom()
    .scaleExtent([0.3, 4])
    .on('zoom', (event) => {
      graphContainer.attr('transform', event.transform);
      currentTransform = event.transform;  // transform 저장
    });

  svg.call(graphZoom);
  
  // 저장된 transform 복원 (graphContainer 생성 후)
  if (currentTransform) {
    svg.call(graphZoom.transform, currentTransform);
  }

  // Arrow marker for directed edges
  svg.append('defs').append('marker')
    .attr('id', 'arrowhead')
    .attr('viewBox', '-0 -5 10 10')
    .attr('refX', 25)
    .attr('refY', 0)
    .attr('orient', 'auto')
    .attr('markerWidth', 6)
    .attr('markerHeight', 6)
    .append('path')
    .attr('d', 'M 0,-5 L 10,0 L 0,5')
    .attr('fill', 'rgba(101, 209, 255, 0.5)');

  // Stop previous simulation
  if (currentSimulation) {
    currentSimulation.stop();
  }

  // 저장된 위치가 있는지 확인
  const hasExistingPositions = nodes.some(n => n.fx !== undefined && n.fy !== undefined);

  currentSimulation = d3
    .forceSimulation(nodes)
    .force(
      'link',
      d3
        .forceLink(links)
        .id((d) => d.id)
        .distance((d) => 120 + Math.min(d.count || 0, 30))
        .strength(hasExistingPositions ? 0.1 : 0.5)  // 기존 위치 있으면 약하게
    )
    .force('charge', d3.forceManyBody().strength(hasExistingPositions ? -50 : -350))  // 기존 위치 있으면 약하게
    .force('collision', d3.forceCollide().radius(70));

  // 기존 위치가 없을 때만 center force 적용
  if (!hasExistingPositions) {
    currentSimulation
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('x', d3.forceX(width / 2).strength(0.05))
      .force('y', d3.forceY(height / 2).strength(0.05));
  }

  // Link container
  const linkGroup = graphContainer.append('g').attr('class', 'links');
  
  const link = linkGroup
    .selectAll('line')
    .data(links)
    .enter()
    .append('line')
    .attr('class', 'flow-link')
    .attr('stroke', (d) => {
      // Color based on communication type
      if (d.type === 'violation') return 'rgba(255, 102, 102, 0.6)';
      if (d.type === 'warning') return 'rgba(255, 170, 51, 0.5)';
      return 'rgba(101, 209, 255, 0.35)';
    })
    .attr('stroke-width', (d) => Math.max(1.5, Math.log((d.count || 1) + 1) * 1.5))
    .attr('marker-end', 'url(#arrowhead)')
    .style('cursor', 'pointer')
    .on('mouseover', (event, d) => showLinkTooltip(event, d))
    .on('mouseout', hideTooltip);

  // Animate links
  link.attr('stroke-dasharray', function() {
    const length = this.getTotalLength?.() || 100;
    return `${length} ${length}`;
  })
  .attr('stroke-dashoffset', function() {
    return this.getTotalLength?.() || 100;
  })
  .transition()
  .duration(1000)
  .attr('stroke-dashoffset', 0);

  // Node container
  const nodeGroup = graphContainer
    .append('g')
    .attr('class', 'nodes')
    .selectAll('g')
    .data(nodes)
    .enter()
    .append('g')
    .attr('class', 'flow-node')
    .style('cursor', 'grab')
    .call(
      d3.drag()
        .on('start', (event, d) => {
          if (!event.active) currentSimulation.alphaTarget(0.3).restart();
          d.fx = d.x;
          d.fy = d.y;
          d3.select(event.sourceEvent.target.parentNode).style('cursor', 'grabbing');
        })
        .on('drag', (event, d) => {
          d.fx = event.x;
          d.fy = event.y;
        })
        .on('end', (event, d) => {
          if (!event.active) currentSimulation.alphaTarget(0);
          // Keep node fixed after drag
          d3.select(event.sourceEvent.target.parentNode).style('cursor', 'grab');
        })
    );

  // Outer glow circle (pulse animation for active)
  nodeGroup
    .append('circle')
    .attr('r', (d) => {
      const baseSize = d.type === 'registry' ? 40 : 28;
      return baseSize + Math.min(10, Math.log((d.metrics?.events || 0) + 1) * 5);
    })
    .attr('fill', (d) => getNodeColor(d.status, d.type))
    .attr('opacity', (d) => d.type === 'registry' ? 0.25 : 0.15)
    .attr('class', (d) => `node-glow status-${(d.status || 'unknown').toLowerCase()}`);

  // Core circle
  nodeGroup
    .append('circle')
    .attr('r', (d) => {
      const baseSize = d.type === 'registry' ? 22 : 14;
      return baseSize + Math.min(6, Math.log((d.metrics?.events || 0) + 1) * 3);
    })
    .attr('fill', (d) => getNodeColor(d.status, d.type))
    .attr('stroke', (d) => d.type === 'registry' ? '#fff' : 'rgba(255, 255, 255, 0.8)')
    .attr('stroke-width', (d) => d.type === 'registry' ? 3 : 2)
    .attr('class', 'node-core')
    .on('mouseover', (event, d) => showNodeTooltip(event, d))
    .on('mousemove', (event, d) => showNodeTooltip(event, d))
    .on('mouseout', hideTooltip)
    .on('click', (event, d) => {
      event.stopPropagation();
      showNodeDetailPanel(d, links);
    })
    .on('dblclick', (event, d) => {
      // Double click to release fixed position
      d.fx = null;
      d.fy = null;
      currentSimulation.alpha(0.3).restart();
    });

  // Status indicator
  nodeGroup
    .append('circle')
    .attr('r', 4)
    .attr('cx', (d) => 10 + Math.min(4, Math.log((d.metrics?.events || 0) + 1) * 2))
    .attr('cy', (d) => -10 - Math.min(4, Math.log((d.metrics?.events || 0) + 1) * 2))
    .attr('fill', (d) => {
      if (d.metrics?.violations > 0) return '#ff6666';
      if (d.status === 'warning') return '#ffaa33';
      return '#4ef6b2';
    })
    .attr('stroke', '#0d1526')
    .attr('stroke-width', 2);

  // Labels
  nodeGroup
    .append('text')
    .attr('dy', (d) => 30 + Math.min(6, Math.log((d.metrics?.events || 0) + 1) * 3))
    .attr('text-anchor', 'middle')
    .attr('class', 'node-label')
    .attr('fill', 'rgba(255, 255, 255, 0.9)')
    .attr('font-size', '10px')
    .attr('font-weight', '500')
    .text((d) => {
      const name = d.name || d.id;
      return name.length > 12 ? name.substring(0, 12) + '…' : name;
    });

  // Event count badge
  nodeGroup
    .filter((d) => (d.metrics?.events || 0) > 0)
    .append('text')
    .attr('dy', -2)
    .attr('text-anchor', 'middle')
    .attr('fill', '#fff')
    .attr('font-size', '9px')
    .attr('font-weight', 'bold')
    .text((d) => d.metrics?.events || 0);

  currentSimulation.on('tick', () => {
    link
      .attr('x1', (d) => d.source.x)
      .attr('y1', (d) => d.source.y)
      .attr('x2', (d) => d.target.x)
      .attr('y2', (d) => d.target.y);

    nodeGroup.attr('transform', (d) => `translate(${d.x}, ${d.y})`);
    
    // 노드 위치 저장
    nodes.forEach(node => {
      nodePositions.set(node.id, { 
        x: node.x, 
        y: node.y, 
        fx: node.fx, 
        fy: node.fy 
      });
    });
  });

  // 저장된 위치가 있으면 시뮬레이션 거의 정지, 없으면 애니메이션
  if (hasExistingPositions) {
    // 기존 위치가 있으면 시뮬레이션 멈추고 수동으로 위치 적용
    currentSimulation.stop();
    
    // 수동으로 노드 위치 적용
    link
      .attr('x1', (d) => d.source.x)
      .attr('y1', (d) => d.source.y)
      .attr('x2', (d) => d.target.x)
      .attr('y2', (d) => d.target.y);
    nodeGroup.attr('transform', (d) => `translate(${d.x}, ${d.y})`);
  } else {
    // 처음 렌더링이면 부드러운 애니메이션
    currentSimulation.alpha(1).restart();
  }

  function showNodeTooltip(event, node) {
    if (!tooltip) return;
    tooltip.classList.remove('hidden');
    
    const rect = svgElement.getBoundingClientRect();
    tooltip.style.left = `${event.clientX - rect.left + 15}px`;
    tooltip.style.top = `${event.clientY - rect.top - 10}px`;

    const metrics = node.metrics || { events: 0, violations: 0 };
    const plugins = Array.isArray(node.plugins)
      ? node.plugins.map((p) => (typeof p === 'string' ? p : p.name)).filter(Boolean)
      : [];

    const connections = links.filter(l => 
      l.source.id === node.id || l.target.id === node.id ||
      l.source === node.id || l.target === node.id
    ).length;

    tooltip.innerHTML = `
      <div class="tooltip-title">${node.name || node.id}</div>
      <div class="tooltip-meta">${translateStatus(node.status)}</div>
      <ul>
        <li><strong>${metrics.events || 0}</strong>건의 이벤트</li>
        <li><strong>${metrics.violations || 0}</strong>건의 위반</li>
        <li><strong>${connections}</strong>개의 연결</li>
        <li><strong>${plugins.length}</strong>개의 플러그인</li>
      </ul>
      <div style="font-size: 9px; color: rgba(147, 164, 196, 0.6); margin-top: 4px;">
        드래그: 이동 | 더블클릭: 고정 해제
      </div>
    `;
  }

  function showLinkTooltip(event, link) {
    if (!tooltip) return;
    tooltip.classList.remove('hidden');
    
    const rect = svgElement.getBoundingClientRect();
    tooltip.style.left = `${event.clientX - rect.left + 15}px`;
    tooltip.style.top = `${event.clientY - rect.top - 10}px`;

    const sourceName = link.source.name || link.source.id || link.source;
    const targetName = link.target.name || link.target.id || link.target;

    tooltip.innerHTML = `
      <div class="tooltip-title">통신 연결</div>
      <ul>
        <li><strong>${sourceName}</strong> → <strong>${targetName}</strong></li>
        <li><strong>${link.count || 0}</strong>건의 통신</li>
        ${link.type ? `<li>유형: ${link.type}</li>` : ''}
      </ul>
    `;
  }

  function hideTooltip() {
    if (!tooltip) return;
    tooltip.classList.add('hidden');
  }

  // Setup control buttons
  setupGraphControls(svg, width, height);
  } catch (renderError) {
    console.error('그래프 렌더링 에러:', renderError);
  }
}

function setupGraphControls(svg, width, height) {
  const zoomInBtn = document.getElementById('graph-zoom-in');
  const zoomOutBtn = document.getElementById('graph-zoom-out');
  const resetBtn = document.getElementById('graph-reset');

  if (zoomInBtn) {
    zoomInBtn.onclick = () => {
      svg.transition().duration(300).call(graphZoom.scaleBy, 1.3);
    };
  }

  if (zoomOutBtn) {
    zoomOutBtn.onclick = () => {
      svg.transition().duration(300).call(graphZoom.scaleBy, 0.7);
    };
  }

  if (resetBtn) {
    resetBtn.onclick = () => {
      // 저장된 상태 초기화
      currentTransform = null;
      nodePositions.clear();
      
      // 화면 리셋
      svg.transition().duration(500).call(
        graphZoom.transform,
        d3.zoomIdentity.translate(0, 0).scale(1)
      );
      
      // 노드 고정 해제 및 시뮬레이션 재시작
      if (currentSimulation) {
        currentSimulation.nodes().forEach(node => {
          node.fx = null;
          node.fy = null;
        });
        currentSimulation.alpha(0.5).restart();
      }
    };
  }
}

// Real-time graph sync interval
let graphSyncInterval = null;

function startGraphSync() {
  // Sync every 10 seconds
  if (graphSyncInterval) clearInterval(graphSyncInterval);
  graphSyncInterval = setInterval(() => {
    loadAgentFlow(false);
  }, 10000);
}

function stopGraphSync() {
  if (graphSyncInterval) {
    clearInterval(graphSyncInterval);
    graphSyncInterval = null;
  }
}

// ========== Node Detail Panel ==========
let selectedNodeId = null;

function showNodeDetailPanel(node, links) {
  const panel = document.getElementById('node-detail-panel');
  if (!panel) return;

  selectedNodeId = node.id;
  
  // 패널 표시
  panel.classList.remove('hidden');
  panel.classList.add('visible');

  // 헤더 업데이트
  const statusDot = document.getElementById('panel-status-dot');
  const nodeName = document.getElementById('panel-node-name');
  
  if (statusDot) {
    statusDot.className = `node-status-dot ${node.type === 'registry' ? 'registry' : (node.status || 'unknown').toLowerCase()}`;
  }
  if (nodeName) {
    nodeName.textContent = node.name || node.id;
  }

  // 기본 정보 업데이트
  const basicInfo = document.getElementById('panel-basic-info');
  if (basicInfo) {
    const connections = links.filter(l => 
      l.source.id === node.id || l.target.id === node.id ||
      l.source === node.id || l.target === node.id
    ).length;

    basicInfo.innerHTML = `
      <span class="label">ID</span>
      <span class="value">${node.id}</span>
      <span class="label">유형</span>
      <span class="value">${getNodeTypeLabel(node.type)}</span>
      <span class="label">상태</span>
      <span class="value">${translateStatus(node.status)}</span>
      <span class="label">연결</span>
      <span class="value">${connections}개</span>
      ${node.plugins?.length ? `
        <span class="label">플러그인</span>
        <span class="value">${node.plugins.length}개</span>
      ` : ''}
    `;
  }

  // 통계 업데이트
  const stats = document.getElementById('panel-stats');
  if (stats) {
    const metrics = node.metrics || { events: 0, violations: 0 };
    stats.innerHTML = `
      <div class="stat-item">
        <div class="stat-value">${metrics.events || 0}</div>
        <div class="stat-label">이벤트</div>
      </div>
      <div class="stat-item">
        <div class="stat-value ${metrics.violations > 0 ? 'danger' : ''}">${metrics.violations || 0}</div>
        <div class="stat-label">위반</div>
      </div>
    `;
  }

  // 관련 이벤트 로드
  loadNodeEvents(node.id, node.type);

  // 패널 닫기 버튼 이벤트
  const closeBtn = document.getElementById('panel-close');
  if (closeBtn) {
    closeBtn.onclick = hideNodeDetailPanel;
  }
}

function hideNodeDetailPanel() {
  const panel = document.getElementById('node-detail-panel');
  if (panel) {
    panel.classList.remove('visible');
    panel.classList.add('hidden');
  }
  selectedNodeId = null;
}

function getNodeTypeLabel(type) {
  const labels = {
    'registry': '레지스트리',
    'agent': '에이전트',
    'external': '외부 에이전트'
  };
  return labels[type] || type || '알 수 없음';
}

async function loadNodeEvents(nodeId, nodeType) {
  const eventList = document.getElementById('panel-events');
  if (!eventList) return;

  eventList.innerHTML = '<div class="no-events">로딩 중...</div>';

  try {
    const response = await fetch(`${API_BASE}/api/logs?limit=100`);
    if (!response.ok) throw new Error('로그를 불러오지 못했습니다');
    
    const logsData = await response.json();
    const logs = Array.isArray(logsData) ? logsData : (logsData.logs || []);

    // 노드 ID에서 검색 키워드 추출 (이름 기반 매칭용)
    const nodeIdLower = nodeId.toLowerCase();
    const nodeKeywords = [];
    
    // ID에서 에이전트 이름 부분 추출 (예: "oneth.ai#agent:DeliveryAgent.v1.0.0")
    const idParts = nodeId.match(/[:#]([^.:#]+)/g);
    if (idParts) {
      idParts.forEach(part => {
        const cleanPart = part.replace(/[:#]/g, '').toLowerCase();
        if (cleanPart && cleanPart.length > 2) {
          nodeKeywords.push(cleanPart);
        }
      });
    }
    nodeKeywords.push(nodeIdLower);

    // 해당 노드와 관련된 로그 필터링
    let relatedLogs;
    if (nodeType === 'registry') {
      relatedLogs = logs.filter(log => log.source === 'registry');
    } else {
      relatedLogs = logs.filter(log => {
        const agentId = (log.agent_id || log.agentId || '').toLowerCase();
        const calleeId = (log.callee_id || log.target_agent || '').toLowerCase();
        
        // 정확히 일치
        if (agentId === nodeIdLower || calleeId === nodeIdLower) return true;
        
        // 키워드 기반 매칭
        for (const keyword of nodeKeywords) {
          if (agentId.includes(keyword) || keyword.includes(agentId) ||
              calleeId.includes(keyword) || keyword.includes(calleeId)) {
            return true;
          }
        }
        
        return false;
      });
    }

    // 최근 10개만 표시
    relatedLogs = relatedLogs.slice(0, 10);

    if (relatedLogs.length === 0) {
      eventList.innerHTML = '<div class="no-events">관련 이벤트가 없습니다</div>';
      return;
    }

    eventList.innerHTML = relatedLogs.map(log => {
      const rawVerdict = log.verdict || log.status || '';
      const verdict = (typeof rawVerdict === 'string' ? rawVerdict : String(rawVerdict || '')).toLowerCase();
      const isViolation = ['violation', 'blocked', 'denied'].includes(verdict);
      const timestamp = log.timestamp ? new Date(log.timestamp).toLocaleString() : '';
      const message = log.message || log.details || getPolicyLabel(log.policy_type) || '이벤트';

      return `
        <div class="event-item">
          <div class="event-header">
            <span class="event-type ${isViolation ? 'violation' : ''}">${isViolation ? '위반' : '이벤트'}</span>
            <span class="event-time">${timestamp}</span>
          </div>
          <div class="event-message">${truncateMessage(message, 60)}</div>
        </div>
      `;
    }).join('');

  } catch (error) {
    console.error('노드 이벤트 로드 실패:', error);
    eventList.innerHTML = '<div class="no-events">이벤트를 불러오지 못했습니다</div>';
  }
}

function truncateMessage(message, maxLength) {
  if (!message) return '';
  if (message.length <= maxLength) return message;
  return message.substring(0, maxLength) + '...';
}

// SVG 클릭 시 패널 닫기
document.addEventListener('DOMContentLoaded', () => {
  const svgElement = document.getElementById('agent-flow-graph');
  if (svgElement) {
    svgElement.addEventListener('click', (event) => {
      // 노드가 아닌 빈 영역 클릭 시 패널 닫기
      if (event.target === svgElement || event.target.tagName === 'svg') {
        hideNodeDetailPanel();
      }
    });
  }
});
