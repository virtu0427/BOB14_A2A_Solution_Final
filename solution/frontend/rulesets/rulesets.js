// rulesets.js - 닫기 버튼 버그 수정 및 멀티 셀렉트 포함

const API_BASE = window.location.origin;

// =========================================================
// [CORE] API 호출 함수 (실제 백엔드/Redis 연동)
// =========================================================
async function fetchJson(url, options = {}) {
  const opts = { ...options };
  opts.headers = {
    ...(options.headers || {}),
  };

  // 기본적으로 JSON 응답을 기대하고 에러를 예외로 전달한다.
  let response;
  try {
    response = await fetch(url, opts);
  } catch (err) {
    throw new Error(`네트워크 오류: ${err.message || err}`);
  }

  const isJson =
    response.headers.get("content-type")?.includes("application/json");

  if (!response.ok) {
    let detail = response.statusText;
    if (isJson) {
      try {
        const payload = await response.json();
        detail = payload?.error || payload?.detail || detail;
      } catch (_) {
        /* ignore parse error */ // 노이즈를 줄이기 위해 무시
      }
    } else {
      try {
        detail = await response.text();
      } catch (_) {
        /* ignore parse error */
      }
    }
    throw new Error(detail || `요청 실패 (${response.status})`);
  }

  if (!isJson) {
    return {};
  }

  try {
    return await response.json();
  } catch (_) {
    return {};
  }
}

// --- State ---
let selectedGroupId = null;
let allRulesets = [];
let allGroups = [];
let allAgents = [];
let allUsers = [];
let selectedUsersForAdd = [];
let allTenants = [];
let currentSelectedTools = []; // 멀티 셀렉트용 상태

// --- Initialization ---
window.addEventListener("DOMContentLoaded", async () => {
  try {
    initModalEvents();
    initGroupActions();
    await refreshAll();

    // 외부 클릭 시 멀티 셀렉트 닫기
    document.addEventListener("click", (e) => {
      const wrapper = document.getElementById("target-tool-multiselect");
      if (wrapper && !wrapper.contains(e.target)) {
        const list = document.getElementById("tool-multiselect-list");
        if (list) list.classList.remove("show");
      }
    });
  } catch (error) {
    console.error("Initialization failed:", error);
  }
});

async function refreshAll() {
  try {
    const rulesetsResp = await fetchJson(`${API_BASE}/api/rulesets`);
    allRulesets = Array.isArray(rulesetsResp) ? rulesetsResp : [];

    const groupsResp = await fetchJson(`${API_BASE}/api/rulesets/groups`);
    allGroups = Array.isArray(groupsResp) ? groupsResp : [];

    const usersResp = await fetchJson(`${API_BASE}/api/rulesets/users`);
    allUsers = Array.isArray(usersResp) ? usersResp : [];

    allTenants = await fetchJson(`${API_BASE}/api/rulesets/tenants`).catch(
      () => []
    );
    if (!Array.isArray(allTenants)) allTenants = [];

    try {
      const agentsResp = await fetchJson(`${API_BASE}/api/agents`);
      allAgents = Array.isArray(agentsResp) ? agentsResp : [];
    } catch (err) {
      allAgents = [];
    }

    renderGroupList();
    if (selectedGroupId && !allGroups.find((g) => g.id === selectedGroupId)) {
      selectedGroupId = null;
    }

    if (selectedGroupId) {
      renderGroupDetail(selectedGroupId);
    } else if (allGroups.length > 0) {
      selectGroup(allGroups[0].id);
    } else {
      const placeholder = document.getElementById("group-detail-placeholder");
      const content = document.getElementById("group-detail-content");
      if (placeholder) placeholder.classList.remove("hidden");
      if (content) content.classList.add("hidden");
    }
  } catch (e) {
    console.error("Refresh failed:", e);
  }
}

function selectGroup(groupId) {
  selectedGroupId = groupId;
  renderGroupList();
  renderGroupDetail(groupId);
}

function initModalEvents() {
  document.querySelectorAll(".modal-overlay").forEach((o) => {
    o.addEventListener("click", (e) => {
      if (e.target === o) closeModal(o.id);
    });
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      const activeModal = document.querySelector(".modal-overlay.active");
      if (activeModal) closeModal(activeModal.id);
    }
  });
}

function initGroupActions() {
  const btnAddGroup = document.getElementById("btn-add-group");
  if (btnAddGroup)
    btnAddGroup.addEventListener("click", () => openGroupModal());

  const btnEditGroup = document.getElementById("btn-edit-group");
  if (btnEditGroup) {
    btnEditGroup.addEventListener("click", () => {
      const group = allGroups.find((g) => g.id === selectedGroupId);
      if (group) openGroupModal(group);
    });
  }

  const btnDeleteGroup = document.getElementById("btn-delete-group");
  if (btnDeleteGroup) {
    btnDeleteGroup.addEventListener("click", async () => {
      const group = allGroups.find((g) => g.id === selectedGroupId);
      if (!group || !group.tenant_id) {
        alert("선택된 그룹이나 테넌트 정보가 없습니다.");
        return;
      }
      if (!confirm("이 그룹을 삭제하시겠습니까?")) return;
      try {
        await fetchJson(
          `${API_BASE}/api/rulesets/groups/${group.tenant_id}/${group.id}`,
          { method: "DELETE" }
        );
        selectedGroupId = null;
        await refreshAll();
      } catch (err) {
        alert(`그룹 삭제에 실패했습니다: ${err.message}`);
      }
    });
  }

  // [수정된 부분] 그룹 모달 닫기 버튼 이벤트 리스너 추가
  const btnCancelGroup = document.getElementById("btn-cancel-group");
  if (btnCancelGroup) {
    btnCancelGroup.addEventListener("click", () => closeModal("group-modal"));
  }

  const btnAddMember = document.getElementById("btn-add-member");
  if (btnAddMember)
    btnAddMember.addEventListener("click", () => openMemberModal());

  const searchInput = document.getElementById("user-search-input");
  if (searchInput) {
    searchInput.addEventListener("input", (e) =>
      renderUserList(e.target.value)
    );
  }

  const btnCancelMember = document.getElementById("btn-cancel-member");
  if (btnCancelMember) {
    btnCancelMember.addEventListener("click", () => closeModal("member-modal"));
  }

  const btnConfirmAddMember = document.getElementById("btn-confirm-add-member");
  if (btnConfirmAddMember) {
    btnConfirmAddMember.addEventListener("click", async () => {
      if (selectedUsersForAdd.length > 0 && selectedGroupId) {
        const group = allGroups.find((g) => g.id === selectedGroupId);
        if (!group) {
          alert("그룹 정보 오류");
          return;
        }

        const existing = (group.members || []).map((m) =>
          typeof m === "string" ? m : m.email
        );
        const merged = Array.from(
          new Set([...existing, ...selectedUsersForAdd])
        );

        try {
          await fetchJson(
            `${API_BASE}/api/rulesets/groups/${group.tenant_id}/${group.id}/members`,
            {
              method: "PUT",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ members: merged }),
            }
          );
          closeModal("member-modal");
          selectedUsersForAdd = [];
          document.getElementById("btn-confirm-add-member").disabled = true;
          await refreshAll();
        } catch (err) {
          alert(`멤버 추가에 실패했습니다: ${err.message}`);
        }
      }
    });
  }

  const groupForm = document.getElementById("group-form");
  if (groupForm) {
    groupForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const groupId = document.getElementById("group-edit-id").value.trim();
      const name = document.getElementById("group-name").value.trim();
      const description = document.getElementById("group-desc").value.trim();

      if (!name) {
        alert("그룹 이름을 입력하세요.");
        return;
      }

      if (groupId) {
        const group = allGroups.find((g) => g.id === groupId);
        try {
          await fetchJson(
            `${API_BASE}/api/rulesets/groups/${group.tenant_id}/${group.id}`,
            {
              method: "PUT",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ name, description }),
            }
          );
          closeModal("group-modal");
          await refreshAll();
          selectGroup(group.id);
        } catch (err) {
          alert("그룹 수정에 실패했습니다.");
        }
        return;
      }

      const tenantId = slugify(name);
      if (!tenantId) {
        alert("유효하지 않은 그룹 이름");
        return;
      }
      const newId = `g_${Date.now().toString(36)}`;

      try {
        const created = await fetchJson(`${API_BASE}/api/rulesets/groups`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            tenant_id: tenantId,
            tenant_name: name,
            id: newId,
            name,
            description,
          }),
        });
        closeModal("group-modal");
        await refreshAll();
        if (created?.id) selectGroup(created.id);
      } catch (err) {
        alert(`그룹 생성에 실패했습니다: ${err.message}`);
      }
    });
  }

  const btnCreateGroupRule = document.getElementById("btn-create-group-rule");
  if (btnCreateGroupRule) {
    btnCreateGroupRule.addEventListener("click", () => {
      const group = allGroups.find((g) => g.id === selectedGroupId);
      openRulesetForm(null, {
        scope: "group",
        groupId: selectedGroupId,
        tenantId: group?.tenant_id,
      });
    });
  }
}

// --- Modal Functions ---
function openGroupModal(group = null) {
  const modal = document.getElementById("group-modal");
  const title = document.getElementById("group-modal-title");
  const form = document.getElementById("group-form");

  if (!modal || !title || !form) return;
  form.reset();

  if (group) {
    title.textContent = "그룹 수정";
    document.getElementById("group-edit-id").value = group.id;
    document.getElementById("group-name").value = group.name;
    document.getElementById("group-desc").value = group.description || "";
  } else {
    title.textContent = "새 그룹 생성";
    document.getElementById("group-edit-id").value = "";
  }
  openModal("group-modal");
}

function openMemberModal() {
  selectedUsersForAdd = [];
  document.getElementById("user-search-input").value = "";
  document.getElementById("btn-confirm-add-member").disabled = true;
  document.getElementById("selected-user-count").textContent = "0명 선택됨";
  renderUserList();
  openModal("member-modal");
}

// --- Render Functions ---

function renderGroupList() {
  const list = document.getElementById("group-list");
  if (!list) return;
  list.innerHTML = "";

  allGroups.forEach((group) => {
    const li = document.createElement("li");
    li.className = `group-nav-item ${
      group.id === selectedGroupId ? "active" : ""
    }`;
    li.innerHTML = `<span>${group.name}</span> <i class="fas fa-chevron-right"></i>`;
    li.onclick = () => selectGroup(group.id);
    list.appendChild(li);
  });
}

function renderGroupDetail(groupId) {
  const group = allGroups.find((g) => g.id === groupId);
  if (!group) return;

  document.getElementById("group-detail-placeholder").classList.add("hidden");
  document.getElementById("group-detail-content").classList.remove("hidden");
  document.getElementById("selected-group-name").textContent = group.name;
  document.getElementById("selected-group-desc").textContent =
    group.description || "";

  // Members
  const memberTbody = document.getElementById("group-member-table-body");
  memberTbody.innerHTML = "";
  const memberTemplate = document.getElementById("member-row-template");

  const members = Array.isArray(group.members) ? group.members : [];
  if (members.length === 0) {
    memberTbody.innerHTML =
      '<tr><td colspan="4" class="empty-state">등록된 멤버가 없습니다.</td></tr>';
  } else {
    members.forEach((member) => {
      const email = typeof member === "string" ? member : member.email;
      const user = allUsers.find((u) => u.email === email);
      const row = memberTemplate.content.cloneNode(true);

      if (user) {
        row.querySelector(".member-name").textContent = user.name || user.email;
        row.querySelector(".member-title").textContent =
          user.title || (user.tenants || []).join(", ") || "-";
        row.querySelector(".member-email").textContent = user.email;
      } else {
        row.querySelector(".member-name").textContent = email || "Unknown";
        row.querySelector(".member-title").textContent = "-";
        row.querySelector(".member-email").textContent = email || "-";
      }
      row.querySelector("button").onclick = () =>
        removeMember(group.id, email, group.tenant_id);
      memberTbody.appendChild(row);
    });
  }

  // Group Rules (Tool Multi-Select Display Update)
  const tbody = document.getElementById("group-rules-body");
  tbody.innerHTML = "";
  const rules = allRulesets.filter((r) => r.group_id === groupId);

  if (rules.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="4" class="empty-state">설정된 정책이 없습니다.</td></tr>';
  } else {
    const tpl = document.getElementById("ruleset-row-template");
    rules.forEach((r) => {
      const row = tpl.content.cloneNode(true);
      row.querySelector(".ruleset-name").textContent = r.name;

      let desc = r.description;
      if (!desc && r.target_agent) {
        // 멀티 툴 표시 로직
        let toolDisplay = "";
        if (
          r.tool_names &&
          Array.isArray(r.tool_names) &&
          r.tool_names.length > 0
        ) {
          toolDisplay = `${r.tool_names.length}개 Tool`;
          if (r.tool_names.length === 1) toolDisplay = r.tool_names[0];
        } else if (r.tool_name) {
          toolDisplay = r.tool_name;
        } else {
          toolDisplay = "모든 Tool";
        }

        const action = r.rules?.action === "deny" ? "차단" : "검증";
        desc = `${r.target_agent}의 ${toolDisplay} 사용 ${action}`;
      }
      row.querySelector(".ruleset-desc").textContent = desc || "-";

      const typeCell = row.querySelector(".ruleset-type");
      if (typeCell) typeCell.style.display = "none";

      const statusCell = row.querySelector(".ruleset-status");
      const btn = document.createElement("button");
      btn.className = `toggle-btn ${r.enabled ? "on" : "off"}`;
      btn.innerHTML = r.enabled
        ? '<i class="fas fa-toggle-on"></i>'
        : '<i class="fas fa-toggle-off"></i>';
      btn.onclick = async (e) => {
        e.stopPropagation();
        try {
          await fetchJson(
            `${API_BASE}/api/rulesets/${encodeURIComponent(r.ruleset_id)}`,
            {
              method: "PUT",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ enabled: !r.enabled }),
            }
          );
          refreshAll();
        } catch (err) {
          alert("상태 변경에 실패했습니다.");
        }
      };
      statusCell.appendChild(btn);

      row
        .querySelector('[data-action="edit"]')
        .addEventListener("click", () =>
          openRulesetForm(r, { scope: "group", groupId, tenantId: r.tenant_id })
        );
      row
        .querySelector('[data-action="delete"]')
        .addEventListener("click", async () => {
          if (confirm("정책을 삭제하시겠습니까?")) {
            try {
              await fetchJson(
                `${API_BASE}/api/rulesets/${encodeURIComponent(r.ruleset_id)}`,
                { method: "DELETE" }
              );
              refreshAll();
            } catch (err) {
              alert("삭제에 실패했습니다.");
            }
          }
        });
      tbody.appendChild(row);
    });
  }
}

function renderUserList(keyword = "") {
  const tbody = document.getElementById("user-list-body");
  tbody.innerHTML = "";

  const currentGroup = allGroups.find((g) => g.id === selectedGroupId);
  const existingMembers = (currentGroup?.members || []).map((m) =>
    typeof m === "string" ? m : m.email
  );

  const filteredUsers = allUsers.filter((user) => {
    if (existingMembers.includes(user.email)) return false;
    if (!keyword) return true;
    const lowerKey = keyword.toLowerCase();
    return (
      (user.name || "").toLowerCase().includes(lowerKey) ||
      (user.email || "").toLowerCase().includes(lowerKey) ||
      (user.title || "").toLowerCase().includes(lowerKey)
    );
  });

  if (filteredUsers.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="4" class="empty-state">검색 결과가 없거나 추가할 수 있는 사용자가 없습니다.</td></tr>';
    return;
  }

  filteredUsers.forEach((user) => {
    const tr = document.createElement("tr");
    tr.className = "user-select-row";
    if (selectedUsersForAdd.includes(user.email)) tr.classList.add("selected");

    tr.innerHTML = `
      <td style="text-align: center;"><div class="radio-indicator"></div></td>
      <td class="font-medium" style="text-align: center;">${
        user.name || user.email
      }</td>
      <td class="text-secondary text-sm" style="text-align: center;">${
        user.title || (user.tenants || []).join(", ") || "-"
      }</td>
      <td class="text-secondary" style="text-align: center;">${user.email}</td>
    `;

    tr.onclick = () => {
      const email = user.email;
      const index = selectedUsersForAdd.indexOf(email);
      if (index > -1) {
        selectedUsersForAdd.splice(index, 1);
        tr.classList.remove("selected");
      } else {
        selectedUsersForAdd.push(email);
        tr.classList.add("selected");
      }
      const count = selectedUsersForAdd.length;
      document.getElementById("btn-confirm-add-member").disabled = count === 0;
      document.getElementById(
        "selected-user-count"
      ).textContent = `${count}명 선택됨`;
    };
    tbody.appendChild(tr);
  });
}

// --- Unified Form Logic (Multi-Select Support) ---
function openRulesetForm(rule = null, context = {}) {
  const body = document.getElementById("ruleset-modal-body");
  const template = document.getElementById("ruleset-form-template");
  if (!body || !template) return;

  body.innerHTML = "";
  const node = template.content.cloneNode(true);
  const form = node.querySelector("form");
  const { scope, groupId, tenantId } = context;
  const groupMeta = allGroups.find((g) => g.id === groupId);

  form.querySelector("#ruleset-group-id").value = groupId || "";
  const tenantInput = form.querySelector("#ruleset-tenant-id");
  if (tenantInput)
    tenantInput.value =
      tenantId || rule?.tenant_id || groupMeta?.tenant_id || "";

  // Group scope (접근 제한 설정)
  if (scope === "group") {
    document.getElementById("ruleset-modal-title").textContent =
      "그룹 접근 제한 설정";

    const fieldsToHide = [
      "#type-select-container",
      "#enabled-checkbox-container",
      "#validation-rules-container",
      "#tool-name-manual-container",
    ];
    fieldsToHide.forEach((sel) => {
      const el = form.querySelector(sel);
      if (el) el.classList.add("hidden");
    });

    const targetSection = form.querySelector("#target-selection-area");
    if (targetSection) targetSection.classList.remove("hidden");

    const agentSelect = form.querySelector("#target-agent-select");
    const multiSelectHeader = form.querySelector("#tool-multiselect-header");
    const multiSelectList = form.querySelector("#tool-multiselect-list");
    const toolManual = form.querySelector("#ruleset-tool-name");

    // 에이전트 목록 채우기
    agentSelect.innerHTML = '<option value="">에이전트 선택...</option>';
    allAgents.forEach((a) => {
      const opt = document.createElement("option");
      opt.value = a.agent_id || a.id;
      opt.textContent = a.name || a.agent_id || a.id;
      agentSelect.appendChild(opt);
    });

    currentSelectedTools = [];

    // [중요] 멀티 셀렉트 렌더링 함수
    async function populateToolsMulti(aid, preSelected = []) {
      multiSelectHeader.querySelector(".placeholder").textContent =
        "로딩 중...";
      multiSelectList.innerHTML = "";
      currentSelectedTools = [];

      if (!aid) {
        multiSelectHeader.querySelector(".placeholder").textContent =
          "에이전트를 먼저 선택하세요";
        return;
      }

      try {
        const resp = await fetchJson(
          `${API_BASE}/api/rulesets/agents/${encodeURIComponent(aid)}/tools`
        );
        const tools = Array.isArray(resp.tools) ? resp.tools : [];

        if (tools.length === 0) {
          multiSelectHeader.querySelector(".placeholder").textContent =
            "등록된 Tool이 없습니다";
          if (toolManual) toolManual.classList.remove("hidden");
          return;
        }

        // 수동 입력 숨김
        if (toolManual) toolManual.classList.add("hidden");

        // 툴 목록 생성 (체크박스)
        multiSelectHeader.querySelector(".placeholder").textContent =
          "Tool 선택...";

        tools.forEach((tid) => {
          const optionDiv = document.createElement("div");
          optionDiv.className = "multi-select-option";

          const checkbox = document.createElement("input");
          checkbox.type = "checkbox";
          checkbox.value = tid;
          checkbox.id = `chk-tool-${tid}`;

          // 기존 선택된 값 반영
          if (preSelected.includes(tid)) {
            checkbox.checked = true;
            currentSelectedTools.push(tid);
          }

          const label = document.createElement("label");
          label.htmlFor = `chk-tool-${tid}`;
          label.textContent = tid;

          // 이벤트: 체크박스 변경 시 상태 업데이트
          const toggleSelection = () => {
            if (checkbox.checked) {
              if (!currentSelectedTools.includes(tid))
                currentSelectedTools.push(tid);
            } else {
              currentSelectedTools = currentSelectedTools.filter(
                (t) => t !== tid
              );
            }
            updateHeader();
          };

          checkbox.addEventListener("change", toggleSelection);
          optionDiv.addEventListener("click", (e) => {
            if (e.target !== checkbox && e.target !== label) {
              checkbox.checked = !checkbox.checked;
              toggleSelection();
            }
          });

          optionDiv.appendChild(checkbox);
          optionDiv.appendChild(label);
          multiSelectList.appendChild(optionDiv);
        });

        updateHeader();
      } catch (err) {
        console.warn("tool list fetch failed", err);
        multiSelectHeader.querySelector(".placeholder").textContent =
          "목록 로드 실패";
      }
    }

    // 헤더 텍스트 업데이트
    function updateHeader() {
      const span = multiSelectHeader.querySelector(".placeholder");
      if (currentSelectedTools.length === 0) {
        span.textContent = "Tool 선택... (0개)";
        span.style.color = "var(--text-secondary)";
      } else {
        span.textContent = `${
          currentSelectedTools.length
        }개 선택됨: ${currentSelectedTools.slice(0, 2).join(", ")}${
          currentSelectedTools.length > 2 ? "..." : ""
        }`;
        span.style.color = "#fff";
      }
    }

    // 드롭다운 토글 이벤트
    multiSelectHeader.addEventListener("click", () => {
      multiSelectList.classList.toggle("show");
    });

    // 에이전트 변경 시 툴 목록 갱신
    agentSelect.addEventListener("change", (e) => {
      populateToolsMulti(e.target.value);
    });

    // 수정 모드: 기존 데이터 채우기
    if (rule && rule.target_agent) {
      agentSelect.value = rule.target_agent;
      // 기존 저장된 툴 목록 (배열이거나, 단일 문자열일 수 있음)
      let initialTools = [];
      if (rule.tool_names && Array.isArray(rule.tool_names)) {
        initialTools = rule.tool_names;
      } else if (rule.tool_name) {
        initialTools = [rule.tool_name];
      }
      populateToolsMulti(rule.target_agent, initialTools);
    }

    const typeInput = form.querySelector('[name="type"]');
    if (typeInput) typeInput.value = "tool_validation";
  }

  // 기본 정보 채우기
  if (rule) {
    form.querySelector('[name="ruleset_id"]').value = rule.ruleset_id;
    form.querySelector('[name="ruleset_id"]').disabled = true;
    form.querySelector('[name="name"]').value = rule.name;
    form.querySelector('[name="description"]').value = rule.description || "";
    const enabledCb = form.querySelector('[name="enabled"]');
    if (enabledCb) enabledCb.checked = rule.enabled;
  }

  // 폼 제출 (저장)
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());

    if (scope === "group") {
      data.enabled = true;
      data.rules = { action: "deny" };
      data.type = "tool_validation";
      data.scope = "group";
      data.group_id = groupId;
      data.tenant_id =
        form.querySelector("#ruleset-tenant-id")?.value ||
        groupMeta?.tenant_id ||
        "";
      data.target_agent = form.querySelector("#target-agent-select").value;

      // [중요] 멀티 셀렉트된 값 저장
      data.tool_names = currentSelectedTools;
      // 하위 호환성을 위해 tool_name에도 첫 번째 값을 넣거나 콤마 스트링 넣기 (선택 사항)
      data.tool_name = currentSelectedTools.join(",");

      if (!data.target_agent || currentSelectedTools.length === 0) {
        alert("대상 에이전트와 최소 1개 이상의 Tool을 선택해주세요.");
        return;
      }
    }

    try {
      if (rule && rule.ruleset_id) {
        await fetchJson(
          `${API_BASE}/api/rulesets/${encodeURIComponent(rule.ruleset_id)}`,
          {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data),
          }
        );
      } else {
        await fetchJson(`${API_BASE}/api/rulesets`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(data),
        });
      }
      closeModal("ruleset-modal");
      refreshAll();
    } catch (err) {
      alert("정책 저장에 실패했습니다.");
    }
  });

  body.appendChild(node);
  const cancelBtn = body.querySelector("#btn-cancel-ruleset");
  if (cancelBtn)
    cancelBtn.addEventListener("click", () => closeModal("ruleset-modal"));

  openModal("ruleset-modal");
}

// --- Utils ---
function removeMember(groupId, email, tenantId) {
  if (!confirm("이 멤버를 그룹에서 제거하시겠습니까?")) return;
  fetchJson(`${API_BASE}/api/rulesets/groups/${tenantId}/${groupId}/members`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      members: (allGroups.find((g) => g.id === groupId)?.members || [])
        .map((m) => (typeof m === "string" ? m : m.email))
        .filter((addr) => addr !== email),
    }),
  })
    .then(() => refreshAll())
    .catch(() => alert("멤버 삭제 실패"));
}

function openModal(id) {
  const el = document.getElementById(id);
  if (el) {
    el.classList.remove("hidden");
    el.classList.add("active");
  }
}
function closeModal(id) {
  const el = document.getElementById(id);
  if (el) {
    el.classList.add("hidden");
    el.classList.remove("active");
  }
}
function slugify(name) {
  return name
    .toLowerCase()
    .replace(/[^\w\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-");
}
