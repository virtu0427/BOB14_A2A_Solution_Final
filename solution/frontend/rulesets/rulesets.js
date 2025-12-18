// rulesets.js - API 연동 + JWT 모달 + 멀티툴 선택

const API_BASE = window.location.origin;

async function fetchJson(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: {
      ...(options.headers || {}),
      Accept: "application/json",
    },
  });
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try {
      const err = await res.json();
      if (err?.error || err?.message) msg = err.error || err.message;
      if (err?.detail) msg += ` | detail: ${err.detail}`;
    } catch (_e) {
      /* ignore */
    }
    throw new Error(msg);
  }
  return res.json();
}

// --- State ---
let selectedGroupId = null;
let allRulesets = [];
let allGroups = [];
let allAgents = [];
let allUsers = [];
let selectedUsersForAdd = [];
let allTenants = [];
let currentSelectedTools = [];

function generateNextRuleId() {
  const prefix = "rule-";
  const numbers = new Set();
  allRulesets.forEach((r) => {
    const m = String(r?.ruleset_id || "").toLowerCase().match(/^rule-(\d+)$/);
    if (m) numbers.add(Number(m[1]));
  });
  let n = 1;
  while (numbers.has(n)) n += 1;
  return `${prefix}${n}`;
}

// --- Initialization ---
window.addEventListener("DOMContentLoaded", async () => {
  try {
    initModalEvents();
    initGroupActions();
    await refreshAll();

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

async function refreshAll(options = {}) {
  const { skipAgents = false } = options;
  try {
    allRulesets = await fetchJson(`${API_BASE}/api/rulesets`);
    allGroups = await fetchJson(`${API_BASE}/api/rulesets/groups`);
    allUsers = await fetchJson(`${API_BASE}/api/rulesets/users`);
    allTenants = await fetchJson(`${API_BASE}/api/rulesets/tenants`).catch(
      () => []
    );
    if (!skipAgents) {
      try {
        allAgents = await fetchJson(`${API_BASE}/api/agents`);
      } catch (err) {
        allAgents = [];
      }
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

async function refreshAgentPolicy(agentId, tenantId, options = {}) {
  const { suppressErrors = true } = options;
  if (!agentId) {
    return;
  }

  const payload = tenantId ? { tenant: tenantId } : {};
  try {
    await fetchJson(
      `${API_BASE}/api/agents/${encodeURIComponent(agentId)}/refresh-policy`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      }
    );
    return true;
  } catch (error) {
    console.warn("Agent refresh failed:", error.message);
    if (!suppressErrors) {
      throw error;
    }
    return false;
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
  if (btnAddGroup) btnAddGroup.addEventListener("click", () => openGroupModal());

  const btnEditGroup = document.getElementById("btn-edit-group");
  if (btnEditGroup) {
    btnEditGroup.addEventListener("click", () => {
      const group = allGroups.find((g) => g.id === selectedGroupId);
      if (group) openGroupModal(group);
    });
  }

  const btnApplyGroupRules = document.getElementById("btn-apply-group-rules");
  if (btnApplyGroupRules) {
    btnApplyGroupRules.addEventListener("click", () =>
      applyGroupRulesToAgents(btnApplyGroupRules)
    );
  }

  const btnDeleteGroup = document.getElementById("btn-delete-group");
  if (btnDeleteGroup) {
    btnDeleteGroup.addEventListener("click", () => {
    const group = allGroups.find((g) => g.id === selectedGroupId);
      if (!group || !group.tenant_id) {
        alert("선택한 그룹이나 테넌트 정보가 없습니다.");
        return;
      }
      if (!confirm("해당 그룹을 삭제하시겠습니까?")) return;
      fetchJson(
        `${API_BASE}/api/rulesets/groups/${group.tenant_id}/${group.id}`,
        { method: "DELETE" }
      )
        .then(async () => {
          selectedGroupId = null;
          // 그룹 삭제 직후에도 에이전트 목록 재조회(및 서버 로그)를 건너뛴다.
          await refreshAll({ skipAgents: true });
        })
        .catch((err) => alert(`그룹 삭제에 실패했습니다: ${err.message}`));
    });
  }

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
        const merged = Array.from(new Set([...existing, ...selectedUsersForAdd]));

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
        // 그룹 생성 직후에는 에이전트 목록 재조회(및 서버 로그)를 건너뛴다.
        await refreshAll({ skipAgents: true });
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

async function applyGroupRulesToAgents(buttonEl) {
  const btn = buttonEl || document.getElementById("btn-apply-group-rules");
  const group = allGroups.find((g) => g.id === selectedGroupId);
  if (!group) {
    alert("그룹을 먼저 선택해 주세요.");
    return;
  }

  const groupRules = allRulesets.filter(
    (r) => r.group_id === group.id && r.target_agent
  );
  if (!groupRules.length) {
    alert("이 그룹에 적용할 룰셋이 없습니다.");
    return;
  }

  const targets = [];
  const seen = new Set();
  groupRules.forEach((rule) => {
    const agentId = rule.target_agent || rule.agent_id;
    if (!agentId) return;
    const tenantId = rule.tenant_id || group.tenant_id || "";
    const key = `${agentId}__${tenantId}`;
    if (seen.has(key)) return;
    seen.add(key);
    targets.push({ agentId, tenantId });
  });

  if (!targets.length) {
    alert("룰셋 대상 agent가 없습니다.");
    return;
  }

  const originalLabel = btn?.textContent;
  if (btn) {
    btn.disabled = true;
    btn.textContent = "적용 중...";
  }

  const failures = [];
  for (const target of targets) {
    try {
      await refreshAgentPolicy(target.agentId, target.tenantId, {
        suppressErrors: false,
      });
    } catch (err) {
      const msg = err?.message || String(err);
      failures.push(`${target.agentId}: ${msg}`);
    }
  }

  if (btn) {
    btn.disabled = false;
    btn.textContent = originalLabel || "룰셋 적용";
  }

  if (failures.length) {
    alert(`일부 agent 정책 새로고침에 실패했습니다:\\n${failures.join("\\n")}`);
    return;
  }

  alert("그룹의 룰셋을 적용했습니다.");
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
        let toolDisplay = "";
        if (r.tool_names && Array.isArray(r.tool_names) && r.tool_names.length) {
          toolDisplay =
            r.tool_names.length === 1
              ? r.tool_names[0]
              : `${r.tool_names.length}개 Tool`;
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
        await refreshAgentPolicy(r.target_agent, r.tenant_id);
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
          await refreshAgentPolicy(r.target_agent, r.tenant_id);
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

// --- Unified Form Logic (multi-tool) ---
function openRulesetForm(rule = null, context = {}) {
  const body = document.getElementById("ruleset-modal-body");
  const template = document.getElementById("ruleset-form-template");
  if (!body || !template) return;

  body.innerHTML = "";
  const node = template.content.cloneNode(true);
  const form = node.querySelector("form");
  const { scope, groupId, tenantId } = context;
  const groupMeta = allGroups.find((g) => g.id === groupId);

  // 기본 ID/이름 자동 채우기
  const idInput = form.querySelector("#ruleset-id");
  const nameInput = form.querySelector("#ruleset-name");
  if (!rule && idInput && nameInput) {
    const nextId = generateNextRuleId();
    idInput.value = nextId;
    nameInput.value = "";
  } else if (rule) {
    if (idInput) {
      idInput.value = rule.ruleset_id;
      idInput.disabled = true;
    }
    if (nameInput) nameInput.value = rule.name || rule.ruleset_id || "";
  }

  form.querySelector("#ruleset-group-id").value = groupId || "";
  const tenantInput = form.querySelector("#ruleset-tenant-id");
  if (tenantInput)
    tenantInput.value =
      tenantId || rule?.tenant_id || groupMeta?.tenant_id || "";

  if (scope === "group") {
    document.getElementById("ruleset-modal-title").textContent =
      "그룹 접근 허용 설정";

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

    agentSelect.innerHTML = '<option value="">Select agent...</option>';
    allAgents.forEach((a) => {
      const opt = document.createElement("option");
      opt.value = a.agent_id || a.id;
      opt.textContent = a.name || a.agent_id || a.id;
      agentSelect.appendChild(opt);
    });

    currentSelectedTools = [];

    async function populateToolsMulti(aid, preSelected = []) {
      multiSelectHeader.querySelector(".placeholder").textContent = "Loading...";
      multiSelectList.innerHTML = "";
      currentSelectedTools = [];

      if (!aid) {
        multiSelectHeader.querySelector(".placeholder").textContent =
          "Select an agent first";
        return;
      }

      try {
        const resp = await fetchJson(
          `${API_BASE}/api/rulesets/agents/${encodeURIComponent(aid)}/tools`
        );
        const tools = Array.isArray(resp.tools) ? resp.tools : [];
        if (tools.length === 0) {
          multiSelectHeader.querySelector(".placeholder").textContent =
            "No tools available";
          if (toolManual) toolManual.classList.remove("hidden");
          return;
        }

        if (toolManual) toolManual.classList.add("hidden");
        multiSelectHeader.querySelector(".placeholder").textContent =
          "Select tools...";

        tools.forEach((tid) => {
          const optionDiv = document.createElement("div");
          optionDiv.className = "multi-select-option";

          const checkbox = document.createElement("input");
          checkbox.type = "checkbox";
          checkbox.value = tid;
          checkbox.id = `chk-tool-${tid}`;

          if (preSelected.includes(tid)) {
            checkbox.checked = true;
            currentSelectedTools.push(tid);
          }

          const label = document.createElement("label");
          label.htmlFor = `chk-tool-${tid}`;
          label.textContent = tid;

          const toggleSelection = () => {
            if (checkbox.checked) {
              if (!currentSelectedTools.includes(tid)) currentSelectedTools.push(tid);
            } else {
              currentSelectedTools = currentSelectedTools.filter((t) => t !== tid);
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
          "Failed to load tools";
        if (toolManual) toolManual.classList.remove("hidden");
      }
    }

    function updateHeader() {
      const span = multiSelectHeader.querySelector(".placeholder");
      if (currentSelectedTools.length === 0) {
        span.textContent = "Select tools... (0)";
        span.style.color = "var(--text-secondary)";
      } else {
        span.textContent = `${currentSelectedTools.length} selected: ${currentSelectedTools
          .slice(0, 2)
          .join(", ")}${currentSelectedTools.length > 2 ? "..." : ""}`;
        span.style.color = "#fff";
      }
    }

    multiSelectHeader.addEventListener("click", () => {
      multiSelectList.classList.toggle("show");
    });

    agentSelect.addEventListener("change", (e) => {
      populateToolsMulti(e.target.value);
    });

    if (rule && rule.target_agent) {
      agentSelect.value = rule.target_agent;
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

  if (rule) {
    const descriptionInput = form.querySelector('[name="description"]');
    if (descriptionInput) descriptionInput.value = rule.description || "";

    const enabledCb = form.querySelector('[name="enabled"]');
    if (enabledCb) enabledCb.checked = rule.enabled;
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());
    if (data.ruleset_id) {
      data.ruleset_id = data.ruleset_id.trim();
    } else if (!rule) {
      data.ruleset_id = generateNextRuleId();
    }

    const trimmedName = (data.name || "").trim();
    data.name = trimmedName || data.ruleset_id;

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
      data.tool_names = currentSelectedTools;
      data.tool_name = currentSelectedTools.join(",");

      if (!data.target_agent || !currentSelectedTools.length) {
        alert("대상 에이전트와 최소 1개 Tool을 선택해주세요.");
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
        if (data.target_agent) {
          await refreshAgentPolicy(data.target_agent, data.tenant_id);
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
