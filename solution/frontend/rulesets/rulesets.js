// rulesets.js - API 연동 (모달 UI 유지)

const API_BASE = window.location.origin;
let verifiedToken = null;
let pendingAction = null;

async function fetchJson(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: {
      ...(options.headers || {}),
      ...(verifiedToken ? { Authorization: verifiedToken } : {}),
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

function requireAdminToken(nextAction) {
  if (verifiedToken) {
    if (typeof nextAction === "function") nextAction();
    return;
  }
  pendingAction = nextAction;
  openTokenModal();
}

function openTokenModal() {
  const modal = document.getElementById("token-modal");
  if (!modal) {
    // Fallback: simple prompt when modal markup is unavailable
    const raw = window.prompt("관리자 JWT를 입력하세요 (Bearer ...)", "");
    if (raw) verifyAdminToken(raw);
    return;
  }
  openModal("token-modal");
  const input = modal.querySelector("#token-input");
  const status = modal.querySelector("#token-status");
  if (status) {
    status.textContent = "";
    status.classList.remove("error");
  }
  if (input) {
    input.value = "";
    input.focus();
    if (typeof input.select === "function") input.select();
  }
}

function closeTokenModal() {
  closeModal("token-modal");
}

async function verifyAdminToken(rawToken) {
  const modal = document.getElementById("token-modal");
  const status = modal?.querySelector("#token-status");
  const tokenValue = rawToken.toLowerCase().startsWith("bearer ")
    ? rawToken
    : `Bearer ${rawToken}`;

  try {
    const res = await fetch(`${API_BASE}/api/verify-admin`, {
      method: "GET",
      headers: { Authorization: tokenValue },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "관리자 토큰이 유효하지 않습니다.");
    }
    verifiedToken = tokenValue;
    closeTokenModal();
    if (typeof pendingAction === "function") {
      const action = pendingAction;
      pendingAction = null;
      action();
    }
  } catch (error) {
    if (status) {
      status.textContent = error.message || "토큰 인증에 실패했습니다.";
      status.classList.add("error");
    } else {
      alert(error.message || "토큰 인증에 실패했습니다.");
    }
  }
}

// --- Initialization ---
window.addEventListener("DOMContentLoaded", async () => {
  try {
    initModalEvents();
    initTokenModal();
    initGroupActions();
    await refreshAll();
  } catch (error) {
    console.error("Initialization failed:", error);
  }
});

async function refreshAll() {
  try {
    allRulesets = await fetchJson(`${API_BASE}/api/rulesets`);
    allGroups = await fetchJson(`${API_BASE}/api/rulesets/groups`);
    // Ensure tenant_id is present for newly created groups even if API omits it
    allGroups = (allGroups || []).map((g) => ({
      ...g,
      tenant_id: g.tenant_id || g.tenant || g.tenantId || "",
    }));
    allUsers = await fetchJson(`${API_BASE}/api/rulesets/users`);
    allTenants = await fetchJson(`${API_BASE}/api/rulesets/tenants`).catch(
      () => []
    );
    try {
      allAgents = await fetchJson(`${API_BASE}/api/agents`);
    } catch (err) {
      console.warn("Failed to load agents", err);
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

function initTokenModal() {
  const modal = document.getElementById("token-modal");
  const closeBtn = document.getElementById("token-modal-close");
  const cancelBtn = document.getElementById("token-form-cancel");
  const form = document.getElementById("token-form");

  closeBtn?.addEventListener("click", () => closeTokenModal());
  cancelBtn?.addEventListener("click", () => closeTokenModal());
  modal?.addEventListener("click", (e) => {
    if (e.target === modal) closeTokenModal();
  });
  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const input = form.querySelector("#token-input");
    const status = form.querySelector("#token-status");
    if (!input || !input.value.trim()) {
      if (status) {
        status.textContent = "토큰을 입력해주세요.";
        status.classList.add("error");
      }
      return;
    }
    if (status) {
      status.textContent = "토큰 검증 중...";
      status.classList.remove("error");
    }
    await verifyAdminToken(input.value.trim());
  });
}

function initGroupActions() {
  const btnAddGroup = document.getElementById("btn-add-group");
  if (btnAddGroup)
    btnAddGroup.addEventListener("click", () =>
      requireAdminToken(() => openGroupModal())
    );

  const btnCancelGroup = document.getElementById("btn-cancel-group");
  btnCancelGroup?.addEventListener("click", () => closeModal("group-modal"));

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
      if (!verifiedToken) {
        requireAdminToken(() => btnDeleteGroup.click());
        return;
      }
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
        console.error(err);
        alert(`그룹 삭제에 실패했습니다: ${err.message}`);
      }
    });
  }

  const btnAddMember = document.getElementById("btn-add-member");
  if (btnAddMember) btnAddMember.addEventListener("click", () => openMemberModal());

  const searchInput = document.getElementById("user-search-input");
  if (searchInput) {
    searchInput.addEventListener("input", (e) => renderUserList(e.target.value));
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
        if (!group || !group.tenant_id) {
          alert("그룹의 tenant 정보가 없습니다.");
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
          console.error(err);
          alert(`멤버 추가에 실패했습니다: ${err.message}`);
        }
      }
    });
  }

  const groupForm = document.getElementById("group-form");
  if (groupForm) {
    groupForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!verifiedToken) {
        requireAdminToken(() => groupForm.requestSubmit());
        return;
      }
      const groupId = document.getElementById("group-edit-id").value.trim();
      const name = document.getElementById("group-name").value.trim();
      const description = document.getElementById("group-desc").value.trim();

      if (!name) {
        alert("그룹 이름을 입력하세요.");
        return;
      }

      if (groupId) {
        // update
        const group = allGroups.find((g) => g.id === groupId);
        if (!group || !group.tenant_id) {
          alert("그룹 또는 테넌트 정보를 찾을 수 없습니다.");
          return;
        }
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
          console.error(err);
          alert("그룹 수정에 실패했습니다.");
        }
        return;
      }

      const tenantId = slugify(name);
      if (!tenantId) {
        alert("그룹 이름에서 유효한 ID를 만들 수 없습니다.");
        return;
      }
      const newId = slugify(name) || `g_${Date.now().toString(36)}`;
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
        console.error(err);
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

  // Members Table
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

  // Group Rules Table
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
      if (!desc && r.target_agent && r.tool_name) {
        const action = r.rules?.action === "deny" ? "차단" : "검증";
        desc = `${r.target_agent}의 ${r.tool_name} 사용 ${action}`;
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
          console.error(err);
          alert("상태 변경에 실패했습니다.");
        }
      };
      statusCell.appendChild(btn);

      row
        .querySelector('[data-action="edit"]')
        .addEventListener("click", () =>
          openRulesetForm(r, {
            scope: "group",
            groupId,
            tenantId: r.tenant_id,
          })
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
              console.error(err);
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

    const isSelected = selectedUsersForAdd.includes(user.email);
    if (isSelected) tr.classList.add("selected");

    tr.innerHTML = `
      <td style="text-align: center;">
        <div class="radio-indicator"></div>
      </td>
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

// --- Unified Form Logic ---
function openRulesetForm(rule = null, context = {}) {
  const body = document.getElementById("ruleset-modal-body");
  const template = document.getElementById("ruleset-form-template");
  if (!body || !template) return;

  body.innerHTML = "";
  const node = template.content.cloneNode(true);
  const form = node.querySelector("form");
  const { scope, groupId, tenantId } = context;
  const groupMeta = allGroups.find((g) => g.id === groupId);

  applyAutoGeneratedName(form, rule);
  form.querySelector("#ruleset-group-id").value = groupId || "";
  const tenantInput = form.querySelector("#ruleset-tenant-id");
  if (tenantInput) {
    tenantInput.value =
      tenantId || rule?.tenant_id || groupMeta?.tenant_id || "";
  }

  // Group scope
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
    const toolSelect = form.querySelector("#target-tool-select");
    const toolManual = form.querySelector("#ruleset-tool-name");

    agentSelect.innerHTML = '<option value="">에이전트 선택...</option>';
    allAgents.forEach((a) => {
      const opt = document.createElement("option");
      opt.value = a.agent_id || a.id;
      opt.textContent = a.name || a.agent_id || a.id;
      agentSelect.appendChild(opt);
    });

    async function populateTools(aid) {
      toolSelect.innerHTML = '<option value="">툴 선택...</option>';
      toolSelect.disabled = true;
      if (toolManual) toolManual.value = "";

      if (!aid) return;
      try {
        const resp = await fetchJson(
          `${API_BASE}/api/rulesets/agents/${encodeURIComponent(aid)}/tools`
        );
        const tools = Array.isArray(resp.tools) ? resp.tools : [];
        if (tools.length === 0) {
          toolSelect.innerHTML =
            '<option value="">등록된 Tool이 없습니다</option>';
          toolSelect.disabled = true;
          if (toolManual) toolManual.classList.remove("hidden");
          return;
        }
        toolSelect.innerHTML = '<option value="">Tool 선택...</option>';
        tools.forEach((tid) => {
          const opt = document.createElement("option");
          opt.value = tid;
          opt.textContent = tid;
          toolSelect.appendChild(opt);
        });
        toolSelect.disabled = false;
        if (toolManual) toolManual.classList.add("hidden");
      } catch (err) {
        console.warn("tool list fetch failed", err);
        toolSelect.innerHTML =
          '<option value="">툴 목록을 불러오지 못했습니다</option>';
        toolSelect.disabled = true;
        if (toolManual) toolManual.classList.remove("hidden");
      }
    }

    agentSelect.addEventListener("change", (e) => {
      populateTools(e.target.value);
    });

    // Populate for edit
    if (rule && rule.target_agent) {
      agentSelect.value = rule.target_agent;
      populateTools(rule.target_agent).then(() => {
        if (rule.tool_name) {
          toolSelect.value = rule.tool_name;
          if (!toolSelect.value && toolManual) {
            toolManual.value = rule.tool_name;
            toolManual.classList.remove("hidden");
          }
        }
      });
    }

    const typeInput = form.querySelector('[name="type"]');
    if (typeInput) typeInput.value = "tool_validation";
  }

  // Fill Basic Info
  if (rule) {
    const descriptionInput = form.querySelector('[name="description"]');
    if (descriptionInput) descriptionInput.value = rule.description || "";

    const enabledCb = form.querySelector('[name="enabled"]');
    if (enabledCb) enabledCb.checked = rule.enabled;
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    applyAutoGeneratedName(form, rule);
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
      data.tool_name =
        form.querySelector("#target-tool-select").value ||
        form.querySelector("#ruleset-tool-name")?.value ||
        "";

      if (!data.target_agent || !data.tool_name) {
        alert("대상 에이전트와 Tool을 선택하거나 입력해주세요.");
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
      console.error(err);
      alert("정책 저장에 실패했습니다.");
    }
  });

  body.appendChild(node);

  const cancelBtn = body.querySelector("#btn-cancel-ruleset");
  if (cancelBtn) {
    cancelBtn.addEventListener("click", () => closeModal("ruleset-modal"));
  }

  openModal("ruleset-modal");
}

// --- Utils ---
function removeMember(groupId, email, tenantId) {
  if (!confirm("이 멤버를 그룹에서 제거하시겠습니까?")) return;
  if (!tenantId) {
    alert("그룹의 tenant 정보가 없습니다.");
    return;
  }
  const remaining = (allGroups.find((g) => g.id === groupId)?.members || [])
    .map((m) => (typeof m === "string" ? m : m.email))
    .filter((addr) => addr !== email);

  fetchJson(
    `${API_BASE}/api/rulesets/groups/${tenantId}/${groupId}/members`,
    {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ members: remaining }),
    }
  )
    .then(() => refreshAll())
    .catch((err) => {
      console.error(err);
      alert("멤버 삭제에 실패했습니다.");
    });
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
function getTypeLabel(t) {
  const m = {
    prompt_validation: "프롬프트 검증",
    tool_validation: "Tool 제어",
    response_filtering: "응답 필터링",
  };
  return m[t] || t;
}

function slugify(name) {
  return name
    .toLowerCase()
    .replace(/[^\w\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-");
}

function applyAutoGeneratedName(form, rule) {
  const nameInput = form.querySelector("#ruleset-name");
  const idInput = form.querySelector("#ruleset-id");
  const displayInput = form.querySelector("#ruleset-name-display");

  const baseName =
    (rule?.name || rule?.ruleset_id || "").trim() ||
    generateNextRulesetName();
  const rulesetId = (rule?.ruleset_id || "").trim() || baseName;

  if (displayInput) displayInput.value = baseName;
  if (nameInput) nameInput.value = baseName;
  if (idInput) idInput.value = rulesetId;
}

function generateNextRulesetName() {
  const prefix = "rule-";
  const usedNumbers = new Set();

  allRulesets.forEach((r) => {
    const label = String(r?.name || r?.ruleset_id || "").toLowerCase();
    const match = label.match(/^rule-(\d+)$/);
    if (match) usedNumbers.add(Number(match[1]));
  });

  let candidate = 1;
  while (usedNumbers.has(candidate)) candidate += 1;
  return `${prefix}${candidate}`;
}
