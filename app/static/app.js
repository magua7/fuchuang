async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    credentials: "same-origin",
    ...options,
  });

  let payload = null;
  try {
    payload = await response.json();
  } catch (error) {
    payload = null;
  }

  if (!response.ok) {
    throw new Error((payload && (payload.message || payload.detail)) || "请求失败");
  }

  return payload;
}

function setText(id, value) {
  const node = document.getElementById(id);
  if (node) {
    node.textContent = value;
  }
}

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatTime(value) {
  if (!value) {
    return "-";
  }
  return new Date(value).toLocaleString("zh-CN", { hour12: false });
}

function formatCount(value) {
  return Number(value || 0).toLocaleString("zh-CN");
}

function isScreenPage() {
  return document.body.dataset.page === "screen";
}

const ACTION_LABELS = {
  allowed: "放行",
  blocked: "拦截",
  error: "错误",
};

const RULE_LABELS = {
  manual_block: "手动封禁",
  sql_injection: "SQL 注入",
  xss: "跨站脚本",
  path_traversal: "目录穿越",
  command_injection: "命令注入",
  scanner_probe: "扫描探测",
  brute_force: "暴力破解",
  webshell_upload: "WebShell 上传",
  cve_exploit_attempt: "CVE 漏洞利用",
};

const SEVERITY_LABELS = {
  high: "高危",
  medium: "中危",
  low: "低危",
};

const ALERT_STATUS_LABELS = {
  real_attack: "真实攻击行为",
  customer_business: "客户业务行为",
  pending_business: "待确认业务行为",
  notified_event: "已通报事件告警",
  pending: "待确认业务行为",
  resolved: "已通报事件告警",
  resolved_event: "已通报事件告警",
  not_applicable: "未分类流量",
};

const ALERT_STATUS_KEYS = [
  "real_attack",
  "customer_business",
  "pending_business",
  "notified_event",
];

const HANDLED_STATUS_LABELS = {
  handled: "已处理流量",
  unhandled: "未处理流量",
  not_applicable: "未处理流量",
};

const SCREEN_REGION_IDS = {
  华北: "screen-region-huabei",
  华东: "screen-region-huadong",
  华南: "screen-region-huanan",
  华中: "screen-region-huazhong",
  西部: "screen-region-xibu",
  东北: "screen-region-dongbei",
  本地: "screen-region-bendi",
  海外: "screen-region-haiwai",
  未知: "screen-region-haiwai",
};

const LOGS_PAGE_SIZE = 20;
const BLOCKED_IPS_PAGE_SIZE = 20;
let currentLogsPage = 1;
let currentBlockedIpsPage = 1;
let currentAlertView = "all";
let currentHandledView = "all";
let currentLogsScope = "all";
const selectedLogEntries = new Map();

function actionLabel(value) {
  return ACTION_LABELS[value] || value || "-";
}

function ruleLabel(value) {
  return RULE_LABELS[value] || value || "-";
}

function severityLabel(value) {
  return SEVERITY_LABELS[value] || value || "-";
}

function normalizeAlertStatus(value) {
  if (value === "pending") {
    return "pending_business";
  }
  if (value === "resolved" || value === "resolved_event") {
    return "notified_event";
  }
  return value || "not_applicable";
}

function alertStatusLabel(value) {
  const normalized = normalizeAlertStatus(value);
  return ALERT_STATUS_LABELS[normalized] || normalized || "-";
}

function handledStatusLabel(value) {
  return HANDLED_STATUS_LABELS[value] || value || "-";
}

function formatHeaders(headers) {
  if (!headers || typeof headers !== "object" || !Object.keys(headers).length) {
    return "无请求头记录";
  }
  return Object.entries(headers)
    .map(([key, value]) => `${key}: ${value}`)
    .join("\n");
}

function buildAnalysisNarrative(overview) {
  const total = Number(overview.total_requests || 0);
  const blocked = Number(overview.blocked_requests || 0);
  const uniqueIps = Number(overview.unique_ips || 0);
  const topAttackList = Array.isArray(overview.top_attack_types) ? overview.top_attack_types : [];
  const topAttack = topAttackList[0] && topAttackList[0].name
    ? ruleLabel(topAttackList[0].name)
    : "暂无明显攻击";
  const topAttackCount = Number((topAttackList[0] && topAttackList[0].count) || 0);

  if (blocked > 0) {
    return {
      headline: `近 24 小时累计拦截 ${formatCount(blocked)} 次异常请求`,
      copy: `当前总请求 ${formatCount(total)} 次，独立来源 IP ${formatCount(uniqueIps)} 个。最活跃的攻击类型为 ${topAttack}，共命中 ${formatCount(topAttackCount)} 次。`,
    };
  }

  if (total > 0) {
    return {
      headline: `近 24 小时已处理 ${formatCount(total)} 次访问流量`,
      copy: `当前暂无明确拦截峰值，但已记录 ${formatCount(uniqueIps)} 个来源 IP。建议继续观察登录接口、参数访问和上传入口。`,
    };
  }

  return {
    headline: "当前整体态势稳定",
    copy: "尚未采集到足够流量数据，可以先访问被保护站点或模拟攻击来生成展示样本。",
  };
}

function fillCommonMetrics(overview, options = {}) {
  const prefix = options.prefix || "";
  setText(`${prefix}metric-total`, formatCount(overview.total_requests || 0));
  setText(`${prefix}metric-blocked`, formatCount(overview.blocked_requests || 0));
  setText(`${prefix}metric-ips`, formatCount(overview.unique_ips || 0));
  setText(`${prefix}metric-alert-high`, formatCount(overview.high_risk_alerts || 0));

  if (!prefix) {
    setText("metric-manual-blocks", formatCount(overview.blocked_ip_count || 0));
    setText("metric-alert-total", formatCount(overview.total_alerts || 0));
    setText("metric-alert-unhandled", formatCount(overview.unhandled_alerts || 0));
    setText("metric-alert-handled", formatCount(overview.handled_alerts || 0));
    setText("metric-alert-pending", formatCount(overview.pending_alerts || 0));
    setText("metric-alert-resolved", formatCount(overview.resolved_alerts || 0));
    setText("metric-bruteforce", formatCount(overview.brute_force_events || 0));
    setText("metric-webshell", formatCount(overview.webshell_upload_events || 0));
    setText("metric-cve", formatCount(overview.cve_alert_events || 0));
    setText("map-total", formatCount(overview.total_requests || 0));
    setText("map-rate", `${overview.blocked_rate || 0}%`);
  }

  if (prefix === "screen-") {
    setText("screen-metric-blocked-ips", formatCount(overview.blocked_ip_count || 0));
    setText("screen-metric-alert-pending", formatCount(overview.pending_alerts || 0));
    setText("screen-metric-alert-resolved", formatCount(overview.resolved_alerts || 0));
    setText("screen-metric-bruteforce", formatCount(overview.brute_force_events || 0));
    setText("screen-metric-webshell", formatCount(overview.webshell_upload_events || 0));
    setText("screen-block-rate", `${overview.blocked_rate || 0}%`);

    const total = Number(overview.total_requests || 0);
    const passRate = total ? Math.max(0, 100 - Number(overview.blocked_rate || 0)).toFixed(1) : "0.0";
    setText("screen-pass-rate", `${passRate}%`);
  }
}

function renderRankList(containerId, items, emptyText, options = {}) {
  const container = document.getElementById(containerId);
  if (!container) {
    return;
  }

  if (!items.length) {
    container.innerHTML = `<div class="empty-state">${escapeHtml(emptyText)}</div>`;
    return;
  }

  const itemClass = container.classList.contains("screen-rank-list") ? "screen-rank-item" : "rank-item";
  const valueClass = container.classList.contains("screen-rank-list") ? "screen-count-pill" : "count-pill";
  const labelFormatter = options.labelFormatter || ((item) => item.name);
  const valueFormatter = options.valueFormatter || ((item) => item.count);

  container.innerHTML = items
    .map(
      (item, index) => `
        <div class="${itemClass}">
          <div>
            <span class="rank-order">${String(index + 1).padStart(2, "0")}</span>
            <strong>${escapeHtml(labelFormatter(item))}</strong>
          </div>
          <span class="${valueClass}">${escapeHtml(valueFormatter(item))}</span>
        </div>
      `
    )
    .join("");
}

function renderHighRiskAlerts(items) {
  const container = document.getElementById("high-risk-alerts");
  if (!container) {
    return;
  }

  if (!items.length) {
    container.innerHTML = `<div class="empty-state">最近 24 小时没有高危事件</div>`;
    return;
  }

  container.innerHTML = items
    .map(
      (item) => {
        const alertStatus = normalizeAlertStatus(item.alert_status);
        return `
        <div class="alert-item high">
          <div>
            <strong>${escapeHtml(
              item.cve_id ? `${ruleLabel(item.attack_type)} · ${item.cve_id}` : ruleLabel(item.attack_type)
            )}</strong>
            <div class="muted-text">${escapeHtml(item.client_ip)} · ${escapeHtml(item.path)}</div>
            <div class="muted-text">${escapeHtml(formatTime(item.created_at))}</div>
          </div>
          <span class="status-pill alert ${escapeHtml(alertStatus)}">
            ${escapeHtml(alertStatusLabel(alertStatus))}
          </span>
        </div>
      `;
      }
    )
    .join("");
}

function renderBlockedIps(items) {
  const container = document.getElementById("blocked-ips");
  if (!container) {
    return;
  }

  if (!items.length) {
    container.innerHTML = `<div class="empty-state">当前没有手动封禁的 IP</div>`;
    return;
  }

  container.innerHTML = items
    .map(
      (item) => `
        <div class="blocked-item">
          <div>
            <strong>${escapeHtml(item.ip)}</strong>
            <div class="muted-text">${escapeHtml(item.reason || "手动封禁")}</div>
            <div class="muted-text">${escapeHtml(formatTime(item.created_at))}</div>
          </div>
          <button class="small-button" type="button" data-unblock="${escapeHtml(item.id)}">解封</button>
        </div>
      `
    )
    .join("");

  container.querySelectorAll("button[data-unblock]").forEach((button) => {
    button.addEventListener("click", async () => {
      const id = button.getAttribute("data-unblock");
      await fetchJson(`/api/blocked-ips/${id}`, { method: "DELETE" });
      if (document.body.dataset.page === "block") {
        await refreshBlockPage();
      } else {
        await refreshDashboard();
      }
    });
  });
}

function renderBlockedIpsPagination(payload) {
  const summary = document.getElementById("blocked-pagination-summary");
  const container = document.getElementById("blocked-pagination");
  if (!summary || !container) {
    return;
  }

  const total = Number(payload.total || 0);
  const page = Number(payload.page || 1);
  const pageSize = Number(payload.page_size || BLOCKED_IPS_PAGE_SIZE);
  const totalPages = Number(payload.total_pages || 0);

  if (!total) {
    summary.textContent = "暂无封禁 IP";
    container.innerHTML = "";
    return;
  }

  const start = (page - 1) * pageSize + 1;
  const end = Math.min(total, page * pageSize);
  summary.textContent = `显示第 ${start}-${end} 条，共 ${total} 条，当前第 ${page}/${Math.max(totalPages, 1)} 页`;

  const buttons = [];
  buttons.push(`
    <button class="pagination-button" type="button" data-block-page="${page - 1}" ${page <= 1 ? "disabled" : ""}>
      上一页
    </button>
  `);

  const pageNumbers = [];
  const windowSize = 5;
  const startPage = Math.max(1, page - 2);
  const endPage = Math.min(totalPages, startPage + windowSize - 1);
  const adjustedStart = Math.max(1, endPage - windowSize + 1);
  for (let value = adjustedStart; value <= endPage; value += 1) {
    pageNumbers.push(value);
  }

  pageNumbers.forEach((value) => {
    buttons.push(`
      <button class="pagination-button ${value === page ? "active" : ""}" type="button" data-block-page="${value}">
        ${value}
      </button>
    `);
  });

  buttons.push(`
    <button class="pagination-button" type="button" data-block-page="${page + 1}" ${page >= totalPages ? "disabled" : ""}>
      下一页
    </button>
  `);

  container.innerHTML = buttons.join("");
  container.querySelectorAll("button[data-block-page]").forEach((button) => {
    button.addEventListener("click", async () => {
      const nextPage = Number(button.getAttribute("data-block-page") || "1");
      if (!nextPage || nextPage === currentBlockedIpsPage) {
        return;
      }
      currentBlockedIpsPage = nextPage;
      await refreshBlockPage();
    });
  });
}

function renderLogDispositionControl(logId, alertStatus) {
  const currentStatus = alertStatus === "not_applicable" ? "pending_business" : alertStatus;

  const options = ALERT_STATUS_KEYS
    .map(
      (value) => `
        <option value="${escapeHtml(value)}" ${value === currentStatus ? "selected" : ""}>
          ${escapeHtml(alertStatusLabel(value))}
        </option>
      `
    )
    .join("");

  return `
    <label class="status-select-wrap ${escapeHtml(currentStatus)}">
      <span class="status-select-label">处置分类</span>
      <div class="status-select-inline">
        <select class="status-select ${escapeHtml(currentStatus)}" data-status-select-id="${escapeHtml(logId)}">
          ${options}
        </select>
        <button class="small-button disposition" type="button" data-status-id="${escapeHtml(logId)}">处置</button>
      </div>
    </label>
  `;
}

function getSelectedDisposition(logId) {
  const select = document.querySelector(`select[data-status-select-id="${logId}"]`);
  return select ? select.value : "";
}

function renderHandledStatusBadge(handledStatus) {
  const normalized = handledStatus === "handled" ? "handled" : "unhandled";
  return `<span class="status-pill handled ${escapeHtml(normalized)}">${escapeHtml(handledStatusLabel(normalized))}</span>`;
}

function renderAlertCategoryBadge(alertStatus) {
  const normalized = normalizeAlertStatus(alertStatus);
  return `<span class="status-pill alert ${escapeHtml(normalized)}">${escapeHtml(alertStatusLabel(normalized))}</span>`;
}

function renderLogs(items) {
  const body = document.getElementById("logs-body");
  if (!body) {
    return;
  }

  if (!items.length) {
    body.innerHTML = `<tr><td colspan="13"><div class="empty-state">暂无日志</div></td></tr>`;
    syncLogsSelectionUi([]);
    return;
  }

  body.innerHTML = items
    .map((item) => {
      const reason = item.attack_type
        ? `${ruleLabel(item.attack_type)}${item.cve_id ? ` · ${item.cve_id}` : ""}${item.attack_detail ? ` / ${item.attack_detail}` : ""}`
        : "-";
      const alertStatus = normalizeAlertStatus(item.alert_status);
      const handledStatus = item.handled_status || "not_applicable";
      const severityClass = item.severity || "low";
      const upstreamStatus = item.upstream_status || item.status_code || "-";

      const buttons = [
        `<button class="small-button detail" type="button" data-detail-id="${escapeHtml(item.id)}">详情</button>`,
        `<button class="small-button neutral" type="button" data-ip="${escapeHtml(item.client_ip)}">封禁</button>`,
      ];

      buttons.push(renderLogDispositionControl(item.id, alertStatus));

      return `
        <tr class="${severityClass === "high" ? "log-row-high" : ""} ${alertStatus !== "not_applicable" ? `log-row-${alertStatus}` : ""}">
          <td class="checkbox-column">
            <input
              class="log-select-checkbox"
              type="checkbox"
              data-log-id="${escapeHtml(item.id)}"
              data-ip="${escapeHtml(item.client_ip)}"
              ${selectedLogEntries.has(String(item.id)) ? "checked" : ""}
            />
          </td>
          <td>${escapeHtml(formatTime(item.created_at))}</td>
          <td><code>${escapeHtml(item.client_ip)}</code></td>
          <td>${escapeHtml(item.method)}</td>
          <td><code title="${escapeHtml(item.path)}">${escapeHtml(item.path)}</code></td>
          <td><span class="status-pill ${escapeHtml(item.action || "allowed")}">${escapeHtml(actionLabel(item.action))}</span></td>
          <td><span class="status-pill severity ${escapeHtml(severityClass)}">${escapeHtml(severityLabel(item.severity))}</span></td>
          <td>${renderHandledStatusBadge(handledStatus)}</td>
          <td>${renderAlertCategoryBadge(alertStatus)}</td>
          <td><code title="${escapeHtml(reason)}">${escapeHtml(reason)}</code></td>
          <td>${escapeHtml(upstreamStatus)}</td>
          <td>${escapeHtml(item.duration_ms || 0)} ms</td>
          <td><div class="row-actions">${buttons.join("")}</div></td>
        </tr>
      `;
    })
    .join("");

  body.querySelectorAll("button[data-ip]").forEach((button) => {
    button.addEventListener("click", async () => {
      const ip = button.getAttribute("data-ip");
      const reason = window.prompt(`请输入封禁 ${ip} 的原因`, "手动封禁");
      if (reason === null) {
        return;
      }
      await blockIp(ip, reason || "手动封禁");
    });
  });

  body.querySelectorAll("button[data-detail-id]").forEach((button) => {
    button.addEventListener("click", async () => {
      await openLogDetail(button.getAttribute("data-detail-id"));
    });
  });

  body.querySelectorAll("button[data-status-id]").forEach((button) => {
    button.addEventListener("click", async () => {
      const logId = button.getAttribute("data-status-id");
      const alertStatus = getSelectedDisposition(logId);
      if (!alertStatus) {
        return;
      }
      await updateLogStatus(logId, alertStatus);
    });
  });

  body.querySelectorAll(".log-select-checkbox").forEach((checkbox) => {
    checkbox.addEventListener("change", () => {
      const logId = checkbox.getAttribute("data-log-id");
      const ip = checkbox.getAttribute("data-ip") || "";
      if (!logId) {
        return;
      }
      if (checkbox.checked) {
        selectedLogEntries.set(logId, ip);
      } else {
        selectedLogEntries.delete(logId);
      }
      syncLogsSelectionUi(items);
    });
  });

  syncLogsSelectionUi(items);
}

function syncLogsSelectionUi(items) {
  const selectAll = document.getElementById("logs-select-all");
  const summary = document.getElementById("logs-selected-summary");
  const bulkButton = document.getElementById("bulk-block-button");
  const bulkDispositionButton = document.getElementById("bulk-disposition-button");
  if (!selectAll || !summary || !bulkButton || !bulkDispositionButton) {
    return;
  }

  const pageIds = items.map((item) => String(item.id));
  Array.from(selectedLogEntries.keys()).forEach((id) => {
    if (!pageIds.includes(String(id))) {
      selectedLogEntries.delete(id);
    }
  });
  const selectedCount = pageIds.filter((id) => selectedLogEntries.has(id)).length;
  const uniqueIps = new Set(
    pageIds
      .filter((id) => selectedLogEntries.has(id))
      .map((id) => selectedLogEntries.get(id))
      .filter(Boolean)
  );

  selectAll.checked = items.length > 0 && selectedCount === items.length;
  selectAll.indeterminate = selectedCount > 0 && selectedCount < items.length;
  summary.textContent = `已选 ${selectedCount} 条流量，涉及 ${uniqueIps.size} 个 IP`;
  bulkButton.disabled = uniqueIps.size === 0;
  bulkDispositionButton.disabled = selectedCount === 0;
}

function renderLogsPagination(payload) {
  const summary = document.getElementById("logs-pagination-summary");
  const container = document.getElementById("logs-pagination");
  if (!summary || !container) {
    return;
  }

  const total = Number(payload.total || 0);
  const page = Number(payload.page || 1);
  const pageSize = Number(payload.page_size || LOGS_PAGE_SIZE);
  const totalPages = Number(payload.total_pages || 0);

  if (!total) {
    summary.textContent = "暂无流量日志";
    container.innerHTML = "";
    return;
  }

  const start = (page - 1) * pageSize + 1;
  const end = Math.min(total, page * pageSize);
  summary.textContent = `显示第 ${start}-${end} 条，共 ${total} 条，当前第 ${page}/${Math.max(totalPages, 1)} 页`;

  const pageNumbers = [];
  const windowSize = 5;
  const startPage = Math.max(1, page - 2);
  const endPage = Math.min(totalPages, startPage + windowSize - 1);
  const adjustedStart = Math.max(1, endPage - windowSize + 1);
  for (let value = adjustedStart; value <= endPage; value += 1) {
    pageNumbers.push(value);
  }

  const buttons = [];
  buttons.push(`
    <button class="pagination-button" type="button" data-page="${page - 1}" ${page <= 1 ? "disabled" : ""}>
      上一页
    </button>
  `);

  pageNumbers.forEach((value) => {
    buttons.push(`
      <button class="pagination-button ${value === page ? "active" : ""}" type="button" data-page="${value}">
        ${value}
      </button>
    `);
  });

  buttons.push(`
    <button class="pagination-button" type="button" data-page="${page + 1}" ${page >= totalPages ? "disabled" : ""}>
      下一页
    </button>
  `);

  container.innerHTML = buttons.join("");
  container.querySelectorAll("button[data-page]").forEach((button) => {
    button.addEventListener("click", async () => {
      const nextPage = Number(button.getAttribute("data-page") || "1");
      if (!nextPage || nextPage === currentLogsPage) {
        return;
      }
      selectedLogEntries.clear();
      currentLogsPage = nextPage;
      await refreshLogsPage();
    });
  });
}

function renderAlertViewTabs(overview) {
  setText("alert-view-total", formatCount(overview.total_requests || 0));
  setText("alert-view-real-attack", formatCount(overview.real_attack_alerts || 0));
  setText("alert-view-customer-business", formatCount(overview.customer_business_alerts || 0));
  setText("alert-view-pending-business", formatCount(overview.pending_business_alerts || 0));
  setText("alert-view-notified-event", formatCount(overview.notified_event_alerts || overview.resolved_event_alerts || 0));

  document.querySelectorAll(".alert-view-tab").forEach((button) => {
    const view = button.getAttribute("data-alert-view") || "all";
    button.classList.toggle("active", view === currentAlertView);
  });
}

function renderHandledViewTabs(overview) {
  setText("handled-view-total", formatCount(overview.total_requests || 0));
  setText("handled-view-unhandled", formatCount(overview.unhandled_alerts || 0));
  setText("handled-view-handled", formatCount(overview.handled_alerts || 0));

  document.querySelectorAll(".alert-process-tab").forEach((button) => {
    const view = button.getAttribute("data-handled-view") || "all";
    button.classList.toggle("active", view === currentHandledView);
  });
}

function renderLogScopeTabs(overview) {
  setText("log-scope-total", formatCount(overview.total_requests || 0));
  setText("log-scope-alerts", formatCount(overview.total_alerts || 0));

  document.querySelectorAll(".log-scope-tab").forEach((button) => {
    const view = button.getAttribute("data-log-scope") || "all";
    button.classList.toggle("active", view === currentLogsScope);
  });
}

function applyAlertView(view) {
  currentAlertView = view;

  const statusSelect = document.getElementById("log-alert-status");
  if (statusSelect) {
    statusSelect.value = view === "all" ? "" : view;
  }

  const totalNode = document.getElementById("metric-total");
  const realAttackNode = document.getElementById("alert-view-real-attack");
  const customerBusinessNode = document.getElementById("alert-view-customer-business");
  const pendingBusinessNode = document.getElementById("alert-view-pending-business");
  const notifiedEventNode = document.getElementById("alert-view-notified-event");
  renderAlertViewTabs({
    total_requests: (totalNode && totalNode.textContent) || "0",
    real_attack_alerts: (realAttackNode && realAttackNode.textContent) || "0",
    customer_business_alerts: (customerBusinessNode && customerBusinessNode.textContent) || "0",
    pending_business_alerts: (pendingBusinessNode && pendingBusinessNode.textContent) || "0",
    notified_event_alerts: (notifiedEventNode && notifiedEventNode.textContent) || "0",
  });
}

function applyHandledView(view) {
  currentHandledView = view;

  const totalNode = document.getElementById("metric-total");
  const unhandledNode = document.getElementById("handled-view-unhandled");
  const handledNode = document.getElementById("handled-view-handled");
  renderHandledViewTabs({
    total_requests: (totalNode && totalNode.textContent) || "0",
    unhandled_alerts: (unhandledNode && unhandledNode.textContent) || "0",
    handled_alerts: (handledNode && handledNode.textContent) || "0",
  });
}

function applyLogScope(view) {
  currentLogsScope = view;

  const totalNode = document.getElementById("metric-total");
  const alertNode = document.getElementById("metric-alert-total");
  renderLogScopeTabs({
    total_requests: (totalNode && totalNode.textContent) || "0",
    total_alerts: (alertNode && alertNode.textContent) || "0",
  });
}

async function blockIp(ip, reason) {
  await fetchJson("/api/blocked-ips", {
    method: "POST",
    body: JSON.stringify({ ip, reason }),
  });

  if (document.body.dataset.page === "block") {
    currentBlockedIpsPage = 1;
    await refreshBlockPage();
  } else if (document.body.dataset.page === "dashboard") {
    await refreshDashboard();
  } else if (document.body.dataset.page === "logs") {
    await refreshLogsPage();
  }
}

async function bulkBlockSelectedLogs() {
  const selectedIps = Array.from(new Set(Array.from(selectedLogEntries.values()).filter(Boolean)));
  if (!selectedIps.length) {
    return;
  }

  const reason = window.prompt(
    `将批量封禁 ${selectedIps.length} 个 IP，请输入统一封禁原因`,
    "批量处置异常流量来源"
  );
  if (reason === null) {
    return;
  }

  for (const ip of selectedIps) {
    await fetchJson("/api/blocked-ips", {
      method: "POST",
      body: JSON.stringify({ ip, reason: reason || "批量处置异常流量来源" }),
    });
  }

  selectedLogEntries.clear();
  await refreshLogsPage();
}

async function bulkDispositionSelectedLogs() {
  const logIds = Array.from(selectedLogEntries.keys()).map((value) => Number(value)).filter(Boolean);
  const categorySelect = document.getElementById("bulk-disposition-status");
  const alertStatus = categorySelect ? categorySelect.value : "";
  if (!logIds.length || !alertStatus) {
    return;
  }

  await fetchJson("/api/logs/disposition/bulk", {
    method: "POST",
    body: JSON.stringify({
      log_ids: logIds,
      alert_status: alertStatus,
    }),
  });

  selectedLogEntries.clear();
  await refreshLogsPage();
}

async function updateLogStatus(logId, alertStatus) {
  await fetchJson(`/api/logs/${logId}/status`, {
    method: "PATCH",
    body: JSON.stringify({ alert_status: alertStatus }),
  });
  await refreshLogsPage();
}

async function openLogDetail(logId) {
  const detail = await fetchJson(`/api/logs/${logId}`);

  setText("detail-created-at", formatTime(detail.created_at));
  setText("detail-client-ip", detail.client_ip || "-");
  setText("detail-ip-location", (detail.ip_geo && detail.ip_geo.label) || "未知位置");
  setText("detail-ip-isp", (detail.ip_geo && detail.ip_geo.isp) || "-");
  setText("detail-action", actionLabel(detail.action));
  setText("detail-severity", severityLabel(detail.severity));
  setText("detail-handled-status", handledStatusLabel(detail.handled_status));
  setText("detail-alert-status", alertStatusLabel(detail.alert_status));
  setText("detail-cve", detail.cve_id || "-");
  setText(
    "detail-request-line",
    `${detail.method || "-"} ${detail.path || "/"}${detail.query_string ? `?${detail.query_string}` : ""}`
  );
  setText("detail-query", detail.query_string || "无查询参数");
  setText("detail-headers", formatHeaders(detail.request_headers));
  setText("detail-payload", detail.body_preview || "无 payload 预览");
  setText(
    "detail-rule",
    detail.attack_type
      ? `${ruleLabel(detail.attack_type)}${detail.cve_id ? ` · ${detail.cve_id}` : ""}${detail.attack_detail ? `\n${detail.attack_detail}` : ""}`
      : "无命中规则"
  );

  const backdrop = document.getElementById("log-detail-backdrop");
  if (backdrop) {
    backdrop.removeAttribute("hidden");
  }
  const drawer = document.getElementById("log-detail-drawer");
  if (drawer) {
    drawer.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");
  }
}

function closeLogDetail() {
  const backdrop = document.getElementById("log-detail-backdrop");
  if (backdrop) {
    backdrop.setAttribute("hidden", "hidden");
  }
  const drawer = document.getElementById("log-detail-drawer");
  if (drawer) {
    drawer.classList.remove("open");
    drawer.setAttribute("aria-hidden", "true");
  }
}

function renderScreenRegions(geoBuckets) {
  Object.values(SCREEN_REGION_IDS).forEach((id) => setText(id, "0"));
  (geoBuckets || []).forEach((item) => {
    const targetId = SCREEN_REGION_IDS[item.name];
    if (targetId) {
      setText(targetId, formatCount(item.count || 0));
    }
  });
}

function renderScreenTrend(items) {
  const container = document.getElementById("screen-trend");
  if (!container) {
    return;
  }

  if (!items || !items.length) {
    container.innerHTML = `<div class="empty-state">暂无趋势数据</div>`;
    return;
  }

  const maxTotal = Math.max(...items.map((item) => Number(item.total || 0)), 1);
  const maxBlocked = Math.max(...items.map((item) => Number(item.blocked || 0)), 1);
  const maxHigh = Math.max(...items.map((item) => Number(item.high || 0)), 1);

  container.innerHTML = items
    .map((item) => {
      const totalHeight = Math.max(10, Math.round((Number(item.total || 0) / maxTotal) * 100));
      const blockedHeight = Math.max(8, Math.round((Number(item.blocked || 0) / maxBlocked) * 100));
      const highHeight = Math.max(6, Math.round((Number(item.high || 0) / maxHigh) * 100));
      return `
        <div class="screen-trend-column">
          <div class="screen-trend-stack">
            <span class="screen-trend-bar total" style="height:${totalHeight}%"></span>
            <span class="screen-trend-bar blocked" style="height:${blockedHeight}%"></span>
            <span class="screen-trend-bar high" style="height:${highHeight}%"></span>
          </div>
          <strong>${escapeHtml(item.total || 0)}</strong>
          <span>${escapeHtml(item.label)}</span>
        </div>
      `;
    })
    .join("");
}

function renderScreenAlertFeed(items) {
  const container = document.getElementById("screen-alert-feed");
  if (!container) {
    return;
  }

  if (!items || !items.length) {
    container.innerHTML = `<div class="empty-state">最近暂无需要关注的告警</div>`;
    return;
  }

  container.innerHTML = items
    .map(
      (item) => {
        const alertStatus = normalizeAlertStatus(item.alert_status);
        return `
        <div class="screen-alert-item ${escapeHtml(item.severity || "medium")}">
          <div class="screen-alert-main">
            <div class="screen-alert-topline">
              <strong>${escapeHtml(item.cve_id || ruleLabel(item.attack_type))}</strong>
              <span class="status-pill alert ${escapeHtml(alertStatus)}">
                ${escapeHtml(alertStatusLabel(alertStatus))}
              </span>
            </div>
            <p>${escapeHtml(item.path || "/")}</p>
            <div class="screen-alert-meta">
              <span>${escapeHtml(item.client_ip)}</span>
              <span>${escapeHtml(formatTime(item.created_at))}</span>
            </div>
          </div>
        </div>
      `;
      }
    )
    .join("");
}

function renderScreenCveFeed(items) {
  const container = document.getElementById("screen-cve-feed");
  if (!container) {
    return;
  }

  if (!items || !items.length) {
    container.innerHTML = `<div class="empty-state">最近暂无 CVE 利用告警</div>`;
    return;
  }

  container.innerHTML = items
    .map(
      (item) => `
        <div class="screen-chip">
          <span>${escapeHtml(item.name)}</span>
          <strong>${escapeHtml(item.count)}</strong>
        </div>
      `
    )
    .join("");
}

function renderDashboardSummary(overview) {
  const narrative = buildAnalysisNarrative(overview);
  setText("analysis-headline", narrative.headline);
  setText("analysis-copy", narrative.copy);
}

function renderScreenSummary(overview) {
  const narrative = buildAnalysisNarrative(overview);
  setText("screen-headline", narrative.headline);
  setText("screen-copy", narrative.copy);
}

function buildLogsUrl() {
  const params = new URLSearchParams();
  const actionNode = document.getElementById("log-action");
  const severityNode = document.getElementById("log-severity");
  const alertStatusNode = document.getElementById("log-alert-status");
  const keywordNode = document.getElementById("log-keyword");
  const action = (actionNode && actionNode.value) || "";
  const severity = (severityNode && severityNode.value) || "";
  const alertStatus = (alertStatusNode && alertStatusNode.value) || "";
  const keyword = (keywordNode && keywordNode.value.trim()) || "";
  params.set("page", String(currentLogsPage));
  params.set("page_size", String(LOGS_PAGE_SIZE));

  if (currentHandledView === "handled" || currentHandledView === "unhandled") {
    params.set("handled_status", currentHandledView);
  }

  if (action) {
    params.set("action", action);
  }
  if (severity) {
    params.set("severity", severity);
  }
  if (ALERT_STATUS_KEYS.includes(currentAlertView)) {
    params.set("alert_status", currentAlertView);
  } else if (alertStatus) {
    params.set("alert_status", normalizeAlertStatus(alertStatus));
  }
  if (keyword) {
    params.set("keyword", keyword);
  }

  return `/api/logs?${params.toString()}`;
}

function buildBlockedIpsUrl() {
  const params = new URLSearchParams();
  params.set("page", String(currentBlockedIpsPage));
  params.set("page_size", String(BLOCKED_IPS_PAGE_SIZE));
  return `/api/blocked-ips?${params.toString()}`;
}

async function refreshDashboard() {
  const [runtime, overview] = await Promise.all([
    fetchJson("/api/runtime"),
    fetchJson("/api/overview"),
  ]);

  setText("runtime-user", runtime.username || "admin");
  fillCommonMetrics(overview);
  renderDashboardSummary(overview);
  renderHighRiskAlerts(overview.latest_high_risk_alerts || []);
  renderRankList("attack-types", overview.top_attack_types || [], "最近 24 小时没有拦截记录", {
    labelFormatter: (item) => ruleLabel(item.name),
    valueFormatter: (item) => formatCount(item.count || 0),
  });
  renderRankList("source-ips", overview.top_source_ips || [], "最近 24 小时没有访问记录", {
    valueFormatter: (item) => formatCount(item.count || 0),
  });
  renderRankList("top-paths", overview.top_paths || [], "最近 24 小时没有路径数据", {
    valueFormatter: (item) => formatCount(item.count || 0),
  });
}

async function refreshBlockPage() {
  const [runtime, overview, blockedIps] = await Promise.all([
    fetchJson("/api/runtime"),
    fetchJson("/api/overview"),
    fetchJson(buildBlockedIpsUrl()),
  ]);

  if (blockedIps.total_pages && currentBlockedIpsPage > blockedIps.total_pages) {
    currentBlockedIpsPage = blockedIps.total_pages;
    return refreshBlockPage();
  }

  setText("runtime-user", runtime.username || "admin");
  fillCommonMetrics(overview);
  renderBlockedIps(blockedIps.items || []);
  renderBlockedIpsPagination(blockedIps);
}

async function refreshLogsPage() {
  const [runtime, overview, logs] = await Promise.all([
    fetchJson("/api/runtime"),
    fetchJson("/api/overview"),
    fetchJson(buildLogsUrl()),
  ]);

  if (logs.total_pages && currentLogsPage > logs.total_pages) {
    currentLogsPage = logs.total_pages;
    return refreshLogsPage();
  }

  setText("runtime-user", runtime.username || "admin");
  fillCommonMetrics(overview);
  renderLogScopeTabs(overview);
  renderHandledViewTabs(overview);
  renderAlertViewTabs(overview);
  renderLogs(logs.items || []);
  renderLogsPagination(logs);
}

async function refreshScreenPage() {
  const [runtime, overview] = await Promise.all([
    fetchJson("/api/runtime"),
    fetchJson("/api/overview"),
  ]);

  setText("runtime-user", runtime.username || "admin");
  fillCommonMetrics(overview, { prefix: "screen-" });
  renderScreenSummary(overview);
  renderScreenRegions(overview.geo_buckets || []);
  renderScreenTrend(overview.hourly_trend || []);
  renderScreenAlertFeed(overview.recent_alert_stream || []);
  renderScreenCveFeed(overview.top_cve_ids || []);
  renderRankList("screen-attack-types", overview.top_attack_types || [], "最近暂无攻击类型数据", {
    labelFormatter: (item) => ruleLabel(item.name),
    valueFormatter: (item) => formatCount(item.count || 0),
  });
  renderRankList("screen-source-ips", overview.top_source_ips || [], "最近暂无源 IP 数据", {
    valueFormatter: (item) => formatCount(item.count || 0),
  });
  renderRankList("screen-paths", overview.top_paths || [], "最近暂无路径数据", {
    valueFormatter: (item) => formatCount(item.count || 0),
  });
}

function setupLoginForm() {
  const form = document.getElementById("login-form");
  if (!form) {
    return;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const errorNode = document.getElementById("login-error");
    errorNode.hidden = true;

    const formData = new FormData(form);
    try {
      await fetchJson("/api/login", {
        method: "POST",
        body: JSON.stringify({
          username: formData.get("username"),
          password: formData.get("password"),
        }),
      });
      window.location.href = "/dashboard";
    } catch (error) {
      errorNode.textContent = error.message;
      errorNode.hidden = false;
    }
  });
}

function setupAuthenticatedPage() {
  const logoutButton = document.getElementById("logout-button");
  if (logoutButton) {
    logoutButton.addEventListener("click", async () => {
      await fetchJson("/api/logout", { method: "POST" });
      window.location.href = "/login";
    });
  }
}

function setupDashboard() {
  setupAuthenticatedPage();

  refreshDashboard().catch((error) => {
    window.alert(`加载总览数据失败：${error.message}`);
  });

  window.setInterval(() => {
    refreshDashboard().catch(() => {});
  }, 20000);
}

function setupBlockPage() {
  setupAuthenticatedPage();
  currentBlockedIpsPage = 1;

  const blockForm = document.getElementById("block-form");
  if (blockForm) {
    blockForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const ip = document.getElementById("block-ip").value.trim();
      const reason = document.getElementById("block-reason").value.trim();
      if (!ip) {
        return;
      }
      await blockIp(ip, reason || "手动封禁");
      blockForm.reset();
    });
  }

  refreshBlockPage().catch((error) => {
    window.alert(`加载 IP 封禁数据失败：${error.message}`);
  });

  window.setInterval(() => {
    refreshBlockPage().catch(() => {});
  }, 20000);
}

function setupLogsPage() {
  setupAuthenticatedPage();
  currentLogsPage = 1;
  currentLogsScope = "all";
  currentAlertView = "all";
  currentHandledView = "all";

  document.querySelectorAll(".log-scope-tab").forEach((button) => {
    button.addEventListener("click", async () => {
      const view = button.getAttribute("data-log-scope") || "all";
      if (view === currentLogsScope) {
        return;
      }
      selectedLogEntries.clear();
      currentLogsPage = 1;
      applyLogScope(view);
      await refreshLogsPage();
    });
  });

  const filterForm = document.getElementById("log-filter-form");
  if (filterForm) {
    filterForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      selectedLogEntries.clear();
      currentLogsPage = 1;
      await refreshLogsPage();
    });
  }

  document.querySelectorAll(".alert-view-tab").forEach((button) => {
    button.addEventListener("click", async () => {
      const view = button.getAttribute("data-alert-view") || "all";
      if (view === currentAlertView) {
        return;
      }
      selectedLogEntries.clear();
      currentLogsPage = 1;
      applyAlertView(view);
      await refreshLogsPage();
    });
  });

  document.querySelectorAll(".alert-process-tab").forEach((button) => {
    button.addEventListener("click", async () => {
      const view = button.getAttribute("data-handled-view") || "all";
      if (view === currentHandledView) {
        return;
      }
      selectedLogEntries.clear();
      currentLogsPage = 1;
      applyHandledView(view);
      await refreshLogsPage();
    });
  });

  const statusSelect = document.getElementById("log-alert-status");
  if (statusSelect) {
    statusSelect.addEventListener("change", async () => {
      const value = normalizeAlertStatus(statusSelect.value || "");
      currentAlertView = ALERT_STATUS_KEYS.includes(value) ? value : "all";
      selectedLogEntries.clear();
      currentLogsPage = 1;
      await refreshLogsPage();
    });
  }

  const selectAll = document.getElementById("logs-select-all");
  if (selectAll) {
    selectAll.addEventListener("change", () => {
      document.querySelectorAll(".log-select-checkbox").forEach((checkbox) => {
        const logId = checkbox.getAttribute("data-log-id");
        const ip = checkbox.getAttribute("data-ip") || "";
        checkbox.checked = selectAll.checked;
        if (!logId) {
          return;
        }
        if (selectAll.checked) {
          selectedLogEntries.set(logId, ip);
        } else {
          selectedLogEntries.delete(logId);
        }
      });
      const pageItems = Array.from(document.querySelectorAll(".log-select-checkbox")).map((checkbox) => ({
        id: checkbox.getAttribute("data-log-id") || "",
      }));
      syncLogsSelectionUi(pageItems);
    });
  }

  const bulkBlockButton = document.getElementById("bulk-block-button");
  if (bulkBlockButton) {
    bulkBlockButton.addEventListener("click", async () => {
      await bulkBlockSelectedLogs();
    });
  }

  const bulkDispositionButton = document.getElementById("bulk-disposition-button");
  if (bulkDispositionButton) {
    bulkDispositionButton.addEventListener("click", async () => {
      await bulkDispositionSelectedLogs();
    });
  }

  const detailClose = document.getElementById("log-detail-close");
  if (detailClose) {
    detailClose.addEventListener("click", closeLogDetail);
  }
  const detailBackdrop = document.getElementById("log-detail-backdrop");
  if (detailBackdrop) {
    detailBackdrop.addEventListener("click", closeLogDetail);
  }

  refreshLogsPage().catch((error) => {
    window.alert(`加载日志数据失败：${error.message}`);
  });

  window.setInterval(() => {
    refreshLogsPage().catch(() => {});
  }, 20000);
}

function setupScreenClock() {
  const updateClock = () => {
    const now = new Date();
    const text = now.toLocaleString("zh-CN", { hour12: false });
    setText("screen-time", text);
  };
  updateClock();
  window.setInterval(updateClock, 1000);
}

function setupScreenPage() {
  setupAuthenticatedPage();
  setupScreenClock();

  refreshScreenPage().catch((error) => {
    window.alert(`加载态势大屏失败：${error.message}`);
  });

  window.setInterval(() => {
    refreshScreenPage().catch(() => {});
  }, 15000);
}

document.addEventListener("DOMContentLoaded", () => {
  setupLoginForm();

  if (document.body.dataset.page === "dashboard") {
    setupDashboard();
  }

  if (document.body.dataset.page === "logs") {
    setupLogsPage();
  }

  if (document.body.dataset.page === "block") {
    setupBlockPage();
  }

  if (isScreenPage()) {
    setupScreenPage();
  }
});
