import { createThreatGlobe } from "/static/screen-earth.js?v=20260328screen10";

const SCREEN_RULE_LABELS = {
  manual_block: "手动封禁",
  sql_injection: "SQL 注入",
  xss: "跨站脚本",
  path_traversal: "目录穿越",
  command_injection: "命令执行",
  scanner_probe: "扫描探测",
  brute_force: "暴力破解",
  webshell_upload: "WebShell 上传",
  cve_exploit_attempt: "CVE 利用",
};

const SCREEN_SEVERITY_COLORS = {
  critical: "#fb7185",
  high: "#f97316",
  medium: "#fbbf24",
  low: "#38bdf8",
};

function screenFetchJson(url, options = {}) {
  return fetch(url, {
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  }).then(async (response) => {
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
  });
}

function screenFormatCount(value) {
  return Number(value || 0).toLocaleString("zh-CN");
}

function screenFormatDateTime(value) {
  if (!value) {
    return "-";
  }
  return new Date(value).toLocaleString("zh-CN", { hour12: false });
}

function screenRuleLabel(value) {
  return SCREEN_RULE_LABELS[value] || value || "-";
}

function setNodeText(id, value) {
  const node = document.getElementById(id);
  if (node) {
    node.textContent = value;
  }
}

function createEmptyState(text) {
  const node = document.createElement("div");
  node.className = "empty-state";
  node.textContent = text;
  return node;
}

function renderSimpleRankList(containerId, items, options = {}) {
  const container = document.getElementById(containerId);
  if (!container) {
    return;
  }

  container.innerHTML = "";
  if (!items || !items.length) {
    container.appendChild(createEmptyState(options.emptyText || "暂无数据"));
    return;
  }

  const maxCount = Math.max(...items.map((item) => Number(item.count || 0)), 1);
  items.forEach((item, index) => {
    const row = document.createElement("article");
    row.className = "threat-rank-item";
    const label = options.labelFormatter ? options.labelFormatter(item) : item.name || item.ip || "-";
    const sub = options.subFormatter ? options.subFormatter(item) : "";
    const value = screenFormatCount(item.count || 0);
    const width = Math.max(10, Math.round((Number(item.count || 0) / maxCount) * 100));
    row.innerHTML = `
      <div class="threat-rank-item__top">
        <div>
          <div class="threat-rank-item__label">${String(index + 1).padStart(2, "0")} · ${label}</div>
          <div class="threat-rank-item__sub">${sub}</div>
        </div>
        <div class="threat-rank-item__count">${value}</div>
      </div>
      <div class="threat-rank-item__bar"><span style="width:${width}%"></span></div>
    `;
    container.appendChild(row);
  });
}

function renderSeverity(screenData) {
  const donut = document.getElementById("screen-severity-donut");
  const legend = document.getElementById("screen-severity-legend");
  if (!donut || !legend) {
    return;
  }

  const items = (screenData.severity_distribution || []).map((item) => ({
    ...item,
    key:
      item.name === "危急"
        ? "critical"
        : item.name === "高危"
          ? "high"
          : item.name === "中危"
            ? "medium"
            : "low",
  }));

  const total = items.reduce((sum, item) => sum + Number(item.count || 0), 0);
  setNodeText("screen-severity-total", screenFormatCount(total));

  let angle = 0;
  const segments = items.map((item) => {
    const ratio = total ? Number(item.count || 0) / total : 0;
    const nextAngle = angle + ratio * 360;
    const result = `${SCREEN_SEVERITY_COLORS[item.key]} ${angle.toFixed(2)}deg ${nextAngle.toFixed(2)}deg`;
    angle = nextAngle;
    return result;
  });
  donut.style.background = segments.length
    ? `conic-gradient(${segments.join(", ")})`
    : "conic-gradient(#38bdf8 0deg 360deg)";

  legend.innerHTML = "";
  items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "threat-severity__item";
    row.innerHTML = `
      <div class="threat-severity__name">
        <i class="threat-severity__swatch threat-severity__swatch--${item.key}"></i>
        <span>${item.name}</span>
      </div>
      <strong>${screenFormatCount(item.count || 0)}</strong>
    `;
    legend.appendChild(row);
  });
}

function renderRecentAlerts(items) {
  const container = document.getElementById("screen-recent-alerts");
  if (!container) {
    return;
  }

  container.innerHTML = "";
  if (!items || !items.length) {
    container.appendChild(createEmptyState("最近暂无重点告警"));
    return;
  }

  items.forEach((item) => {
    const severity = item.severity === "high" ? "high" : "medium";
    const card = document.createElement("article");
    card.className = `threat-alert-item ${severity === "medium" ? "threat-alert-item--medium" : ""}`;
    card.innerHTML = `
      <div class="threat-alert-item__top">
        <div class="threat-alert-item__title">${item.cve_id || screenRuleLabel(item.attack_type)}</div>
        <span class="threat-alert-item__tag">${severity === "high" ? "高危" : "重点关注"}</span>
      </div>
      <div class="threat-alert-item__path">${item.path || "/"}</div>
      <div class="threat-alert-item__meta">${item.client_ip} · ${item.location || "未知位置"} · ${screenFormatDateTime(item.created_at)}</div>
    `;
    container.appendChild(card);
  });
}

function buildSvgPath(values, width, height, padding, maxValue) {
  const innerWidth = width - padding.left - padding.right;
  const innerHeight = height - padding.top - padding.bottom;
  return values
    .map((value, index) => {
      const x = padding.left + (innerWidth * index) / Math.max(values.length - 1, 1);
      const y = padding.top + innerHeight - (innerHeight * value) / maxValue;
      return `${index === 0 ? "M" : "L"} ${x.toFixed(2)} ${y.toFixed(2)}`;
    })
    .join(" ");
}

function renderTrendChart(items) {
  const chart = document.getElementById("screen-trend-chart");
  if (!chart) {
    return;
  }

  const width = 960;
  const height = 240;
  const padding = { top: 18, right: 24, bottom: 30, left: 24 };
  chart.innerHTML = "";

  if (!items || !items.length) {
    return;
  }

  const totals = items.map((item) => Number(item.total || 0));
  const blocked = items.map((item) => Number(item.blocked || 0));
  const high = items.map((item) => Number(item.high || 0));
  const maxValue = Math.max(...totals, ...blocked, ...high, 1);
  const innerHeight = height - padding.top - padding.bottom;

  for (let step = 0; step < 5; step += 1) {
    const y = padding.top + (innerHeight * step) / 4;
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", String(padding.left));
    line.setAttribute("x2", String(width - padding.right));
    line.setAttribute("y1", String(y));
    line.setAttribute("y2", String(y));
    line.setAttribute("stroke", "rgba(148, 163, 184, 0.14)");
    line.setAttribute("stroke-width", "1");
    chart.appendChild(line);
  }

  const defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
  defs.innerHTML = `
    <linearGradient id="screenGradientTotal" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.62"></stop>
      <stop offset="100%" stop-color="#38bdf8" stop-opacity="0.02"></stop>
    </linearGradient>
  `;
  chart.appendChild(defs);

  const totalPath = buildSvgPath(totals, width, height, padding, maxValue);
  const blockedPath = buildSvgPath(blocked, width, height, padding, maxValue);
  const highPath = buildSvgPath(high, width, height, padding, maxValue);
  const areaPath = `${totalPath} L ${width - padding.right} ${height - padding.bottom} L ${padding.left} ${height - padding.bottom} Z`;

  const area = document.createElementNS("http://www.w3.org/2000/svg", "path");
  area.setAttribute("d", areaPath);
  area.setAttribute("fill", "url(#screenGradientTotal)");
  chart.appendChild(area);

  [
    { d: totalPath, stroke: "#38bdf8", width: 3 },
    { d: blockedPath, stroke: "#f59e0b", width: 2.4 },
    { d: highPath, stroke: "#fb7185", width: 2.2 },
  ].forEach((item) => {
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", item.d);
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", item.stroke);
    path.setAttribute("stroke-width", String(item.width));
    path.setAttribute("stroke-linejoin", "round");
    path.setAttribute("stroke-linecap", "round");
    chart.appendChild(path);
  });

  items.forEach((item, index) => {
    if (index % 3 !== 0 && index !== items.length - 1) {
      return;
    }
    const x = padding.left + ((width - padding.left - padding.right) * index) / Math.max(items.length - 1, 1);
    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.setAttribute("x", String(x));
    text.setAttribute("y", String(height - 8));
    text.setAttribute("fill", "rgba(191, 219, 254, 0.72)");
    text.setAttribute("font-size", "11");
    text.setAttribute("text-anchor", "middle");
    text.textContent = item.label || "--";
    chart.appendChild(text);
  });

  const yAxisValue = document.createElementNS("http://www.w3.org/2000/svg", "text");
  yAxisValue.setAttribute("x", String(width - padding.right));
  yAxisValue.setAttribute("y", String(padding.top + 4));
  yAxisValue.setAttribute("fill", "rgba(191, 219, 254, 0.72)");
  yAxisValue.setAttribute("font-size", "11");
  yAxisValue.setAttribute("text-anchor", "end");
  yAxisValue.textContent = `峰值 ${screenFormatCount(maxValue)}`;
  chart.appendChild(yAxisValue);
}

function renderScreenData(payload) {
  const overview = payload.overview || {};

  setNodeText("screen-total-alerts", screenFormatCount(overview.total_alerts || 0));
  setNodeText("screen-total-ips", screenFormatCount(overview.unique_ips || 0));
  setNodeText("screen-blocked-requests", screenFormatCount(overview.blocked_requests || 0));
  setNodeText("screen-high-risk", screenFormatCount(overview.high_risk_alerts || 0));
  setNodeText("screen-blocked-ips", screenFormatCount(overview.blocked_ip_count || 0));
  setNodeText("screen-target-name", payload.target?.name || "防护主站");
  setNodeText("screen-target-label", payload.target?.label || "中国 · 业务区");

  renderSimpleRankList("screen-victim-top5", payload.victim_targets_top5 || [], {
    emptyText: "最近暂无受害入口数据",
  });
  renderSimpleRankList("screen-attack-ip-top5", payload.attack_ip_top5 || [], {
    emptyText: "最近暂无攻击 IP",
    labelFormatter: (item) => item.ip,
    subFormatter: (item) => item.label || item.geo_label || "未知位置",
  });
  renderSimpleRankList("screen-type-top5", payload.top_attack_types || [], {
    emptyText: "最近暂无攻击类型数据",
    labelFormatter: (item) => screenRuleLabel(item.name),
  });
  renderSimpleRankList("screen-origin-top5", payload.attack_source_top5 || [], {
    emptyText: "最近暂无来源地区数据",
  });

  renderSeverity(payload);
  renderRecentAlerts(payload.recent_alerts || []);
  renderTrendChart(payload.timeline_24h || []);
}

function setupClock() {
  const refreshNode = document.querySelector(".threat-screen__runtime");

  const update = () => {
    const now = new Date();
    const week = "日一二三四五六";
    const dateText = `${now.getFullYear()}/${String(now.getMonth() + 1).padStart(2, "0")}/${String(now.getDate()).padStart(2, "0")} 星期${week[now.getDay()]}`;
    const timeText = now.toLocaleTimeString("zh-CN", { hour12: false });
    setNodeText("screen-date", dateText);
    setNodeText("screen-time", timeText);
    if (refreshNode) {
      refreshNode.textContent = `最近更新 ${timeText}`;
    }
  };

  update();
  window.setInterval(update, 1000);
}

function setupLogout() {
  const button = document.getElementById("logout-button");
  if (!button) {
    return;
  }

  button.addEventListener("click", async () => {
    await screenFetchJson("/api/logout", { method: "POST" });
    window.location.href = "/login";
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  if (document.body.dataset.page !== "screen-v3") {
    return;
  }

  setupClock();
  setupLogout();
  try {
    const globe = await createThreatGlobe(
      document.getElementById("threat-globe-stage"),
      document.getElementById("threat-globe-labels")
    );

    const refresh = async () => {
      const payload = await screenFetchJson("/api/screen");
      renderScreenData(payload);
      globe.setData(payload);
    };

    refresh().catch((error) => {
      window.alert(`加载态势大屏失败：${error.message}`);
    });

    window.setInterval(() => {
      refresh().catch(() => {});
    }, 15000);
  } catch (error) {
    window.alert(`3D 地球初始化失败：${error.message || error}`);
  }
});
