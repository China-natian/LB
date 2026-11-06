// onego 资产管理前端逻辑（纯原生 JS，无构建链）
const state = {
  file: "",
  category: "web",
  filter: "__all__",
  page: 1,
  pageSize: 200,
  filters: [],
  // onego patch: 视图切换与全文搜索
  view: "list",   // list | hosts
  q: "",          // 搜索词（ip: 前缀为 IP 精确匹配）
  // onego patch: 主机视图数据缓存与排序
  // ""=默认顺序 | ip-asc/ip-desc=按 IP | ports-desc/ports-asc=按开放端口数
  hosts: [],
  hostSort: "",
};

const $ = (id) => document.getElementById(id);

// onego patch: 分类 key → 中文名映射（详情面板展示用）
const CAT_NAMES = {
  web: "Web 资产", db: "数据库", remote: "远程管理",
  middleware: "中间件/消息队列", cloud: "云原生/容器",
  win: "Windows 相关", mail: "邮件服务", other: "其他服务",
};

// ===== 工具函数 =====
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

// onego patch: 顶部浮层提示（导出路径/错误等），4 秒自动消失
let toastTimer = null;
function toast(msg) {
  const el = $("toast");
  el.textContent = msg;
  el.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add("hidden"), 4000);
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).error || msg; } catch (_) {}
    throw new Error(msg);
  }
  return res.json();
}

// ===== 文件列表 =====
async function loadFiles() {
  const data = await api("/api/files");
  const sel = $("fileSelect");
  sel.innerHTML = "";
  if (!data.files || data.files.length === 0) {
    sel.innerHTML = '<option value="">（未发现结果文件）</option>';
    $("loadInfo").textContent = "工作目录下没有 .dat / json / csv 结果文件";
    return;
  }
  for (const f of data.files) {
    const opt = document.createElement("option");
    opt.value = f.path || f.name;
    opt.textContent = `${f.name}  (${f.size}, ${f.mod_time})`;
    sel.appendChild(opt);
  }
  if (state.file) sel.value = state.file;
}

// ===== 加载结果 =====
async function loadFile(file) {
  if (!file) return;
  state.file = file;
  $("loadInfo").textContent = "加载中…";
  try {
    const data = await api("/api/load", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ file }),
    });
    $("loadInfo").textContent = `已加载 ${data.count} 条记录 · ${data.file}`;
    state.page = 1;
    state.filter = "__all__";
    // onego patch: 切换文件时重置搜索
    state.q = "";
    $("searchInput").value = "";
    renderSearchChip();
    renderCards();
    renderTabs();
    renderFilters();
    renderView();
  } catch (e) {
    $("loadInfo").textContent = "加载失败: " + e.message;
  }
}

async function loadResult() {
  loadFile($("fileSelect").value);
}

// ===== 分类卡片 =====
async function renderCards() {
  const data = await api("/api/summary");
  const box = $("cards");
  box.innerHTML = "";
  for (const c of data.categories) {
    const div = document.createElement("div");
    div.className = "card" + (c.key === state.category ? " active" : "");
    div.innerHTML = `<div class="name">${esc(c.name)}</div>
      <div class="stat">${c.count} 条 | ${c.ips} IP | ${c.ports} 端口</div>`;
    div.onclick = () => {
      state.category = c.key;
      state.filter = "__all__";
      state.page = 1;
      renderCards();
      renderTabs();
      renderFilters();
      renderView();
    };
    box.appendChild(div);
  }
}

// ===== 分类 Tab =====
async function renderTabs() {
  const data = await api("/api/summary");
  const box = $("tabs");
  box.innerHTML = "";
  for (const c of data.categories) {
    const btn = document.createElement("button");
    btn.className = "tab" + (c.key === state.category ? " active" : "");
    btn.textContent = `${c.name} (${c.count})`;
    btn.onclick = () => {
      state.category = c.key;
      state.filter = "__all__";
      state.page = 1;
      renderCards();
      renderTabs();
      renderFilters();
      renderView();
    };
    box.appendChild(btn);
  }
}

// ===== 筛选按钮 =====
async function renderFilters() {
  const data = await api(`/api/assets?category=${state.category}&page=1&page_size=1`);
  const box = $("filters");
  box.innerHTML = "";
  const options = [["全部", "__all__"], ...(data.filters || [])];
  for (const [label, value] of options) {
    const btn = document.createElement("button");
    btn.className = "filter-chip" + (value === state.filter ? " active" : "");
    btn.textContent = label;
    btn.onclick = () => {
      state.filter = value;
      state.page = 1;
      renderFilters();
      renderView();
    };
    box.appendChild(btn);
  }
}

// ===== 表格 =====
// onego patch: 表头按分类自适应——web 用 HTTP 语义模板；非 web 分类的探测返回
// 与 HTTP 不同，改用协议/状态/指纹/提取信息等 .dat 实测字段模板，
// 且当前页整列为空时自动隐藏该列（全部数据来自 .dat，不引入推测信息）
const WEB_COLS = ["IP", "端口", "状态码", "长度", "标题", "技术栈", "中间件", "漏洞"];
const WEB_WIDTHS = ["13%", "6%", "7%", "7%", null, "19%", "13%", "16%"];
const NONWEB_COLS = [
  { name: "IP", w: "12%", always: true },
  { name: "端口", w: "6%", always: true },
  { name: "协议", w: "7%", field: "protocol" },
  { name: "状态", w: "9%", always: true },
  { name: "指纹 / 服务", w: null, always: true },
  { name: "提取信息", w: "24%", field: "extracts" },
  { name: "漏洞", w: "13%", field: "vulns" },
];
let lastTotal = 0; // 最近一次请求的总条数，供翻页上界保护使用

// colgroup 随列集合重建（列宽按比例分配，随窗口宽度等比伸缩；
// 窄于 table min-width(960px) 时出现横向滚动条）
function setColgroup(widths) {
  const table = document.querySelector("#table");
  const old = table.querySelector("colgroup");
  if (old) old.remove();
  const colgroup = document.createElement("colgroup");
  colgroup.innerHTML = widths
    .map((w) => (w ? `<col style="width:${w}">` : "<col>"))
    .join("");
  table.insertBefore(colgroup, table.firstChild);
}

// onego patch: 非 web 行单元格渲染（一列一字段，均为 .dat 实测数据）
function nonwebCell(a, col) {
  switch (col.name) {
    case "IP":
      return `<td class="ip"><span class="ip-text">${esc(a.ip)}</span><span class="ip-filter" title="筛选该 IP 的全部端口">⌖</span></td>`;
    case "端口":
      return `<td>${esc(a.port)}</td>`;
    case "协议":
      return `<td>${esc(a.protocol)}</td>`;
    case "状态":
      return `<td class="${statusClass(a.status)}">${esc(a.status)}</td>`;
    case "指纹 / 服务":
      // onego patch: 确定指纹白色正常字体；仅推测指纹（原版 f.IsGuess()）灰色斜体弱化
      return `<td class="${a.title_src === "finger" && a.title_guess ? "finger-guess" : ""}" title="${esc(a.title)}">${esc(a.title)}${marksHtml(a.marks)}</td>`;
    case "提取信息":
      return `<td title="${esc(a.extracts)}">${esc(a.extracts)}</td>`;
    case "漏洞":
      return `<td class="${a.vulns ? "vuln" : ""}">${esc(a.vulns)}</td>`;
    default:
      return "<td></td>";
  }
}

async function renderTable() {
  const params = new URLSearchParams({
    category: state.category,
    filter: state.filter,
    page: state.page,
    page_size: state.pageSize,
  });
  // onego patch: 全文搜索（含 ip: 精确匹配）随列表请求下发
  if (state.q) params.set("q", state.q);
  const data = await api(`/api/assets?${params}`);

  // onego patch: 页码越界钳制——超出末页时自动回退到末页重新请求，
  // 避免切换筛选后残留旧页码导致的"无限下一页"与空表格
  const totalPagesNow = Math.max(1, Math.ceil(data.total / state.pageSize));
  if (state.page > totalPagesNow) {
    state.page = totalPagesNow;
    const fixParams = new URLSearchParams({
      category: state.category,
      filter: state.filter,
      page: state.page,
      page_size: state.pageSize,
    });
    if (state.q) fixParams.set("q", state.q);
    const fixed = await api(`/api/assets?${fixParams}`);
    Object.assign(data, fixed);
  }

  const thead = document.querySelector("#table thead");
  const tbody = document.querySelector("#table tbody");

  // onego patch: 按分类选择表头模板；非 web 模板中当前页无数据的可选列自动隐藏
  const isWeb = state.category === "web";
  const rows = data.assets || [];
  let headers, widths;
  if (isWeb) {
    headers = WEB_COLS.map((c) => `<th>${c}</th>`).join("");
    widths = WEB_WIDTHS;
  } else {
    const cols = NONWEB_COLS.filter((c) => c.always || rows.some((a) => a[c.field]));
    headers = cols.map((c) => `<th>${c.name}</th>`).join("");
    widths = cols.map((c) => c.w);
  }
  setColgroup(widths);
  thead.innerHTML = "<tr>" + headers + "</tr>";

  if (rows.length === 0) {
    const hint = data.total === 0
      ? "暂无数据 — 当前分类/筛选条件下没有记录"
      : "暂无数据 — 请先加载 .dat 结果文件";
    tbody.innerHTML = `<tr><td colspan="${isWeb ? WEB_COLS.length : NONWEB_COLS.length}"><div class="empty">${hint}</div></td></tr>`;
  } else if (isWeb) {
    // onego patch: 行携带 ip/port 供详情面板使用；标题列指纹兜底灰色显示；
    // 行末标记点提示附加信息；IP 列提供"筛选该 IP"图标
    tbody.innerHTML = rows.map((a) => `<tr data-ip="${esc(a.ip)}" data-port="${esc(a.port)}">
      <td class="ip"><span class="ip-text">${esc(a.ip)}</span><span class="ip-filter" title="筛选该 IP 的全部端口">⌖</span></td>
      <td>${esc(a.port)}</td>
      <td class="${statusClass(a.status)}">${esc(a.status)}</td>
      <td class="len">${a.length || ""}</td>
      <td class="${a.title_src === "finger" && a.title_guess ? "finger-guess" : ""}" title="${esc(a.title)}">${esc(a.title)}${marksHtml(a.marks)}</td>
      <td>${esc(a.tech)}</td>
      <td>${esc(a.midware)}</td>
      <td class="${a.vulns ? "vuln" : ""}">${esc(a.vulns)}</td>
    </tr>`).join("");
  } else {
    // onego patch: 非 web 分类按实测字段模板渲染（协议/状态/指纹/提取信息/漏洞）
    const cols = NONWEB_COLS.filter((c) => c.always || rows.some((a) => a[c.field]));
    tbody.innerHTML = rows.map((a) =>
      `<tr data-ip="${esc(a.ip)}" data-port="${esc(a.port)}">` +
      cols.map((c) => nonwebCell(a, c)).join("") +
      `</tr>`).join("");
  }

  const totalPages = Math.max(1, Math.ceil(data.total / state.pageSize));
  lastTotal = data.total;
  $("pageInfo").textContent = `第 ${data.total === 0 ? 0 : (state.page - 1) * state.pageSize + 1}-${Math.min(state.page * state.pageSize, data.total)} 条 / 共 ${data.total} 条 · ${state.page}/${totalPages} 页`;
  // onego patch: 边界禁用翻页按钮，防止无限翻页
  $("prevBtn").disabled = state.page <= 1;
  $("nextBtn").disabled = state.page >= totalPages;
}

function statusClass(status) {
  const code = parseInt(status, 10);
  if (code >= 200 && code < 300) return "status-2xx";
  if (code >= 300 && code < 400) return "status-3xx";
  if (code >= 400 && code < 500) return "status-4xx";
  if (code >= 500) return "status-5xx";
  return "";
}

// ===== onego patch: 视图调度 =====
function renderView() {
  if (state.view === "hosts") renderHosts();
  else renderTable();
}

function setView(view) {
  state.view = view;
  $("viewListBtn").classList.toggle("active", view === "list");
  $("viewHostsBtn").classList.toggle("active", view === "hosts");
  $("listView").classList.toggle("hidden", view !== "list");
  $("hostsView").classList.toggle("hidden", view !== "hosts");
  $("prevBtn").style.display = view === "list" ? "" : "none";
  $("nextBtn").style.display = view === "list" ? "" : "none";
  // onego patch: 主机视图按 IP 全量聚合，分类卡片、筛选标签与分类 Tab 均不适用，
  // 全部隐藏（列表视图恢复）
  $("cards").classList.toggle("hidden", view === "hosts");
  $("filters").classList.toggle("hidden", view === "hosts");
  $("tabs").classList.toggle("hidden", view === "hosts");
  renderView();
}

// ===== onego patch: 标记点 =====
function marksHtml(marks) {
  if (!marks || !marks.length) return "";
  const title = { extracts: "含提取信息（IP/域名等）", cert: "含 cert 域名", vuln: "含漏洞命中" };
  return `<span class="marks">` +
    marks.map((m) => `<i class="mark mark-${m}" title="${title[m] || m}"></i>`).join("") +
    `</span>`;
}

// ===== onego patch: 主机视图（按 IP 事实聚合） =====
const HOST_COLS = ["IP", "开放端口数", "端口范围", "端口列表", "服务构成", "附加信息"];

async function renderHosts() {
  // onego patch: 主机视图按 IP 聚合全量数据，不受分类/筛选标签约束（保留搜索）
  const params = new URLSearchParams();
  if (state.q) params.set("q", state.q);
  const box = $("hostsView");
  box.innerHTML = `<div class="empty">加载中…</div>`;
  const data = await api(`/api/hosts?${params}`);
  state.hosts = data.hosts || [];
  if (state.hosts.length === 0) {
    box.innerHTML = `<div class="empty">暂无主机 — 当前分类/筛选条件下没有记录</div>`;
    $("pageInfo").textContent = "共 0 台主机";
    return;
  }
  box.innerHTML = `<table class="hosts-table">
    <thead><tr>${HOST_COLS.map((c, i) => {
      // onego patch: IP 与开放端口数两列可排序，再次点击循环回默认顺序
      if (i === 0) return `<th class="sortable" id="hostSortIp" title="按 IP 排序，再点恢复默认顺序">${c}<span class="sort-arrow"></span></th>`;
      if (i === 1) return `<th class="sortable" id="hostSortPorts" title="按开放端口数排序，再点恢复默认顺序">${c}<span class="sort-arrow"></span></th>`;
      return `<th>${c}</th>`;
    }).join("")}</tr></thead>
    <tbody></tbody></table>`;
  renderHostsTable();
  $("pageInfo").textContent = `共 ${data.total} 台主机 · 点击行弹出该 IP 全部端口卡片`;
}

// onego patch: 按当前排序状态渲染主机行
function sortedHosts() {
  const hosts = state.hosts.slice();
  if (state.hostSort === "ip-asc") {
    hosts.sort((a, b) => ipNum(a.ip) - ipNum(b.ip));
  } else if (state.hostSort === "ip-desc") {
    hosts.sort((a, b) => ipNum(b.ip) - ipNum(a.ip));
  } else if (state.hostSort === "ports-desc" || state.hostSort === "ports-asc") {
    const dir = state.hostSort === "ports-asc" ? 1 : -1;
    hosts.sort((a, b) => (a.port_count - b.port_count) * dir || (ipNum(a.ip) - ipNum(b.ip)));
  }
  return hosts;
}

function ipNum(ip) {
  return String(ip).split(".").reduce((acc, p) => acc * 256 + (parseInt(p, 10) || 0), 0);
}

function renderHostsTable() {
  const tbody = $("hostsView").querySelector("tbody");
  if (!tbody) return;
  tbody.innerHTML = sortedHosts().map((h) => `<tr class="host-row" data-ip="${esc(h.ip)}">
      <td class="ip">${esc(h.ip)}</td>
      <td>${h.port_count}</td>
      <td class="len">${esc(h.port_range)}</td>
      <td class="host-ports">${h.ports.map(esc).join(", ")}</td>
      <td class="host-services">${h.services.map(esc).join(" ")}</td>
      <td>${marksHtml(hostMarks(h))}</td>
    </tr>`).join("");
  // onego patch: 两个可排序表头分别更新激活态与箭头方向
  updateSortTh("hostSortIp", ["ip-asc", "ip-desc"]);
  updateSortTh("hostSortPorts", ["ports-desc", "ports-asc"]);
}

function updateSortTh(id, modes) {
  const th = $(id);
  if (!th) return;
  const mode = modes.find((m) => m === state.hostSort) || "";
  th.classList.toggle("active", !!mode);
  th.querySelector(".sort-arrow").textContent =
    mode ? (mode.endsWith("desc") ? " ▼" : " ▲") : "";
}

// onego patch: 点击表头循环切换——当前列 降序/升序 后第三次点击恢复默认顺序；
// 点击另一列则直接启用该列的首选方向
function cycleHostSort(key) {
  const order = key === "ip" ? ["ip-asc", "ip-desc", ""] : ["ports-desc", "ports-asc", ""];
  const idx = order.indexOf(state.hostSort);
  state.hostSort = order[(idx + 1) % order.length];
  renderHostsTable();
}

function hostMarks(h) {
  const marks = [];
  if (h.has_extracts) marks.push("extracts");
  if (h.has_host) marks.push("cert");
  if (h.has_vulns) marks.push("vuln");
  return marks;
}

// onego patch: 主机弹窗分区列模板——Web 区沿用 HTTP 语义列，非 Web 区沿用实测
// 字段列（与列表视图规则一致）；区内整列为空的可选列自动隐藏，不再展示"分类"列
const MODAL_WEB_COLS = [
  { name: "端口", always: true },
  { name: "状态码", always: true },
  { name: "长度", field: "length" },
  { name: "标题", always: true },
  { name: "技术栈", field: "tech" },
  { name: "中间件", field: "midware" },
  { name: "漏洞", field: "vulns" },
];
const MODAL_NONWEB_COLS = [
  { name: "端口", always: true },
  { name: "协议", field: "protocol" },
  { name: "状态", always: true },
  { name: "指纹 / 服务", always: true },
  { name: "提取信息", field: "extracts" },
  { name: "漏洞", field: "vulns" },
];

function modalWebCell(a, col) {
  switch (col.name) {
    case "端口":
      return `<td>${esc(a.port)}</td>`;
    case "状态码":
      return `<td class="${statusClass(a.status)}">${esc(a.status)}</td>`;
    case "长度":
      return `<td class="len">${a.length || ""}</td>`;
    case "标题":
      return `<td class="${a.title_src === "finger" && a.title_guess ? "finger-guess" : ""}" title="${esc(a.title)}">${esc(a.title)}${marksHtml(a.marks)}</td>`;
    case "技术栈":
      return `<td>${esc(a.tech)}</td>`;
    case "中间件":
      return `<td>${esc(a.midware)}</td>`;
    case "漏洞":
      return `<td class="${a.vulns ? "vuln" : ""}">${esc(a.vulns)}</td>`;
    default:
      return "<td></td>";
  }
}

function modalSection(title, colDefs, rows, cellFn) {
  const cols = colDefs.filter((c) => c.always || rows.some((a) => a[c.field]));
  // onego patch: 分区标题可点击折叠/展开，端口多的分区收起后不挤占另一分区
  return `<div class="modal-section">
    <div class="modal-section-title" title="点击折叠/展开"><span class="collapse-arrow">▾</span>${title}</div>
    <div class="modal-section-body">
      <table class="host-sub-table">
        <thead><tr>${cols.map((c) => `<th>${c.name}</th>`).join("")}</tr></thead>
        <tbody>${rows.map((a) =>
          `<tr class="host-sub" data-ip="${esc(a.ip)}" data-port="${esc(a.port)}">` +
          cols.map((c) => cellFn(a, c)).join("") + `</tr>`).join("")}</tbody>
      </table>
    </div>
  </div>`;
}

// onego patch: 主机端口列表弹出卡片（Web/非 Web 分区展示，端口多时不挤占概览页）
async function openHostModal(ip) {
  $("hostModalTitle").textContent = `${ip} · 全部端口`;
  $("hostModalBody").innerHTML = `<div class="empty">加载中…</div>`;
  $("hostModal").classList.remove("hidden");
  try {
    // 不带分类参数：跨分类展示该 IP 的全部服务，便于判断端口间关联
    const data = await api(`/api/assets?q=${encodeURIComponent("ip:" + ip)}&page=1&page_size=2000`);
    const byPort = (x, y) => (parseInt(x.port, 10) || 0) - (parseInt(y.port, 10) || 0);
    const webRows = (data.assets || []).filter((a) => a.category === "web").sort(byPort);
    const otherRows = (data.assets || []).filter((a) => a.category !== "web").sort(byPort);
    const html = [];
    if (webRows.length) html.push(modalSection(`Web 端口 (${webRows.length})`, MODAL_WEB_COLS, webRows, modalWebCell));
    if (otherRows.length) html.push(modalSection(`其他端口 (${otherRows.length})`, MODAL_NONWEB_COLS, otherRows, nonwebCell));
    $("hostModalBody").innerHTML = html.length
      ? html.join("") + `<div class="modal-hint">点击分区标题折叠/展开 · 点击行查看端口详情 · 点击卡片外围返回主机视图</div>`
      : `<div class="empty">该 IP 暂无记录</div>`;
  } catch (e) {
    $("hostModalBody").innerHTML = `<div class="empty">加载失败: ${esc(e.message)}</div>`;
  }
}

function closeHostModal() {
  $("hostModal").classList.add("hidden");
}

function closeDetail() {
  $("detailPanel").classList.remove("open");
}

// ===== onego patch: 端口信息详情面板 =====
async function openDetail(ip, port) {
  if (!ip || !port) return;
  const panel = $("detailPanel");
  $("detailTitle").textContent = `${ip}:${port}`;
  $("detailBody").innerHTML = `<div class="empty">加载中…</div>`;
  panel.classList.add("open");
  try {
    const d = await api(`/api/record?ip=${encodeURIComponent(ip)}&port=${encodeURIComponent(port)}`);
    renderDetail(d);
  } catch (e) {
    $("detailBody").innerHTML = `<div class="empty">详情加载失败: ${esc(e.message)}</div>`;
  }
}

function renderDetail(d) {
  let html = "";
  html += section("基础信息", kvRows([
    ["IP", d.ip], ["端口", d.port], ["协议", d.protocol], ["状态", d.status],
    ["响应长度", d.length], ["响应耗时", d.timing ? d.timing + " ms" : ""],
    ["分类", CAT_NAMES[d.category] || d.category],
  ]));
  html += section("HTTP 信息", kvRows([
    ["标题", d.title], ["URI", d.uri], ["Cert 域名", d.host, true], ["中间件", d.midware],
  ]));
  if (d.frameworks && d.frameworks.length) {
    html += section(`指纹 (${d.frameworks.length})`, d.frameworks.map((f) => {
      const bits = [];
      if (f.version) bits.push(f.version);
      // onego patch: product 为 .dat 指纹 CPE 实测属性（328 条记录携带），与版本并列展示
      if (f.product && f.product !== f.name) bits.push(f.product);
      if (f.tags && f.tags.length) bits.push(f.tags.join(" "));
      if (f.froms && f.froms.length) bits.push("[" + f.froms.join(",") + "]");
      return `<div class="detail-item">
        <span class="searchable${f.is_focus ? " focus" : ""}${f.is_guess ? " finger-guess-text" : ""}" data-search="${esc(f.name)}">${esc(f.name)}</span>
        <span class="detail-sub">${esc(bits.join(" · "))}</span>
        ${f.is_focus ? '<span class="tag tag-focus">focus</span>' : ""}
        ${f.is_guess ? '<span class="tag tag-guess">guess</span>' : ""}</div>`;
    }).join(""));
  }
  if (d.extracteds && Object.keys(d.extracteds).length) {
    let items = "";
    for (const [k, vs] of Object.entries(d.extracteds)) {
      items += `<div class="detail-item"><span class="detail-key">${esc(k)}</span>: ` +
        vs.map((v) => `<span class="searchable" data-search="${esc(v)}">${esc(v)}</span>`).join(" ") +
        `</div>`;
    }
    html += section("提取信息", items);
  }
  if (d.vulns && d.vulns.length) {
    html += section(`漏洞 (${d.vulns.length})`, d.vulns.map((v) => `
      <div class="detail-item">
        <span class="sev sev-${esc(v.severity || "unknown")}">${esc(v.severity || "unknown")}</span>
        <span class="searchable" data-search="${esc(v.name)}">${esc(v.name)}</span>
        ${v.tags && v.tags.length ? `<span class="detail-sub">${esc(v.tags.join(" "))}</span>` : ""}
      </div>
      ${v.payload ? `<div class="detail-sub-block">payload: ${esc(v.payload)}</div>` : ""}
      ${v.detail ? `<div class="detail-sub-block">detail: ${esc(v.detail)}</div>` : ""}
    `).join(""));
  }
  $("detailBody").innerHTML = html;
}

function section(title, inner) {
  if (!inner) return "";
  return `<div class="detail-section"><div class="detail-section-title">${title}</div>${inner}</div>`;
}

function kvRows(items) {
  const rows = items
    .filter(([, v]) => v !== "" && v != null)
    .map(([k, v, searchable]) => `<div class="detail-item"><span class="detail-key">${k}</span>: ` +
      (searchable ? `<span class="searchable" data-search="${esc(v)}">${esc(v)}</span>` : esc(v)) +
      `</div>`);
  return rows.join("") || `<div class="detail-item dim">无</div>`;
}

// ===== onego patch: 搜索与回填 =====
function setSearch(q) {
  state.q = q;
  $("searchInput").value = q;
  state.page = 1;
  renderSearchChip();
  renderView();
}

function renderSearchChip() {
  const chip = $("searchChip");
  if (!state.q) {
    chip.classList.add("hidden");
    chip.innerHTML = "";
    return;
  }
  chip.classList.remove("hidden");
  chip.innerHTML = `搜索/筛选: <b>${esc(state.q)}</b> <button id="clearSearch" class="btn btn-sm">✕ 清除</button>`;
  $("clearSearch").onclick = () => setSearch("");
}

// ===== 事件绑定 =====
$("loadBtn").onclick = loadResult;
$("refreshBtn").onclick = loadFiles;
$("exportBtn").onclick = async () => {
  if (!state.file) return;
  // onego patch: WKWebView 不支持附件下载，改为服务端写文件到本地，
  // 界面 toast 提示保存路径（window.location 跳转会替换整个 GUI 无法返回）
  try {
    const data = await api(`/api/export?category=${state.category}&filter=${encodeURIComponent(state.filter)}`);
    toast(`已导出 ${data.count} 条 → ${data.path}`);
  } catch (e) {
    toast("导出失败: " + e.message);
  }
};
$("prevBtn").onclick = () => { if (state.page > 1) { state.page--; renderTable(); } };
// onego patch: 下一页增加上界保护（兜底，正常由按钮 disabled 拦截）
$("nextBtn").onclick = () => {
  const totalPages = Math.max(1, Math.ceil((lastTotal ?? 0) / state.pageSize));
  if (state.page < totalPages) { state.page++; renderTable(); }
};

// onego patch: 双击单元格全选该格内容，便于快捷键复制（不自动写剪贴板）
document.querySelector("#table tbody").addEventListener("dblclick", (e) => {
  const td = e.target.closest("td");
  if (!td) return;
  const range = document.createRange();
  range.selectNodeContents(td);
  const sel = window.getSelection();
  sel.removeAllRanges();
  sel.addRange(range);
});

// onego patch: 列表行单击打开详情面板；IP 图标单击筛选该 IP
document.querySelector("#table tbody").addEventListener("click", (e) => {
  const tr = e.target.closest("tr[data-ip]");
  if (!tr) return;
  if (e.target.closest(".ip-filter")) {
    setSearch("ip:" + tr.dataset.ip);
    return;
  }
  openDetail(tr.dataset.ip, tr.dataset.port);
});

// onego patch: 主机视图——IP/端口数表头点击切换排序，主机行单击弹出端口卡片
$("hostsView").addEventListener("click", (e) => {
  if (e.target.closest("#hostSortIp")) {
    cycleHostSort("ip");
    return;
  }
  if (e.target.closest("#hostSortPorts")) {
    cycleHostSort("ports");
    return;
  }
  const hostRow = e.target.closest("tr.host-row");
  if (hostRow) openHostModal(hostRow.dataset.ip);
});

// onego patch: 主机端口卡片——行单击打开右侧端口详情；
// 点击卡片外围（遮罩）或关闭按钮，同时关闭卡片与右侧详情，返回主机视图
$("hostModal").addEventListener("click", (e) => {
  if (e.target === $("hostModal")) {
    closeHostModal();
    closeDetail();
    return;
  }
  // onego patch: 分区标题折叠/展开切换
  const secTitle = e.target.closest(".modal-section-title");
  if (secTitle) {
    secTitle.closest(".modal-section").classList.toggle("collapsed");
    return;
  }
  const tr = e.target.closest("tr.host-sub");
  if (tr) openDetail(tr.dataset.ip, tr.dataset.port);
});
$("hostModalClose").onclick = () => {
  closeHostModal();
  closeDetail();
};

// onego patch: 详情面板内可搜索值点击回填搜索框
$("detailBody").addEventListener("click", (e) => {
  const el = e.target.closest(".searchable");
  if (!el) return;
  setSearch(el.dataset.search);
});
$("detailClose").onclick = closeDetail;
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    // 卡片打开时：同时关闭卡片与右侧详情；否则仅关闭详情
    if (!$("hostModal").classList.contains("hidden")) closeHostModal();
    closeDetail();
  }
});

// onego patch: 视图切换与搜索
$("viewListBtn").onclick = () => setView("list");
$("viewHostsBtn").onclick = () => setView("hosts");
$("searchBtn").onclick = () => setSearch($("searchInput").value.trim());
$("searchInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") setSearch($("searchInput").value.trim());
});

// ===== 初始化 =====
loadFiles().then(() => {
  // 若 URL 带 ?file=xxx 则自动加载（--gui -F 场景，支持绝对路径）
  const q = new URLSearchParams(window.location.search).get("file");
  if (q) {
    $("fileSelect").value = q;
    loadFile(q);
  }
}).catch((e) => { $("loadInfo").textContent = "初始化失败: " + e.message; });
