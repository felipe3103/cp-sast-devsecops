// Dashboard executivo do SentinelaSAST. Sem dependências externas: gráficos em SVG.
"use strict";

const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEV_LABEL = { CRITICAL: "Crítica", HIGH: "Alta", MEDIUM: "Média", LOW: "Baixa", INFO: "Info" };
const SEV_VAR = { CRITICAL: "--sev-critical", HIGH: "--sev-high", MEDIUM: "--sev-medium", LOW: "--sev-low", INFO: "--sev-info" };
const SVGNS = "http://www.w3.org/2000/svg";

const state = { project: "", scanId: null, findings: [] };
const $ = (sel) => document.querySelector(sel);
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const sevBadge = (s) => `<span class="sev" style="--c: var(${SEV_VAR[s] || "--sev-info"})">${SEV_LABEL[s] || esc(s)}</span>`;

async function api(path, opts = {}) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (_) { /* corpo não-JSON */ }
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return res.json();
}

// ------------------------------------------------------------------ tooltip
const tip = $("#tooltip");
function showTip(evt, html) {
  tip.innerHTML = html;
  tip.classList.add("show");
  const pad = 14, w = tip.offsetWidth, h = tip.offsetHeight;
  let x = evt.clientX + pad, y = evt.clientY + pad;
  if (x + w > innerWidth - 8) x = evt.clientX - w - pad;
  if (y + h > innerHeight - 8) y = evt.clientY - h - pad;
  tip.style.left = `${x}px`; tip.style.top = `${y}px`;
}
const hideTip = () => tip.classList.remove("show");
addEventListener("scroll", hideTip, { passive: true });

function el(tag, attrs = {}, parent) {
  const node = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  if (parent) parent.appendChild(node);
  return node;
}
function svgRoot(container, width, height) {
  container.innerHTML = "";
  return el("svg", { viewBox: `0 0 ${width} ${height}`, role: "img" }, container);
}
// Barra com cantos arredondados só na ponta de dados (4px), ancorada à base.
function barPath(x, y, w, h, horizontal, roundEnd = true) {
  const r = roundEnd ? Math.min(4, horizontal ? h / 2 : w / 2, horizontal ? w : h) : 0;
  if (horizontal) return `M${x},${y} h${w - r} q${r},0 ${r},${r} v${h - 2 * r} q0,${r} ${-r},${r} h${-(w - r)} z`;
  return `M${x},${y + h} v${-(h - r)} q0,${-r} ${r},${-r} h${w - 2 * r} q${r},0 ${r},${r} v${h - r} z`;
}
function legend(container, keys) {
  const div = document.createElement("div");
  div.className = "legend";
  div.innerHTML = keys.map((k) => `<span><i style="background: var(${SEV_VAR[k]})"></i>${SEV_LABEL[k]}</span>`).join("");
  container.appendChild(div);
}

// --------------------------------------------------- gráfico: severidade
function chartSeverity(data) {
  const box = $("#chart-severity");
  const total = SEVS.reduce((a, s) => a + (data[s] || 0), 0);
  if (!total) { box.innerHTML = '<div class="empty">Nenhum achado aberto 🎉</div>'; return; }
  const W = 360, rowH = 30, labelW = 64, H = SEVS.length * rowH;
  const max = Math.max(...SEVS.map((s) => data[s] || 0));
  const svg = svgRoot(box, W, H);
  SEVS.forEach((s, i) => {
    const v = data[s] || 0, y = i * rowH + 6, bw = v ? Math.max(3, (v / max) * (W - labelW - 70)) : 0;
    const t = el("text", { x: 0, y: y + 13 }, svg); t.textContent = SEV_LABEL[s];
    if (bw) el("path", { d: barPath(labelW, y, bw, 18, true), fill: css(SEV_VAR[s]) }, svg);
    const vl = el("text", { x: labelW + bw + 6, y: y + 13, class: "value-label" }, svg);
    vl.textContent = `${v} · ${Math.round((v / total) * 100)}%`;
    const hit = el("rect", { x: 0, y: i * rowH, width: W, height: rowH, fill: "transparent" }, svg);
    hit.addEventListener("mousemove", (e) => showTip(e, `<b>Severidade ${SEV_LABEL[s]}</b><div class="tt-row"><span>Achados</span><span>${v}</span></div><div class="tt-row"><span>Participação</span><span>${((v / total) * 100).toFixed(1)}%</span></div>`));
    hit.addEventListener("mouseleave", hideTip);
  });
}

// ------------------------------------------------------ gráfico: tendência
function chartTrend(trend) {
  const box = $("#chart-trend");
  if (!trend.length) { box.innerHTML = '<div class="empty">Sem varreduras concluídas ainda.</div>'; return; }
  const keys = SEVS.filter((s) => trend.some((t) => t[s]));
  const W = 720, H = 220, L = 34, B = 34, T = 10;
  const totals = trend.map((t) => keys.reduce((a, k) => a + t[k], 0));
  const max = Math.max(1, ...totals);
  const step = niceStep(max), top = Math.ceil(max / step) * step;
  const svg = svgRoot(box, W, H);
  const plotH = H - B - T, slot = (W - L) / trend.length, bw = Math.min(42, slot * 0.6);
  for (let v = 0; v <= top; v += step) {
    const y = T + plotH - (v / top) * plotH;
    el("line", { x1: L, x2: W, y1: y, y2: y, class: "gridline" }, svg);
    const t = el("text", { x: L - 6, y: y + 4, "text-anchor": "end" }, svg); t.textContent = v;
  }
  trend.forEach((t, i) => {
    const x = L + i * slot + (slot - bw) / 2;
    let y = T + plotH;
    const present = keys.filter((k) => t[k]);
    present.forEach((k, j) => {
      const h = (t[k] / top) * plotH;
      const gap = j > 0 ? 2 : 0; // 2px de superfície entre segmentos
      el("path", { d: barPath(x, y - h + gap, bw, Math.max(0, h - gap), false, j === present.length - 1), fill: css(SEV_VAR[k]) }, svg);
      y -= h;
    });
    if (t.gate_failed !== null && t.gate_failed !== undefined) {
      const mark = el("text", { x: x + bw / 2, y: y - 4, "text-anchor": "middle", class: "value-label" }, svg);
      mark.textContent = totals[i];
    }
    const lbl = el("text", { x: x + bw / 2, y: H - B + 14, "text-anchor": "middle" }, svg);
    lbl.textContent = `#${t.scan_id}`;
    const d = el("text", { x: x + bw / 2, y: H - B + 27, "text-anchor": "middle" }, svg);
    d.textContent = new Date(t.date).toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit" });
    const hit = el("rect", { x: L + i * slot, y: T, width: slot, height: plotH + B, fill: "transparent" }, svg);
    hit.addEventListener("mousemove", (e) => showTip(e,
      `<b>Varredura #${t.scan_id} · ${esc(t.project)}</b>` +
      keys.map((k) => `<div class="tt-row"><span>${SEV_LABEL[k]}</span><span>${t[k]}</span></div>`).join("") +
      `<div class="tt-row"><span>Total</span><span>${totals[i]}</span></div>` +
      (t.gate_failed === null ? "" : `<div>Security Gate: ${t.gate_failed ? "❌ reprovado" : "✅ aprovado"}</div>`)));
    hit.addEventListener("mouseleave", hideTip);
    hit.addEventListener("click", () => selectScan(t.scan_id));
    hit.style.cursor = "pointer";
  });
  legend(box, keys);
}
function niceStep(max) {
  const raw = max / 4, mag = 10 ** Math.floor(Math.log10(raw || 1));
  return [1, 2, 5, 10].map((m) => m * mag).find((s) => s >= raw) || mag;
}

// ------------------------------------------- gráfico: barras horizontais
function chartHBar(box, rows, { stacked, labelW = 150, color, maxChars = 24, cutStart = true }) {
  if (!rows.length) { box.innerHTML = '<div class="empty">Sem dados.</div>'; return; }
  const W = 400, rowH = 30, H = rows.length * rowH;
  const max = Math.max(...rows.map((r) => r.total));
  const svg = svgRoot(box, W, H);
  const usable = W - labelW - 34;
  rows.forEach((r, i) => {
    const y = i * rowH + 6;
    const name = r.label.length <= maxChars ? r.label
      : cutStart ? "…" + r.label.slice(-(maxChars - 1)) : r.label.slice(0, maxChars - 1) + "…";
    const t = el("text", { x: 0, y: y + 13 }, svg); t.textContent = name;
    let x = labelW;
    const parts = stacked ? SEVS.filter((s) => r[s]) : ["_"];
    parts.forEach((s, j) => {
      const v = stacked ? r[s] : r.total;
      const w = (v / max) * usable, gap = j > 0 ? 2 : 0;
      el("path", { d: barPath(x + gap, y, Math.max(1, w - gap), 18, true, j === parts.length - 1), fill: stacked ? css(SEV_VAR[s]) : color }, svg);
      x += w;
    });
    const vl = el("text", { x: x + 6, y: y + 13, class: "value-label" }, svg); vl.textContent = r.total;
    const hit = el("rect", { x: 0, y: i * rowH, width: W, height: rowH, fill: "transparent" }, svg);
    hit.addEventListener("mousemove", (e) => showTip(e, `<b>${esc(r.label)}</b>` + (stacked
      ? SEVS.filter((s) => r[s]).map((s) => `<div class="tt-row"><span>${SEV_LABEL[s]}</span><span>${r[s]}</span></div>`).join("")
      : "") + `<div class="tt-row"><span>Total</span><span>${r.total}</span></div>`));
    hit.addEventListener("mouseleave", hideTip);
    if (r.onClick) { hit.style.cursor = "pointer"; hit.addEventListener("click", r.onClick); }
  });
  if (stacked) legend(box, SEVS.filter((s) => rows.some((r) => r[s])));
}

// -------------------------------------------------------------------- KPIs
function renderKpis(k) {
  const items = [
    ["Achados abertos", k.open_findings, `${k.files_scanned} arquivos · ${k.lines_scanned.toLocaleString("pt-BR")} linhas`],
    ["Críticos", k.critical, "corrigir imediatamente", "--sev-critical"],
    ["Altos", k.high, "bloqueiam o pipeline", "--sev-high"],
    ["Risco acumulado", k.risk_score, "soma dos scores 0–10"],
    ["Security Gate", k.gate_failed ? `${k.gate_failed} ❌` : "OK ✅", k.gate_failed ? "projeto(s) reprovado(s)" : "todos aprovados"],
    ["Triados por IA", k.ai_triaged, `${k.ai_false_positives} falso(s) positivo(s) descartado(s)`],
    ["Novos / corrigidos", `${k.new_since_last} / ${k.fixed_since_last}`, "vs. varredura anterior"],
  ];
  $("#kpis").innerHTML = items.map(([label, value, sub, color]) => `
    <div class="kpi"><div class="label">${color ? `<span class="dot" style="background: var(${color})"></span>` : ""}${label}</div>
    <div class="value">${esc(value)}</div><div class="sub">${esc(sub)}</div></div>`).join("");
}

// ------------------------------------------------------------------ dados
async function loadMetrics() {
  const m = await api(`/api/v1/metrics${state.project ? `?project=${encodeURIComponent(state.project)}` : ""}`);
  renderKpis(m.kpis);
  chartSeverity(m.severity);
  chartTrend(m.trend);
  chartHBar($("#chart-files"), m.top_files.map((f) => ({ ...f, label: f.file, onClick: () => filterFile(f.file) })), { stacked: true });
  chartHBar($("#chart-owasp"), m.owasp.map(([label, total]) => ({ label: label.replace(":2021", ""), total })), { stacked: false, labelW: 210, maxChars: 32, cutStart: false, color: css("--accent") });
  const scans = await api(`/api/v1/scans?limit=50${state.project ? `&project=${encodeURIComponent(state.project)}` : ""}`);
  const sel = $("#scan-select");
  sel.innerHTML = scans.map((s) => `<option value="${s.id}">#${s.id} · ${esc(s.project)} · ${esc(s.status)}${s.gate_failed ? " · ❌" : s.gate_failed === false ? " · ✅" : ""}</option>`).join("");
  if (!state.scanId || !scans.some((s) => s.id === state.scanId)) {
    const done = scans.find((s) => s.status === "completed");
    state.scanId = done ? done.id : scans[0]?.id ?? null;
  }
  if (state.scanId) sel.value = state.scanId;
  await loadFindings();
}

async function loadProjects() {
  const projects = await api("/api/v1/projects");
  const sel = $("#project-filter");
  const current = sel.value;
  sel.innerHTML = '<option value="">Todos</option>' + projects.map((p) => `<option>${esc(p.name)}</option>`).join("");
  sel.value = current;
}

let fileFilter = "";
function filterFile(file) { fileFilter = fileFilter === file ? "" : file; loadFindings(); }

async function loadFindings() {
  const tbody = $("#findings tbody");
  if (!state.scanId) { tbody.innerHTML = '<tr><td colspan="6" class="empty">Nenhuma varredura. Envie um projeto ao lado.</td></tr>'; return; }
  const params = new URLSearchParams();
  if ($("#sev-filter").value) params.set("severity", $("#sev-filter").value);
  if ($("#status-filter").value) params.set("status", $("#status-filter").value);
  if (fileFilter) params.set("file", fileFilter);
  const scan = await api(`/api/v1/scans/${state.scanId}`);
  $("#scan-label").textContent = `· varredura #${scan.id} (${scan.project})${fileFilter ? ` · arquivo ${fileFilter}` : ""}` +
    (scan.status !== "completed" ? ` · ${scan.status}${scan.error ? ": " + scan.error : ""}` : "");
  $("#btn-sarif").href = `/api/v1/scans/${state.scanId}/report.sarif`;
  state.findings = await api(`/api/v1/scans/${state.scanId}/findings?${params}`);
  tbody.innerHTML = state.findings.length ? state.findings.map((f) => `
    <tr data-id="${f.id}">
      <td>${sevBadge(f.severity)}</td>
      <td><code>${esc(f.rule_id)}</code><div class="muted">${esc(f.cwe)}</div></td>
      <td><code>${esc(f.file)}:${f.line}</code></td>
      <td>${esc(f.title)}<div class="muted">${esc(f.message)}</div></td>
      <td class="num">${f.risk_score}</td>
      <td>${{ none: "—", pending: "⏳", done: "🤖", failed: "⚠" }[f.ai_status] || "—"}${f.status !== "open" ? `<div class="muted">${esc(f.status)}</div>` : ""}</td>
    </tr>`).join("") : '<tr><td colspan="6" class="empty">Nenhum achado com esses filtros.</td></tr>';
  if (scan.status === "queued" || scan.status === "running" || state.findings.some((f) => f.ai_status === "pending")) {
    setTimeout(() => loadMetrics().catch(console.error), 2500);
  }
}

function selectScan(id) { state.scanId = id; fileFilter = ""; loadFindings(); }

// ------------------------------------------------------------ detalhe
async function openFinding(id) {
  const f = await api(`/api/v1/findings/${id}`);
  $("#d-title").innerHTML = `${sevBadge(f.severity)} ${esc(f.title)}`;
  let html = `<div class="meta"><span class="badge">${esc(f.rule_id)}</span><span class="badge">${esc(f.cwe)}</span>
    ${f.owasp ? `<span class="badge">${esc(f.owasp)}</span>` : ""}<span class="badge">confiança ${esc(f.confidence)}</span>
    <span class="badge">${esc(f.engine)}</span><span class="badge">risco ${f.risk_score}</span></div>
    <p>${esc(f.message)}</p><p class="muted"><code>${esc(f.file)}:${f.line}</code></p>`;
  if (f.context) {
    html += "<h3>Código</h3><pre class=\"code\">" + f.context.lines.map((l, i) => {
      const n = f.context.start + i;
      return `<span class="${n === f.line ? "hl" : ""}"><span class="ln">${String(n).padStart(4)}</span>${esc(l)}</span>`;
    }).join("") + "</pre>";
  } else if (f.snippet) {
    html += `<h3>Código</h3><pre class="code"><span class="hl">${esc(f.snippet)}</span></pre>`;
  }
  if (f.trace && f.trace.length) {
    html += "<h3>Fluxo de dados (taint)</h3><ol class=\"trace\">" +
      f.trace.map((s) => `<li><code>${s.file && s.file !== f.file ? esc(s.file) + ":" : "L"}${s.line}</code> ${esc(s.description)}</li>`).join("") + "</ol>";
  }
  html += `<h3>Remediação recomendada</h3><p>${esc(f.remediation)}</p>`;
  html += `<h3>Análise por IA</h3><div id="ai-panel">${renderAI(f.ai)}</div>
    <div class="row gap" style="justify-content:flex-start;margin-top:10px">
      <button id="btn-ai-one">${f.ai ? "Reanalisar" : "Analisar"} com IA</button>
      <select id="status-set"><option value="open">Aberto</option><option value="false_positive">Falso positivo</option>
        <option value="accepted_risk">Risco aceito</option><option value="fixed">Corrigido</option></select>
    </div>`;
  $("#d-body").innerHTML = html;
  $("#status-set").value = f.status;
  $("#status-set").onchange = async (e) => {
    await api(`/api/v1/findings/${id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: e.target.value }) });
    loadMetrics();
  };
  $("#btn-ai-one").onclick = async (e) => {
    e.target.disabled = true; e.target.textContent = "Analisando…";
    try { $("#ai-panel").innerHTML = renderAI(await api(`/api/v1/findings/${id}/ai`, { method: "POST" })); loadMetrics(); }
    catch (err) { $("#ai-panel").innerHTML = `<p>Erro: ${esc(err.message)}</p>`; }
    finally { e.target.disabled = false; e.target.textContent = "Reanalisar com IA"; }
  };
  $("#drawer").classList.add("open");
  $("#drawer").setAttribute("aria-hidden", "false");
}

function renderAI(ai) {
  if (!ai) return '<p class="muted">Ainda não analisado. O LLM local (Ollama/Llama 3) classifica o achado, ajusta a severidade e propõe uma correção validada.</p>';
  if (ai.error) return `<p>⚠ ${esc(ai.error)}</p>`;
  const verdict = { true_positive: "✅ Verdadeiro positivo", false_positive: "🚫 Falso positivo", uncertain: "❔ Incerto", needs_review: "👀 Requer revisão humana" }[ai.verdict] || esc(ai.verdict);
  const fix = ai.fix_validated === true ? "✅ correção validada (compila e não dispara a regra)" : ai.fix_validated === false ? `⚠ ${esc(ai.fix_validation_note)}` : "";
  return `<div class="ai-box">
    <div class="meta"><span class="badge">${verdict}</span>
      ${ai.source === "llm" ? `<span class="badge">confiança ${Math.round(ai.confidence * 100)}%</span><span class="badge">${esc(ai.model)}</span>` : '<span class="badge">base de conhecimento (LLM offline)</span>'}
      ${ai.severity !== ai.original_severity ? `<span class="badge">severidade ${esc(ai.original_severity)} → ${esc(ai.severity)}</span>` : ""}</div>
    <p>${esc(ai.justification)}</p>
    ${ai.exploit_scenario ? `<p><b>Cenário de exploração:</b> ${esc(ai.exploit_scenario)}</p>` : ""}
    <p><b>Correção:</b> ${esc(ai.remediation)}</p>
    ${ai.fixed_code ? `<pre class="code"><span>${esc(ai.fixed_code)}</span></pre>` : ""}
    ${fix ? `<p class="hint">${fix}</p>` : ""}
    ${(ai.notes || []).map((n) => `<p class="hint">ℹ ${esc(n)}</p>`).join("")}
  </div>`;
}

// ----------------------------------------------------------------- eventos
$("#findings tbody").addEventListener("click", (e) => {
  const tr = e.target.closest("tr[data-id]");
  if (tr) openFinding(tr.dataset.id).catch((err) => alertMsg(err.message));
});
$("#d-close").onclick = () => { $("#drawer").classList.remove("open"); $("#drawer").setAttribute("aria-hidden", "true"); };
document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("#d-close").click(); });
$("#scan-select").onchange = (e) => selectScan(Number(e.target.value));
$("#sev-filter").onchange = loadFindings;
$("#status-filter").onchange = loadFindings;
$("#project-filter").onchange = (e) => { state.project = e.target.value; state.scanId = null; loadMetrics(); };
$("#btn-ai-all").onclick = async () => {
  if (!state.scanId) return;
  const r = await api(`/api/v1/scans/${state.scanId}/ai`, { method: "POST" });
  alertMsg(`${r.queued} achado(s) enviados para triagem por IA.`);
  loadFindings();
};

function alertMsg(text) { $("#scan-msg").textContent = text; }

$("#form-upload").onsubmit = async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  try {
    const s = await api("/api/v1/scans/upload", { method: "POST", body: fd });
    alertMsg(`Varredura #${s.id} enfileirada.`);
    state.scanId = s.id; await loadProjects(); await loadMetrics();
  } catch (err) { alertMsg(`Erro: ${err.message}`); }
};
$("#form-git").onsubmit = async (e) => {
  e.preventDefault();
  const body = JSON.stringify({ repo_url: new FormData(e.target).get("repo_url") });
  try {
    const s = await api("/api/v1/scans/git", { method: "POST", headers: { "Content-Type": "application/json" }, body });
    alertMsg(`Varredura #${s.id} enfileirada (clonando repositório…).`);
    state.scanId = s.id; await loadProjects(); await loadMetrics();
  } catch (err) { alertMsg(`Erro: ${err.message}`); }
};

// Tema: respeita o sistema, com alternância manual que vence nos dois sentidos.
$("#theme-toggle").onclick = () => {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem("theme", root.dataset.theme); } catch (_) { /* armazenamento indisponível */ }
  loadMetrics();
};
try { const t = localStorage.getItem("theme"); if (t) document.documentElement.dataset.theme = t; } catch (_) { /* idem */ }

(async function init() {
  api("/api/v1/ai/status").then((s) => {
    const b = $("#ai-badge");
    b.textContent = s.available ? `IA: ${s.model} online` : "IA: offline (base de conhecimento)";
  }).catch(() => { $("#ai-badge").textContent = "IA: indisponível"; });
  await loadProjects();
  await loadMetrics();
})().catch((err) => alertMsg(`Erro ao carregar: ${err.message}`));
