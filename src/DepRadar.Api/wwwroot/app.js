"use strict";

const els = {
  input: document.getElementById("packageInput"),
  scan: document.getElementById("scanButton"),
  ecosystem: document.getElementById("ecosystemSelect"),
  status: document.getElementById("status"),
  intro: document.getElementById("intro"),
  results: document.getElementById("results"),
  overall: document.getElementById("overall"),
  graph: document.getElementById("graph"),
  tableBody: document.querySelector("#riskTable tbody"),
  drill: document.getElementById("drill"),
  upgrade: document.getElementById("upgrade"),
  report: document.getElementById("reportButton"),
  sbom: document.getElementById("sbomButton"),
  chatInput: document.getElementById("chatInput"),
  chatButton: document.getElementById("chatButton"),
  chatAnswer: document.getElementById("chatAnswer"),
  diffFrom: document.getElementById("diffFrom"),
  diffTo: document.getElementById("diffTo"),
  diffButton: document.getElementById("diffButton"),
  diffResult: document.getElementById("diffResult"),
  driftMeta: document.getElementById("driftMeta"),
  driftResult: document.getElementById("driftResult"),
  projectToggle: document.getElementById("projectToggle"),
  projectPanel: document.getElementById("projectPanel"),
  projectInput: document.getElementById("projectInput"),
  projectScan: document.getElementById("projectScanButton"),
  projectResults: document.getElementById("projectResults"),
};

const LEVEL_COLOR = {
  None: "#34d399", Low: "#34d399", Medium: "#fbbf24", High: "#fb923c", Critical: "#f87171",
};

let currentPackage = null;
let riskRows = [];
let vulnPaths = {};
let remediations = {};
let currentDrillPkg = null;
let sortKey = "score";
let sortAsc = true;
let activeSingleScanId = null;
const projectScans = new Map(); // scanId -> { packageId, chip }

// ---- SignalR live progress -------------------------------------------------

const connection = new signalR.HubConnectionBuilder()
  .withUrl("/hubs/scan")
  .withAutomaticReconnect()
  .build();

connection.on("ScanUpdated", (scan) => {
  if (projectScans.has(scan.id)) {
    updateProjectChip(scan);
    return;
  }
  if (scan.id !== activeSingleScanId) return;

  setStatus(scan.status, `${scan.packagesDiscovered} pkgs · ${scan.edgesWritten} edges`);
  if (scan.status === "Completed") {
    loadResults(scan.rootPackageId);
  } else if (scan.status === "Failed") {
    setStatus("Failed", scan.error || "scan failed", true);
  }
});

connection.start().catch((err) => console.error("SignalR connect failed", err));

// ---- Scan ------------------------------------------------------------------

els.scan.addEventListener("click", startScan);
els.input.addEventListener("keydown", (e) => { if (e.key === "Enter") startScan(); });
document.querySelectorAll(".example").forEach((b) =>
  b.addEventListener("click", () => { els.input.value = b.dataset.package; startScan(); }));

async function startScan() {
  const pkg = els.input.value.trim();
  if (!pkg) return;

  const eco = els.ecosystem ? els.ecosystem.value : "nuget";
  if (eco !== "nuget") {
    els.scan.disabled = true;
    try {
      await loadLiveResults(eco, pkg);
    } finally {
      els.scan.disabled = false;
    }
    return;
  }

  els.scan.disabled = true;
  els.intro.classList.add("hidden");
  els.results.classList.add("hidden");
  setStatus("Queued", "submitting…");

  try {
    const res = await fetch(`/api/packages/${encodeURIComponent(pkg)}/scan`, { method: "POST" });
    if (!res.ok) throw new Error(`scan request failed (${res.status})`);
    const scan = await res.json();
    activeSingleScanId = scan.id;
    await connection.invoke("Subscribe", scan.id);
    setStatus(scan.status, "waiting for the worker…");
  } catch (err) {
    setStatus("Failed", err.message, true);
  } finally {
    els.scan.disabled = false;
  }
}

function setStatus(state, detail, failed) {
  const cls = failed ? "pill failed" : "pill";
  els.status.innerHTML = `<span class="${cls}">${state}</span>${detail ? ` ${detail}` : ""}`;
}

const placeholders = {
  nuget: "NuGet package id, e.g. Serilog.Sinks.Console",
  npm: "npm package, e.g. express — or lodash@4.17.20",
  pypi: "PyPI package, e.g. requests — or requests@2.19.1",
  cargo: "crate, e.g. serde — or regex@1.5.4",
  go: "Go module, e.g. golang.org/x/text — or …@v0.3.7",
};
els.ecosystem.addEventListener("change", () => {
  els.input.placeholder = placeholders[els.ecosystem.value] || placeholders.nuget;
});

// ---- Live multi-ecosystem mode ----------------------------------------------
// npm/PyPI/Cargo/Go resolve in-process (no queue, no DB); the DB-backed panels hide.

async function loadLiveResults(eco, raw) {
  const [pkg, version] = splitVersion(raw);
  currentPackage = pkg;
  els.intro.classList.add("hidden");
  els.results.classList.add("hidden");
  setStatus("Scanning", `resolving ${pkg} on ${eco} — this runs live and can take a moment…`);

  const path = pkg.split("/").map(encodeURIComponent).join("/");
  const dto = await getJson(`/api/live/${eco}/${path}${version ? `?version=${encodeURIComponent(version)}` : ""}`);
  if (!dto) {
    setStatus("Failed", `'${pkg}' could not be resolved on ${eco}.`, true);
    return;
  }

  vulnPaths = {};
  remediations = {};
  const levelByPkg = {};
  dto.risk.packages.forEach((p) => { levelByPkg[p.packageId.toLowerCase()] = p.level; });

  els.overall.textContent = `health ${dto.risk.overallScore}/100 (${dto.risk.overallLevel}) · ${dto.risk.packagesAssessed} packages · live`;
  renderGraph(dto.graph, levelByPkg);
  riskRows = dto.risk.packages;
  renderTable();

  els.results.classList.add("live");
  els.results.classList.remove("hidden");
  setStatus("Completed", `${dto.risk.packagesAssessed} packages assessed (live, not persisted)`);
}

// "name@version" → [name, version]; Go pseudo/npm scoped names keep their inner @.
function splitVersion(raw) {
  const at = raw.lastIndexOf("@");
  return at > 0 ? [raw.slice(0, at), raw.slice(at + 1)] : [raw, null];
}

// ---- Results ---------------------------------------------------------------

async function loadResults(pkg) {
  currentPackage = pkg;
  els.results.classList.remove("live");
  els.intro.classList.add("hidden");
  els.chatAnswer.innerHTML = "";
  els.diffResult.innerHTML = "";
  els.diffFrom.value = "";
  els.diffTo.value = "";
  setStatus("Completed", "rendering report…");

  const [graph, risk, upgrade, paths] = await Promise.all([
    getJson(`/api/packages/${encodeURIComponent(pkg)}/graph`),
    getJson(`/api/packages/${encodeURIComponent(pkg)}/graph/risk`),
    getJson(`/api/packages/${encodeURIComponent(pkg)}/upgrade`),
    getJson(`/api/packages/${encodeURIComponent(pkg)}/vulnerability-paths`),
  ]);

  if (!risk) return;

  vulnPaths = {};
  (paths ? paths.paths : []).forEach((p) => { vulnPaths[p.package.toLowerCase()] = p.path; });

  const levelByPkg = {};
  risk.packages.forEach((p) => { levelByPkg[p.packageId.toLowerCase()] = p.level; });

  els.overall.textContent = `health ${risk.overallScore}/100 (${risk.overallLevel}) · ${risk.packagesAssessed} packages`;
  renderGraph(graph, levelByPkg);
  riskRows = risk.packages;
  renderTable();
  renderUpgrade(upgrade);

  els.results.classList.remove("hidden");
  setStatus("Completed", `${risk.packagesAssessed} packages assessed`);

  loadDrift(pkg);
  loadRemediations(pkg);
}

async function loadRemediations(pkg) {
  remediations = {};
  const data = await getJson(`/api/packages/${encodeURIComponent(pkg)}/remediation`);
  (data ? data.remediations : []).forEach((r) => { remediations[r.package.toLowerCase()] = r.safeVersion; });
  if (currentDrillPkg) showDrill(currentDrillPkg); // re-render the open drill with the fix
}

async function loadDrift(pkg) {
  els.driftMeta.textContent = "";
  els.driftResult.innerHTML = "<span class='ai'>loading history…</span>";
  const drift = await getJson(`/api/packages/${encodeURIComponent(pkg)}/drift`);
  if (!drift) { els.driftResult.innerHTML = "<span class='ai'>no scan history yet</span>"; return; }

  if (!drift.hasBaseline) {
    els.driftResult.innerHTML = "<span class='ai'>baseline recorded — re-scan later to track drift over time</span>";
    return;
  }

  const since = new Date(drift.from).toLocaleString();
  const delta = drift.netHealthDelta > 0 ? `+${drift.netHealthDelta}` : `${drift.netHealthDelta}`;
  const deltaClass = drift.netHealthDelta > 0 ? "good" : drift.netHealthDelta < 0 ? "bad" : "";
  els.driftMeta.innerHTML = `since ${escapeHtml(since)} · net health <span class="diff-delta ${deltaClass}">${delta}</span>`;

  if (!drift.events.length) {
    els.driftResult.innerHTML = "<span class='ai'>no changes since the previous scan</span>";
    return;
  }

  const sev = (s) => (s === "None" ? "good" : s === "Medium" ? "warn" : s === "Low" ? "" : "bad");
  els.driftResult.innerHTML = `<ul class="drift-list">${drift.events.map((e) =>
    `<li class="${sev(e.severity)}"><span class="drift-kind">${escapeHtml(driftLabel(e.kind))}</span> `
    + `<span class="drift-pkg">${escapeHtml(e.package)}</span> — ${escapeHtml(e.detail)}</li>`).join("")}</ul>`;
}

function driftLabel(kind) {
  return ({
    BecameVulnerable: "▲ vulnerable", BecameDeprecated: "▲ deprecated", BecameArchived: "▲ archived",
    BecameStale: "▲ stale", HealthRegressed: "▼ health", HealthImproved: "△ health",
    AdvisoryCleared: "✓ cleared", PackageAdded: "+ added", PackageRemoved: "− removed",
  })[kind] || kind;
}

async function getJson(url) {
  const res = await fetch(url);
  return res.ok ? res.json() : null;
}

function renderGraph(graph, levelByPkg) {
  if (!graph) { els.graph.innerHTML = ""; return; }

  const nodes = graph.nodes.map((n) => ({
    data: {
      id: n.packageId,
      label: `${n.packageId}\n${n.version}`,
      color: LEVEL_COLOR[levelByPkg[n.packageId.toLowerCase()] || "None"],
      root: n.isRoot ? 1 : 0,
    },
  }));
  const edges = graph.edges.map((e) => ({ data: { source: e.fromId, target: e.toId } }));

  cytoscape({
    container: els.graph,
    elements: [...nodes, ...edges],
    style: [
      { selector: "node", style: {
          "background-color": "data(color)", "label": "data(label)", "color": "#e6edf3",
          "font-size": 9, "text-wrap": "wrap", "text-valign": "center", "text-halign": "center",
          "width": 26, "height": 26, "text-max-width": 90 } },
      { selector: "node[root = 1]", style: { "width": 40, "height": 40, "border-width": 3, "border-color": "#2dd4bf" } },
      { selector: "edge", style: {
          "width": 1.4, "line-color": "#2b3b57", "target-arrow-color": "#2b3b57",
          "target-arrow-shape": "triangle", "curve-style": "bezier", "arrow-scale": 0.8 } },
    ],
    layout: { name: "cose", animate: false, padding: 20 },
  });
}

function renderTable() {
  const rows = [...riskRows].sort((a, b) => {
    const x = a[sortKey], y = b[sortKey];
    const cmp = typeof x === "number" ? x - y : String(x).localeCompare(String(y));
    return sortAsc ? cmp : -cmp;
  });

  els.tableBody.innerHTML = rows.map((p, i) => `
    <tr data-index="${i}">
      <td>${escapeHtml(p.packageId)}</td>
      <td>${escapeHtml(p.version)}</td>
      <td class="num">${p.score}</td>
      <td><span class="badge ${p.level}">${p.level}</span></td>
    </tr>`).join("");

  els.tableBody.querySelectorAll("tr").forEach((tr) => {
    tr.addEventListener("click", () => showDrill(rows[Number(tr.dataset.index)]));
  });
}

function showDrill(pkg) {
  currentDrillPkg = pkg;
  if (!pkg.findings.length) {
    els.drill.innerHTML = `<strong>${escapeHtml(pkg.packageId)} ${escapeHtml(pkg.version)}</strong> — no findings.`;
    return;
  }
  const items = pkg.findings.map((f) =>
    `<li><span class="badge ${f.level}">${f.level}</span> ${escapeHtml(f.category)}: ${escapeHtml(f.message)}</li>`).join("");
  const key = pkg.packageId.toLowerCase();
  const path = vulnPaths[key];
  const via = path && path.length > 1
    ? `<div class="drill-path">pulled in via ${path.map((p) => escapeHtml(p)).join(" → ")}</div>`
    : "";
  const safe = remediations[key];
  const fix = safe
    ? `<div class="drill-fix">fix available: upgrade to ${escapeHtml(safe)}</div>`
    : "";
  els.drill.innerHTML = `<strong>${escapeHtml(pkg.packageId)} ${escapeHtml(pkg.version)}</strong><ul>${items}</ul>${via}${fix}`;
}

function renderUpgrade(advice) {
  if (!advice) { els.upgrade.innerHTML = "<span class='narrative'>No upgrade advice available.</span>"; return; }
  const points = advice.keyPoints.map((p) => `<li>${escapeHtml(p)}</li>`).join("");
  els.upgrade.innerHTML = `
    <div class="rec">${escapeHtml(advice.fromVersion)} → ${escapeHtml(advice.toVersion)}: ${escapeHtml(advice.recommendation)}
      ${advice.llmUsed ? "" : "<span style='font-size:12px;color:#5b6b82'>(templated — set an LLM key for an AI narrative)</span>"}</div>
    <div class="narrative">${escapeHtml(advice.narrative)}</div>
    ${points ? `<ul>${points}</ul>` : ""}`;
}

document.querySelectorAll("#riskTable th[data-sort]").forEach((th) => {
  th.addEventListener("click", () => {
    const key = th.dataset.sort;
    sortAsc = sortKey === key ? !sortAsc : true;
    sortKey = key;
    renderTable();
  });
});

els.report.addEventListener("click", async () => {
  if (!currentPackage) return;
  const res = await fetch(`/api/packages/${encodeURIComponent(currentPackage)}/report`);
  if (!res.ok) return;
  const text = await res.text();
  const url = URL.createObjectURL(new Blob([text], { type: "text/markdown" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = `${currentPackage}-depradar-report.md`;
  a.click();
  URL.revokeObjectURL(url);
});

// ---- Project scan (.csproj / packages.lock.json) ---------------------------

els.projectToggle.addEventListener("click", () => els.projectPanel.classList.toggle("hidden"));
els.projectScan.addEventListener("click", submitProject);

async function submitProject() {
  const content = els.projectInput.value.trim();
  if (!content) return;
  els.projectScan.disabled = true;
  els.projectResults.innerHTML = "<span class='state'>parsing…</span>";

  try {
    const res = await fetch("/api/projects/scan", {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: content,
    });
    if (!res.ok) throw new Error(`project scan failed (${res.status})`);

    const dto = await res.json();
    els.projectResults.innerHTML = "";
    projectScans.clear();
    for (const pkg of dto.packages) {
      const chip = addProjectChip(pkg.packageId);
      projectScans.set(pkg.scanId, { packageId: pkg.packageId, chip });
      await connection.invoke("Subscribe", pkg.scanId);
    }
  } catch (err) {
    els.projectResults.innerHTML = `<span class="state" style="color:#f87171">${escapeHtml(err.message)}</span>`;
  } finally {
    els.projectScan.disabled = false;
  }
}

function addProjectChip(packageId) {
  const chip = document.createElement("span");
  chip.className = "chip";
  chip.innerHTML = `${escapeHtml(packageId)} <span class="state">Queued</span>`;
  els.projectResults.appendChild(chip);
  return chip;
}

function updateProjectChip(scan) {
  const entry = projectScans.get(scan.id);
  if (!entry) return;

  if (scan.status === "Completed") {
    const link = document.createElement("a");
    link.className = "chip";
    link.href = `/?package=${encodeURIComponent(entry.packageId)}`;
    link.innerHTML = `${escapeHtml(entry.packageId)} <span class="state" style="color:#34d399">✓ view report</span>`;
    entry.chip.replaceWith(link);
    entry.chip = link;
  } else {
    entry.chip.querySelector(".state").textContent = scan.status;
  }
}

// ---- SBOM + chat -----------------------------------------------------------

els.sbom.addEventListener("click", async () => {
  if (!currentPackage) return;
  const res = await fetch(`/api/packages/${encodeURIComponent(currentPackage)}/sbom`);
  if (!res.ok) return;
  const text = await res.text();
  const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = `${currentPackage}.cdx.json`;
  a.click();
  URL.revokeObjectURL(url);
});

els.chatButton.addEventListener("click", () => askChat(els.chatInput.value));
els.chatInput.addEventListener("keydown", (e) => { if (e.key === "Enter") askChat(els.chatInput.value); });
document.querySelectorAll(".suggest").forEach((b) =>
  b.addEventListener("click", () => { els.chatInput.value = b.dataset.q; askChat(b.dataset.q); }));

async function askChat(question) {
  const q = (question || "").trim();
  if (!q || !currentPackage) return;
  els.chatButton.disabled = true;
  els.chatAnswer.innerHTML = "<span class='ai'>thinking…</span>";
  try {
    const res = await fetch(`/api/packages/${encodeURIComponent(currentPackage)}/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question: q }),
    });
    if (!res.ok) throw new Error(`chat failed (${res.status})`);
    const dto = await res.json();
    const refs = dto.packages.length
      ? `<div class="refs">${dto.packages.map((p) => `<span class="ref">${escapeHtml(p)}</span>`).join("")}</div>`
      : "";
    const note = dto.llmUsed ? "" : `<span class="ai">· rule-based (set an LLM key for AI answers)</span>`;
    els.chatAnswer.innerHTML = `${escapeHtml(dto.answer)}${note}${refs}`;
  } catch (err) {
    els.chatAnswer.innerHTML = `<span class="ai" style="color:#f87171">${escapeHtml(err.message)}</span>`;
  } finally {
    els.chatButton.disabled = false;
  }
}

els.diffButton.addEventListener("click", runDiff);
[els.diffFrom, els.diffTo].forEach((el) =>
  el.addEventListener("keydown", (e) => { if (e.key === "Enter") runDiff(); }));

async function runDiff() {
  const from = els.diffFrom.value.trim();
  const to = els.diffTo.value.trim();
  if (!from || !to || !currentPackage) return;
  els.diffButton.disabled = true;
  els.diffResult.innerHTML = "<span class='ai'>resolving both versions…</span>";
  try {
    const url = `/api/packages/${encodeURIComponent(currentPackage)}/diff`
      + `?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`;
    const res = await fetch(url);
    if (res.status === 404) throw new Error("one of the versions could not be resolved");
    if (!res.ok) throw new Error(`diff failed (${res.status})`);
    renderDiff(await res.json());
  } catch (err) {
    els.diffResult.innerHTML = `<span class="ai" style="color:#f87171">${escapeHtml(err.message)}</span>`;
  } finally {
    els.diffButton.disabled = false;
  }
}

function renderDiff(d) {
  const delta = d.scoreDelta > 0 ? `+${d.scoreDelta}` : `${d.scoreDelta}`;
  const deltaClass = d.scoreDelta > 0 ? "good" : d.scoreDelta < 0 ? "bad" : "";
  const section = (title, items, cls) => items.length
    ? `<div class="diff-sec"><span class="diff-title ${cls || ""}">${title} (${items.length})</span>`
      + `<ul>${items.map((i) => `<li>${escapeHtml(i)}</li>`).join("")}</ul></div>`
    : "";
  const changes = d.changedPackages.map((c) => `${c.package} ${c.fromVersion} → ${c.toVersion}`);

  els.diffResult.innerHTML =
    `<div class="diff-head">${escapeHtml(d.fromVersion)} → ${escapeHtml(d.toVersion)} · `
    + `health ${d.fromScore} (${d.fromLevel}) → ${d.toScore} (${d.toLevel}) `
    + `<span class="diff-delta ${deltaClass}">${delta}</span></div>`
    + section("New advisories", d.newAdvisories, "bad")
    + section("Cleared advisories", d.resolvedAdvisories, "good")
    + section("Added dependencies", d.addedPackages, "bad")
    + section("Removed dependencies", d.removedPackages, "good")
    + section("Version changes", changes, "")
    + (d.newAdvisories.length + d.resolvedAdvisories.length + d.addedPackages.length
       + d.removedPackages.length + changes.length === 0
        ? "<div class='ai'>no graph or advisory changes</div>" : "");
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// Deep link: /?package=Some.Package loads a previously scanned package's report
// directly (shareable link) and opens its worst finding.
(function deepLink() {
  const params = new URLSearchParams(location.search);
  const pkg = params.get("package");
  if (!pkg) return;
  els.input.value = pkg;

  // ?eco=npm&package=express deep-links straight into the live multi-ecosystem mode.
  const eco = (params.get("eco") || "nuget").toLowerCase();
  if (eco !== "nuget") {
    els.ecosystem.value = eco;
    els.input.placeholder = placeholders[eco] || placeholders.nuget;
    loadLiveResults(eco, pkg);
    return;
  }

  setStatus("Completed", "loading stored report…");
  loadResults(pkg).then(() => {
    // Open a specific package's drill-down (?drill=<id>) or the worst finding by default.
    const drill = params.get("drill");
    const target = drill
      ? riskRows.find((p) => p.packageId.toLowerCase() === drill.toLowerCase())
      : null;
    if (target) {
      showDrill(target);
    } else if (riskRows.length) {
      showDrill(riskRows.reduce((worst, p) => (p.score <= worst.score ? p : worst)));
    }
    const ask = params.get("ask");
    if (ask) {
      els.chatInput.value = ask;
      askChat(ask);
    }
    // Shareable upgrade diff: ?diff=<from>..<to> (e.g. diff=12.0.3..13.0.3)
    const diff = params.get("diff");
    if (diff && diff.includes("..")) {
      const [from, to] = diff.split("..");
      els.diffFrom.value = from;
      els.diffTo.value = to;
      runDiff();
    }
  });
})();
