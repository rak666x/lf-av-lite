/* LF-AV-Lite MVP - Web UI controller (educational, local only)
   This file intentionally avoids any offensive capability.
*/
(() => {
  const $ = (id) => document.getElementById(id);

  // ---- Elements (based on your uploaded HTML)
  const els = {
    // settings
    heuristicsToggle: $("heuristicsToggle"),
    storageSelect: $("storageSelect"),
    saveSettingsBtn: $("saveSettingsBtn"),
    settingsStatus: $("settingsStatus"),

    // tabs/panels
    tabFile: $("tabFile"),
    tabDir: $("tabDir"),
    panelFile: $("panelFile"),
    panelDir: $("panelDir"),

    // file scan
    filePath: $("filePath"),
    scanFileBtn: $("scanFileBtn"),
    filePicker: $("filePicker"),
    uploadScanBtn: $("uploadScanBtn"),

    // dir scan
    dirPath: $("dirPath"),
    recursiveToggle: $("recursiveToggle"),
    scanDirBtn: $("scanDirBtn"),

    // sig update
    sigPath: $("sigPath"),
    updateSigsBtn: $("updateSigsBtn"),

    // results
    clearBtn: $("clearBtn"),
    loadHistoryBtn: $("loadHistoryBtn"),
    output: $("output"),
  };

  // ---- Adjust these if your Express routes differ
  const ENDPOINTS = {
    settings: "/api/settings",
    scanFile: "/api/scan/file",
    scanDir: "/api/scan/directory",
    uploadScan: "/api/scan/upload",
    updateSigs: "/api/signatures/update",
    history: "/api/history",
  };

  // ---- Helpers
  function escapeHtml(str = "") {
    return String(str).replace(/[&<>"']/g, (m) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[m]));
  }

  function setOutput(html) {
    els.output.innerHTML = html;
  }

  function setStatus(msg, ok = true) {
    if (!els.settingsStatus) return;
    els.settingsStatus.textContent = msg;
    els.settingsStatus.style.color = ok ? "" : "var(--danger)";
  }

  function setBusy(isBusy) {
    const buttons = [
      els.saveSettingsBtn,
      els.scanFileBtn,
      els.uploadScanBtn,
      els.scanDirBtn,
      els.updateSigsBtn,
      els.clearBtn,
      els.loadHistoryBtn,
    ].filter(Boolean);

    buttons.forEach((b) => (b.disabled = !!isBusy));

    if (isBusy) {
      setOutput(`<div class="muted small">Working...</div>`);
    }
  }

  async function safeJsonFetch(url, options = {}) {
    const headers = options.headers || {};
    const merged = {
      ...options,
      headers: {
        ...headers,
      },
    };

    const res = await fetch(url, merged);
    const text = await res.text();

    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = { raw: text };
    }

    if (!res.ok) {
      const msg =
        (data && data.error) ||
        (data && data.message) ||
        `Request failed (${res.status})`;
      throw new Error(msg);
    }

    return data;
  }

  async function jsonPost(url, bodyObj) {
    return safeJsonFetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(bodyObj || {}),
    });
  }

  // ---- Tabs
  function activateTab(mode) {
    const isFile = mode === "file";
    els.tabFile.classList.toggle("active", isFile);
    els.tabDir.classList.toggle("active", !isFile);
    els.panelFile.classList.toggle("active", isFile);
    els.panelDir.classList.toggle("active", !isFile);
  }

  // ---- Rendering scan responses
  function statusToPill(status) {
    if (!status) return "pill";
    if (status === "clean") return "pill clean";
    if (status === "eicar_test") return "pill test";
    return "pill warn";
  }

  function friendlyStatus(status) {
    switch (status) {
      case "clean": return "clean";
      case "signature_match": return "signature";
      case "heuristic_flag": return "heuristics";
      case "eicar_test": return "EICAR test";
      default: return status || "unknown";
    }
  }

  function renderScanResponse(data, title = "Scan result") {
    if (!data) {
      return `<div class="muted small">No data returned.</div>`;
    }

    const summary = data.summary || {};
    const results = Array.isArray(data.results) ? data.results : [];
    const flagged = results.filter((r) => r.status && r.status !== "clean");

    const pillClass = flagged.length ? "pill warn" : "pill clean";
    const pillText = flagged.length ? `${flagged.length} flagged` : "clean";

    const header = `
      <div class="result-header">
        <div>
          <div class="result-title">${escapeHtml(title)}</div>
          <div class="result-meta">
            ${escapeHtml(data.timestamp || "")}
            ${data.mode ? " • " + escapeHtml(data.mode) : ""}
          </div>
        </div>
        <div class="${pillClass}">${pillText}</div>
      </div>
    `;

    const kv = `
      <div class="kv">
        <div><span class="k">Target</span><span class="v mono">${escapeHtml(data.target || "")}</span></div>
        <div><span class="k">Heuristics</span><span class="v">${data.heuristics_enabled ? "on" : "off"}</span></div>
        <div><span class="k">Storage</span><span class="v">${escapeHtml(data.storage || "")}</span></div>
        <div><span class="k">Files scanned</span><span class="v">${summary.files_scanned ?? results.length ?? 0}</span></div>
      </div>
    `;

    const flaggedHtml = flagged.length
      ? flagged.map((r) => {
          const reasons = Array.isArray(r.reasons) ? r.reasons : [];
          return `
            <div class="file-row">
              <div class="row">
                <div class="pill ${statusToPill(r.status).split(" ").slice(1).join(" ")}">
                  ${escapeHtml(friendlyStatus(r.status))}
                </div>
                <div class="muted small">risk ${escapeHtml(String(r.risk_score ?? 0))}</div>
              </div>
              <div class="file-path mono">${escapeHtml(r.path || "")}</div>
              ${r.sha256 ? `<div class="muted small mono">sha256: ${escapeHtml(r.sha256)}</div>` : ""}
              ${reasons.length ? `
                <ul class="reason-list">
                  ${reasons.map((x) => `<li>${escapeHtml(x)}</li>`).join("")}
                </ul>
              ` : ""}
            </div>
          `;
        }).join("")
      : `<div class="muted small">No suspicious indicators found.</div>`;

    const raw = escapeHtml(JSON.stringify(data, null, 2));

    return `
      <div class="result-wrap">
        ${header}
        ${kv}
        <div class="divider"></div>
        <div>
          <div class="small muted" style="margin-bottom:6px;">Flagged files</div>
          <div class="stack">${flaggedHtml}</div>
        </div>
        <details class="raw">
          <summary>Raw JSON</summary>
          <pre>${raw}</pre>
        </details>
      </div>
    `;
  }

  function renderHistory(data) {
    // Accept either {items:[...]} or an array
    const items = Array.isArray(data) ? data : (data && data.items) || [];
    if (!items.length) {
      return `<div class="muted small">No history found yet.</div>`;
    }

    const rows = items.slice(0, 50).map((h) => {
      const ts = h.timestamp || "";
      const target = h.target || "";
      const flagged = (h.summary && h.summary.flagged) ?? h.flagged_count ?? 0;
      const mode = h.mode || "";
      return `
        <div class="file-row">
          <div class="row">
            <div class="pill ${flagged ? "warn" : "clean"}">${flagged ? `${flagged} flagged` : "clean"}</div>
            <div class="muted small">${escapeHtml(mode)}</div>
          </div>
          <div class="muted small">${escapeHtml(ts)}</div>
          <div class="file-path mono">${escapeHtml(target)}</div>
        </div>
      `;
    }).join("");

    return `
      <div class="result-wrap">
        <div class="result-header">
          <div>
            <div class="result-title">Scan history (latest)</div>
            <div class="result-meta">Showing up to 50 entries</div>
          </div>
        </div>
        <div class="stack">${rows}</div>
      </div>
    `;
  }

  // ---- Actions
  async function loadSettings() {
    try {
      const data = await safeJsonFetch(ENDPOINTS.settings);
      if (typeof data.heuristics_enabled === "boolean") {
        els.heuristicsToggle.checked = data.heuristics_enabled;
      }
      if (data.storage) {
        els.storageSelect.value = data.storage;
      }
      setStatus("Settings loaded.");
    } catch (err) {
      // Fail softly; defaults on UI
      setStatus("Could not load settings (using UI defaults).", false);
    }
  }

  async function saveSettings() {
    const payload = {
      heuristics_enabled: !!els.heuristicsToggle.checked,
      storage: els.storageSelect.value || "json",
    };

    setBusy(true);
    try {
      await jsonPost(ENDPOINTS.settings, payload);
      setStatus("Settings saved.");
      setOutput(`<div class="muted small">Settings updated.</div>`);
    } catch (err) {
      setStatus(`Settings error: ${err.message}`, false);
      setOutput(`<div class="muted small">Settings update failed.</div>`);
    } finally {
      setBusy(false);
    }
  }

  async function scanFileByPath() {
    const path = (els.filePath.value || "").trim();
    if (!path) {
      setOutput(`<div class="muted small">Please enter a file path.</div>`);
      return;
    }

    setBusy(true);
    try {
      const data = await jsonPost(ENDPOINTS.scanFile, { path });
      setOutput(renderScanResponse(data, "File scan"));
    } catch (err) {
      setOutput(`<div class="muted small">Scan error: ${escapeHtml(err.message)}</div>`);
    } finally {
      setBusy(false);
    }
  }

  async function uploadAndScan() {
    const file = els.filePicker.files && els.filePicker.files[0];
    if (!file) {
      setOutput(`<div class="muted small">Please choose a file to upload.</div>`);
      return;
    }

    const fd = new FormData();
    fd.append("file", file);

    setBusy(true);
    try {
      const data = await safeJsonFetch(ENDPOINTS.uploadScan, {
        method: "POST",
        body: fd,
      });
      setOutput(renderScanResponse(data, "Uploaded file scan"));
    } catch (err) {
      setOutput(`<div class="muted small">Upload/scan error: ${escapeHtml(err.message)}</div>`);
    } finally {
      setBusy(false);
      els.filePicker.value = "";
    }
  }

  async function scanDirectoryByPath() {
    const path = (els.dirPath.value || "").trim();
    if (!path) {
      setOutput(`<div class="muted small">Please enter a directory path.</div>`);
      return;
    }

    const recursive = !!els.recursiveToggle.checked;

    setBusy(true);
    try {
      const data = await jsonPost(ENDPOINTS.scanDir, { path, recursive });
      setOutput(renderScanResponse(data, "Directory scan"));
    } catch (err) {
      setOutput(`<div class="muted small">Scan error: ${escapeHtml(err.message)}</div>`);
    } finally {
      setBusy(false);
    }
  }

  async function updateSignatures() {
    const path = (els.sigPath.value || "").trim();
    if (!path) {
      setOutput(`<div class="muted small">Please enter a local signatures JSON path.</div>`);
      return;
    }

    setBusy(true);
    try {
      const data = await jsonPost(ENDPOINTS.updateSigs, { path });
      const msg = data && data.message ? data.message : "Signatures updated.";
      setOutput(`<div class="muted small">${escapeHtml(msg)}</div>`);
    } catch (err) {
      setOutput(`<div class="muted small">Update error: ${escapeHtml(err.message)}</div>`);
    } finally {
      setBusy(false);
    }
  }

  async function loadHistory() {
    setBusy(true);
    try {
      const data = await safeJsonFetch(ENDPOINTS.history);
      setOutput(renderHistory(data));
    } catch (err) {
      setOutput(`<div class="muted small">History error: ${escapeHtml(err.message)}</div>`);
    } finally {
      setBusy(false);
    }
  }

  function clearOutput() {
    setOutput("");
  }

  // ---- Wire up events
  function bindEvents() {
    els.tabFile.addEventListener("click", () => activateTab("file"));
    els.tabDir.addEventListener("click", () => activateTab("dir"));

    els.saveSettingsBtn.addEventListener("click", saveSettings);

    els.scanFileBtn.addEventListener("click", scanFileByPath);
    els.filePath.addEventListener("keydown", (e) => {
      if (e.key === "Enter") scanFileByPath();
    });

    els.uploadScanBtn.addEventListener("click", uploadAndScan);

    els.scanDirBtn.addEventListener("click", scanDirectoryByPath);
    els.dirPath.addEventListener("keydown", (e) => {
      if (e.key === "Enter") scanDirectoryByPath();
    });

    els.updateSigsBtn.addEventListener("click", updateSignatures);

    els.clearBtn.addEventListener("click", clearOutput);
    els.loadHistoryBtn.addEventListener("click", loadHistory);
  }

  // ---- Init
  document.addEventListener("DOMContentLoaded", async () => {
    bindEvents();
    activateTab("file");
    await loadSettings();
    setOutput(`<div class="muted small">Ready. Choose a scan method above.</div>`);
  });
})();
