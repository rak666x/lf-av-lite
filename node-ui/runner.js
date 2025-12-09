const { spawnSync } = require("child_process");
const path = require("path");
const fs = require("fs");

// Project root is one level above node-ui/
const PROJECT_ROOT = path.resolve(__dirname, "..");
const SCANNER_MODULE = "scanner.main";

function tryPythonExecutables(args, options = {}) {
  const candidates = ["python", "py", "python3"];
  let lastErr = null;

  for (const cmd of candidates) {
    try {
      const res = spawnSync(cmd, ["-m", SCANNER_MODULE, ...args], {
        encoding: "utf8",
        windowsHide: true,
        cwd: PROJECT_ROOT, // critical for module resolution
        ...options
      });

      if (res.error) {
        lastErr = res.error;
        continue;
      }

      return { ...res, used: cmd };
    } catch (e) {
      lastErr = e;
    }
  }

  const msg = lastErr ? (lastErr.message || String(lastErr)) : "Python executable not found.";

  return {
    error: new Error(
      "Python not found. Please install Python 3.10+ and ensure it is on PATH.\n" +
        "Tried: python, py, python3\n" +
        "Details: " + msg
    )
  };
}

function runPython(args) {
  const res = tryPythonExecutables(args);

  if (res.error) {
    return { ok: false, error: res.error, raw: null };
  }

  const stdout = (res.stdout || "").trim();
  const stderr = (res.stderr || "").trim();

  let payload = null;
  if (stdout) {
    try {
      payload = JSON.parse(stdout);
    } catch (_) {
      payload = null;
    }
  }

  if (res.status !== 0) {
    const errMsg =
      (payload && payload.error && payload.error.message) ||
      stderr ||
      "Scanner returned an error.";

    return { ok: false, error: new Error(errMsg), raw: { stdout, stderr, payload } };
  }

  return { ok: true, data: payload, raw: { stdout, stderr, payload } };
}

// Public API used by UI
function scanFile(filePath, heuristicsEnabled, storage) {
  const args = [
    "scan-file",
    "--path",
    filePath,
    "--heuristics",
    heuristicsEnabled ? "true" : "false",
    "--storage",
    storage
  ];
  return runPython(args);
}

function scanDir(dirPath, recursive, heuristicsEnabled, storage) {
  const args = [
    "scan-dir",
    "--path",
    dirPath,
    "--recursive",
    recursive ? "true" : "false",
    "--heuristics",
    heuristicsEnabled ? "true" : "false",
    "--storage",
    storage
  ];
  return runPython(args);
}

function updateSignatures(localSigPath) {
  const args = ["update-signatures", "--file", localSigPath];
  return runPython(args);
}

function getHistory(storage) {
  const args = ["history", "--storage", storage];
  return runPython(args);
}

// Settings live in data/settings.json
function ensureDataSettingsFile() {
  const dataDir = path.resolve(__dirname, "..", "data");
  const settingsPath = path.join(dataDir, "settings.json");

  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  if (!fs.existsSync(settingsPath)) {
    const defaultSettings = {
      heuristics_enabled: true,
      storage: "json"
    };
    fs.writeFileSync(settingsPath, JSON.stringify(defaultSettings, null, 2), "utf8");
  }

  return settingsPath;
}

function loadSettings() {
  const settingsPath = ensureDataSettingsFile();
  try {
    const raw = fs.readFileSync(settingsPath, "utf8");
    const parsed = JSON.parse(raw);

    const heuristics_enabled =
      typeof parsed.heuristics_enabled === "boolean" ? parsed.heuristics_enabled : true;

    const storage = parsed.storage === "sqlite" ? "sqlite" : "json";

    return { heuristics_enabled, storage, settingsPath };
  } catch (_) {
    return { heuristics_enabled: true, storage: "json", settingsPath };
  }
}

function saveSettings(next) {
  const settingsPath = ensureDataSettingsFile();
  const payload = {
    heuristics_enabled: !!next.heuristics_enabled,
    storage: next.storage === "sqlite" ? "sqlite" : "json"
  };
  fs.writeFileSync(settingsPath, JSON.stringify(payload, null, 2), "utf8");
  return payload;
}

module.exports = {
  scanFile,
  scanDir,
  updateSignatures,
  getHistory,
  loadSettings,
  saveSettings
};
