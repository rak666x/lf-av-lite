// node-ui/web-server.js
const path = require("path");
const fs = require("fs");
const express = require("express");
const multer = require("multer");
const { spawn } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const DATA_DIR = path.join(ROOT, "data");
const UPLOADS_DIR = path.join(DATA_DIR, "uploads");
const SETTINGS_PATH = path.join(DATA_DIR, "settings.json");

// ✅ IMPORTANT: your UI lives here
const PUBLIC_DIR = path.join(__dirname, "public");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const DEFAULT_SETTINGS = {
  heuristics_enabled: true,
  storage: "json",
  exclusions: []
};

function loadSettings() {
  try {
    if (!fs.existsSync(SETTINGS_PATH)) {
      fs.writeFileSync(SETTINGS_PATH, JSON.stringify(DEFAULT_SETTINGS, null, 2), "utf8");
      return { ...DEFAULT_SETTINGS };
    }

    const parsed = JSON.parse(fs.readFileSync(SETTINGS_PATH, "utf8"));

    const exclusions = Array.isArray(parsed.exclusions)
      ? parsed.exclusions
      : (typeof parsed.exclusions === "string"
          ? parsed.exclusions
              .split(/[,\n]+/)
              .map(s => s.trim())
              .filter(Boolean)
          : []);

    return {
      heuristics_enabled: !!parsed.heuristics_enabled,
      storage: parsed.storage === "sqlite" ? "sqlite" : "json",
      exclusions
    };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

function saveSettings(next = {}) {
  const exclusions = Array.isArray(next.exclusions)
    ? next.exclusions
    : (typeof next.exclusions === "string"
        ? next.exclusions
            .split(/[,\n]+/)
            .map(s => s.trim())
            .filter(Boolean)
        : []);

  const safe = {
    heuristics_enabled: !!next.heuristics_enabled,
    storage: next.storage === "sqlite" ? "sqlite" : "json",
    exclusions
  };

  fs.writeFileSync(SETTINGS_PATH, JSON.stringify(safe, null, 2), "utf8");
  return safe;
}

// Upload config
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOADS_DIR),
  filename: (_, file, cb) => {
    const safe = (file.originalname || "upload")
      .replace(/[^\w.\-]+/g, "_")
      .slice(0, 80);
    cb(null, `${Date.now()}_${safe}`);
  },
});
const upload = multer({ storage });

// Python runner (module mode to avoid relative import errors)
const PY = process.env.AV_LITE_PYTHON || "python";
function runPython(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(PY, args, { cwd: ROOT, windowsHide: true });
    let out = "", err = "";
    child.stdout.on("data", d => out += d.toString());
    child.stderr.on("data", d => err += d.toString());
    child.on("close", code => {
      if (code !== 0) return reject(new Error(err || `Python exit ${code}`));
      try { resolve(JSON.parse(out)); }
      catch { reject(new Error("Invalid JSON from scanner:\n" + out)); }
    });
  });
}

const app = express();
app.use(express.json({ limit: "1mb" }));

// ✅ Serve your public UI folder
app.use(express.static(PUBLIC_DIR));

// ✅ FIXES "Cannot GET /" and the ENOENT you're seeing
app.get("/", (req, res) => {
  const indexPath = path.join(PUBLIC_DIR, "index.html");
  if (!fs.existsSync(indexPath)) {
    return res.status(500).send("Missing public/index.html");
  }
  res.sendFile(indexPath);
});

// Settings
app.get("/api/settings", (req, res) => res.json(loadSettings()));
app.post("/api/settings", (req, res) => res.json(saveSettings(req.body)));

// Scan file
app.post("/api/scan/file", async (req, res) => {
  try {
    const filePath = (req.body?.path || "").trim();
    if (!filePath) return res.status(400).json({ error: "Missing file path." });

    const s = loadSettings();
    const result = await runPython([
      "-m", "scanner.main",
      "scan-file",
      "--path", filePath,
      "--heuristics", s.heuristics_enabled ? "true" : "false",
      "--storage", s.storage
    ]);

    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Scan directory
app.post("/api/scan/directory", async (req, res) => {
  try {
    const dirPath = (req.body?.path || "").trim();
    const recursive = !!req.body?.recursive;
    if (!dirPath) return res.status(400).json({ error: "Missing directory path." });

    const s = loadSettings();
    const result = await runPython([
      "-m", "scanner.main",
      "scan-dir",
      "--path", dirPath,
      "--recursive", recursive ? "true" : "false",
      "--heuristics", s.heuristics_enabled ? "true" : "false",
      "--storage", s.storage
    ]);

    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Upload & scan
app.post("/api/scan/upload", upload.single("file"), async (req, res) => {
  try {
    const uploaded = req.file?.path;
    if (!uploaded) return res.status(400).json({ error: "No file uploaded." });

    const s = loadSettings();
    const result = await runPython([
      "-m", "scanner.main",
      "scan-file",
      "--path", uploaded,
      "--heuristics", s.heuristics_enabled ? "true" : "false",
      "--storage", s.storage
    ]);

    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Offline signature update
app.post("/api/signatures/update", async (req, res) => {
  try {
    const sigPath = (req.body?.path || "").trim();
    if (!sigPath) return res.status(400).json({ error: "Missing signature update path." });

    const result = await runPython([
      "-m", "scanner.main",
      "update-signatures",
      "--path", sigPath
    ]);

    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// History
app.get("/api/history", async (req, res) => {
  try {
    const s = loadSettings();
    const result = await runPython([
      "-m", "scanner.main",
      "history",
      "--storage", s.storage
    ]);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const PORT = process.env.AVLITE_PORT || 4545;

function start() {
  const server = app.listen(PORT, "127.0.0.1", () => {
    console.log(`AV-Lite server http://127.0.0.1:${PORT}`);
  });
  return server;
}

if (require.main === module) start();

module.exports = { start, PORT };
