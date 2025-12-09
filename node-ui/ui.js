const inquirer = require("inquirer");
const path = require("path");
const fs = require("fs");

const {
  scanFile,
  scanDir,
  updateSignatures,
  getHistory,
  loadSettings,
  saveSettings
} = require("./runner");

function formatReasons(reasons) {
  if (!reasons || !reasons.length) return "";
  return reasons.map((r) => `- ${r}`).join("\n");
}

function printScanSummary(report) {
  const { summary, results, target, mode, heuristics_enabled, storage, timestamp } = report;

  console.log("\n==============================");
  console.log("AV-Lite Scan Complete");
  console.log("==============================");
  console.log(`Time:        ${timestamp}`);
  console.log(`Target:      ${target}`);
  console.log(`Mode:        ${mode}`);
  console.log(`Heuristics:  ${heuristics_enabled ? "ON" : "OFF"}`);
  console.log(`Storage:     ${storage}`);
  console.log("------------------------------");
  console.log(`Files scanned: ${summary?.files_scanned ?? 0}`);
  console.log(`Flagged:       ${summary?.flagged ?? 0}`);

  const flagged = (results || []).filter(r => r.status !== "clean");

  if (flagged.length) {
    console.log("\nFlagged Files:");
    for (const f of flagged) {
      console.log("\n--------------------------------");
      console.log(`Path:  ${f.path}`);
      console.log(`Status:${f.status}`);
      console.log(`Risk:  ${f.risk_score}`);
      if (f.sha256) console.log(`SHA256:${f.sha256}`);
      if (f.reasons?.length) {
        console.log("Reasons:");
        console.log(formatReasons(f.reasons));
      }
    }
  } else {
    console.log("\nNo threats or suspicious indicators found.");
  }

  console.log("");
}

function printHistory(historyPayload) {
  const history = historyPayload?.history || [];

  console.log("\n==============================");
  console.log("Scan History");
  console.log("==============================");

  if (!history.length) {
    console.log("No history yet.\n");
    return;
  }

  // Show most recent first
  const ordered = [...history].sort((a, b) => {
    const ta = Date.parse(a.timestamp || 0);
    const tb = Date.parse(b.timestamp || 0);
    return tb - ta;
  });

  for (const item of ordered) {
    console.log("--------------------------------");
    console.log(`Time:   ${item.timestamp}`);
    console.log(`Target: ${item.target}`);
    console.log(`Mode:   ${item.mode}`);
    console.log(`Heur:   ${item.heuristics_enabled ? "ON" : "OFF"}`);
    console.log(`Store:  ${item.storage}`);
    const sum = item.summary || {};
    console.log(`Scanned:${sum.files_scanned ?? 0}  Flagged:${sum.flagged ?? 0}`);
  }

  console.log("");
}

async function settingsMenu(current) {
  const answers = await inquirer.prompt([
    {
      type: "confirm",
      name: "heuristics_enabled",
      message: "Enable heuristics?",
      default: current.heuristics_enabled
    },
    {
      type: "list",
      name: "storage",
      message: "Choose storage backend for history:",
      choices: [
        { name: "JSON (default)", value: "json" },
        { name: "SQLite (optional)", value: "sqlite" }
      ],
      default: current.storage
    }
  ]);

  const saved = saveSettings(answers);
  console.log("\nSettings saved:");
  console.log(`- Heuristics: ${saved.heuristics_enabled ? "ON" : "OFF"}`);
  console.log(`- Storage:    ${saved.storage.toUpperCase()}\n`);
}

async function promptFilePath() {
  const { filePath } = await inquirer.prompt([
    {
      type: "input",
      name: "filePath",
      message: "Enter the full path to the file:"
    }
  ]);

  return filePath?.trim();
}

async function promptDirPath() {
  const { dirPath } = await inquirer.prompt([
    {
      type: "input",
      name: "dirPath",
      message: "Enter the full path to the directory:"
    }
  ]);

  return dirPath?.trim();
}

async function promptRecursive() {
  const { recursive } = await inquirer.prompt([
    {
      type: "confirm",
      name: "recursive",
      message: "Scan recursively?",
      default: true
    }
  ]);

  return !!recursive;
}

async function promptLocalSigPath() {
  const { sigPath } = await inquirer.prompt([
    {
      type: "input",
      name: "sigPath",
      message: "Enter the local path to the signature JSON file to load:"
    }
  ]);

  return sigPath?.trim();
}

async function handleScanFile(settings) {
  const filePath = await promptFilePath();
  if (!filePath) {
    console.log("No file path provided.\n");
    return;
  }

  const resolved = path.resolve(filePath);

  const res = scanFile(resolved, settings.heuristics_enabled, settings.storage);
  if (!res.ok) {
    console.error("\nScan failed:", res.error.message, "\n");
    return;
  }

  printScanSummary(res.data);
}

async function handleScanDir(settings) {
  const dirPath = await promptDirPath();
  if (!dirPath) {
    console.log("No directory path provided.\n");
    return;
  }

  const recursive = await promptRecursive();
  const resolved = path.resolve(dirPath);

  const res = scanDir(resolved, recursive, settings.heuristics_enabled, settings.storage);
  if (!res.ok) {
    console.error("\nScan failed:", res.error.message, "\n");
    return;
  }

  printScanSummary(res.data);
}

async function handleHistory(settings) {
  const res = getHistory(settings.storage);
  if (!res.ok) {
    console.error("\nFailed to read history:", res.error.message, "\n");
    return;
  }

  printHistory(res.data);
}

async function handleUpdateSignatures() {
  const sigPath = await promptLocalSigPath();
  if (!sigPath) {
    console.log("No signature path provided.\n");
    return;
  }

  const resolved = path.resolve(sigPath);

  if (!fs.existsSync(resolved)) {
    console.log("File does not exist:", resolved, "\n");
    return;
  }

  const res = updateSignatures(resolved);
  if (!res.ok) {
    console.error("\nUpdate failed:", res.error.message, "\n");
    return;
  }

  console.log("\nSignature update complete.");
  if (res.data?.details) {
    console.log(res.data.details);
  }
  console.log("");
}

async function mainMenuLoop() {
  while (true) {
    const settings = loadSettings();

    const { choice } = await inquirer.prompt([
      {
        type: "list",
        name: "choice",
        message: `AV-Lite MVP (Heuristics: ${settings.heuristics_enabled ? "ON" : "OFF"}, Storage: ${settings.storage.toUpperCase()})`,
        choices: [
          { name: "1) Scan a file", value: "scan_file" },
          { name: "2) Scan a directory", value: "scan_dir" },
          { name: "3) View scan history", value: "history" },
          { name: "4) Update signature list (offline file)", value: "update_sigs" },
          { name: "5) Settings", value: "settings" },
          { name: "6) Exit", value: "exit" }
        ]
      }
    ]);

    if (choice === "scan_file") await handleScanFile(settings);
    else if (choice === "scan_dir") await handleScanDir(settings);
    else if (choice === "history") await handleHistory(settings);
    else if (choice === "update_sigs") await handleUpdateSignatures();
    else if (choice === "settings") await settingsMenu(settings);
    else if (choice === "exit") {
      console.log("Goodbye!");
      return;
    }
  }
}

async function startUI() {
  console.log("\nAV-Lite MVP (Educational On-Demand Scanner)");
  console.log("------------------------------------------------");
  console.log("This project demonstrates basic signature + heuristic concepts.");
  console.log("It does NOT provide real-time protection and does NOT alter system defenses.\n");

  await mainMenuLoop();
}

module.exports = { startUI };
