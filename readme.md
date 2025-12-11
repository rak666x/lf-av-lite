# LF-AV-Lite (v1.1 MVP)

**LF-AV-Lite** is a small on-demand AV-style scanner for **Windows 11**.

---

## What this is ✅

This project **is**:

* a safe MVP to demo core AV ideas
* a small **Node + Python** app you can read and extend
* focused on **Windows 11**, but the core logic is portable

---

## What this is not ❌

This project is **not**:

* a production antivirus
* a real-time protection tool
* something that disables or replaces Windows Defender
* evasion, stealth, or malware code
* a tool for bypassing security controls

You should still keep Windows Defender (or another real AV) turned on.

---

## Current Features (v1.1)

### Scanning

* Scan a **single file**
* Scan a **directory** (with optional recursion)
* Simple desktop UI (Electron) that talks to a Python backend:

  * choose file / folder
  * see scan progress and results

### Detection

* **SHA-256 signature checks** (offline, local list)
* Explainable **heuristics**, including:

  * suspicious extensions
  * double extensions (`invoice.pdf.exe`, `resume.docx.js`, etc.)
  * file header vs extension mismatch (e.g. PE file named `.txt`)
  * optional basic entropy signal (simple “this looks packed/weird” hint)
* **EICAR test** detection (standard AV test string, not real malware)

  * clearly labeled as a *harmless* test signature

### History & Storage

* **Scan history**:

  * default: simple **JSON** file
  * optional: **SQLite** history backend
* Option to load and review past scan results

### Offline Signature Updates

* Signatures are stored locally in JSON
* Supports **offline updates** from a local JSON file
* Basic validation so a broken update file doesn’t trash the DB

---

## Install & Setup

### 1) Python backend

From the project root:

LF-AV-LITE uses only standard Python librarys.

No external dependencies required.

Make sure Python 3.x is installed and on your PATH.

### 2) Node UI - Not fully updated

From the project root:

```bash
cd node-ui
npm install
```

### 3) Desktop UI (Electron)

From inside `node-ui`:

```bash
npm run desktop
```

Or, run

run-desktop.bat

This starts the desktop UI, which sends scan requests to the Python scanner.

---

## Safe Demo: EICAR Test

You can test that detection works using the standard **EICAR** test string (used by AV vendors, not real malware).

1. Create a file named:

   ```text
   eicar_test.txt
   ```

2. Paste this exact line into the file:

   ```text
   X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
   ```

3. Save the file.

4. Open LF-AV-Lite and scan `eicar_test.txt` from the desktop UI.

**Expected result:**

* detection status similar to: `eicar_test`
* high risk score
* reason clearly marked as a **harmless test signature**

If that doesn’t show up, the signature pipeline probably isn’t wired correctly.

---

## Heuristic Demo (No Malware Needed)

You can also see the heuristics in action using normal files:

1. Take any harmless file (for example `notes.txt`).

2. Rename it to something sketchy, like:

   * `invoice.pdf.exe`
   * `resume.docx.js`

3. Scan that renamed file with LF-AV-Lite.

**Expected result:**

* a heuristic-based detection (e.g. `heuristic_flag`)
* reasons that explain:

  * double extension
  * executable pretending to be a document
  * why that’s suspicious

This is a simple way to test “common sense” checks without touching real malware.

---

## Offline Signature Update Format

Update files are plain JSON. Example:

```json
{
  "version": "1.0",
  "updated": "YYYY-MM-DD",
  "hashes": {
    "sha256": [
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ]
  }
}
```

How to use it:

1. Create or download a JSON file that matches this structure.
2. In the UI, paste or browse to the **local path** of that file.
3. Click **Update**.

The engine will:

* check that the JSON looks valid
* merge new hashes into your existing local signatures

---

## Windows Notes

* Designed to run as a **normal user-space app**:

  * Most scans work fine without admin
  * Some protected folders may fail due to permissions (that’s normal)
* The project does **not**:

  * hook into the kernel
  * try to hide itself
  * mess with other AV tools

If a file or folder can’t be scanned, the app should tell you instead of silently ignoring it.

---

## License

Intended to be open source. Still Building.
