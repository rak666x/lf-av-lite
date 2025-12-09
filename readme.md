LF-AV-Lite MVP (v1)

LF-AV-Lite is a small educational on-demand antivirus-style scanner built for Windows 11.
This is a defensive learning project, not a replacement for Windows Defender.

It demonstrates how an AV pipeline can work at a high level:

offline signatures (SHA-256)

explainable heuristics

EICAR test detection

scan history

offline signature updates

No real-time monitoring in v1.

What this is (and isn’t)
✅ This is:

a safe MVP to demonstrate core AV concepts

a clean Node + Python project you can build on

Windows 11-first but should run on other OSes

❌ This is NOT:

a production antivirus

a real-time protection tool

something that disables or replaces Windows Defender

evasion, stealth, or malware code

Features (v1)

Scan a single file

Scan a directory (optional recursive)

SHA-256 signature checks (offline)

Balanced heuristics:

suspicious extensions

double-extension masquerading

file header vs extension mismatch

optional basic entropy signal

EICAR test detection (safe demo)

Scan history

JSON default

SQLite optional

Offline signature update from a local JSON file

Install
1) Python

From the root:

pip install -r requirements.txt

2) Node UI
cd node-ui
npm install

Run options
A) CLI (Node menu)
cd node-ui
npm start

B) Desktop UI (Electron)
cd node-ui
npm run desktop


You can also launch it from the root if you created a .bat:

run-desktop.bat

Safe demo (recommended)
1) EICAR test

Create a file named:

eicar_test.txt

Paste this exact line:

X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*


Then scan it using the desktop UI.

Expected result:

status: eicar_test

high risk score

reason clearly labeled as a harmless test signature

2) Heuristic demo (no malware)

Rename any harmless file to:

invoice.pdf.exe

resume.docx.js

Scan it.

Expected result:

heuristic_flag

reasons explaining why it looks suspicious

Offline signature updates

The update file format:

{
  "version": "1.0",
  "updated": "YYYY-MM-DD",
  "hashes": {
    "sha256": [
      "..."
    ]
  }
}


In the UI, paste the local path and update.
The engine validates and merges safely.

Notes for Windows

This project is designed to behave like a normal user-space tool.
It does not require admin privileges for most scans, but some protected folders may fail due to Windows permissions.

Roadmap (v2 ideas)

cleaner history viewer for SQLite

configurable heuristic scoring weights

exportable reports

improved filetype coverage

better scan performance for large folders

License

Educational/portfolio use.
If you reuse this, please keep the safety + defensive intent statement.