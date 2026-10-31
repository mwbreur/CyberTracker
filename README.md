# CyberTracker2026

Network host tracker application with GUI. Scans local subnet, tracks hosts by MAC address, and detects IP changes.

## Features

- Subnet scanning with ping sweep
- MAC address tracking across reboots
- IP change detection
- Host status persistence (active/inactive/suspect)
- GUI interface with real-time updates

## Build Artifacts

PyInstaller executable (`dist/CyberTracker2026.exe`) included in this repo.

## Source

- `network_tracker.py` — Main application source
- `CyberTracker2026.spec` — PyInstaller build configuration
- `dist/` — Compiled executables
- `build/` — Build artifacts (can be ignored)

## Usage

```bash
python network_tracker.py
```

Or run the compiled executable:
```bash
./dist/CyberTracker2026.exe
```

## Data Storage

Host data is stored in `network_hosts.json` for persistent tracking between runs.
