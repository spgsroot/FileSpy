# FileSpy: eBPF Real-time File Write Monitor

**FileSpy** is a lightweight observability tool powered by eBPF that captures file write operations (`vfs_write`) in real-time.

Unlike standard tools like `inotify`, FileSpy operates at the Linux kernel level and provides deep process context: it identifies not just **"who wrote to the file"** (PID/Comm), but **"which script initiated it"** by analyzing command-line arguments directly from process memory.

## Features

*   **Zero-overhead monitoring:** Uses kprobes (eBPF) to intercept system calls with negligible performance impact.
*   **Script Recognition:** Automatically detects the specific script (`.py`, `.sh`, `.js`) running inside an interpreter, even if the process name is generic like `python3` or `node`.
*   **Flexible Filtering:** Monitors only specific file extensions (default: `.txt`, `.log`, `.json`).
*   **JSON Stream Output:** Produces structured JSON logs, ready for ingestion into pipelines (ELK, Vector, Fluentd).

## Tech Stack

*   **Core:** C (eBPF/BCC) — Kernel-space data collection.
*   **User-space:** Python 3 — Data parsing, enrichment, and CLI.
*   **Data Structures:** BPF Per-CPU Array (used to bypass eBPF stack limitations).

## Requirements

*   Linux Kernel 4.15+ (BPF support required).
*   `sudo` privileges (to load eBPF programs into the kernel).
*   Python 3.10+
*   BCC (BPF Compiler Collection) installed on the system.

## Installation & Usage

### 1. Install Dependencies (Ubuntu/Debian)

You will need kernel headers and the BCC toolkit:

```bash
sudo apt-get update
sudo apt-get install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc

### 2. Run
```
# Root privileges are required to interact with eBPF
sudo python3 main.py
```

### Example Output
The tool generates a stream of JSON events for every write to the target files:
```
{
  "id": "a4d958fc-8b33-40e3-8e7a-f96ddc98cd05",
  "timestamp": "2026-01-12T20:38:42.880979",
  "process": {
    "name": "python3",
    "file_path": "tests/writer.py",      
    "exe_path": "bin/python3.10",
    "pid": 157028,
    "uid": 1000
  },
  "file": {
    "name": "app.log",
    "file_path": "var/log/app.log",
    "bytes_written": 128
  },
  "system_ts": 22339121413039
}
```

##№ FAQ
ERROR: Unable to find kernel headers on WSL
```
uname -r 
sudo ln -sf /home/usr/WSL2-Linux-Kernel /lib/modules/$(uname -r)/build
```
