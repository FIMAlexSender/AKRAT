#!/usr/bin/env python3
"""Run one build command and record Linux process/resource measurements."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def read_processes() -> dict[int, tuple[int, int, int, int, int]]:
    """Return PID -> (PPID, RSS bytes, CPU ticks, read bytes, written bytes)."""
    processes: dict[int, tuple[int, int, int, int, int]] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            pid = int(entry.name)
            stat = (entry / "stat").read_text()
            fields = stat[stat.rfind(")") + 2 :].split()
            ppid = int(fields[1])
            cpu_ticks = int(fields[11]) + int(fields[12])
            rss_pages = int(fields[21])
            io = {}
            for line in (entry / "io").read_text().splitlines():
                key, value = line.split(":", 1)
                io[key] = int(value.strip())
            processes[pid] = (
                ppid,
                rss_pages * os.sysconf("SC_PAGE_SIZE"),
                cpu_ticks,
                io.get("read_bytes", 0),
                io.get("write_bytes", 0),
            )
        except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError, IndexError):
            continue
    return processes


def process_tree(root: int, processes: dict[int, tuple[int, int, int, int, int]]) -> set[int]:
    children: dict[int, list[int]] = {}
    for pid, (ppid, *_metrics) in processes.items():
        children.setdefault(ppid, []).append(pid)
    found = {root}
    pending = [root]
    while pending:
        for child in children.get(pending.pop(), []):
            if child not in found:
                found.add(child)
                pending.append(child)
    return found


def available_memory_bytes() -> int | None:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        return None
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("name")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required after --")

    start = time.monotonic()
    child = subprocess.Popen(command)
    peak_tree_rss = 0
    min_host_available: int | None = None
    cpu_ticks_by_pid: dict[int, int] = {}
    io_read_by_pid: dict[int, int] = {}
    io_write_by_pid: dict[int, int] = {}
    clock_ticks = os.sysconf("SC_CLK_TCK")

    while child.poll() is None:
        processes = read_processes()
        pids = process_tree(child.pid, processes)
        current = [processes[pid] for pid in pids if pid in processes]
        peak_tree_rss = max(peak_tree_rss, sum(item[1] for item in current))
        for pid in pids:
            if pid not in processes:
                continue
            _ppid, _rss, cpu_ticks, io_read, io_write = processes[pid]
            cpu_ticks_by_pid[pid] = max(cpu_ticks_by_pid.get(pid, 0), cpu_ticks)
            io_read_by_pid[pid] = max(io_read_by_pid.get(pid, 0), io_read)
            io_write_by_pid[pid] = max(io_write_by_pid.get(pid, 0), io_write)
        available = available_memory_bytes()
        if available is not None:
            min_host_available = available if min_host_available is None else min(min_host_available, available)
        time.sleep(0.5)

    return_code = child.wait()
    duration = time.monotonic() - start
    metrics = {
        "name": args.name,
        "platform": sys.platform,
        "command": command,
        "exit_code": return_code,
        "duration_seconds": round(duration, 3),
        "peak_process_tree_rss_bytes": peak_tree_rss,
        "minimum_host_available_memory_bytes": min_host_available,
        "process_tree_cpu_seconds": round(sum(cpu_ticks_by_pid.values()) / clock_ticks, 3),
        "process_tree_read_bytes": sum(io_read_by_pid.values()),
        "process_tree_write_bytes": sum(io_write_by_pid.values()),
        "sample_interval_seconds": 0.5,
    }
    output = Path("target/ci-metrics") / f"{args.name}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metrics, indent=2), flush=True)
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
