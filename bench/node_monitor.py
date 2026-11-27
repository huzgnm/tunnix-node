#!/usr/bin/env python3
"""Samples memory and CPU usage of a proxy node process.

Run on the node server while bench_client.py runs on the client machine:

    python3 node_monitor.py --process 'tunnix-node' --out results/tunnix.monitor.csv

Common process patterns: tunnix-node, v2node, V2bX, XrayR, xray, rw-core, sing-box.
All processes whose command line matches the regular expression are summed, so
multi-process nodes (for example remnanode: node.js + xray) can be measured with
a pattern such as 'rw-core|node dist/main'.

Output CSV columns: unix_time, rss_kb, cpu_percent, threads, fds, pids
cpu_percent is relative to one core (200 = two cores fully busy).
Stops after --duration seconds or on Ctrl-C.
"""

import argparse
import csv
import os
import re
import subprocess
import sys
import time

CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
HAS_PROC = os.path.isdir("/proc/self")


def find_pids(pattern):
    regex = re.compile(pattern)
    me = os.getpid()
    pids = []
    if HAS_PROC:
        for entry in os.listdir("/proc"):
            if not entry.isdigit() or int(entry) == me:
                continue
            try:
                with open(f"/proc/{entry}/cmdline", "rb") as f:
                    cmd = f.read().replace(b"\0", b" ").decode(errors="replace").strip()
            except OSError:
                continue
            if cmd and regex.search(cmd) and "node_monitor.py" not in cmd:
                pids.append(int(entry))
    else:
        out = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True).stdout
        for line in out.splitlines():
            pid, _, cmd = line.strip().partition(" ")
            if pid.isdigit() and int(pid) != me and regex.search(cmd) and "node_monitor.py" not in cmd:
                pids.append(int(pid))
    return pids


def proc_sample(pid):
    """Returns (rss_kb, cpu_ticks, threads, fds) or None if the process is gone."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            fields = f.read().rsplit(")", 1)[1].split()
        utime, stime, threads = int(fields[11]), int(fields[12]), int(fields[17])
        rss_kb = 0
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss_kb = int(line.split()[1])
                    break
        try:
            fds = len(os.listdir(f"/proc/{pid}/fd"))
        except OSError:
            fds = 0
        return rss_kb, utime + stime, threads, fds
    except (OSError, IndexError, ValueError):
        return None


def ps_sample(pids):
    """Portable fallback (macOS): rss and instantaneous %cpu from ps."""
    out = subprocess.run(
        ["ps", "-o", "rss=,%cpu=", "-p", ",".join(map(str, pids))], capture_output=True, text=True
    ).stdout
    rss = cpu = 0.0
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2:
            rss += float(parts[0])
            cpu += float(parts[1])
    return int(rss), cpu


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--process", required=True, help="regular expression matched against the command line")
    ap.add_argument("--out", required=True, help="CSV output file")
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--duration", type=float, default=0, help="seconds (0 = until Ctrl-C)")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    prev = {}
    prev_time = time.monotonic()
    start = time.time()
    with open(args.out, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["unix_time", "rss_kb", "cpu_percent", "threads", "fds", "pids"])
        print(f"monitoring /{args.process}/ every {args.interval}s -> {args.out}", file=sys.stderr)
        try:
            while not args.duration or time.time() - start < args.duration:
                pids = find_pids(args.process)
                now = time.monotonic()
                if not pids:
                    print("no matching process", file=sys.stderr)
                elif HAS_PROC:
                    rss = threads = fds = 0
                    ticks = {}
                    for pid in pids:
                        s = proc_sample(pid)
                        if s:
                            rss += s[0]
                            ticks[pid] = s[1]
                            threads += s[2]
                            fds += s[3]
                    elapsed = max(now - prev_time, 1e-6)
                    used = sum(t - prev.get(pid, t) for pid, t in ticks.items())
                    cpu = 100.0 * used / CLK_TCK / elapsed if prev else 0.0
                    prev = ticks
                    writer.writerow([f"{time.time():.3f}", rss, f"{cpu:.1f}", threads, fds, len(pids)])
                else:
                    rss, cpu = ps_sample(pids)
                    writer.writerow([f"{time.time():.3f}", rss, f"{cpu:.1f}", 0, 0, len(pids)])
                f.flush()
                prev_time = now
                time.sleep(args.interval)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
