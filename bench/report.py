#!/usr/bin/env python3
"""Builds a comparison table from bench_client.py results and node_monitor.py samples.

    python3 report.py tunnix=results/tunnix v2node=results/v2node > results/report.md

Each argument is LABEL=PREFIX; the files PREFIX.client.json and PREFIX.monitor.csv are read.
Node clocks must be in sync with the client (NTP) because phases are matched by time.
"""

import csv
import json
import sys


def load_monitor(path):
    rows = []
    try:
        with open(path) as f:
            for r in csv.DictReader(f):
                rows.append((float(r["unix_time"]), int(r["rss_kb"]), float(r["cpu_percent"]), int(r["fds"] or 0)))
    except FileNotFoundError:
        pass
    return rows


def window(rows, phase, skip=2.0):
    """Samples inside a phase, skipping the first seconds of ramp-up."""
    if not phase:
        return []
    return [r for r in rows if phase["start"] + skip <= r[0] <= phase["end"]]


def avg(values):
    return sum(values) / len(values) if values else None


def fmt(value, unit="", digits=1):
    if value is None:
        return "-"
    return f"{value:,.{digits}f}{unit}"


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    runs = []
    for arg in sys.argv[1:]:
        label, _, prefix = arg.partition("=")
        client = json.load(open(prefix + ".client.json"))
        runs.append((label, client, load_monitor(prefix + ".monitor.csv")))

    metrics = []

    def add(name, fn):
        metrics.append((name, [fn(c, m) for _, c, m in runs]))

    ph = lambda c, name: c["phases"].get(name)
    mem = lambda m, p, f: f([r[1] / 1024 for r in window(m, p)]) if window(m, p) else None
    cpu = lambda m, p: avg([r[2] for r in window(m, p)])

    add("Idle memory (MiB)", lambda c, m: fmt(mem(m, ph(c, "idle"), avg)))
    add("Peak memory, multi-stream (MiB)", lambda c, m: fmt(mem(m, ph(c, "multi"), max)))
    add("Memory with idle connections (MiB)",
        lambda c, m: fmt(mem(m, ph(c, "conns"), max)))
    add("Idle connections opened",
        lambda c, m: f"{ph(c, 'conns')['opened']}/{ph(c, 'conns')['target']}" if ph(c, "conns") else "-")
    add("Memory per connection (KiB)", lambda c, m: fmt(
        ((mem(m, ph(c, "conns"), max) or 0) - (mem(m, ph(c, "idle"), avg) or 0)) * 1024
        / max(1, ph(c, "conns")["opened"]) if ph(c, "conns") and mem(m, ph(c, "conns"), max) else None))
    add("Single-stream throughput (Mbit/s)", lambda c, m: fmt(ph(c, "single")["mbps"] if ph(c, "single") else None))
    add("Multi-stream throughput (Mbit/s)", lambda c, m: fmt(ph(c, "multi")["mbps"] if ph(c, "multi") else None))
    add("CPU, multi-stream (% of one core)", lambda c, m: fmt(cpu(m, ph(c, "multi"))))
    add("CPU per Gbit/s (% of one core)", lambda c, m: fmt(
        cpu(m, ph(c, "multi")) / (ph(c, "multi")["mbps"] / 1000)
        if ph(c, "multi") and ph(c, "multi")["mbps"] and cpu(m, ph(c, "multi")) is not None else None))
    add("Time to first byte, median (ms)",
        lambda c, m: fmt(ph(c, "latency")["ttfb_ms_median"] if ph(c, "latency") else None))
    add("Time to first byte, p95 (ms)",
        lambda c, m: fmt(ph(c, "latency")["ttfb_ms_p95"] if ph(c, "latency") else None))
    add("Failed requests",
        lambda c, m: str(ph(c, "latency")["failures"]) if ph(c, "latency") else "-")
    add("UDP DNS answered",
        lambda c, m: f"{ph(c, 'udp')['answered']}/{ph(c, 'udp')['queries']}" if ph(c, "udp") else "-")
    add("UDP DNS RTT, median (ms)",
        lambda c, m: fmt(ph(c, "udp")["rtt_ms_median"] if ph(c, "udp") else None))
    add("HTTP bytes downloaded (client)", lambda c, m: f"{c['client_bytes']['down']:,}")

    labels = [label for label, _, _ in runs]
    print("| Metric | " + " | ".join(labels) + " |")
    print("|---|" + "---:|" * len(labels))
    for name, values in metrics:
        print(f"| {name} | " + " | ".join(values) + " |")
    print()
    print("Memory is resident set size of all matched processes. CPU is relative to one core.")
    print("Compare the downloaded byte count with the traffic the panel recorded for the test user.")


if __name__ == "__main__":
    main()
