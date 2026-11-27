# Node benchmark

Tools for comparing proxy node implementations (TunnixNode, v2node, V2bX, XrayR,
remnawave/node, ...) under identical conditions.

| Script | Runs on | Purpose |
|---|---|---|
| `node_monitor.py` | node server | Samples memory, CPU, threads and file descriptors of the node process every second |
| `bench_client.py` | client machine | Drives traffic through the node with an Xray client and records per-phase results |
| `report.py` | anywhere | Merges the results of several runs into a Markdown table |

All scripts use only the Python 3 standard library. The client also needs `curl` and an
[Xray](https://github.com/XTLS/Xray-core/releases) binary.

## What is measured

| Phase | Load | Metrics |
|---|---|---|
| `idle` | none | baseline memory |
| `latency` | sequential HTTPS requests, one new proxied connection each | time to first byte (median, p95), failures |
| `single` | one download stream | throughput |
| `multi` | parallel download streams (`--streams`) | throughput, CPU, CPU per Gbit/s, peak memory |
| `conns` | concurrent idle connections (`--conns`) | connections accepted, memory, memory per connection |
| `udp` | DNS queries over SOCKS5 UDP | answered queries, round-trip time |

The client also prints the number of HTTP bytes downloaded through the node. Compare it with
the traffic the panel recorded for the test user to check accounting accuracy; a difference of
about 0.5 % is expected because inner TLS records and HTTP headers are counted by the node.

## Test setup

Use three machines where possible:

1. **Node server**: the server under test. Only one node implementation runs at a time.
2. **Client**: a separate machine with a fast link to the node server.
3. **Target** (optional but recommended): a web server you control that serves a large file,
   for example nginx serving `/var/www/1g.bin` created with `fallocate -l 1G /var/www/1g.bin`.
   Public speed-test endpoints are rate limited and add noise.

Keep everything else identical between runs: panel, node configuration (protocol, transport,
port, certificate), test user, client machine, target URL and time of day. Prefer a dedicated
test node and user on the panel.

## Procedure

For each implementation:

1. Install it on the node server and attach it to the test node on the panel.
   Uninstall the previous implementation first so that only one listens on the port.
2. Note the test user's traffic on the panel.
3. Start the monitor on the node server, with a pattern matching the node process:

   ```bash
   python3 node_monitor.py --process 'tunnix-node' --out results/tunnix.monitor.csv
   ```

   | Implementation | `--process` pattern |
   |---|---|
   | TunnixNode | `tunnix-node` |
   | v2node | `v2node` |
   | V2bX | `V2bX` |
   | XrayR | `XrayR` |
   | remnawave/node | `rw-core\|dist/main` |

4. Run the client with the subscription link of the test user:

   ```bash
   python3 bench_client.py --label tunnix --xray ./xray \
     --link 'vless://UUID@NODE:443?security=reality&sni=...&pbk=...&sid=...&flow=xtls-rprx-vision&type=tcp' \
     --target-url 'https://target.example.com/1g.bin' \
     --out results/tunnix.client.json
   ```

   For protocols without a share-link parser (Hysteria2, TUIC, ...), pass an Xray outbound
   object with `--outbound outbound.json` instead of `--link`.

5. Stop the monitor with Ctrl-C and copy `results/tunnix.monitor.csv` to the client.
6. Compare the panel traffic with the byte count printed by the client.

Then build the table:

```bash
python3 report.py tunnix=results/tunnix v2node=results/v2node v2bx=results/v2bx > results/report.md
```

Phases are matched by wall-clock time, so the node server and the client must be synchronised
(NTP). Run each implementation at least three times and report the median.

## Options

| Option | Default | Description |
|---|---|---|
| `--duration` | 30 | Seconds for `single`, `multi` and `conns` |
| `--idle` | 20 | Seconds of idle baseline |
| `--streams` | 8 | Parallel streams in `multi` |
| `--conns` | 500 | Concurrent connections in `conns` |
| `--conn-target` | `1.1.1.1:80` | Destination of the idle connections |
| `--target-url` | Cloudflare speed test | Download URL; `{bytes}` is replaced with `--chunk-bytes` |
| `--small-url` | Cloudflare trace | URL for the latency phase |
| `--phases` | all | Comma-separated subset, e.g. `idle,multi,conns` |

Raise the open-file limit on both machines before large `--conns` values (`ulimit -n 65535`).

## Example

TunnixNode 0.1.0 and Xray-core 26.11.9 as the server, VLESS + REALITY + Vision, one macOS
host, downloads from speed.cloudflare.com, 1000 idle connections. Throughput figures are limited
by the Internet link and are shown only to illustrate the report format.

| Metric | TunnixNode | Xray-core |
|---|---:|---:|
| Idle memory (MiB) | 20.7 | 36.3 |
| Peak memory, multi-stream (MiB) | 23.3 | 40.5 |
| Memory with 1000 idle connections (MiB) | 143.3 | 118.6 |
| Memory per connection (KiB) | 125.5 | 86.8 |
| CPU per Gbit/s (% of one core) | 52.7 | 174.4 |
| Time to first byte, median (ms) | 281.0 | 246.9 |
| UDP DNS answered | 30/30 | 30/30 |
