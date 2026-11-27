//! Host statistics in the shape Remnawave expects (read from /proc on Linux).

use std::time::Instant;

use parking_lot::Mutex;
use serde_json::{Value, json};

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn meminfo_kb(key: &str) -> u64 {
    read("/proc/meminfo")
        .lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn memory() -> (u64, u64) {
    let total = meminfo_kb("MemTotal:") * 1024;
    let available = meminfo_kb("MemAvailable:") * 1024;
    (total, available)
}

fn uptime_secs() -> f64 {
    read("/proc/uptime")
        .split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0)
}

fn load_avg() -> [f64; 3] {
    let mut out = [0.0f64; 3];
    #[cfg(unix)]
    // SAFETY: getloadavg writes at most 3 doubles into the buffer.
    unsafe {
        libc::getloadavg(out.as_mut_ptr(), 3);
    }
    out
}

fn uname() -> (String, String, String, String) {
    #[cfg(unix)]
    {
        // SAFETY: utsname is plain data; uname fills it.
        let mut u: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { libc::uname(&mut u) } == 0 {
            let f = |a: &[libc::c_char]| {
                let bytes: Vec<u8> = a
                    .iter()
                    .take_while(|c| **c != 0)
                    .map(|c| *c as u8)
                    .collect();
                String::from_utf8_lossy(&bytes).into_owned()
            };
            return (f(&u.sysname), f(&u.nodename), f(&u.release), f(&u.version));
        }
    }
    (String::new(), String::new(), String::new(), String::new())
}

fn default_interface() -> Option<String> {
    read("/proc/net/route")
        .lines()
        .skip(1)
        .filter_map(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            (cols.len() > 6 && cols[1] == "00000000").then(|| {
                (
                    cols[0].to_string(),
                    cols[6].parse::<u64>().unwrap_or(u64::MAX),
                )
            })
        })
        .min_by_key(|(_, metric)| *metric)
        .map(|(name, _)| name)
}

fn interface_counters(name: &str) -> Option<(u64, u64)> {
    read("/proc/net/dev").lines().find_map(|l| {
        let (iface, rest) = l.split_once(':')?;
        if iface.trim() != name {
            return None;
        }
        let cols: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|v| v.parse().ok())
            .collect();
        Some((*cols.first()?, *cols.get(8)?))
    })
}

fn interfaces() -> Vec<String> {
    read("/proc/net/dev")
        .lines()
        .skip(2)
        .filter_map(|l| l.split_once(':').map(|(n, _)| n.trim().to_string()))
        .collect()
}

fn meminfo(key: &str) -> u64 {
    meminfo_kb(key) * 1024
}

/// CPU busy percentage since the previous call (Linux /proc/stat).
pub fn cpu_percent(prev: &Mutex<Option<(u64, u64)>>) -> f64 {
    let line = read("/proc/stat");
    let Some(cpu) = line.lines().next() else {
        return 0.0;
    };
    let v: Vec<u64> = cpu
        .split_whitespace()
        .skip(1)
        .filter_map(|x| x.parse().ok())
        .collect();
    if v.len() < 4 {
        return 0.0;
    }
    let idle = v[3] + v.get(4).copied().unwrap_or(0);
    let total: u64 = v.iter().sum();
    let mut prev = prev.lock();
    let pct = match *prev {
        Some((pt, pi)) if total > pt => {
            let dt = (total - pt) as f64;
            let di = idle.saturating_sub(pi) as f64;
            ((dt - di) / dt * 100.0).clamp(0.0, 100.0)
        }
        _ => 0.0,
    };
    *prev = Some((total, idle));
    pct
}

fn disk_root() -> (u64, u64) {
    #[cfg(unix)]
    {
        // SAFETY: statvfs fills the struct for a valid C path.
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        let path = b"/\0";
        if unsafe { libc::statvfs(path.as_ptr().cast(), &mut st) } == 0 {
            let frsize = st.f_frsize as u64;
            let total = st.f_blocks as u64 * frsize;
            let free = st.f_bavail as u64 * frsize;
            return (total, total.saturating_sub(free));
        }
    }
    (0, 0)
}

/// Xboard `status` body: cpu %, mem/swap/disk totals and usage in bytes.
pub fn xboard_status(cpu_prev: &Mutex<Option<(u64, u64)>>) -> Value {
    let (mem_total, mem_avail) = memory();
    let swap_total = meminfo("SwapTotal:");
    let swap_free = meminfo("SwapFree:");
    let (disk_total, disk_used) = disk_root();
    json!({
        "cpu": (cpu_percent(cpu_prev) * 100.0).round() / 100.0,
        "mem": {"total": mem_total, "used": mem_total.saturating_sub(mem_avail)},
        "swap": {"total": swap_total, "used": swap_total.saturating_sub(swap_free)},
        "disk": {"total": disk_total, "used": disk_used},
    })
}

pub struct System {
    started: Instant,
    last: Mutex<Option<(Instant, u64, u64)>>,
}

impl System {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            last: Mutex::new(None),
        }
    }

    pub fn core_uptime(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    pub fn reset_core_uptime(&mut self) {
        self.started = Instant::now();
    }

    pub fn info(&self) -> Value {
        let (sysname, hostname, release, version) = uname();
        let cpu_model = read("/proc/cpuinfo")
            .lines()
            .find(|l| {
                l.starts_with("model name") || l.starts_with("Hardware") || l.starts_with("Model")
            })
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| format!("{} CPU", std::env::consts::ARCH));
        json!({
            "arch": match std::env::consts::ARCH { "x86_64" => "x64", "aarch64" => "arm64", a => a },
            "cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
            "cpuModel": cpu_model,
            "memoryTotal": memory().0,
            "hostname": hostname,
            "platform": std::env::consts::OS,
            "release": release,
            "type": sysname,
            "version": version,
            "networkInterfaces": interfaces(),
        })
    }

    pub fn stats(&self) -> Value {
        let (total, available) = memory();
        let interface = default_interface().and_then(|name| {
            let (rx, tx) = interface_counters(&name)?;
            let now = Instant::now();
            let mut last = self.last.lock();
            let (rx_rate, tx_rate) = match *last {
                Some((t, prx, ptx)) if now > t => {
                    let secs = now.duration_since(t).as_secs_f64().max(0.001);
                    (
                        (rx.saturating_sub(prx) as f64 / secs) as u64,
                        (tx.saturating_sub(ptx) as f64 / secs) as u64,
                    )
                }
                _ => (0, 0),
            };
            *last = Some((now, rx, tx));
            Some(json!({
                "interface": name,
                "rxBytesPerSec": rx_rate,
                "txBytesPerSec": tx_rate,
                "rxTotal": rx,
                "txTotal": tx,
            }))
        });
        json!({
            "memoryFree": available,
            "memoryUsed": total.saturating_sub(available),
            "uptime": uptime_secs() as u64,
            "loadAvg": load_avg(),
            "interface": interface,
        })
    }

    /// Stand-in for Xray's Go runtime stats; `uptime` is what the panel uses.
    pub fn core_info(&self) -> Value {
        let rss = memory_stats::memory_stats()
            .map(|m| m.physical_mem as u64)
            .unwrap_or(0);
        json!({
            "numGoroutine": 0,
            "numGC": 0,
            "alloc": rss,
            "totalAlloc": rss,
            "sys": rss,
            "mallocs": 0,
            "frees": 0,
            "liveObjects": 0,
            "pauseTotalNs": 0,
            "uptime": self.core_uptime(),
        })
    }
}
