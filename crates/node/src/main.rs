//! TunnixNode: VPN node for Xboard, XiaoBoard and V2Board panels.

mod acme;
mod builder;
mod config;
mod controller;
mod panel;
mod rw;

use std::path::PathBuf;

use anyhow::{Context, Result};
use log::{error, info};

#[cfg(all(
    not(target_env = "msvc"),
    not(target_os = "ios"),
    not(target_os = "android")
))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn usage() -> ! {
    eprintln!(
        "TunnixNode {VERSION}

Usage:
  tunnix-node server [-c CONFIG]   Run the node (default {})
  tunnix-node check  [-c CONFIG]   Validate the config file
  tunnix-node x25519               Generate a REALITY key pair
  tunnix-node version              Print version
  tunnix-node add-node --panel xiaoboard|xboard|v2board --api-host URL
              --node-id N --api-key KEY [--node-type T] [-c CONFIG]
                                   Add or update a node in the config file
  tunnix-node remove-node --api-host URL --node-id N [-c CONFIG]",
        config::DEFAULT_CONFIG_PATH
    );
    std::process::exit(2);
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let command = if args.is_empty() {
        "server".to_string()
    } else {
        args.remove(0)
    };
    let mut config_path = PathBuf::from(
        std::env::var("TUNNIX_CONFIG").unwrap_or_else(|_| config::DEFAULT_CONFIG_PATH.into()),
    );
    let mut opts: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    while !args.is_empty() {
        let flag = args.remove(0);
        match flag.as_str() {
            "-c" | "--config" if !args.is_empty() => config_path = PathBuf::from(args.remove(0)),
            f if f.starts_with("--") && !args.is_empty() => {
                opts.insert(f.trim_start_matches("--").to_string(), args.remove(0));
            }
            _ => usage(),
        }
    }

    let code = match command.as_str() {
        "version" | "-v" | "--version" => {
            println!(
                "TunnixNode {VERSION} (core {})",
                shoes::tunnix::core_version()
            );
            0
        }
        "x25519" => match shoes::tunnix::generate_reality_keypair() {
            Ok((private, public)) => {
                println!("Private key: {private}\nPublic key: {public}");
                0
            }
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
        "check" => match config::Config::load(&config_path) {
            Ok(c) => {
                println!("OK: {} node(s)", c.nodes.len());
                0
            }
            Err(e) => {
                eprintln!("{e:#}");
                1
            }
        },
        "server" | "run" => match run_server(&config_path) {
            Ok(()) => 0,
            Err(e) => {
                error!("{e:#}");
                eprintln!("{e:#}");
                1
            }
        },
        "add-node" | "remove-node" => {
            match config::edit_nodes(&config_path, command == "add-node", &opts) {
                Ok(msg) => {
                    println!("{msg}");
                    0
                }
                Err(e) => {
                    eprintln!("{e:#}");
                    1
                }
            }
        }
        "help" | "-h" | "--help" => usage(),
        _ => usage(),
    };
    std::process::exit(code);
}

fn run_server(config_path: &std::path::Path) -> Result<()> {
    let config = config::Config::load(config_path)?;
    let _ = shoes::tunnix::init_logging(&config.log.level);
    info!(
        "TunnixNode {VERSION} (core {}) starting with {} node(s)",
        shoes::tunnix::core_version(),
        config.nodes.len()
    );
    std::fs::create_dir_all(&config.data_dir)
        .with_context(|| format!("create {}", config.data_dir.display()))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async move {
        // Install a SIGHUP handler before anything can send one (certificate renewal
        // reloads the core with SIGHUP; the default action would kill the process).
        #[cfg(unix)]
        let _hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        let core = controller::CoreConfig::new(&config.data_dir);
        let acme = acme::AcmeManager::new(&config.data_dir, config.acme_email.clone())?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let mut tasks = Vec::new();
        for node in config.nodes.clone() {
            let ctl = controller::NodeController::new(
                node,
                core.clone(),
                &config.data_dir,
                acme.clone(),
            )?;
            tasks.push(tokio::spawn(ctl.run(shutdown_rx.clone())));
        }

        if let Some(rw) = config.remnawave.clone() {
            let core = core.clone();
            let data_dir = config.data_dir.clone();
            tokio::spawn(async move {
                if let Err(e) = rw::run(rw, core, data_dir).await {
                    error!("Remnawave node API stopped: {e:#}");
                }
            });
        }

        // Start the proxy core once at least one node has a valid config.
        let ready = core.ready.notified();
        tokio::select! {
            _ = ready => {}
            _ = tokio::signal::ctrl_c() => {
                let _ = shutdown_tx.send(true);
                return Ok(());
            }
            _ = sigterm() => {
                let _ = shutdown_tx.send(true);
                return Ok(());
            }
        }
        info!("core config ready at {}", core.path().display());
        let served = shoes::tunnix::run_server(vec![core.path().display().to_string()]).await;

        // Core stopped (signal or fatal error): flush traffic before exiting.
        let _ = shutdown_tx.send(true);
        for t in tasks {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(10), t).await;
        }
        served.map_err(anyhow::Error::from)
    });
    runtime.shutdown_timeout(std::time::Duration::from_secs(3));
    result
}

async fn sigterm() {
    #[cfg(unix)]
    {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
            return;
        }
    }
    std::future::pending::<()>().await
}
