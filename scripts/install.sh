#!/usr/bin/env bash
# TunnixNode installer for Xboard, XiaoBoard, V2Board and Remnawave nodes.
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/huzgnm/tunnix-node/main/scripts/install.sh) \
#       --panel xiaoboard --api-host 'https://panel.example.com' --node-id 1 --api-key 'TOKEN'
#
# Options:
#   --panel      xiaoboard | xboard | v2board | remnawave   (default: xiaoboard)
#   --api-host   panel API URL
#   --node-id    node ID on the panel
#   --api-key    node communication key (server token)
#   --node-type  original V2Board only: vmess | trojan | shadowsocks
#   --secret-key Remnawave: SECRET_KEY from the panel (Nodes > docker-compose)
#   --node-port  Remnawave: NODE_PORT (default: 2222)
#   --mode       docker | systemd   (default: docker)
#   --version    release tag, e.g. v0.1.0 (default: latest)
#   --replace    replace existing nodes instead of adding to them
#   --bbr        enable TCP BBR
#   -y           non-interactive
#
# The --api-host / --node-id / --api-key flags match the v2node installer.
# Remnawave: bash install.sh --panel remnawave --secret-key '...' [--node-port 2222]
set -euo pipefail

REPO="${TUNNIX_REPO:-huzgnm/tunnix-node}"
IMAGE="${TUNNIX_IMAGE:-ghcr.io/${REPO,,}}"
NAME="tunnix-node"
CONF_DIR="/etc/tunnix-node"
CONF="$CONF_DIR/config.json"
DATA_DIR="/var/lib/tunnix-node"
BIN_DIR="/usr/local/tunnix-node"
COMPOSE_DIR="/opt/tunnix-node"
MANAGER="/usr/bin/tunnix"

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
die() { red "Error: $*" >&2; exit 1; }

PANEL="" API_HOST="" NODE_ID="" API_KEY="" NODE_TYPE="" MODE="" VERSION="" REPLACE=0 BBR=0 YES=0 UPDATE_ONLY=0
SECRET_KEY="" NODE_PORT=""
RW_ENV="$CONF_DIR/remnawave.env"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --panel|--panel-type) PANEL="${2:-}"; shift 2 ;;
        --api-host|--api_host) API_HOST="${2:-}"; shift 2 ;;
        --node-id|--node_id) NODE_ID="${2:-}"; shift 2 ;;
        --api-key|--api_key) API_KEY="${2:-}"; shift 2 ;;
        --node-type) NODE_TYPE="${2:-}"; shift 2 ;;
        --secret-key|--secret_key) SECRET_KEY="${2:-}"; shift 2 ;;
        --node-port|--node_port) NODE_PORT="${2:-}"; shift 2 ;;
        --mode) MODE="${2:-}"; shift 2 ;;
        --version) VERSION="${2:-}"; shift 2 ;;
        --replace) REPLACE=1; shift ;;
        --bbr) BBR=1; shift ;;
        -y|--yes) YES=1; shift ;;
        --update-only) UPDATE_ONLY=1; YES=1; shift ;;
        -h|--help) sed -n '2,22p' "$0" 2>/dev/null || true; exit 0 ;;
        v[0-9]*|[0-9]*.[0-9]*) VERSION="$1"; shift ;;
        *) die "unknown option: $1" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "must be run as root"
[[ "$REPO" != CHANGE_ME/* ]] || die "REPO is not configured"

case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "unsupported architecture $(uname -m) (amd64 and arm64 only)" ;;
esac

ask() { # ask VAR "prompt" [default]
    local __var="$1" __q="$2" __def="${3:-}" __ans
    if [[ -n "$__def" ]]; then read -r -p "$__q [$__def]: " __ans </dev/tty || true; else read -r -p "$__q: " __ans </dev/tty || true; fi
    printf -v "$__var" '%s' "${__ans:-$__def}"
}

pkg_install() {
    if command -v apt-get >/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null
    elif command -v dnf >/dev/null; then dnf install -y -q "$@" >/dev/null
    elif command -v yum >/dev/null; then yum install -y -q "$@" >/dev/null
    elif command -v apk >/dev/null; then apk add --no-cache -q "$@" >/dev/null
    else die "no supported package manager to install: $*"; fi
}

choose_panel() {
    [[ -n "$PANEL" ]] && return
    echo "Panel type:"
    echo "  1) XiaoBoard (wyx2685/v2board, v2node API)"
    echo "  2) Xboard (cedar2025)"
    echo "  3) V2Board (vmess / trojan / shadowsocks)"
    echo "  4) Remnawave"
    local c; ask c "Choice" 1
    case "$c" in 1) PANEL=xiaoboard ;; 2) PANEL=xboard ;; 3) PANEL=v2board ;; 4) PANEL=remnawave ;; *) die "invalid choice" ;; esac
}

PANEL="${PANEL,,}"
if [[ $UPDATE_ONLY -eq 1 ]]; then
    [[ -f "$CONF" || -s "$RW_ENV" ]] || die "TunnixNode is not installed ($CONF not found)"
    PANEL=skip
elif [[ -n "$SECRET_KEY" && -z "$PANEL" ]]; then
    PANEL=remnawave
elif [[ -z "$API_HOST" || -z "$NODE_ID" || -z "$API_KEY" ]]; then
    choose_panel
fi
PANEL="${PANEL:-xiaoboard}"
case "$PANEL" in
    skip) ;;
    xiaoboard|v2node|wyx2685) PANEL=xiaoboard ;;
    xboard|v2board) ;;
    remnawave) ;;
    *) die "--panel must be xiaoboard, xboard, v2board or remnawave" ;;
esac

if [[ $UPDATE_ONLY -eq 0 && "$PANEL" == remnawave ]]; then
    [[ -n "$SECRET_KEY" ]] || ask SECRET_KEY "SECRET_KEY (Remnawave > Nodes > docker-compose)"
    [[ -n "$NODE_PORT" ]] || ask NODE_PORT "NODE_PORT" 2222
    SECRET_KEY="${SECRET_KEY#SECRET_KEY=}"; SECRET_KEY="${SECRET_KEY//\"/}"; SECRET_KEY="${SECRET_KEY//\'/}"
    [[ -n "$SECRET_KEY" ]] || die "SECRET_KEY is required"
    [[ "$NODE_PORT" =~ ^[0-9]+$ ]] || die "NODE_PORT must be a number"
elif [[ $UPDATE_ONLY -eq 0 ]]; then
[[ -n "$API_HOST" ]] || ask API_HOST "Panel API URL (e.g. https://panel.example.com)"
[[ -n "$NODE_ID" ]] || ask NODE_ID "Node ID"
[[ -n "$API_KEY" ]] || ask API_KEY "Server token"
if [[ "$PANEL" == v2board && -z "$NODE_TYPE" ]]; then
    ask NODE_TYPE "Node type (vmess | trojan | shadowsocks)" vmess
fi
[[ "$API_HOST" =~ ^https?:// ]] || die "the panel URL must start with http:// or https://"
[[ "$NODE_ID" =~ ^[0-9]+$ ]] || die "the node ID must be a number"
[[ -n "$API_KEY" ]] || die "the server token is required"
fi

if [[ -z "$MODE" ]]; then
    if [[ -f "$CONF_DIR/mode" ]]; then MODE="$(cat "$CONF_DIR/mode")"
    elif [[ $YES -eq 1 ]]; then MODE=docker
    else
        echo "Run mode:"
        echo "  1) Docker (recommended)"
        echo "  2) systemd (native binary)"
        local_c=""; ask local_c "Choice" 1
        [[ "$local_c" == 2 ]] && MODE=systemd || MODE=docker
    fi
fi
[[ "$MODE" == docker || "$MODE" == systemd ]] || die "--mode must be docker or systemd"

command -v curl >/dev/null || pkg_install curl
command -v tar >/dev/null || pkg_install tar

if [[ -z "$VERSION" && -n "${TUNNIX_LOCAL_TARBALL:-}" ]]; then
    VERSION="v0.0.0-local"
fi
if [[ -z "$VERSION" ]]; then
    VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)"
    [[ -n "$VERSION" ]] || die "could not determine the latest release from GitHub"
fi
[[ "$VERSION" == v* ]] || VERSION="v$VERSION"
green "TunnixNode $VERSION | panel: ${PANEL/skip/unchanged} | mode: $MODE | $ARCH"

mkdir -p "$CONF_DIR" "$DATA_DIR"
chmod 700 "$CONF_DIR"
touch "$RW_ENV"; chmod 600 "$RW_ENV"
if [[ "$PANEL" == remnawave ]]; then
    printf 'NODE_PORT=%s\nSECRET_KEY=%s\n' "$NODE_PORT" "$SECRET_KEY" > "$RW_ENV"
fi
if [[ $REPLACE -eq 1 && -f "$CONF" ]]; then
    cp "$CONF" "$CONF.bak.$(date +%s)"
    rm -f "$CONF"
fi

# ---------- download / install ----------
install_docker() {
    if ! command -v docker >/dev/null; then
        yellow "Installing Docker..."
        curl -fsSL https://get.docker.com | sh
    fi
    systemctl enable --now docker >/dev/null 2>&1 || true
    docker compose version >/dev/null 2>&1 || pkg_install docker-compose-plugin
}

run_node_cli() { # runs a tunnix-node subcommand (add-node, x25519, ...)
    if [[ "$MODE" == docker ]]; then
        docker run --rm -v "$CONF_DIR:$CONF_DIR" "$IMAGE:${VERSION#v}" "$@"
    else
        "$BIN_DIR/tunnix-node" "$@"
    fi
}

if [[ "$MODE" == docker ]]; then
    install_docker
    [[ -n "${TUNNIX_LOCAL_IMAGE:-}" ]] || docker pull "$IMAGE:${VERSION#v}"
    mkdir -p "$COMPOSE_DIR"
    cat > "$COMPOSE_DIR/docker-compose.yml" <<EOF
services:
  tunnix-node:
    image: $IMAGE:${VERSION#v}
    container_name: $NAME
    restart: always
    network_mode: host
    command: ["server", "-c", "$CONF"]
    env_file:
      - $RW_ENV
    cap_add:
      - NET_ADMIN
    volumes:
      - $CONF_DIR:$CONF_DIR
      - $DATA_DIR:$DATA_DIR
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    logging:
      driver: json-file
      options:
        max-size: "20m"
        max-file: "3"
EOF
    # Remove a previous systemd install, if any.
    systemctl disable --now "$NAME" >/dev/null 2>&1 || true
else
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    url="https://github.com/$REPO/releases/download/$VERSION/tunnix-node-linux-$ARCH.tar.gz"
    if [[ -n "${TUNNIX_LOCAL_TARBALL:-}" ]]; then
        # Testing: install from a local build instead of GitHub.
        cp "$TUNNIX_LOCAL_TARBALL" "$tmp/tn.tar.gz"
    else
        yellow "Downloading $url"
        curl -fL --retry 3 -o "$tmp/tn.tar.gz" "$url" || die "download failed"
    fi
    if [[ -z "${TUNNIX_LOCAL_TARBALL:-}" ]] && curl -fsSL -o "$tmp/tn.tar.gz.sha256" "$url.sha256"; then
        (cd "$tmp" && echo "$(cut -d' ' -f1 tn.tar.gz.sha256)  tn.tar.gz" | sha256sum -c - >/dev/null) || die "SHA256 checksum mismatch"
    fi
    tar -xzf "$tmp/tn.tar.gz" -C "$tmp"
    install -d "$BIN_DIR"
    install -m 755 "$tmp/tunnix-node" "$BIN_DIR/tunnix-node"
    cat > "/etc/systemd/system/$NAME.service" <<EOF
[Unit]
Description=TunnixNode
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=-$RW_ENV
ExecStart=$BIN_DIR/tunnix-node server -c $CONF
Restart=always
RestartSec=5
LimitNOFILE=1048576
KillSignal=SIGTERM
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    if [[ -f "$COMPOSE_DIR/docker-compose.yml" ]] && command -v docker >/dev/null; then
        docker compose -f "$COMPOSE_DIR/docker-compose.yml" down >/dev/null 2>&1 || true
    fi
fi

if [[ $UPDATE_ONLY -eq 0 && "$PANEL" != remnawave ]]; then
add_args=(add-node -c "$CONF" --panel "$PANEL" --api-host "$API_HOST" --node-id "$NODE_ID" --api-key "$API_KEY")
[[ -n "$NODE_TYPE" ]] && add_args+=(--node-type "$NODE_TYPE")
run_node_cli "${add_args[@]}"
fi
echo "$MODE" > "$CONF_DIR/mode"
echo "$VERSION" > "$CONF_DIR/version"

if [[ $BBR -eq 1 ]]; then
    grep -q 'net.core.default_qdisc' /etc/sysctl.conf || echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
    grep -q 'net.ipv4.tcp_congestion_control' /etc/sysctl.conf || echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1 || true
    green "BBR enabled"
fi

# ---------- management command ----------
cat > "$MANAGER" <<'MANAGER_EOF'
#!/usr/bin/env bash
# tunnix - TunnixNode management
NAME=tunnix-node
CONF_DIR=/etc/tunnix-node
CONF=$CONF_DIR/config.json
COMPOSE=/opt/tunnix-node/docker-compose.yml
BIN=/usr/local/tunnix-node/tunnix-node
REPO_FILE=$CONF_DIR/repo
MODE=$(cat $CONF_DIR/mode 2>/dev/null || echo docker)
REPO=$(cat $REPO_FILE 2>/dev/null)

cli() {
    if [[ $MODE == docker ]]; then
        local image; image=$(sed -n 's/^ *image: *//p' $COMPOSE | head -n1)
        docker run --rm -v $CONF_DIR:$CONF_DIR "$image" "$@"
    else $BIN "$@"; fi
}
svc() {
    if [[ $MODE == docker ]]; then
        case $1 in
            start) docker compose -f $COMPOSE up -d ;;
            stop) docker compose -f $COMPOSE stop ;;
            restart) docker compose -f $COMPOSE up -d --force-recreate ;;
            status) docker ps -a --filter name=^/$NAME$ --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}' ;;
            log) docker logs -f --tail 200 $NAME ;;
        esac
    else
        case $1 in
            log) journalctl -u $NAME -e --no-pager -f ;;
            *) systemctl $1 $NAME ;;
        esac
    fi
}
usage() {
cat <<EOF
Usage: tunnix <command>
  start | stop | restart | status | log      control the service
  add   --panel P --api-host URL --node-id N --api-key K [--node-type T]
                                             add a node
  remove --api-host URL --node-id N          remove a node
  config                                     edit the configuration
  update [vX.Y.Z]                            update to a release
  x25519                                     generate a REALITY key pair
  version                                    show the version
  uninstall                                  remove TunnixNode
EOF
}

case "${1:-}" in
    start|stop|restart|status|log) svc "$1" ;;
    add) shift; cli add-node -c $CONF "$@" && svc restart ;;
    remove) shift; cli remove-node -c $CONF "$@" && svc restart ;;
    config) ${EDITOR:-vi} $CONF && cli check -c $CONF && svc restart ;;
    update) shift; V=${1:-}; [[ -n $V ]] && V="--version $V"
        TUNNIX_REPO=$REPO bash <(curl -fsSL "https://raw.githubusercontent.com/$REPO/main/scripts/install.sh") --mode $MODE $V --update-only ;;
    x25519) cli x25519 ;;
    version) cli version ;;
    uninstall)
        read -r -p "Remove TunnixNode and its configuration? [y/N] " a; [[ $a == y || $a == Y ]] || exit 0
        if [[ $MODE == docker ]]; then docker compose -f $COMPOSE down; rm -rf /opt/tunnix-node
        else systemctl disable --now $NAME; rm -f /etc/systemd/system/$NAME.service; systemctl daemon-reload; rm -rf /usr/local/tunnix-node; fi
        rm -rf $CONF_DIR /var/lib/tunnix-node /usr/bin/tunnix; echo "Removed." ;;
    *) usage ;;
esac
MANAGER_EOF
chmod +x "$MANAGER"
echo "$REPO" > "$CONF_DIR/repo"

# ---------- start ----------
if [[ "$MODE" == docker ]]; then
    docker compose -f "$COMPOSE_DIR/docker-compose.yml" up -d --force-recreate
else
    systemctl enable "$NAME" >/dev/null 2>&1
    systemctl restart "$NAME"
fi
sleep 3
green "TunnixNode $VERSION installed."
if [[ "$PANEL" == remnawave ]]; then
    yellow "Remnawave: add this server on the panel with port $NODE_PORT, and allow that port from the panel IP only."
fi
echo "Manage with: tunnix status | tunnix log | tunnix add ... | tunnix update"
"$MANAGER" status || true
