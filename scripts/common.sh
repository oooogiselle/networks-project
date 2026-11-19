# common.sh - shared settings and helpers for the namespace scripts.
# Sourced, not executed.

# Topology (spec Figure 1)
NS_INSIDE=inside
NS_FW=fw
NS_OUTSIDE=outside

CLIENT_A=10.0.1.2
CLIENT_B=10.0.1.3
FW_INSIDE=10.0.1.1
SERVER=10.0.2.2
ATTACKER=10.0.2.3
FW_OUTSIDE=10.0.2.1

# Scratch space for server files, pid files and logs.
RUN_DIR=${RUN_DIR:-/tmp/tunwall-test}

say()  { printf '>> %s\n' "$*"; }
warn() { printf '!! %s\n' "$*" >&2; }
die()  { printf '!! %s\n' "$*" >&2; exit 1; }

need_root() {
    [ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo $0 $*)"
}

# Run a command inside a namespace.
in_ns() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

# Package that provides each tool on Debian/Ubuntu.
pkg_for() {
    case $1 in
        ip) echo iproute2 ;;
        ping) echo iputils-ping ;;
        dig) echo dnsutils ;;
        dnsmasq) echo dnsmasq-base ;;   # binary only; no system service
        sha256sum|timeout) echo coreutils ;;
        *) echo "$1" ;;
    esac
}

# check_deps tool... : die listing every missing tool and the apt command.
check_deps() {
    local missing=() pkgs=() t
    for t in "$@"; do
        if ! command -v "$t" >/dev/null 2>&1; then
            missing+=("$t")
            pkgs+=("$(pkg_for "$t")")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        die "missing tools: ${missing[*]}
   install with: sudo apt-get install -y ${pkgs[*]}"
    fi
}

# wait_tcp ns ip port [tries] : wait until a TCP port accepts connections.
wait_tcp() {
    local ns=$1 ip=$2 port=$3 tries=${4:-50}
    while [ "$tries" -gt 0 ]; do
        if in_ns "$ns" bash -c "exec 3<>/dev/tcp/$ip/$port" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
        tries=$((tries - 1))
    done
    return 1
}
