#!/usr/bin/env bash
#
# CVETodo Agent installer for Linux and macOS.
#
# Downloads the latest release from GitHub, installs it to /usr/local/bin,
# writes the configuration, and registers the agent as a system service
# (systemd on Linux, launchd on macOS) that scans the system once a day.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/CVE-Todo/CVETodo-agent/main/install.sh | sudo bash
#
# Non-interactive:
#   curl -fsSL ... | sudo CVETODO_API_KEY=your-key CVETODO_TEAM_ID=your-team bash
#
# To disable the agent later:
#   - cvetodo-agent service stop        (or 'service uninstall')
#   - set 'agent.enabled: false' in /etc/cvetodo-agent/.cvetodo-agent.yaml
#   - systemctl stop cvetodo-agent / systemctl disable cvetodo-agent

set -euo pipefail

REPO="CVE-Todo/CVETodo-agent"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/cvetodo-agent"
CONFIG_FILE="${CONFIG_DIR}/.cvetodo-agent.yaml"
DATA_DIR="/var/lib/cvetodo-agent/data"

# --- Preconditions -----------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this installer must be run as root (use sudo)." >&2
    exit 1
fi

case "$(uname -s)" in
    Linux)  OS="linux" ;;
    Darwin) OS="darwin" ;;
    *) echo "Error: unsupported operating system: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
    x86_64|amd64) ARCH="amd64" ;;
    *) echo "Error: unsupported architecture: $(uname -m) (only amd64 builds are published)" >&2; exit 1 ;;
esac

# --- Download latest release -------------------------------------------------

echo "Looking up the latest CVETodo Agent release..."
TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep -m1 '"tag_name"' | cut -d'"' -f4)
if [ -z "$TAG" ]; then
    echo "Error: could not determine the latest release tag." >&2
    exit 1
fi

TARBALL="cvetodo-agent-${TAG}-${OS}-${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${TAG}/${TARBALL}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${TAG}/SHA256SUMS"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading ${TARBALL} (${TAG})..."
curl -fsSL "$URL" -o "${TMP_DIR}/${TARBALL}"

# Verify the artifact against the published checksums before unpacking
if curl -fsSL "$CHECKSUMS_URL" -o "${TMP_DIR}/SHA256SUMS" 2>/dev/null; then
    echo "Verifying checksum..."
    (cd "$TMP_DIR" && grep " ${TARBALL}\$" SHA256SUMS | sha256sum -c -) || {
        echo "Error: checksum verification failed for ${TARBALL}. Aborting." >&2
        exit 1
    }
else
    echo "Warning: no SHA256SUMS published for release ${TAG}; skipping checksum verification." >&2
fi

tar -xzf "${TMP_DIR}/${TARBALL}" -C "$TMP_DIR"

# --- Install binary ----------------------------------------------------------

# Stop an existing service before replacing the binary (upgrade path)
if command -v cvetodo-agent >/dev/null 2>&1; then
    cvetodo-agent service stop >/dev/null 2>&1 || true
fi

install -m 0755 "${TMP_DIR}/cvetodo-agent" "${INSTALL_DIR}/cvetodo-agent"
echo "Installed cvetodo-agent to ${INSTALL_DIR}."

# --- Configuration -----------------------------------------------------------

if [ -f "$CONFIG_FILE" ]; then
    echo "Existing configuration found at ${CONFIG_FILE} - keeping it."
else
    API_KEY="${CVETODO_API_KEY:-}"
    TEAM_ID="${CVETODO_TEAM_ID:-}"

    if [ -z "$API_KEY" ] || [ -z "$TEAM_ID" ]; then
        if [ ! -e /dev/tty ]; then
            echo "Error: no terminal available for prompts." >&2
            echo "Re-run with CVETODO_API_KEY and CVETODO_TEAM_ID environment variables set." >&2
            exit 1
        fi
        echo ""
        echo "To obtain your API key and team ID: log into https://cvetodo.com,"
        echo "open your team settings and generate a key under 'Agent Keys'."
        echo ""
        if [ -z "$API_KEY" ]; then
            printf "Enter your CVETodo team API key: "
            read -r API_KEY < /dev/tty
        fi
        if [ -z "$TEAM_ID" ]; then
            printf "Enter your CVETodo team ID: "
            read -r TEAM_ID < /dev/tty
        fi
    fi

    if [ -z "$API_KEY" ] || [ -z "$TEAM_ID" ]; then
        echo "Error: an API key and team ID are required." >&2
        exit 1
    fi

    mkdir -p "$CONFIG_DIR" "$DATA_DIR"

    if [ "$OS" = "linux" ]; then
        SCANNERS='    - "dpkg"
    - "rpm"
    - "pip"
    - "npm"'
    else
        SCANNERS='    - "pip"
    - "npm"'
    fi

    cat > "$CONFIG_FILE" <<EOF
# CVETodo Agent Configuration
api:
  base_url: "https://cvetodo.com"
  api_key: "${API_KEY}"
  team_id: "${TEAM_ID}"
  timeout: "30s"

agent:
  enabled: true       # set to false to disable all scanning without uninstalling
  name: "$(hostname)"
  scan_interval: "24h"
  report_interval: "24h"
  data_dir: "${DATA_DIR}"

log_level: "info"
log_format: "text"

scanner:
  enabled_scanners:
${SCANNERS}
EOF
    chmod 600 "$CONFIG_FILE"
    echo "Configuration written to ${CONFIG_FILE}."
fi

# --- Service -----------------------------------------------------------------

echo "Registering the CVETodo Agent service..."
"${INSTALL_DIR}/cvetodo-agent" service install

echo ""
echo "CVETodo Agent installed successfully."
echo "It runs as a system service and scans this system once a day."
echo ""
echo "To turn it off:"
echo "  - cvetodo-agent service stop        (until next boot)"
echo "  - cvetodo-agent service uninstall   (remove entirely)"
echo "  - set 'agent.enabled: false' in ${CONFIG_FILE}"
if [ "$OS" = "linux" ]; then
    echo "  - systemctl stop cvetodo-agent / systemctl disable cvetodo-agent"
fi
