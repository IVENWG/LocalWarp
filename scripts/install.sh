#!/usr/bin/env bash
# ==============================================================================
# LocalWarp Connector: macOS One-Line Installer
# Install:   curl -fsSL https://localwarp.com/install.sh | bash
# Uninstall: curl -fsSL https://localwarp.com/install.sh | bash -s uninstall
# ==============================================================================
set -e

REPO="IVENWG/LocalWarp"
INSTALL_DIR="${HOME}/.local/bin"
BINARY_NAME="localwarp-connector"
TARGET_PATH="${INSTALL_DIR}/${BINARY_NAME}"
PLIST="${HOME}/Library/LaunchAgents/com.localwarp.connector.plist"
SERVICE_NAME="localwarp-connector"
SERVICE_FILE="${HOME}/.config/systemd/user/${SERVICE_NAME}.service"

do_uninstall() {
    echo "=================================================="
    echo "    LocalWarp Connector Uninstall                "
    echo "=================================================="
    OS="$(uname -s)"
    if [ "${OS}" = "Darwin" ]; then
        if [ -f "${PLIST}" ]; then
            launchctl bootout "gui/$(id -u)/com.localwarp.connector" 2>/dev/null \
                || launchctl unload "${PLIST}" 2>/dev/null || true
            rm -f "${PLIST}"
            echo "[+] Removed launchd agent."
        fi
    else
        systemctl --user disable --now "${SERVICE_NAME}" 2>/dev/null || true
        rm -f "${SERVICE_FILE}"
        systemctl --user daemon-reload 2>/dev/null || true
        echo "[+] Removed systemd user service."
    fi
    rm -f "${TARGET_PATH}"
    rm -f /tmp/localwarp-connector.log /tmp/localwarp-connector.err
    echo "[+] Removed binary and logs."
    echo ""
    echo "Done. Your iPhone pairing records and iTunes are NOT affected."
}

if [ "${1}" = "uninstall" ] || [ "${1}" = "--uninstall" ] || [ "${1}" = "-u" ]; then
    do_uninstall
    exit 0
fi

echo "=================================================="
echo "    LocalWarp iPhone Location Connector Setup    "
echo "=================================================="

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}" in
    Darwin)
        PLATFORM="macos"
        ;;
    Linux)
        echo "[-] Linux is not supported yet. Please use Windows or macOS."
        exit 1
        ;;
    *)
        echo "[-] Unsupported operating system: ${OS}"
        echo "    For Windows, please run install.ps1 via PowerShell."
        exit 1
        ;;
esac

case "${ARCH}" in
    x86_64|amd64)
        MACHINE="x64"
        ;;
    arm64|aarch64)
        MACHINE="arm64"
        ;;
    *)
        echo "[-] Unsupported architecture: ${ARCH}"
        exit 1
        ;;
esac

echo "[+] Detected: ${PLATFORM} (${MACHINE})"

mkdir -p "${INSTALL_DIR}"

DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/LocalWarp-Connector-${PLATFORM}-${MACHINE}"

# Stage in the destination directory, then rename atomically. Writing directly
# over a running executable can fail or damage the installed version.
STAGED_BINARY="$(mktemp "${INSTALL_DIR}/.localwarp-connector.XXXXXX")"
trap 'rm -f "${STAGED_BINARY}"' EXIT

echo "[*] Downloading standalone LocalWarp Connector binary..."
LOCAL_DEV_BUILD=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    LOCAL_DEV_BUILD="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)/dist/connectors/LocalWarp-Connector-${PLATFORM}-${MACHINE}"
fi

DOWNLOAD_OK=0
if [ "${LOCALWARP_USE_LOCAL_BUILD:-0}" != "1" ]; then
    if command -v curl >/dev/null 2>&1; then
        if curl -fsSL "${DOWNLOAD_URL}" -o "${STAGED_BINARY}" 2>/dev/null; then
            DOWNLOAD_OK=1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget -qO "${STAGED_BINARY}" "${DOWNLOAD_URL}" 2>/dev/null; then
            DOWNLOAD_OK=1
        fi
    fi
fi

if [ "${DOWNLOAD_OK}" -eq 0 ]; then
    if [ -n "${LOCAL_DEV_BUILD}" ] && [ -f "${LOCAL_DEV_BUILD}" ]; then
        echo "[+] Falling back to local build: ${LOCAL_DEV_BUILD}"
        cp "${LOCAL_DEV_BUILD}" "${STAGED_BINARY}"
    else
        echo "[-] Download from GitHub Releases failed or release not yet published."
        exit 1
    fi
fi

if [ -n "${LOCALWARP_EXPECTED_SHA256:-}" ]; then
    if command -v shasum >/dev/null 2>&1; then
        ACTUAL_SHA256="$(shasum -a 256 "${STAGED_BINARY}" | awk '{print $1}')"
    elif command -v sha256sum >/dev/null 2>&1; then
        ACTUAL_SHA256="$(sha256sum "${STAGED_BINARY}" | awk '{print $1}')"
    else
        echo "[-] Neither shasum nor sha256sum available to verify LOCALWARP_EXPECTED_SHA256."
        exit 1
    fi
    if [ "${ACTUAL_SHA256}" != "${LOCALWARP_EXPECTED_SHA256}" ]; then
        echo "[-] SHA-256 mismatch! Expected ${LOCALWARP_EXPECTED_SHA256}, got ${ACTUAL_SHA256}"
        exit 1
    fi
    echo "[+] Verified binary SHA-256: ${ACTUAL_SHA256}"
fi

chmod +x "${STAGED_BINARY}"
mv -f "${STAGED_BINARY}" "${TARGET_PATH}"
trap - EXIT
echo "[+] Binary installed to: ${TARGET_PATH}"

# Service auto-start registration
echo "[*] Configuring auto-start service..."
if [ "${PLATFORM}" = "macos" ]; then
    LAUNCH_DIR="${HOME}/Library/LaunchAgents"
    mkdir -p "${LAUNCH_DIR}"
    cat <<EOF > "${PLIST}"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.localwarp.connector</string>
    <key>ProgramArguments</key>
    <array>
        <string>${TARGET_PATH}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/localwarp-connector.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/localwarp-connector.err</string>
</dict>
</plist>
EOF
    launchctl bootout "gui/$(id -u)/com.localwarp.connector" 2>/dev/null || true
    # 优先现代 bootstrap 语法，旧版 macOS 回退到已废弃但可用的 load；
    # 两者都失败时给出手动命令兜底，不能让安装停在半成品状态
    launchctl bootstrap "gui/$(id -u)" "${PLIST}" 2>/dev/null \
        || launchctl load "${PLIST}" 2>/dev/null \
        || echo "[-] 自动启动服务失败，请手动执行: launchctl load ${PLIST}"
    echo "[+] macOS launchd service configured and started!"
fi

wait_for_connector_health() {
    # launchd may take several seconds to spawn the bundled service after bootstrap.
    # Wait for readiness so a successful install does not immediately print a false
    # connection error while the service is still starting.
    command -v curl >/dev/null 2>&1 || return 1
    for ((attempt = 1; attempt <= 30; attempt++)); do
        if curl -fs --max-time 1 http://127.0.0.1:28888/health | grep -q '"healthy"'; then
            return 0
        fi
        if [ "${attempt}" -lt 30 ]; then
            sleep 1
        fi
    done
    return 1
}

if wait_for_connector_health; then
    echo ""
    echo "=================================================="
    echo "  🎉 LocalWarp Connector is ONLINE!              "
    echo "  Return to the workbench to continue.           "
    echo "  Listening on: http://127.0.0.1:28888           "
    echo "  Web Studio:   https://localwarp.com/app        "
    echo "  Uninstall:                                     "
    echo "  curl -fsSL https://localwarp.com/install.sh | bash -s uninstall"
    echo "=================================================="
else
    echo ""
    echo "[!] Connector installed but did not become ready within 30 seconds."
    echo "[*] Return to the workbench and select Recheck."
    echo "[*] If it remains offline, inspect /tmp/localwarp-connector.err"
fi
