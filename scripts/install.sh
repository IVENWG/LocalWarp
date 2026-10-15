#!/usr/bin/env bash
# ==============================================================================
# LocalWarp Connector: Universal Unix One-Line Installer (macOS & Linux)
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
    echo "    LocalWarp Connector Uninstall (macOS/Linux)   "
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
        PLATFORM="linux"
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

# CI 只产出 linux-x64：arm64 Linux 明确提示，避免下载必然失败的产物
if [ "${PLATFORM}" = "linux" ] && [ "${MACHINE}" = "arm64" ]; then
    echo "[-] Linux arm64 暂无官方构建。请在 x86_64 Linux 上使用，或克隆仓库自行运行 scripts/build_connector.py 构建。"
    exit 1
fi

mkdir -p "${INSTALL_DIR}"

DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/LocalWarp-Connector-${PLATFORM}-${MACHINE}"

echo "[*] Downloading standalone LocalWarp Connector binary..."
# Fallback to local build if available in dev environment
# （curl | bash 管道态下 BASH_SOURCE 为空，此时必须跳过本地构建回退）
LOCAL_DEV_BUILD=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    LOCAL_DEV_BUILD="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)/dist/connectors/LocalWarp-Connector-${PLATFORM}-${MACHINE}"
fi
if [ -n "${LOCAL_DEV_BUILD}" ] && [ -f "${LOCAL_DEV_BUILD}" ]; then
    echo "[+] Using local build: ${LOCAL_DEV_BUILD}"
    cp "${LOCAL_DEV_BUILD}" "${TARGET_PATH}"
else
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${DOWNLOAD_URL}" -o "${TARGET_PATH}" || {
            rm -f "${TARGET_PATH}"
            echo "[-] Download from GitHub Releases failed or release not yet published."
            exit 1
        }
    else
        wget -qO "${TARGET_PATH}" "${DOWNLOAD_URL}" || {
            rm -f "${TARGET_PATH}"
            echo "[-] Download from GitHub Releases failed or release not yet published."
            exit 1
        }
    fi
fi

chmod +x "${TARGET_PATH}"
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
elif [ "${PLATFORM}" = "linux" ]; then
    SYSTEMD_DIR="${HOME}/.config/systemd/user"
    mkdir -p "${SYSTEMD_DIR}"
    cat <<EOF > "${SERVICE_FILE}"
[Unit]
Description=LocalWarp iPhone Location Connector Daemon
After=network.target

[Service]
Type=simple
ExecStart=${TARGET_PATH}
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload 2>/dev/null || true
    systemctl --user enable --now "${SERVICE_NAME}.service" 2>/dev/null || true
    echo "[+] Linux systemd user service configured and started!"
fi

# Health check
sleep 2
if command -v curl >/dev/null 2>&1 && curl -fsS --max-time 3 http://127.0.0.1:28888/health | grep -q '"healthy"'; then
    echo ""
    echo "=================================================="
    echo "  🎉 LocalWarp Connector is ONLINE!              "
    echo "  Listening on: http://127.0.0.1:28888           "
    echo "  Web Studio:   https://localwarp.com/app        "
    echo "  Uninstall:                                     "
    echo "  curl -fsSL https://localwarp.com/install.sh | bash -s uninstall"
    echo "=================================================="
else
    echo ""
    echo "[!] Service registered. Check status: http://127.0.0.1:28888/health"
    echo "[*] Logs: /tmp/localwarp-connector.log"
fi
