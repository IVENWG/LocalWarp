#!/usr/bin/env bash
set -e

# ==============================================================================
# LocalWarp Connector Launcher (macOS & Linux)
# ==============================================================================
echo "============================================="
echo "   LocalWarp Connector Daemon (Scheme C)     "
echo "============================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MACHINE="$(uname -m)"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [ "${OS}" = "darwin" ]; then
    OS="macos"
fi

if [ "${MACHINE}" = "x86_64" ]; then
    ARCH="x64"
elif [ "${MACHINE}" = "arm64" ] || [ "${MACHINE}" = "aarch64" ]; then
    ARCH="arm64"
else
    ARCH="${MACHINE}"
fi

STANDALONE_BIN="${SCRIPT_DIR}/dist/connectors/LocalWarp-Connector-${OS}-${ARCH}"

# 1. Prefer compiled zero-dependency standalone binary if present
if [ -f "${STANDALONE_BIN}" ]; then
    echo "[+] Found standalone zero-dependency binary!"
    echo "[+] Launching ${STANDALONE_BIN}..."
    exec "${STANDALONE_BIN}" "$@"
fi

# 2. Fallback to Python source execution
echo "[*] Standalone binary not found. Running from Python source..."
# 只注入 src/poc：pymobiledevice3 统一走 pip 安装版本（vendored 副本仅作为
# server.py 内部的兜底搜索路径，pip 版存在时永远优先）。PYTHONPATH 未定义时
# 不追加尾部空条目（POSIX 空条目等价于把 cwd 引入模块搜索路径）
export PYTHONPATH="${SCRIPT_DIR}/src/poc${PYTHONPATH:+:$PYTHONPATH}"

if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 could not be found. Please install Python 3.10+ or download the prebuilt binary."
    exit 1
fi

exec python3 "${SCRIPT_DIR}/src/backend/server.py" "$@"
