# 连接器第三方许可与分发核查

更新时间：2026-10-19。本文记录仓库中可核实的依赖事实，不构成法律意见。

## 当前阻断项

连接器运行依赖固定为 `pymobiledevice3==11.36.0`，构建脚本会将其模块打入独立发行包。该项目的许可证为 GPL-3.0-or-later，可在其上游源码仓库和发行元数据中核对。此前本文件声称“发行物未引入 GPL 代码”是错误的，不能继续作为分发合规结论。

项目还使用 `scripts/sync-public-repo.sh` 将连接器源代码同步到公开仓库。同步清单现包含连接器入口、多设备实现、worker 钩子、构建校验器和锁定的依赖文件；这只解决源文件清单缺漏，尚未证明公开仓库已更新、发布包可复现，或已经满足适用于 LocalWarp 分发方式的全部许可义务。

**在闭源或商业二进制发布前，须由有资质的法律顾问确认可采用的许可路径。**可评估的工程路径包括：按兼容 GPL 的条件发布完整连接器及构建所需源码、取得适用的商业授权，或移除该依赖并以独立实现替代。不得把未经审查的二进制描述为已完成 GPL 合规。

## 构建与审计约束

- `requirements-connector.txt` 是连接器运行依赖清单；`requirements-connector-build.txt` 固定 PyInstaller 版本。
- `scripts/build_connector.py` 在构建前核对 PyInstaller、pymobiledevice3 和 pytun-pmd3 版本；它从锁定的 Python 环境选取依赖，不再把 `external_research/pymobiledevice3` 的开发副本加入 PyInstaller 搜索路径。
- 最新临时 macOS 包的 PyInstaller 归档中可见 `pymobiledevice3-11.36.0.dist-info/licenses/LICENSE`。这证明该依赖的许可证文本进入了包，不单独证明完整源码交付或其他许可义务已满足。
- `scripts/verify_connector_build.py` 现检查发行包是否包含 CoreDevice、多设备、运行时模块以及内嵌 `pymobiledevice3` 许可证元数据（`license_metadata`），并检测系统代码签名状态（`signature`）；传入 `--require-signed` 时，若二进制未通过 macOS Developer ID + Gatekeeper（`spctl --assess`）或 Windows Authenticode 校验，将直接返回非零退出码阻断发布。
- 前端下载面板（`src/frontend/src/localwarp/ConnectorDownloads.tsx`）已显式提供连接器公开源码仓库（`https://github.com/IVENWG/LocalWarp`）与 GPL-3.0-or-later 许可说明入口。
- `scripts/sync-public-repo.sh` 只在指定公开仓库的本地克隆中同步并暂存文件（含 `docs/licensing.md`），不提交、不推送。执行同步后仍需核实目标仓库文件、构建结果和许可证声明。
- 每次发布应保留运行依赖及构建依赖的精确版本、对应源码位置、第三方许可证副本、构建日志和产物校验结果。

## 其他研究资料

关于 Apple 专有资产、历史上调研的 WLOC 与其他第三方项目的内容，见各自研究文档。它们不替代对当前发行包实际依赖清单的审查。
