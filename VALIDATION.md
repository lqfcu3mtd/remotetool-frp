# 验证记录

验证日期：2026-10-08。环境：dot 云 Linux amd64；官方 Go 1.25.1；官方 FRP 0.71.0 二进制。所有网络测试仅使用 loopback，所有测试凭据为临时生成，不含真实现场资料。

## 已通过

- `go test ./...`：不依赖 FRP 的 registry、权限、UI HTTP handler、配置验证、探测预算单元测试。真实 FRP 用例在未设置环境变量时明确 skip。
- `go vet ./...`。
- `FRP_TEST_DIR=... go test -race -count=2 ./...`：完整套件连续两轮通过，包含真实 `frps`/`frpc`，约 58 秒。
- 单独 supervisor 测试连续三轮通过 race detector，包含验证 TLS 证书的 STCP 转发。
- `CGO_ENABLED=0` 交叉构建：Windows amd64、Linux amd64、Linux arm64、Linux ARMv7。构建产物未放入源码仓库。

## 真实 FRP 覆盖

- 两个映射到不同的本地测试目标，验证返回 payload 来自对应目标。
- 24 个同时连接，每个传输约 64 KiB 的 echo 数据。
- 新增映射使用 reload，原有 TCP 流保持可用。
- 停止/删除映射撤销已经建立的流，要求实际 EOF/连接重置，不能用超时冒充关闭。分别覆盖多映射和最后一个映射。
- 破坏性变更会重启该实例的 frpc，因此其他映射短暂断开；验证它们可重新连接。
- 停止后重新启动、删除后关闭监听、完整现场 agent 重启、relay frps 重启恢复。
- 目标 TCP 服务停止时，端点仍显示在线；目标另行显示不可达。
- 管理 API 真实断开超过 10 秒后，两端停用 frpc；控制恢复后可重新协调。
- 管理员租约真实过期，现场撤销 provider；管理员恢复后重新协调。
- frpc 崩溃后的退避重启、运行文件清理。

## 权限与边界覆盖

- 管理员/端点令牌隔离，端点不能使用管理员 API，也不能取得其他端点映射。
- IP 字面量、CIDR 与端口 allowlist；重复本机端口、映射数量限制、格式错误 JSON。
- Host/Origin 防护、本地 UI token 认证、UI 响应不泄露 STCP key。
- 远程管理 API 强制 HTTPS，HTTP 重定向拒绝，远程 FRP 必须验证 TLS CA。
- 1024 个阻塞探测共享一个可取消的批次预算，测试中的 50 ms 截止时间可及时结束，不按映射数线性阻塞心跳。
- Linux 文件权限断言；Windows 不以 Unix mode 位代替 ACL。

## 尚未验证 / 明确限制

- 尚未在实际 Windows 机器、ARM 网关、5G 网络或真实目标设备上运行。交叉构建不能替代设备实测。Windows 复测方法见 [WINDOWS-TEST.md](WINDOWS-TEST.md)。
- 浏览器视觉/点击交互尚未手工验证；HTTP handler 与 UI 安全边界已自动验证。
- 没有公网部署，没有防火墙变更，没有真实证书/凭据配置。
- Windows 非正常退出的进程树清理由服务管理器负责；Linux 使用父线程退出信号作为额外防护。正常退出会清理 frpc。
- FRP 0.71.0 无 visitor runtime 状态 API；configured-unverified 不宣称已成功转发。实际 payload 测试与现场 TCP 探测分别验证不同层次。
- 一个可信组织、一个管理员实例，内存映射；没有持久数据库、多租户隔离、审计/升级/安装器。

## 发现并修复的问题

原版 FRP reload 删除 provider/visitor 后，已经建立的 TCP 流仍可能继续传输。已将移除、禁用和任何目标/密钥/权限相关变更改为重启对应 frpc，并添加持有已建立流的撤销回归测试。新增映射仍采用 reload。

批量目标探测原先可能按并发批次数累加超时，现改为整个批次 1 秒预算，且能被退出上下文取消。中心请求体在获取 registry 锁前完成有限读取，避免慢请求占据全局锁。
