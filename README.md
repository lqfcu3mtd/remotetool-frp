# RemoteTool FRP MVP

一个薄管理层：中心登记现场端，管理员选择现场端以及**现场能访问的目标 IP/端口**，在管理员电脑的 `127.0.0.1` 建立 TCP 入口。数据转发全部由原版 FRP 的 STCP provider/visitor 完成。

```
管理员浏览器 → 本机 remotetool admin → 中心 remotetool server
管理员 frpc visitor → frps ← 现场 frpc provider → 现场网络内目标 IP:port
                           ↑
                    现场 remotetool agent
                    向中心出站轮询
```

不实现自定义隧道、VPN、虚拟网卡、远程桌面或文件传输功能。管理员程序必须运行在需要本机端口的电脑上。中心网页本身无法在管理员电脑绑定端口。

## 范围与依赖

- Go 1.25+ 构建；运行时不需要 Go、Node、Python 或第三方 Go 包。
- 原版 **FRP 0.71.0**，版本严格检查；分别下载目标平台的 `frpc` / `frps`。
- 每个现场端一个 `frpc`，管理员一个 `frpc`，可承载多个映射。
- 新增映射使用已验证的 `frpc reload -c`；撤销或变更已有映射会重启该实例的 frpc，确保旧连接立即断开。不依赖 Store API。
- 此 MVP 是**一个可信组织、一个运行中的管理员实例**模型。没有多租户/RBAC、审计数据库、安装程序或自动升级。
- 映射仅存内存。中心重启会清空映射；现场重新注册，管理员重新创建所需映射。这是保守的 MVP 行为，不会自动恢复旧授权。

## 构建

```sh
go build -trimpath -o remotetool .
go test ./...
```

交叉编译示例（在支持该命令格式的 shell 中）：

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o dist/remotetool-linux-arm64 .
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -o dist/remotetool-linux-armv7 .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o dist/remotetool-windows-amd64.exe .
```

交叉编译成功不等于设备实测。嵌入式 Linux 要核对 CPU 架构、内核兼容性、内存与 FRP 对应构建。Windows 示例中的 `binary` 改为 `C:/RemoteTool/frpc.exe`。配置路径相对当前工作目录。

## 配置并启动

`examples/` 全部为占位配置，不含可用凭据。复制为私有 `*.local.json`，按需改 IP、允许网段、端口与文件路径。不要提交实际配置/密钥。

1. 准备一个管理员 API 令牌、每个现场端独立 API 令牌，以及一个 FRP 连接令牌。各自至少 24 字符，使用密码管理器等产生的高熵值；不要复用管理员与端点令牌。占位值会被拒绝。
2. 中心运行原版 `frps -c frps.toml`。示例仅绑定 loopback；远程部署时自行选择服务地址和网络访问策略。FRP 服务证书需要匹配配置的域名/IP，agent/admin 的 `trustedCA` 指向信任的 CA。TLS 加密本身不等于验证服务端身份，因此客户端强制提供 CA。
3. 中心 `server.local.json` 对远程访问设置如 `"listen":"0.0.0.0:8443"`，并增加 `"tlsCert":"./control.crt"`、`"tlsKey":"./control.key"`。非 loopback 明文监听会被拒绝。也可将默认 loopback API 置于正确配置的 HTTPS 反向代理之后。
4. `remotetool server -config server.local.json`
5. 现场 `remotetool agent -config agent.local.json`。配置的 `endpointId` 必须与其令牌在中心对应的端点一致；中心和现场均检查目标 allowlist。
6. 管理员电脑 `remotetool admin -config admin.local.json`。打开打印的 `http://127.0.0.1:8181`，输入本次启动的临时 UI 令牌。令牌仅在页面内存中，不放 URL/localStorage。保持管理员程序运行，浏览器可以关闭。
7. 选择现场端，填写目标 IP、目标端口和管理员本机端口。例如现场 `192.168.10.20:502` → 管理员 `127.0.0.1:1502`。在原有业务软件中使用后者。

若管理 API 使用私有 CA，agent/admin 顶层增加 `"centralCA":"./control-ca.crt"`。管理 API 与 FRP 的证书设置相互独立。现场仅需向管理 API 和 FRP relay 出站连接；目标服务无需公网端口。

`allowedCIDRs` 必须明确给出。目标仅接受 IP 字面量，不接受 DNS 名；`allowedPorts` 省略时允许该网段所有 TCP 端口。请尽量缩小到实际服务，并避免把危险的设备管理端口加入允许范围。

## 状态与生命周期

- **现场在线**：管理 API 最近收到该端点心跳；不代表 FRP 隧道健康。
- **FRP 提供端 running**：FRP 状态 API 报告 provider 已注册；不代表目标应用可用。
- **目标 reachable**：现场完成目标 TCP 握手；不验证 HTTP、Modbus、SSH 等应用层，也不是从管理员完成端到端探测。
- **访问端 configured-unverified**：FRP 已接受 visitor 配置；FRP 0.71.0 不提供 visitor 运行状态 API，不能据此宣称端到端健康。端口冲突等需结合实际连接检查。
- 新增映射通过 reload，不中断既有映射。停止/删除/变更已有映射会重启该端 frpc，以撤销已建立连接，因此同一实例的其他映射也会短暂断开，业务客户端需要重连。原版 FRP 单纯 reload 只关监听，无法保证撤销已建立流，所以不能将其当作安全撤销。
- 操作通常在下一轮轮询及配置应用后生效。管理员轮询每 2 秒；异常会增加延迟。目标探测每批总预算 1 秒，最多 8 路并发，预算耗尽显示 unknown，不阻塞控制循环。
- 中心默认管理员租约 15 秒。管理员失联后，中心不再下发活动映射。客户端连续无法联系中心 10 秒后清空本地 FRP 配置并停止进程。网络操作有超时，因此撤销不是瞬时的。
- FRP 自身处理 relay 重连；管理程序重试意外退出的 frpc。目标离线单独标记，不把现场误判为离线。
- 普通退出会停止子进程并清除临时 FRP 配置；Linux 额外设置父进程退出时终止 frpc。不要用强制杀进程替代正常退出；部署时由操作系统服务管理器管理整组进程，确保强杀/崩溃时清理子进程。尤其 Windows 应配置服务包装器的子进程清理。
- 映射删除不保留历史；没有重启恢复或不可丢失的数据库。管理员多实例会竞争相同映射，不受支持。

## 安全边界

管理令牌与 FRP 令牌由操作人员私下配置，不由该项目创建账户或持久访问凭据。映射 STCP secret 与本地 FRP API 密码均临时生成，仅在进程/受限运行目录中使用。FRP API 仅绑定 loopback，受随机密码保护；管理 UI 也只绑定 `127.0.0.1`，校验 Host、Origin、Bearer token，且不启用跨域访问。

Linux/macOS 临时目录 0700、配置 0600。Windows 的 Unix mode 位不能替代 NTFS ACL；请运行在独立受信账户下，确保配置和 runtimeDir 只有该账户可读。管理员与现场机器上的其他高权限用户仍在信任边界内。

共享 FRP token 的现场端属于同一信任域。STCP 只凭每映射 secret 授权访问；此 MVP 不是恶意租户隔离方案。公网 frps 请保留 `proxyBindAddr="127.0.0.1"`，不要开放 FRP dashboard/vhost 等额外能力，使用专用 relay。配置仍需运维人员审查，代码不自动部署或修改防火墙。

## 测试

单元/HTTP 测试不需要 FRP：

```sh
go test ./...
```

真实 STCP 集成测试需要官方下载的同版本二进制：

```sh
FRP_TEST_DIR=/absolute/path/frp_0.71.0_linux_amd64 go test -race -count=1 ./...
```

未设置环境变量时，真实 FRP 用例应显示 skip，不能把它算作集成通过。测试仅启动 loopback 临时服务器，凭据只用于该次测试；不会部署公网服务。`insecureLocalTest:true` 仅限显式 loopback FRP 地址的本地测试，不允许远程关闭证书校验。

实测结果和剩余限制见 [VALIDATION.md](VALIDATION.md)。

## 官方依据

- [FRP v0.71.0 release](https://github.com/fatedier/frp/releases/tag/v0.71.0)
- [STCP 官方示例](https://gofrp.org/en/docs/examples/stcp/)
- [v0.71.0 frpc 配置](https://github.com/fatedier/frp/blob/v0.71.0/conf/frpc_full_example.toml)
- [v0.71.0 frps 配置](https://github.com/fatedier/frp/blob/v0.71.0/conf/frps_full_example.toml)

项目目前未添加许可声明，许可选择由仓库所有者决定。FRP 本身遵循其上游许可；仓库不打包 FRP 二进制。
