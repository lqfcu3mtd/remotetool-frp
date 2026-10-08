# Windows 本机复测（不连接现场、不改防火墙）

范围：在已授权的 Windows 开发环境编译本项目，运行单元测试及**真实 FRP loopback 集成测试**。测试不启动公网监听，不打开 Windows 防火墙端口，不使用真实现场/业务配置。

## 前置检查

PowerShell：

```powershell
go version
git --version
```

需要受支持的 Go 1.25 或更新版本。如果未安装，请先检查是否已有官方 Go 安装；如需安装，仅使用 https://go.dev/dl/ 官方来源，并遵守本机安装授权。

下载 FRP **v0.71.0 Windows amd64** 官方发布包，核验发布资产来源/校验值后，解压到私有临时目录。例如 `C:\Temp\frp_0.71.0_windows_amd64`，应包含 `frpc.exe`、`frps.exe`：

https://github.com/fatedier/frp/releases/tag/v0.71.0

```powershell
& 'C:\Temp\frp_0.71.0_windows_amd64\frpc.exe' --version
& 'C:\Temp\frp_0.71.0_windows_amd64\frps.exe' --version
```

两个命令必须返回 `0.71.0`。不要用来源不明的同名程序，不要添加杀毒/安全绕过设置。

## 编译及测试

在本仓库目录：

```powershell
go test -count=1 -v ./...
go vet ./...
go build -trimpath -o remotetool.exe .
$env:FRP_TEST_DIR = 'C:\Temp\frp_0.71.0_windows_amd64'
go test -count=1 -v ./...
Remove-Item Env:FRP_TEST_DIR
```

未设置 FRP_TEST_DIR 的第一轮仅运行独立测试；真实 FRP 用例会 skip。第二轮必须看到真实 FRP 用例 PASS，不能把 skip 当通过。记录 Go 版本、FRP 版本、测试输出和 Windows 版本。

Race detector 可选；Windows 的 `go test -race` 需要受支持的 C 工具链。不要因为缺少 C 编译器而谎报 race 通过，也不必为此安装额外工具；先完成普通集成测试并记录限制。

测试使用 `t.TempDir()` 临时配置、随机测试秘密及自动分配的 loopback 端口；退出清理进程/配置。不使用示例占位凭据连接任何服务。测试失控时先终止本次测试启动的进程，勿批量杀死机器已有的 frpc/frps。

## 浏览器 UI 补充验证

自动测试覆盖 UI 的 Host/Origin/token 检查和状态秘密清除，但不能代替浏览器交互验证。若要手工 UI 联调，请在本地测试配置中指定 loopback 的中心与 relay，使用一次性测试令牌，并显式设置 `frp.insecureLocalTest=true`（仅允许 literal loopback 地址）。运行 `remotetool.exe admin -config <临时配置>`，打开终端打印的本地 URL，输入临时 UI 令牌。

重点检查：登录错误与重试、重复点击、多个映射、停止/启动/删除、目标关闭但端点在线、relay 重启重连、端口冲突。UI 的 configured-unverified 不能视为转发成功，必须向本地 visitor 端口发送实际测试请求核对 payload。

不要把临时配置、令牌、证书或 runtimeDir 提交仓库。远程正式部署必须使用 TLS 验证与真实运维配置；本文件不授权部署。
