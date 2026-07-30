# CredAgent: 基于FUSE的凭证保护系统

一个零信任凭证保护系统，可防止AI代理泄露api-key、AKSK、private Key、password等应用身份凭证。

## 概述

CredAgent统一加密存储凭证内容，并通过用户文件系统(FUSE)向应用程序提供文件方式访问凭据文件。当应用程序访问文件时，对源程序身份、完整性、访问次数、参数语义进行校验，判断安全后才会解密返回凭据给应用程序。


核心原理：
1. **凭证加密存储**：原始凭证文件被加密存储在安全的"飞地"（Enclave）中，永远不会以明文形式保存在磁盘上
2. **FUSE虚拟文件系统**：通过FUSE技术创建一个虚拟文件系统，拦截对受保护文件的访问请求
3. **验证策略**：验证程序uid的权限、程序或脚本的完整性、同一PID允许Open文件的次数、cmdline的语义分析。

## Components Overview

The CredAgent system consists of three main components:

### 1. credagent (飞地守护进程)
- **功能**：后台服务进程，管理凭据、访问控制和FUSE文件系统
- **职责**：
  - 存储和管理加密的凭证文件
  - 执行访问策略验证
  - 挂载FUSE文件系统
  - 实现凭据文件的Open、Read等文件操作
  - 程序Open文件时，获取进程上下文信息并进行策略验证

### 2. credctl (凭证操作CLI工具)
- **功能**：命令行工具，用于保护和释放凭证文件，配置保护策略
- **职责**：
  - 将原始凭证文件移入credagent，安全清除原始文件并创建文件符号链接指向FUSE文件路径
  - 定义访问凭据文件时的访问控制策略
  - 动态管理授权程序（追加/移除/刷新SHA256）
  - 查看受保护文件和访问控制策略
  - 导出凭据内容（dump）和更新凭据内容（restore），无需解除保护
  - 还原原始凭据文件

### 3. credreq (接收器CLI工具)
- **功能**：命令行工具，用于接收和处理凭据文件
- **职责**：
  - 接收外部凭据文件
  - 处理凭据的安全导入流程
  - 提供凭据传输的安全验证机制

## 如何给OS安装、配置FUSE

### Ubuntu/Debian系统

1. **安装FUSE支持**
```bash
sudo apt update
sudo apt install fuse libfuse-dev
```

2. **更新FUSE配置**
```bash
echo "user_allow_other" | sudo tee -a /etc/fuse.conf
```

2. **启用用户挂载**
```bash
sudo sh -c "echo 'user_allow_other' >> /etc/fuse.conf"
```

### macOS系统

1. **安装macFUSE**
   - 访问 https://osxfuse.github.io/ 下载并安装macFUSE
   - 或使用Homebrew安装：
   ```bash
   brew install --cask macfuse
   ```

2. **重启系统**
   - 安装完成后需要重启系统以加载macFUSE内核扩展

### 验证FUSE安装

#### Linux系统
```bash
# 检查FUSE模块是否已加载
lsmod | grep fuse

# 检查FUSE版本
fusermount -V
```

#### macOS系统
```bash
# 检查macFUSE是否正确安装
kextstat | grep fuse
```

## 编译

### Linux

#### 编译环境要求
- Go 1.21+
- 支持FUSE的Linux内核

#### 编译组件

```bash
#cd 项目根目录
go build -o credagent ./cmd/credagent
go build -o credctl ./cmd/credctl
go build -o credreq ./cmd/credreq
```

> **cmdline 防篡改检测（`cmdline_trusted_source`）**
>
> 脚本类解释器（Python、Node、Ruby、Perl 等）可以在运行时篡改 `/proc/<pid>/cmdline`，伪装成合法脚本绕过 SHA256 校验。credagent 通过可信 cmdline 来源在进程 execve 时采集原始命令行参数，与 `/proc` 中读到的值比对，检测篡改行为。
>
> 在配置文件中设置 `cmdline_trusted_source` 字段启用此功能：
>
> ```json
> {
>   "cmdline_trusted_source": "ebpf,auditd"
> }
> ```
>
> 支持的来源（按配置顺序尝试，第一个可用的生效）：
>
> | 来源 | 原理 | 环境要求 |
> |------|------|----------|
> | `ebpf` | eBPF hook `sys_enter_execve`，内核层采集 cmdline 存入 BPF hash map | Linux >= 5.2，BTF 启用（`/sys/kernel/btf/vmlinux` 存在），syscall tracepoints 可用 |
> | `auditd` | Linux audit 子系统记录 execve argv，credagent 实时解析 audit 日志 | auditd 已安装且 enabled，无 `task,never` 规则阻断（credagent 启动时自动处理） |
>
> **降级行为**：
> - 不配置或配置的来源均不可用 → 使用 `/proc/<pid>/cmdline`，无篡改检测能力
> - WSL2 环境下 eBPF 和 auditd 均不可用，自动降级
>
> **auditd 来源说明**：
> - 启动时自动扫描系统中的解释器 realpath（python、perl、ruby、node、php、java），仅对这些解释器添加 execve audit 规则
> - 规则使用 `-k credagent_cmdline` 标签，不影响其他审计规则
> - 如果系统存在 `-a task,never` 规则（阻止所有 syscall 审计），credagent 会自动移除该规则以启用审计，退出时恢复
> - credagent 退出时自动清理所有添加的 audit 规则
>
> **eBPF 来源说明**：
>
> eBPF 字节码（`internal/execsnoop/execsnoop_x86_bpfel.o`）和 Go 绑定代码已预生成并提交到仓库，`go build` 即包含 eBPF 支持，**无需额外编译步骤**。`bpf2go` 将字节码嵌入 Go 二进制，编译后的 credagent 可直接分发到其他节点，目标节点无需安装 clang 或任何编译工具。
>
> 如果目标节点内核不支持 BTF 或 syscall tracepoints 未注册，credagent 启动时自动跳过 eBPF，日志输出 `eBPF execsnoop: syscall tracepoints not available`。

#### 重新生成 eBPF 字节码

当修改了 eBPF C 源码（`internal/execsnoop/bpf/execsnoop.c`）后，需要重新生成字节码和 Go 绑定代码：

```bash
# 安装编译依赖（仅生成字节码的开发机需要，目标运行节点不需要）
sudo apt-get install clang libbpf-dev

# 重新生成 eBPF 字节码和 Go 绑定代码
go generate ./internal/execsnoop/

# 重新编译 credagent
go build -o credagent ./cmd/credagent
```

生成后请将更新的 `execsnoop_x86_bpfel.o` 和 `execsnoop_x86_bpfel.go` 提交到仓库。

### macOS

#### 编译环境要求
- Go 1.21+
- macFUSE

#### 编译组件

```bash
#cd 项目根目录
go build -o credagent ./cmd/credagent
go build -o credctl ./cmd/credctl
go build -o credreq ./cmd/credreq
```

> **macOS 不支持 eBPF cmdline 防篡改检测**
>
> macOS 没有 eBPF 支持，编译时 eBPF 模块自动排除。credagent 使用 `/proc` 等效接口获取进程 cmdline，但**无法检测进程运行时篡改 cmdline 的攻击**。脚本类程序（如 Python）可能通过修改 `sys.argv` 等方式伪造 cmdline，存在绕过策略引擎的风险。

## 安装

### 使用INSTALL脚本安装

项目提供了自动化安装脚本，可根据操作系统选择：

#### Linux安装
使用`INSTALL`脚本在Linux系统上一键安装所有组件、配置文件和服务。

```bash
# 1. 首先构建所有二进制文件（如果尚未构建）
go build -o credagent ./cmd/credagent
go build -o credctl ./cmd/credctl
go build -o credreq ./cmd/credreq

# 2. 运行安装脚本（需要root权限）
sudo ./INSTALL
```

Linux安装脚本会执行以下操作：
- 创建系统用户和组`credagent`
- 将二进制文件复制到`/usr/local/bin/`
- 安装配置文件到`/usr/local/etc/credagent/`
- 安装systemd服务文件到`/etc/systemd/system/`
- 重载systemd守护进程

#### macOS安装
使用`INSTALL_MACOS`脚本在macOS系统上一键安装所有组件、配置文件和launchd服务。

```bash
# 1. 首先构建所有二进制文件（如果尚未构建）
go build -o credagent ./cmd/credagent
go build -o credctl ./cmd/credctl
go build -o credreq ./cmd/credreq

# 2. 运行安装脚本（需要root权限）
sudo ./INSTALL_MACOS
```

macOS安装脚本会执行以下操作：
- 将二进制文件复制到`/usr/local/bin/`
- 安装配置文件到`/usr/local/etc/credagent/`
- 创建launchd服务文件到`/Library/LaunchDaemons/`
- 设置适当的文件权限

### 手动安装

如果不想使用安装脚本，也可以手动安装：

```bash
# 1. 构建二进制文件
go build -o credctl ./cmd/credctl
go build -o credagent ./cmd/credagent
go build -o credreq ./cmd/credreq

# 2. 创建系统用户和目录
sudo groupadd -r credagent
sudo useradd -r -s /sbin/nologin -M -g credagent credagent
sudo mkdir -p /usr/local/bin
sudo mkdir -p /usr/local/etc/credagent/engine
sudo mkdir -p /usr/local/etc/credagent/credctl
sudo mkdir -p /var/log/credagent

# 3. 安装二进制文件
sudo cp credctl credagent credreq /usr/local/bin/
sudo chown root:root /usr/local/bin/credagent

# 4. 安装配置文件
sudo cp config.template/config/engine/config.json /usr/local/etc/credagent/engine/config.json
sudo cp config.template/config/credctl/config.json /usr/local/etc/credagent/credctl/config.json

# 5. 安装systemd服务文件
sudo cp credagent.service /etc/systemd/system/
sudo chmod 644 /etc/systemd/system/credagent.service

# 6. 重载systemd守护进程
sudo systemctl daemon-reload
```

## 配置文件

安装后，系统会在`/usr/local/etc/credagent/`目录下创建配置文件：

### credagent配置文件

credagent守护进程的配置文件，默认位于`/usr/local/etc/credagent/engine/config.json`：

```json
{
  "enclave": {
    "socket_dir": "/run/credagent",
    "master_key_file": "/usr/local/etc/credagent/engine/master.key",
    "baseline_file": "/var/lib/credagent/baseline.enc"
  },
  "monitor": {
    "mount_point": "/mnt/credagent/shielded"
  },
  "credagent": {
    "api_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "api_key": "YOUR_API_KEY_HERE",
    "model_name": "qwen-turbo",
    "timeout_seconds": 30
  },
  "log_level": "info",
  "cmdline_trusted_source": "ebpf,auditd"
}
```
- socket_dir： unix socket file所在目录，其中enclave.sock用于credagent与credctl/credreq之间通信。
- master_key_file： 机密凭据数据的密钥。credagent还把管理员密码文件保存在相同路径下。
- baseline_file： 凭据内容和元数据的保存文件。
- mount_point： FUSE文件系统的挂载位置。
- credagent：LLM AI模型配置，用于评估凭据访问风险。使用BASIC策略，无需配置。
- cmdline_trusted_source：cmdline 防篡改检测的可信来源，逗号分隔。可选值：`ebpf`、`auditd`。不配置则仅使用 `/proc` 读取 cmdline（无篡改检测）。

### credctl配置文件

默认位于`/usr/local/etc/credagent/credctl/config.json`：

```json
{
  "enclave": {
    "socket_dir": "/run/credagent"
  },
  "monitor": {
    "mount_point": "/mnt/credagent/shielded"
  },
  "log_level": "info"
}
```

**注意**：首次安装后，请修改API密钥和其他敏感配置项。

## 系统服务配置

根据操作系统不同，安装脚本会自动安装相应的服务：

### Linux系统服务配置

Linux安装脚本会自动安装credagent systemd服务：

#### credagent.service

CredAgent守护进程服务，负责管理加密凭证、访问策略验证和FUSE文件系统：

```ini
[Unit]
Description=CredAgent Enclave Daemon (with integrated FUSE)
After=network.target

[Service]
Type=simple
User=root
Group=root

UMask=0007

RuntimeDirectory=credagent
RuntimeDirectoryMode=0751
StateDirectory=credagent
StateDirectoryMode=0751

ExecStartPre=+/usr/bin/bash -c "/usr/bin/fusermount -uz /mnt/credagent/shielded || true"
ExecStartPre=+/usr/bin/mkdir -p /mnt/credagent/shielded/
ExecStartPre=+/usr/bin/chmod 755 /mnt/credagent/shielded/

MountFlags=shared
DeviceAllow=/dev/fuse rw

ExecStart=/usr/local/bin/credagent run --mount /mnt/credagent/shielded/ --socket-dir /run/credagent --baseline-file /var/lib/credagent/baseline.enc --config /usr/local/etc/credagent/engine/config.json
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=credagent

ExecStopPost=+/bin/bash -c "/usr/bin/mountpoint -q /mnt/credagent/shielded && /usr/bin/fusermount -uz /mnt/credagent/shielded || true"

[Install]
WantedBy=multi-user.target
```

### macOS系统服务配置

macOS安装脚本会自动安装credagent launchd服务：

#### com.credagent.enclave.plist

CredAgent守护进程服务，负责管理加密凭证、访问策略验证和FUSE文件系统：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.credagent.enclave</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/credagent</string>
        <string>run</string>
        <string>--mount</string>
        <string>/usr/local/var/credagent/shielded/</string>
        <string>--socket-dir</string>
        <string>/var/run/credagent</string>
        <string>--baseline-file</string>
        <string>/usr/local/var/credagent/baseline.enc</string>
        <string>--config</string>
        <string>/usr/local/etc/credagent/engine/config.json</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/usr/local/var/log/credagent/credagent.log</string>
    <key>StandardErrorPath</key>
    <string>/usr/local/var/log/credagent/credagent.err</string>
</dict>
</plist>
```

## 如何配置和启动程序

### 1. 初始化系统

首次安装后，必须先初始化系统：

```bash
# 初始化credagent（生成加密密钥和管理员口令）
sudo /usr/local/bin/credagent init --config /usr/local/etc/credagent/engine/config.json
```

按照提示设置主密钥文件路径和管理员密码。

### 2. 启动服务

#### Linux系统
```bash
# 启动服务
sudo systemctl start credagent

# 设置开机自启
sudo systemctl enable credagent
```

#### macOS系统
```bash
# 启动服务
sudo launchctl load /Library/LaunchDaemons/com.credagent.enclave.plist

# 服务会自动在系统启动时运行，无需额外设置
```

### 3. 验证服务状态

#### Linux系统
```bash
# 检查服务状态
sudo systemctl status credagent

# 查看实时日志
sudo journalctl -u credagent -f
```

#### macOS系统
```bash
# 检查服务状态
sudo launchctl list | grep credagent

# 查看实时日志
tail -f /usr/local/var/log/credagent/credagent.log
```

## 如何保护凭据文件

### 1. 使用credctl保护凭据文件

credctl protect 可以将目标凭据文件内容安全保存进credagent，并安全删除原始凭据文件，使用符号链接替代。
并定义允许访问凭据文件的程序和访问控制策略。

```bash
# 保护git凭证文件，使用基本验证策略
credctl protect --strategy BASIC --program-permit /usr/bin/ssh --measure true --open-frequency 2 ~/.ssh/id_rsa
```
>--config config.json credctl的config.json文件。配置文件已安装到默认位置，程序会自动找到，无需--config指定。\
>--strategy BASIC 基础零信任策略，不使用AI风险评估。\
>--program-permit /usr/bin/ssh   仅允许/usr/bin/ssh 程序访问（可多次指定添加多个程序）\
>--measure true 对/usr/bin/ssh程序度量，程序完整性一致才允许访问凭据（需明确指定true或false）\
>--open-frequency 2  一个进程最多只能Open该文件2次\
>--writable false  是否允许授权程序修改凭据文件（默认false，见下方重要说明）\
~/.ssh/id_rsa  保护的凭据文件

> **重要：`--writable` 参数说明**
> - `--writable false`（默认）：凭据文件为只读模式，授权程序只能读取凭据内容，无法修改
> - `--writable true`：允许授权程序对凭据文件进行写入/修改操作
> - **适用场景**：某些凭据文件需要被授权程序更新，例如：
>   - **Cookie文件**：浏览器会定期更新cookie内容
>   - **OAuth令牌文件**：OAuth凭证过期后需要刷新更新
>   - **会话令牌文件**：会话token过期后自动刷新
> - 如果不设置 `--writable true`，这些需要更新的凭据文件将无法被授权程序修改，可能导致认证失败

```bash
#查看~/.ssh/id_rsa，已替换成符号链接
$ls -l ~/.ssh/id_rsa
lrw------- 1 user user 40 Apr  8 11:06 .ssh/id_rsa -> /mnt/credagent/mnt/shielded/59524298d125
```

```bash
# 对于解释型程序
credctl protect --strategy BASIC --program-permit skills/web-search/scripts/search.py --measure true --open-frequency 1 skills/web-search/api-key/key.txt 
```
>--program-permit skills/web-search/scripts/search.py 指向python main程序入口脚本。进程访问时会度量该脚本完整性。

```bash
# 保护需要更新的凭据文件（如OAuth令牌、Cookie文件）
credctl protect --strategy BASIC --program-permit /usr/bin/aliyun --measure true --writable true ~/.aliyun/config.json
```
>--writable true 允许aliyun CLI工具更新配置文件中的凭证信息（如OAuth令牌刷新）。\
>如果不设置此参数，aliyun CLI在尝试更新凭证时将收到"Permission denied"错误。

### 1.1 选择合适的writable设置

| 凭据类型 | 推荐设置 | 说明 |
|---------|---------|------|
| SSH私钥 (`id_rsa`) | `--writable false` | 私钥文件通常不需要修改 |
| API Key文件 | `--writable false` | API Key通常是静态的 |
| OAuth令牌文件 | `--writable true` | OAuth token会过期刷新 |
| Cookie文件 | `--writable true` | 浏览器会定期更新cookie |
| 会话配置文件 | `--writable true` | 云服务CLI工具可能需要更新凭证 |

### 2. 管理受保护的文件

```bash
# 列出所有受保护的文件
./credctl list
# 返回如下内容
Protected Files in Enclave:
Total Count: 1
------------------------------------------------------------------------------------------------------
id           Target Path                      Permissions          Strategy           Open Frequency  Writable  Measure  Permitted Program
------------------------------------------------------------------------------------------------------
59524298d125 /home/user/.ssh/id_rsa            0600 (uid:1000,gid:1000) BASIC        2               false     true     /usr/bin/ssh
------------------------------------------------------------------------------------------------------
Use 'credctl inspect <id>' to view full details of a specific credential.
```

> `Permitted Program` 列仅显示程序路径，SHA256 详情请使用 `credctl inspect <id>` 查看。

```bash
# 以JSON格式列出所有受保护的文件
./credctl list --json
# 返回如下内容
[
  {
    "id": "59524298d125",
    "target_path": "/home/user/.ssh/id_rsa",
    "strategy": "BASIC",
    "permissions": "0600 (uid:1000,gid:1000)",
    "owner_uid": 1000,
    "owner_gid": 1000,
    "mode": 384,
    "permitted_program": "/usr/bin/ssh",
    "program_sha256": [
      "47adf415134df7eff017e9557634696ba6b2a09f5a3bb1436d91d99b8a1cd5a6"
    ],
    "open_frequency": "2",
    "writable": false,
    "measure": true
  }
]
```

```bash
# 释放受保护的文件（恢复到原始位置，需要输入管理员密码）
# 1. 删除原位置的符号链接
rm /home/user/.ssh/id_rsa
# 2. 释放、还原会原始凭据文件（使用list命令中显示的SHA id）
./credctl release 59524298d125
```
> 注意：release 命令使用 SHA id 作为参数，可通过 `credctl list` 查看受保护文件的 id。

```bash
# 仅删除受保护文件（不恢复到原始位置，谨慎使用！需要输入管理员密码）
./credctl remove /home/user/.ssh/id_rsa
```
> 注意：remove 命令使用原始文件路径作为参数，而不是 id。

### 3. 导出和更新凭据内容（dump / restore）

当需要编辑受保护凭据的内容时，不必执行 release + 编辑 + re-protect 的完整流程。`dump` 和 `restore` 可以在不解除保护的前提下导出和更新凭据内容，baseline 的元数据和访问规则保持不变。

```bash
# 导出凭据内容到 stdout
credctl dump 59524298d125

# 导出凭据内容到文件
credctl dump -w /tmp/config.json 59524298d125

# 从文件更新凭据内容
credctl restore -f /tmp/config.json 59524298d125

# 直接从参数更新凭据内容
credctl restore -s 'new-secret-value' 59524298d125
```

> **组合用法**：可以将 dump、文本处理和 restore 串联使用，一行命令完成编辑：
> ```bash
> credctl restore -s "$(credctl dump 59524298d125 | sed 's/old-value/new-value/g')" 59524298d125
> ```
> 其中 dump 和 restore 各需输入一次管理员密码。

> **安全提示**：`--secret/-s` 的值会出现在进程列表和 shell 历史中，敏感内容建议使用 `--file/-f`。

### 4. 查看和更新受保护文件详情

```bash
# 查看受保护文件的详细信息（包含完整 program_sha256 列表）
./credctl inspect 59524298d125

# 以JSON格式输出详细信息
./credctl inspect 59524298d125 --json
```

```bash
# 更新受保护文件的安全策略（整体替换 program-permit 列表）
./credctl update 59524298d125 --strategy BASIC
./credctl update 59524298d125 --program-permit /usr/bin/psql --measure true
./credctl update 59524298d125 --open-frequency 10
./credctl update 59524298d125 --writable true
```
> 注意：`update --program-permit` 会替换整个授权程序列表；如需增量追加或移除单个程序，请使用 `attach` / `detach`。
> 使用 `--program-permit` 时必须同时使用 `--measure` 并明确指定 true 或 false。

### 5. 动态管理授权程序（attach / detach / refresh）

`update` 命令会整体替换授权程序列表。对于只需增量调整的场景，可使用以下三个子命令：

#### attach — 追加新的授权程序

```bash
# 向已保护文件追加新的授权程序（自动计算并存储 SHA256）
./credctl attach -p /usr/bin/psql 59524298d125
./credctl attach -p /usr/bin/psql -p /usr/bin/pg_dump 59524298d125
```

输出示例：
```
Successfully updated credential 59524298d125
Added (1):   [/usr/bin/psql]
Skipped (1): [/usr/bin/pg_dump] (already exist)
  Hint: use 'credctl refresh' to update SHA256 for already-authorized programs.
```

> - 已存在的程序会被跳过（Skipped），不会覆盖。
> - 若程序文件已更新，使用 `credctl refresh` 刷新其 SHA256。

#### detach — 移除已授权程序

```bash
# 从已保护文件中移除授权程序（同时删除对应 SHA256）
./credctl detach -p /usr/bin/pg_dump 59524298d125
./credctl detach -p /usr/bin/psql -p /usr/bin/pg_dump 59524298d125
```

输出示例：
```
Successfully updated credential 59524298d125
Removed (1):   [/usr/bin/pg_dump]
Not found (1): [/usr/bin/nonexistent] (not in allowed list)
```

> - 程序路径必须在磁盘上真实存在，否则命令报错。
> - 不在授权列表中的程序会被报告为 Not found，不影响其他移除操作。

#### refresh — 刷新已授权程序的 SHA256

当授权程序文件被更新（如系统升级）后，存储的 SHA256 会失效，导致 measure 校验失败。使用 `refresh` 重新计算并更新 SHA256：

```bash
# 刷新已授权程序的 SHA256 值
./credctl refresh -p /usr/bin/psql 59524298d125
./credctl refresh -p /usr/bin/psql -p /usr/bin/pg_dump 59524298d125
```

输出示例：
```
Successfully refreshed credential 59524298d125
Refreshed (1):      [/usr/bin/psql]
Not authorized (1): [/usr/bin/nonexistent]
  Hint: use 'credctl attach' to add new programs to the allowed list.
```

> - 仅刷新已授权列表中存在的程序；未授权程序会报告为 Not authorized（不会自动添加）。
> - 若需要追加新程序，请使用 `credctl attach`。

### 6. 访问受保护的凭据

一旦文件被保护，原始位置将创建一个符号链接指向FUSE挂载点。只有合法程序才能访问凭据文件

```bash
# 非法程序访问凭据文件时，访问会被拒绝
$ sudo cat .ssh/id_rsa
cat: .ssh/id_rsa: Permission denied
```
但`ssh`和`git(实际也是使用ssh)`依然可以访问凭据文件

## 保护OpenClaw skill的凭据文件

### 保护host执行环境中的凭据文件
OpenClaw会直接使用exec工具在host环境中调用程序，这种情况无需任何差异性操作。

### 保护sandbox执行环境中的凭据文件
1. 配置openclaw.json中的sandbox配置，把host中FUSE挂载点，挂载到sandbox同名位置：
```json
// openclaw.json中sandbox增加配置：
"sandbox": {
        "mode": "non-main",
        "workspaceAccess": "none",
        "scope": "session",
        "docker": {
          "image": "openclaw-sandbox:bookworm-slim",
          "containerPrefix": "openclaw-sbx-",
          "network": "bridge",
          "binds": [
            "/mnt/credagent/shielded/:/mnt/credagent/shielded/:slave"   //映射FUSE文件系统同名挂载点
          ],
          "dangerouslyAllowExternalBindSources": true   //允许外部映射，否则binds中映射会被安全策略拒绝
        },
        "prune": {
          "idleHours": 2,
          "maxAgeDays": 7
        }
      }
```
>这样操作，可使沙箱中的符号链接指向/mnt/credagent/shielded/xxxxxx时有效的，并能被host上的credagent响应。对于runc沙箱，credagent可以在host上看到sandbox中的访问进程，并获取到进程上下文，也能度量到访问程序和脚本。

## 【附录】各程序命令行参数和用法详解
各命令工具的具体参数和用法请参考`Docs/manual.md`。

## License

This project is licensed under the Apache License 2.0 — see the [LICENSE](LICENSE) file for details.