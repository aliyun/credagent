# CredAgent 系统使用手册

本文档详细说明了 CredAgent 系统各个组件的命令行参数、用法和配置文件格式。

## 目录
1. [credagent 守护进程](#credagent-守护进程)
2. [credctl 命令行工具](#credctl-命令行工具)
3. [配置文件详解](#配置文件详解)
4. [安全配置（`security.json`）](#安全配置securityjson)
5. [cmdline 防篡改检测（`cmdline_trusted_source`）](#cmdline-防篡改检测cmdline_trusted_source)
6. [服务文件](#服务文件)
7. [配置优先级关系](#配置优先级关系)

## credagent 守护进程

credagent 守护进程是 CredAgent 系统的核心组件，负责管理凭据、访问控制和 FUSE 文件系统。

### 命令行规格

```bash
credagent [command] [flags]
```

#### 可用命令

- `run` - 运行守护进程
- `init` - 初始化守护进程（创建主密钥和管理员密码）
- `help [command]` - 显示任何命令的帮助信息

#### run 命令参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--key-file` | `-k` | 包含 32 字节 AES-256 主密钥的文件路径 | |
| `--socket-dir` | `-d` | Unix 域套接字文件目录 | `/run/credagent` |
| `--baseline-file` | `-b` | 加密基线存储文件路径 | |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/engine/config.json` |
| `--mount` | | FUSE 文件系统挂载点 | `/mnt/shielded` |
| `--log-level` | `-l` | 日志级别（debug, info, warning, error） | `info` |
| `--use-bufnet` | | 用于测试的内部标志 | |
| `--auto-init` | | 首次启动时若缺失则自动生成主密钥和管理员密码（云镜像 / 无人值守场景） | |

##### 关于 Socket 文件的说明

在 `--socket-dir` 指定的目录中，credagent 守护进程会创建一个 Unix 域套接字文件：

- `enclave.sock` - credagent 守护进程的 gRPC 接口，供 credctl 等外部工具使用，用于保护/释放凭据文件和访问控制管理。

FUSE 文件系统已集成在 credagent 进程内部，策略验证通过进程内函数调用完成，无需额外的 IPC 通信。

#### init 命令参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--key-file` | `-k` | 要创建的主密钥文件路径 | `/usr/local/etc/credagent/master.key` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/engine/config.json` |

##### init 命令详细说明

`init` 命令用于初始化 credagent 守护进程所需的环境：

1. **主密钥生成** - 创建一个 32 字节的 AES-256 主密钥文件，用于加密所有受保护的凭据。
2. **管理员密码设置** - 提示用户输入并设置管理员密码，用于执行敏感操作（如释放凭据、删除受保护文件、dump/restore 等）。
3. **配置验证** - 验证提供的配置文件有效性。
4. **基础环境准备** - 确保必要的目录存在并具有正确的权限。

执行 `./credagent init` 后，系统会提示您输入管理员密码，该密码将在后续管理操作中使用。

### 用法示例

```bash
# 使用配置文件启动
./credagent run --config config.json

# 自定义参数启动（含 FUSE 挂载点）
./credagent run --key-file /custom/path/master.key --socket-dir /custom/path --baseline-file /custom/path/baseline.enc --mount /mnt/shielded

# 使用默认路径初始化
./credagent init

# 自定义主密钥文件路径初始化
./credagent init --key-file /custom/path/master.key --config /path/to/config.json
```

## credctl 命令行工具

credctl 是用于保护和释放凭据文件的命令行工具。

### 命令行规格

```bash
credctl [command] [flags]
```

### 可用命令

- `protect` - 保护一个凭据文件，将其移入 enclave
- `release` - 释放一个凭据文件，将其从 enclave 还原（参数为 SHA id）
- `remove` - 从 enclave 中删除一个受保护的凭据（不还原，参数为原始文件路径）
- `list` - 列出所有受保护的凭据文件
- `inspect` - 查看特定受保护文件的详细信息（包含完整 SHA256 列表）
- `update` - 更新受保护文件的安全配置选项（整体替换授权程序列表）
- `attach` - 向已保护文件增量追加授权程序（自动计算 SHA256）
- `detach` - 从已保护文件移除授权程序（成对删除 SHA256）
- `refresh` - 刷新已授权程序的 SHA256 值（用于程序更新后重新度量）
- `dump` - 导出受保护凭据的明文内容（不修改 baseline）
- `restore` - 更新受保护凭据的内容（baseline 元数据和规则不变）
- `version` - 打印 credctl 版本号
- `completion` - 为指定 shell 生成自动补全脚本
- `help [command]` - 显示任何命令的帮助信息

### 通用参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/protector/config.json` |
| `--log-level` | `-l` | 日志级别（debug, info, warning, error） | `info` |

### protect 子命令参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--strategy` | `-s` | 凭据保护策略（ONE_TIME_USE\|PID_BIND\|SPEC_VERIFICATION\|BASIC） | BASIC |
| `--program-permit` | `-p` | 允许访问此凭据的二进制文件完整路径（可多次指定添加多个程序） | 必填 |
| `--measure` | `-m` | 是否度量并存储允许的二进制文件的 SHA256 哈希值（需明确指定 true 或 false） | 无默认值 |
| `--open-frequency` | `-o` | 凭据可被打开的最大次数（0 表示无限制） | 0 |
| `--writable` | `-w` | 是否允许凭据文件被修改（true/false） | false |
| `--socket-dir` | `-d` | Unix 域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

#### `--writable` 使用指引

| 凭据类型 | 推荐设置 | 说明 |
|---------|---------|------|
| SSH 私钥（`id_rsa`） | `--writable false` | 私钥文件通常不需要修改 |
| API Key 文件 | `--writable false` | API Key 通常是静态的 |
| OAuth 令牌文件 | `--writable true` | OAuth token 会过期刷新 |
| Cookie 文件 | `--writable true` | 浏览器会定期更新 cookie |
| 会话配置文件 | `--writable true` | 云服务 CLI 工具可能需要更新凭据 |

如果不为需要刷新的凭据（OAuth token、cookie、会话令牌）设置 `--writable true`，授权程序在尝试更新时将收到 "Permission denied"，可能导致认证失败。

### list 子命令参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--json` | `-j` | 以 JSON 格式输出结果 | false |
| `--socket-dir` | `-d` | Unix 域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

### inspect 子命令参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--json` | `-j` | 以 JSON 格式输出详细信息 | false |
| `--socket-dir` | `-d` | Unix 域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

> 参数 `<id>` 是受保护文件的 SHA 标识符，可通过 `credctl list` 命令查看。

### update 子命令参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--strategy` | `-s` | 更新验证策略（ONE_TIME_USE\|PID_BIND\|SPEC_VERIFICATION\|BASIC） | |
| `--program-permit` | `-p` | 更新程序许可路径（必须与 `--measure` 一起使用）。会**整体替换**授权程序列表 | |
| `--measure` | `-m` | 是否度量 SHA256（必须与 `--program-permit` 一起使用，需明确指定 true 或 false） | 无默认值 |
| `--open-frequency` | `-o` | 更新最大打开次数（0 表示无限制） | |
| `--writable` | `-w` | 更新是否允许文件被修改（true/false） | |
| `--socket-dir` | `-d` | Unix 域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

> 参数 `<id>` 是受保护文件的 SHA 标识符。
> **重要**：`--program-permit` 和 `--measure` 必须同时指定；update 模式下 `--measure` 无默认值，需明确设置为 true 或 false。
> `update --program-permit` 会**整体替换**授权程序列表。如需增量调整，请使用 `attach` / `detach`。

### attach 子命令参数

向已保护凭据文件增量追加授权程序，自动计算并存储 SHA256。已存在的程序会被跳过并报告。

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--program-permit` | `-p` | 要追加的程序路径（可多次指定）。必填 | |
| `--socket-dir` | `-d` | Unix 域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

> 参数 `<id>` 是受保护文件的 SHA 标识符（可通过 `credctl list` 查看）。

### detach 子命令参数

从已保护凭据文件中移除授权程序，并成对删除对应的 SHA256。

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--program-permit` | `-p` | 要移除的程序路径（可多次指定）。必填 | |
| `--socket-dir` | `-d` | Unix 域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

> 参数 `<id>` 是受保护文件的 SHA 标识符。
> 程序路径必须在磁盘上真实存在，否则命令报错。
> 不在授权列表中的程序会被报告为 Not found，不影响其他移除操作。

### refresh 子命令参数

重新计算并更新已授权程序的 SHA256 值。用于程序更新（如系统升级）后重新建立度量基线。

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--program-permit` | `-p` | 要刷新 SHA256 的程序路径（可多次指定）。**可选**：不指定则刷新全部已授权程序 | |
| `--socket-dir` | `-d` | Unix 域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

> 参数 `<id>` 是受保护文件的 SHA 标识符。
> **不指定 `-p` 时，将刷新该凭据全部已授权程序的 SHA256 值**（命令执行前会显示醒目警告）。
> 仅更新已在授权列表中的程序；未授权的程序会报告为"未授权"，不会被自动添加。
> 若需追加新程序，请使用 `credctl attach`。

#### 输出格式

refresh 执行后会逐行显示每个程序的刷新结果：

```
  [刷新]   /usr/bin/psql      afeb5***4ed3a -> bc12f***9a7e2
  [刷新]   /usr/bin/pg_dump   e3a1c***8bf02 -> e3a1c***8bf02
  [未刷新] /usr/bin/awk (未授权，请使用 credctl attach 添加)

刷新完成: 2 已刷新, 1 未刷新
```

- `[刷新]` — 程序 SHA256 已成功更新，显示旧值→新值（缩略格式）
- `[未刷新]` — 未刷新，可能原因：程序未授权、程序文件不存在等

### dump 子命令参数

导出受保护凭据的明文内容，不修改 baseline。默认输出到 stdout，可通过 `--write` 写入文件。

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--write` | `-w` | 将内容写入指定文件（不指定则输出到 stdout） | |
| `--socket-dir` | `-d` | Unix 域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

> 参数 `<id>` 是受保护文件的 SHA 标识符（可通过 `credctl list` 查看）。
> 密码提示通过 `/dev/tty` 输出，不会污染 stdout，可安全用于管道和命令替换。

### restore 子命令参数

更新受保护凭据的内容，baseline 的元数据（路径、权限等）和访问规则（策略、授权程序等）保持不变。必须通过 `--file` 或 `--secret` 指定新内容（二选一，互斥）。

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--file` | `-f` | 从指定文件读取新内容 | |
| `--secret` | `-s` | 直接从参数指定新内容（注意：值会出现在进程列表和 shell 历史中） | |
| `--socket-dir` | `-d` | Unix 域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

> 参数 `<id>` 是受保护文件的 SHA 标识符。
> `--file` 和 `--secret` 互斥，必须且只能指定其一。
> **安全提示**：`--secret/-s` 的值会出现在 `/proc/PID/cmdline` 和 shell 历史记录中，敏感内容建议使用 `--file/-f`。

### release 子命令参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--socket-dir` | `-d` | Unix 域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

> 参数 `<id>` 是受保护文件的 SHA 标识符（可通过 `credctl list` 查看），而非原始文件路径。

### remove 子命令参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--socket-dir` | `-d` | Unix 域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

> 参数 `<target_filepath>` 是原始凭据文件的完整路径，而非 SHA 标识符。

### 用法示例

```bash
# 一次性使用策略
./credctl protect --strategy ONE_TIME_USE --program-permit /usr/bin/psql --measure true /etc/psql/passwd

# 命令规范验证策略
./credctl protect --strategy SPEC_VERIFICATION --program-permit /usr/bin/psql --program-permit /usr/bin/pg_dump --measure true /etc/psql/passwd

# 基本验证策略，同时测量二进制文件
./credctl protect --strategy BASIC --program-permit /usr/bin/cat --measure true /etc/myfile.txt

# 允许文件被修改
./credctl protect --strategy BASIC --program-permit /usr/bin/vim --measure false --writable true /etc/myfile.txt

# 列出所有受保护的文件
./credctl list

# 以 JSON 格式列出
./credctl list --json

# 查看特定受保护文件的详细信息（包含完整 SHA256 列表）
./credctl inspect 59524298d125

# 以 JSON 格式查看详细信息
./credctl inspect 59524298d125 --json

# 更新受保护文件的策略（整体替换授权程序列表）
./credctl update 59524298d125 --strategy ONE_TIME_USE
./credctl update 59524298d125 --program-permit /usr/bin/psql --measure true
./credctl update 59524298d125 --open-frequency 10
./credctl update 59524298d125 --writable true

# 增量追加授权程序（不影响其他已授权程序）
./credctl attach -p /usr/bin/pg_dump 59524298d125
./credctl attach -p /usr/bin/psql -p /usr/bin/pg_dump 59524298d125

# 移除授权程序
./credctl detach -p /usr/bin/pg_dump 59524298d125

# 刷新已授权程序的 SHA256（程序更新后使用）
./credctl refresh -p /usr/bin/psql 59524298d125
./credctl refresh -p /usr/bin/psql -p /usr/bin/pg_dump 59524298d125

# 刷新全部已授权程序的 SHA256（不指定 -p）
./credctl refresh 59524298d125

# 导出凭据内容到 stdout
./credctl dump 59524298d125

# 导出凭据内容到文件
./credctl dump -w /tmp/config.json 59524298d125

# 从文件更新凭据内容
./credctl restore -f /tmp/config.json 59524298d125

# 直接从参数更新凭据内容
./credctl restore -s 'new-secret-value' 59524298d125

# 组合用法：导出 → 修改 → 更新（需输入两次密码）
./credctl restore -s "$(./credctl dump 59524298d125 | sed 's/old/new/g')" 59524298d125

# 释放受保护的文件（使用 SHA id）
./credctl release 59524298d125

# 删除受保护的文件（使用原始文件路径）
./credctl remove /path/to/original/credential/file
```

## 配置文件详解

CredAgent 系统使用 JSON 格式的配置文件来管理各个组件的设置。

### credagent 配置文件 (engine/config.json)

```json
{
  "enclave": {
    "socket_dir": "/run/credagent",
    "master_key_file": "/usr/local/etc/credagent/master.key",
    "baseline_file": "/var/credagent/baseline-store.enc"
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

#### 配置项说明

- **enclave.socket_dir**：Unix 域套接字文件的目录。
- **enclave.master_key_file**：主密钥文件的存储位置。credagent 还把管理员密码文件保存在相同路径下。
- **enclave.baseline_file**：加密基线存储文件的路径。
- **monitor.mount_point**：FUSE 文件系统的挂载点。
- **credagent.api_url**：LLM 服务的 API URL（用于 AI 风险评估，BASIC 策略不需要）。
- **credagent.api_key**：LLM 服务的 API 密钥。
- **credagent.model_name**：使用的 LLM 模型名称。
- **credagent.timeout_seconds**：API 请求的超时时间（秒）。
- **log_level**：日志级别（debug, info, warning, error）。
- **cmdline_trusted_source**：cmdline 防篡改检测的可信来源，逗号分隔。见 [cmdline 防篡改检测](#cmdline-防篡改检测cmdline_trusted_source)。

### credctl 配置文件 (credctl/config.json)

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

#### 配置项说明

- **enclave.socket_dir**：Unix 域套接字文件的目录。
- **monitor.mount_point**：FUSE 文件系统的挂载点。
- **log_level**：日志级别（debug, info, warning, error）。

### 默认配置文件位置

- **Engine / 守护进程配置文件**：`/usr/local/etc/credagent/engine/config.json`
- **安全策略配置文件**：`/usr/local/etc/credagent/engine/security.json`
- **credctl 配置文件**：`/usr/local/etc/credagent/credctl/config.json`

如果未显式指定配置文件，程序将尝试从这些默认位置加载配置。

## 安全配置（`security.json`）

`security.json` 配置策略引擎在每次 `open()` 对进程做证明时执行的防攻击检查。所有检查都是可选的；出厂模板全部为 `enabled: false`——按需开启后重启 `credagent` 生效。

顶层结构：

```json
{
  "cmdline_trusted_source": ["ebpf"],
  "antiattack_options": {
    "trusted_harness": [],
    "binary_check":            { "enabled": false, "trusted_programs": [] },
    "ancestor_check":          { "enabled": false, "max_depth": 5 },
    "process_status_check":    { "enabled": false },
    "library_injection_check": { "enabled": false, "trusted_lib_paths": [] },
    "env_var_check":           { "enabled": false, "trusted_env": {} },
    "interpreter_check":       { "...": "按解释器配置，见下文" },
    "fd_share_check":          { "enabled": false }
  }
}
```

`cmdline_trusted_source` 是顶层字段（不在 `antiattack_options` 内），仅 Linux 有；见 [cmdline 防篡改检测](#cmdline-防篡改检测cmdline_trusted_source)。

### 检查项

| 检查项 | 检测 / 阻止 | 子字段 |
|---|---|---|
| `binary_check` | 二进制信任校验——请求进程及其祖先的路径安全性与属主 | `enabled`、`trusted_programs[]` |
| `ancestor_check` | 遍历祖先进程链，在 `max_depth` 内逐级校验祖先 | `enabled`、`max_depth` |
| `process_status_check` | 检测是否有 tracer/debugger 附着（`TracerPid`）以及 seccomp 状态 | `enabled` |
| `library_injection_check` | 检测可疑的注入共享库（Linux `.so`、macOS `.dylib`） | `enabled`、`trusted_lib_paths[]` |
| `env_var_check` | 检测通过环境变量的动态链接器注入——`LD_PRELOAD` / `LD_LIBRARY_PATH` / `LD_AUDIT`（Linux）和 `DYLD_INSERT_LIBRARIES`（macOS）。对**所有二进制**生效，不限于解释器 | `enabled`、`trusted_env{}` |
| `interpreter_check` | 对 Python/Node/Perl/Ruby/Java/PHP 逐解释器做证明——可信环境、可信脚本、可执行路径 | 每个解释器一个 `enabled`；外加 `trusted_env{}`、`trusted_scripts[]`、`exe_paths[]` |
| `fd_share_check` | 检测跨进程文件描述符共享（未授权进程被递送已打开的 fd）并拉黑 | `enabled` |
| `trusted_harness` | 受信任的 harness 程序，绕过解释器检查 | 路径数组 |

### `interpreter_check` 结构

每个解释器独立配置，**只有一个 `enabled` 开关**（不做更细的子检查开关），外加信任列表：

```json
"interpreter_check": {
  "python": { "enabled": true,  "trusted_env": {}, "trusted_scripts": ["skills/web-search/scripts/search.py"], "exe_paths": ["/usr/bin/python3"] },
  "node":   { "enabled": false, "trusted_env": {}, "trusted_scripts": [], "exe_paths": [] },
  "perl":   { "enabled": false, "trusted_env": {}, "trusted_scripts": [], "exe_paths": [] },
  "ruby":   { "enabled": false, "trusted_env": {}, "trusted_scripts": [], "exe_paths": [] },
  "java":   { "enabled": false, "trusted_env": {}, "exe_paths": [] },
  "php":    { "enabled": false, "trusted_env": {}, "trusted_scripts": [], "exe_paths": [] }
}
```

- `trusted_env`：对该解释器视为安全的环境变量（按 key 分组）及其取值。
- `trusted_scripts`：被度量并允许运行的入口脚本。
- `exe_paths`：允许运行可信脚本的解释器二进制 realpath。

### 启动摘要

`credagent` 启动时会打印已加载的策略，例如：

```
Security policy loaded from security.json: enabled=[interpreter_check], disabled=[binary_check, ancestor_check, process_status_check, library_injection_check, env_var_check, fd_share_check]
```

注意：只要 `interpreter_check` 块存在，摘要就将其报告为 `enabled`，与各解释器自身的 `enabled` 标志无关——每个解释器的 `enabled` 才决定它是否真正被证明。

## cmdline 防篡改检测（`cmdline_trusted_source`）

脚本类解释器（Python、Node、Ruby、Perl 等）可以在运行时篡改 `/proc/<pid>/cmdline`，伪装成合法脚本绕过 SHA256 校验。credagent 通过可信 cmdline 来源在进程 `execve` 时采集原始命令行参数，与 `/proc` 中读到的值比对，检测篡改行为。

在 `engine/config.json` 中设置 `cmdline_trusted_source` 字段启用此功能：

```json
{
  "cmdline_trusted_source": "ebpf,auditd"
}
```

支持的来源（按配置顺序尝试，第一个可用的生效）：

| 来源 | 原理 | 环境要求 |
|------|------|----------|
| `ebpf` | eBPF hook `sys_enter_execve`，内核层采集 cmdline 存入 BPF hash map | Linux >= 5.2，BTF 启用（`/sys/kernel/btf/vmlinux` 存在），syscall tracepoints 可用 |
| `auditd` | Linux audit 子系统记录 execve argv，credagent 实时解析 audit 日志 | auditd 已安装且 enabled，无 `task,never` 规则阻断（credagent 启动时自动处理） |

**降级行为**：
- 不配置或配置的来源均不可用 → 使用 `/proc/<pid>/cmdline`，无篡改检测能力。
- WSL2 环境下 eBPF 和 auditd 均不可用，自动降级。

**auditd 来源说明**：
- 启动时自动扫描系统中的解释器 realpath（python、perl、ruby、node、php、java），仅对这些解释器添加 execve audit 规则。
- 规则使用 `-k credagent_cmdline` 标签，不影响其他审计规则。
- 如果系统存在 `-a task,never` 规则（阻止所有 syscall 审计），credagent 会自动移除该规则以启用审计，退出时恢复。
- credagent 退出时自动清理所有添加的 audit 规则。

**eBPF 来源说明**：
- eBPF 字节码（`internal/execsnoop/execsnoop_x86_bpfel.o`）和 Go 绑定代码已预生成并提交到仓库，`go build` 即包含 eBPF 支持，**无需额外编译步骤**。`bpf2go` 将字节码嵌入 Go 二进制，编译后的 credagent 可直接分发到其他节点，目标节点无需安装 clang 或任何编译工具。
- 如果目标节点内核不支持 BTF 或 syscall tracepoints 未注册，credagent 启动时自动跳过 eBPF，日志输出 `eBPF execsnoop: syscall tracepoints not available`。

### 重新生成 eBPF 字节码

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

## 服务文件

`INSTALL` 脚本会安装服务定义并创建运行时目录。已安装的文件是事实来源；本节仅做摘要。

### Linux（systemd）

安装到 `/etc/systemd/system/credagent.service`。关键字段：

```ini
[Service]
Type=simple
User=root
ExecStartPre=+/usr/bin/bash -c "/usr/bin/fusermount -uz /mnt/credagent/shielded || true"
ExecStartPre=+/usr/bin/mkdir -p /mnt/credagent/shielded/
ExecStart=/usr/local/bin/credagent run --mount /mnt/credagent/shielded/ --socket-dir /run/credagent --baseline-file /var/lib/credagent/baseline.enc --config /usr/local/etc/credagent/engine/config.json
Restart=always
```

用 `systemctl {start,stop,status,enable,disable} credagent` 管理；日志用 `journalctl -u credagent`。

### macOS（launchd）

安装到 `/Library/LaunchDaemons/com.credagent.enclave.plist`。关键字段：

```xml
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
<key>RunAtLoad</key> <true/>
<key>KeepAlive</key> <true/>
```

用 `launchctl {load,unload}` 和 `sudo launchctl list | grep credagent` 管理；日志在 `/usr/local/var/log/credagent/credagent.log`。

## 配置优先级关系

CredAgent 系统遵循以下配置优先级规则（从高到低）：

1. **命令行参数** - 最高优先级，直接通过命令行传递的参数将覆盖配置文件中的任何设置。
2. **配置文件** - 中等优先级，从指定或默认的配置文件中读取的设置。
3. **默认值** - 最低优先级，当命令行参数和配置文件均未提供设置时使用的默认值。

这意味着如果同时提供了命令行参数和配置文件中的相同配置项，则命令行参数的值将被采用；只有在命令行参数未指定的情况下，才会使用配置文件中的对应配置。
