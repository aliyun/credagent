# CredAgent 系统使用手册

本文档详细说明了CredAgent系统的各个组件的命令行参数、用法和配置文件格式。

## 目录
1. [credagent守护进程](#credagent守护进程)
2. [credctl命令行工具](#credctl命令行工具)
3. [credreq命令行工具](#credreq命令行工具)
4. [配置文件详解](#配置文件详解)

## credagent守护进程

credagent守护进程是CredAgent系统的核心组件，负责管理凭证、访问控制和FUSE文件系统。

### 命令行规格

```bash
credagent [command] [flags]
```

#### 可用命令

- `run` - 运行守护进程
- `init` - 初始化守护进程（创建主密钥和管理员密码）
- `help [command]` - 显示任何命令的帮助信息

#### run命令参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--key-file` | `-k` | 包含32字节AES-256主密钥的文件路径 | |
| `--socket-dir` | `-d` | Unix域套接字文件目录 | `/run/credagent` |
| `--baseline-file` | `-b` | 加密基线存储文件路径 | |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/engine/config.json` |
| `--mount` | | FUSE文件系统挂载点 | `/mnt/shielded` |
| `--log-level` | `-l` | 日志级别（debug, info, warning, error） | `info` |
| `--use-bufnet` | | 用于测试的内部标志 | |

##### 关于Socket文件的说明

在 `--socket-dir` 指定的目录中，credagent守护进程会创建一个Unix域套接字文件：

- `enclave.sock` - credagent守护进程的gRPC接口，供credctl和credreq等外部工具使用，用于保护/释放凭证文件和访问控制管理

FUSE文件系统已集成在credagent进程内部，策略验证通过进程内函数调用完成，无需额外的IPC通信。

#### init命令参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--key-file` | `-k` | 要创建的主密钥文件路径 | `/usr/local/etc/credagent/master.key` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/engine/config.json` |

##### init命令详细说明

`init` 命令用于初始化credagent守护进程所需的环境，具体功能包括：

1. **主密钥生成** - 创建一个32字节的AES-256主密钥文件，用于加密所有受保护的凭证
2. **管理员密码设置** - 提示用户输入并设置管理员密码，用于执行敏感操作（如释放凭证、删除受保护文件等）
3. **配置验证** - 验证提供的配置文件有效性
4. **基础环境准备** - 确保必要的目录存在并具有正确的权限

执行 `./credagent init` 后，系统会提示您输入管理员密码，该密码将在后续管理操作中使用。

### 用法示例

```bash
# 使用配置文件启动
./credagent run --config config.json

# 自定义参数启动（含FUSE挂载点）
./credagent run --key-file /custom/path/master.key --socket-dir /custom/path --baseline-file /custom/path/baseline.enc --mount /mnt/shielded

# 使用默认路径初始化
./credagent init

# 自定义主密钥文件路径初始化
./credagent init --key-file /custom/path/master.key --config /path/to/config.json
```

## credctl命令行工具

credctl是用于保护和释放凭证文件的命令行工具。

### 命令行规格

```bash
credctl [command] [flags]
```

### 可用命令

- `protect` - 保护一个凭证文件，将其移动到enclave
- `release` - 释放一个凭证文件，将其从enclave还原（参数为SHA id）
- `remove` - 从enclave中删除一个受保护的凭证文件（不还原，参数为原始文件路径）
- `list` - 列出所有受保护的凭证文件
- `inspect` - 查看特定受保护文件的详细信息（包含完整 SHA256 列表）
- `update` - 更新受保护文件的安全配置选项（整体替换授权程序列表）
- `attach` - 向已保护文件增量追加授权程序（自动计算 SHA256）
- `detach` - 从已保护文件移除授权程序（成对删除 SHA256）
- `refresh` - 刷新已授权程序的 SHA256 值（用于程序更新后重新度量）
- `dump` - 导出受保护凭据的明文内容（不修改baseline）
- `restore` - 更新受保护凭据的内容（不修改baseline元数据和规则）
- `version` - 打印credctl版本号
- `completion` - 为指定shell生成自动补全脚本
- `help [command]` - 显示任何命令的帮助信息

### 通用参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/protector/config.json` |
| `--log-level` | `-l` | 日志级别（debug, info, warning, error） | `info` |

### protect子命令参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--strategy` | `-s` | 凭证保护策略（ONE_TIME_USE\|PID_BIND\|SPEC_VERIFICATION\|BASIC） | BASIC |
| `--program-permit` | `-p` | 允许访问此凭证的二进制文件完整路径（可多次指定添加多个程序） | 必填 |
| `--measure` | `-m` | 是否测量并存储允许的二进制文件的SHA256哈希值（需明确指定true或false） | 无默认值 |
| `--open-frequency` | `-o` | 凭证可被打开的最大次数（0表示无限制） | 0 |
| `--writable` | `-w` | 是否允许凭证文件被修改（true/false） | false |
| `--socket-dir` | `-d` | Unix域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

### list子命令参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--json` | `-j` | 以JSON格式输出结果 | false |
| `--socket-dir` | `-d` | Unix域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

### inspect子命令参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--json` | `-j` | 以JSON格式输出详细信息 | false |
| `--socket-dir` | `-d` | Unix域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

> 参数 `<id>` 是受保护文件的SHA标识符，可通过 `credctl list` 命令查看。

### update子命令参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--strategy` | `-s` | 更新验证策略（ONE_TIME_USE\|PID_BIND\|SPEC_VERIFICATION\|BASIC） | |
| `--program-permit` | `-p` | 更新程序许可路径（必须与--measure一起使用）。会**整体替换**授权程序列表 | |
| `--measure` | `-m` | 是否测量SHA256哈希値（必须与--program-permit一起使用，需明确指定true或false） | 无默认值 |
| `--open-frequency` | `-o` | 更新最大打开次数（0表示无限制） | |
| `--writable` | `-w` | 更新是否允许文件被修改（true/false） | |
| `--socket-dir` | `-d` | Unix域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

> 参数 `<id>` 是受保护文件的SHA标识符。
> **重要**: `--program-permit` 和 `--measure` 必须同时指定，update模式下 `--measure` 无默认値，需明确设置为 true 或 false。
> **注意**: `update --program-permit` 会整体替换授权程序列表。如需增量调整，请使用 `attach` / `detach`。

### attach子命令参数

向已保护凭证文件增量追加授权程序，自动计算并存储 SHA256。已存在的程序会被跳过并报告。

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--program-permit` | `-p` | 要追加的程序路径（可多次指定）。必填 | |
| `--socket-dir` | `-d` | Unix域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

> 参数 `<id>` 是受保护文件的SHA标识符（可通过 `credctl list` 查看）。

### detach子命令参数

从已保护凭证文件中移除授权程序，并成对删除对应的 SHA256。

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--program-permit` | `-p` | 要移除的程序路径（可多次指定）。必填 | |
| `--socket-dir` | `-d` | Unix域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

> 参数 `<id>` 是受保护文件的SHA标识符。
> 程序路径必须在磁盘上真实存在，否则命令报错。
> 不在授权列表中的程序会被报告为 Not found，不影响其他移除操作。

### refresh子命令参数

重新计算并更新已授权程序的 SHA256 值。用于程序更新（如系统升级）后重新建立度量基线。

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--program-permit` | `-p` | 要刷新 SHA256 的程序路径（可多次指定）。**可选**：不指定则刷新全部已授权程序 | |
| `--socket-dir` | `-d` | Unix域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

> 参数 `<id>` 是受保护文件的SHA标识符。
> **不指定 `-p` 时，将刷新该凭证全部已授权程序的 SHA256 值**（命令执行前会显示醒目警告）。
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

### dump子命令参数

导出受保护凭据的明文内容，不修改baseline。默认输出到stdout，可通过`--write`写入文件。

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--write` | `-w` | 将内容写入指定文件（不指定则输出到stdout） | |
| `--socket-dir` | `-d` | Unix域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

> 参数 `<id>` 是受保护文件的SHA标识符（可通过 `credctl list` 查看）。
> 密码提示通过 `/dev/tty` 输出，不会污染stdout，可安全用于管道和命令替换。

### restore子命令参数

更新受保护凭据的内容，baseline的元数据（路径、权限等）和访问规则（策略、授权程序等）保持不变。必须通过`--file`或`--secret`指定新内容（二选一）。

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--file` | `-f` | 从指定文件读取新内容 | |
| `--secret` | `-s` | 直接从参数指定新内容（注意：值会出现在进程列表和shell历史中） | |
| `--socket-dir` | `-d` | Unix域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

> 参数 `<id>` 是受保护文件的SHA标识符。
> `--file` 和 `--secret` 互斥，必须且只能指定其一。
> **安全提示**：`--secret/-s` 的值会出现在 `/proc/PID/cmdline` 和 shell 历史记录中，敏感内容建议使用 `--file/-f`。

### release子命令参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--socket-dir` | `-d` | Unix域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

> 参数 `<id>` 是受保护文件的SHA标识符（可通过 `credctl list` 查看），而非原始文件路径。

### remove子命令参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--socket-dir` | `-d` | Unix域套接字文件目录 | `/run/credagent` |
| `--config` | `-c` | 配置文件路径 | `/usr/local/etc/credagent/credctl/config.json` |

> 参数 `<target_filepath>` 是原始凭证文件的完整路径，而非SHA标识符。

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

# 以JSON格式列出
./credctl list --json

# 查看特定受保护文件的详细信息（包含完整 SHA256 列表）
./credctl inspect 59524298d125

# 以JSON格式查看详细信息
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

# 释放受保护的文件（使用SHA id）
./credctl release 59524298d125

# 删除受保护的文件（使用原始文件路径）
./credctl remove /path/to/original/credential/file
```

## credreq命令行工具

credreq是用于请求临时访问受保护凭证权限的命令行工具。

### 命令行规格

```bash
credreq [command]
```

### 可用命令

- `req` - 请求访问凭证文件的权限
- `completion` - 为指定shell生成自动补全脚本
- `help [command]` - 显示任何命令的帮助信息

### 参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--help` | `-h` | 显示帮助信息 | |

### 用法示例

```bash
# 请求访问凭证文件的权限
./credreq req
```

## 配置文件详解

CredAgent系统使用JSON格式的配置文件来管理各个组件的设置。

### credagent配置文件 (engine/config.json)

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
  "log_level": "info"
}
```

#### 配置项说明

- **enclave.socket_dir**: Unix域套接字文件的目录
- **enclave.master_key_file**: 主密钥文件的存储位置
- **enclave.baseline_file**: 加密基线存储文件的路径
- **monitor.mount_point**: FUSE文件系统的挂载点
- **credagent.api_url**: LLM服务的API URL
- **credagent.api_key**: LLM服务的API密钥
- **credagent.model_name**: 使用的LLM模型名称
- **credagent.timeout_seconds**: API请求的超时时间（秒）
- **log_level**: 日志级别（debug, info, warning, error）

### Protector配置文件 (protector/config.json)

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

- **enclave.socket_dir**: Unix域套接字文件的目录
- **monitor.mount_point**: FUSE文件系统的挂载点
- **log_level**: 日志级别（debug, info, warning, error）

### 默认配置文件位置

- **Enclave/Monitor配置文件**: `/usr/local/etc/credagent/engine/config.json`
- **Protector配置文件**: `/usr/local/etc/credagent/protector/config.json`

如果未显式指定配置文件，程序将尝试从这些默认位置加载配置。

## 配置优先级关系

CredAgent系统遵循以下配置优先级规则（从高到低）：

1. **命令行参数** - 最高优先级，直接通过命令行传递的参数将覆盖配置文件中的任何设置
2. **配置文件** - 中等优先级，从指定或默认的配置文件中读取的设置
3. **默认值** - 最低优先级，当命令行参数和配置文件均未提供设置时使用的默认值

这意味着如果同时提供了命令行参数和配置文件中的相同配置项，则命令行参数的值将被采用；只有在命令行参数未指定的情况下，才会使用配置文件中的对应配置。
