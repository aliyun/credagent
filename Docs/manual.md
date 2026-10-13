# CredAgent System Manual

This document details the command-line flags, usage, and configuration file format of every CredAgent component.

## Table of contents
1. [credagent daemon](#credagent-daemon)
2. [credctl CLI](#credctl-cli)
3. [Configuration](#configuration)
4. [Security configuration (`security.json`)](#security-configuration-securityjson)
5. [cmdline tamper detection (`cmdline_trusted_source`)](#cmdline-tamper-detection-cmdline_trusted_source)
6. [Service files](#service-files)
7. [Configuration precedence](#configuration-precedence)

## credagent daemon

The credagent daemon is the core component of CredAgent. It manages credentials, access control, and the FUSE filesystem.

### Command-line spec

```bash
credagent [command] [flags]
```

#### Available commands

- `run` - run the daemon
- `init` - initialize the daemon (create the master key and admin password)
- `help [command]` - show help for any command

#### `run` flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--key-file` | `-k` | Path to the 32-byte AES-256 master key file | |
| `--socket-dir` | `-d` | Directory for Unix domain socket files | `/run/credagent` |
| `--baseline-file` | `-b` | Path to the encrypted baseline store file | |
| `--config` | `-c` | Path to the configuration file | `/usr/local/etc/credagent/engine/config.json` |
| `--mount` | | FUSE filesystem mount point | `/mnt/shielded` |
| `--log-level` | `-l` | Log level (debug, info, warning, error) | `info` |
| `--use-bufnet` | | Internal flag for testing | |
| `--auto-init` | | Auto-initialize master key and admin password on first start if missing (cloud-image / unattended use) | |

##### About the socket file

In the directory specified by `--socket-dir`, the daemon creates a Unix domain socket:

- `enclave.sock` - the daemon's gRPC interface, used by external tools such as `credctl` for protecting/releasing credential files and managing access control.

The FUSE filesystem is integrated inside the credagent process; policy verification is done via in-process function calls, with no extra IPC.

#### `init` flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--key-file` | `-k` | Path of the master key file to create | `/usr/local/etc/credagent/master.key` |
| `--config` | `-c` | Path to the configuration file | `/usr/local/etc/credagent/engine/config.json` |

##### `init` details

`init` prepares the environment the daemon needs:

1. **Master key generation** - creates a 32-byte AES-256 master key file used to encrypt every protected credential.
2. **Admin password setup** - prompts for an admin password, used for sensitive operations (release, remove, dump, restore, etc.).
3. **Config validation** - validates the supplied config file.
4. **Base environment** - ensures required directories exist with correct permissions.

Running `./credagent init` prompts for the admin password, which is then required for subsequent administrative actions.

### Usage examples

```bash
# Start with a config file
./credagent run --config config.json

# Start with custom parameters (including FUSE mount point)
./credagent run --key-file /custom/path/master.key --socket-dir /custom/path --baseline-file /custom/path/baseline.enc --mount /mnt/shielded

# Initialize with default paths
./credagent init

# Initialize with a custom master key file path
./credagent init --key-file /custom/path/master.key --config /path/to/config.json
```

## credctl CLI

credctl is the command-line tool for protecting and releasing credential files.

### Command-line spec

```bash
credctl [command] [flags]
```

### Available commands

- `protect` - protect a credential file, moving it into the enclave
- `release` - release a credential file, restoring it from the enclave (argument is the SHA id)
- `remove` - delete a protected credential from the enclave without restoring (argument is the original file path)
- `list` - list all protected credential files
- `inspect` - show details of a specific protected file (including the full SHA256 list)
- `update` - update a protected file's security options (wholesale replacement of the authorized-program list)
- `attach` - incrementally append authorized programs to a protected file (auto-computes SHA256)
- `detach` - remove authorized programs from a protected file (deletes the paired SHA256)
- `refresh` - recompute SHA256 for authorized programs (use after a program is updated)
- `dump` - export the plaintext of a protected credential (does not modify the baseline)
- `restore` - update a protected credential's content (baseline metadata and rules unchanged)
- `version` - print the credctl version
- `completion` - generate a shell-completion script
- `help [command]` - show help for any command

### Common flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--config` | `-c` | Path to the configuration file | `/usr/local/etc/credagent/protector/config.json` |
| `--log-level` | `-l` | Log level (debug, info, warning, error) | `info` |

### `protect` flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--strategy` | `-s` | Protection strategy (ONE_TIME_USE\|PID_BIND\|SPEC_VERIFICATION\|BASIC) | BASIC |
| `--program-permit` | `-p` | Full path of a binary allowed to access this credential (may be specified multiple times) | required |
| `--measure` | `-m` | Whether to measure and store the SHA256 of the allowed binary (must be explicitly true or false) | no default |
| `--open-frequency` | `-o` | Maximum number of times the credential may be opened (0 = unlimited) | 0 |
| `--writable` | `-w` | Whether the credential file may be modified (true/false) | false |
| `--socket-dir` | `-d` | Directory for Unix domain socket files | `/run/credagent` |
| `--config` | `-c` | Path to the configuration file | `/usr/local/etc/credagent/credctl/config.json` |

#### `--writable` guidance

| Credential type | Recommended | Reason |
|-----------------|-------------|--------|
| SSH private key (`id_rsa`) | `--writable false` | Private keys are normally static |
| API key file | `--writable false` | API keys are normally static |
| OAuth token file | `--writable true` | OAuth tokens expire and are refreshed |
| Cookie file | `--writable true` | Browsers update cookies periodically |
| Session config file | `--writable true` | Cloud CLIs may need to refresh credentials |

If a credential that needs refreshing (OAuth token, cookie, session) is protected with `--writable false`, the authorized program will get `Permission denied` when it tries to update it, causing authentication failures.

### `list` flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--json` | `-j` | Output as JSON | false |
| `--socket-dir` | `-d` | Directory for Unix domain socket files | `/run/credagent` |
| `--config` | `-c` | Path to the configuration file | `/usr/local/etc/credagent/credctl/config.json` |

### `inspect` flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--json` | `-j` | Output details as JSON | false |
| `--socket-dir` | `-d` | Directory for Unix domain socket files | `/run/credagent` |
| `--config` | `-c` | Path to the configuration file | `/usr/local/etc/credagent/credctl/config.json` |

> The `<id>` argument is the SHA identifier of the protected file, visible via `credctl list`.

### `update` flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--strategy` | `-s` | Update the strategy (ONE_TIME_USE\|PID_BIND\|SPEC_VERIFICATION\|BASIC) | |
| `--program-permit` | `-p` | Update the permitted-program path (must be used with `--measure`). **Wholesale-replaces** the authorized-program list | |
| `--measure` | `-m` | Whether to measure SHA256 (must be used with `--program-permit`; must be explicitly true or false) | no default |
| `--open-frequency` | `-o` | Update the max open count (0 = unlimited) | |
| `--writable` | `-w` | Update whether the file may be modified (true/false) | |
| `--socket-dir` | `-d` | Directory for Unix domain socket files | `/run/credagent` |
| `--config` | `-c` | Path to the configuration file | `/usr/local/etc/credagent/credctl/config.json` |

> The `<id>` argument is the SHA identifier of the protected file.
> **Important**: `--program-permit` and `--measure` must be specified together; under `update`, `--measure` has no default and must be explicitly set to true or false.
> `update --program-permit` **wholesale-replaces** the authorized-program list. For incremental changes, use `attach` / `detach`.

### `attach` flags

Incrementally appends authorized programs to a protected credential, auto-computing and storing their SHA256. Programs already present are skipped and reported.

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--program-permit` | `-p` | Program path to append (may be specified multiple times). Required | |
| `--socket-dir` | `-d` | Directory for Unix domain socket files | `/run/credagent` |
| `--config` | `-c` | Path to the configuration file | `/usr/local/etc/credagent/credctl/config.json` |

> The `<id>` argument is the SHA identifier of the protected file (visible via `credctl list`).

### `detach` flags

Removes authorized programs from a protected credential, deleting the paired SHA256.

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--program-permit` | `-p` | Program path to remove (may be specified multiple times). Required | |
| `--socket-dir` | `-d` | Directory for Unix domain socket files | `/run/credagent` |
| `--config` | `-c` | Path to the configuration file | `/usr/local/etc/credagent/credctl/config.json` |

> The `<id>` argument is the SHA identifier of the protected file.
> The program path must exist on disk, otherwise the command errors.
> Programs not in the authorized list are reported as "Not found" and do not affect other removals.

### `refresh` flags

Recomputes and updates the SHA256 of authorized programs. Use after a program is updated (e.g. a system upgrade) to re-establish the measurement baseline.

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--program-permit` | `-p` | Program path whose SHA256 to refresh (may be specified multiple times). **Optional**: if omitted, refreshes all authorized programs | |
| `--socket-dir` | `-d` | Directory for Unix domain socket files | `/run/credagent` |
| `--config` | `-c` | Path to the configuration file | `/usr/local/etc/credagent/credctl/config.json` |

> The `<id>` argument is the SHA identifier of the protected file.
> When `-p` is omitted, SHA256 is refreshed for **all** authorized programs of that credential (a prominent warning is shown before the command runs).
> Only programs already in the authorized list are updated; unauthorized programs are reported as "not authorized" and are not auto-added.
> To add new programs, use `credctl attach`.

#### Output format

`refresh` prints one line per program:

```
  [refreshed]   /usr/bin/psql      afeb5***4ed3a -> bc12f***9a7e2
  [refreshed]   /usr/bin/pg_dump   e3a1c***8bf02 -> e3a1c***8bf02
  [skipped]     /usr/bin/awk (not authorized; use credctl attach to add it)

refresh complete: 2 refreshed, 1 skipped
```

- `[refreshed]` — SHA256 successfully updated, showing old -> new (truncated form)
- `[skipped]` — not refreshed; e.g. program not authorized or file missing

### `dump` flags

Exports the plaintext of a protected credential without modifying the baseline. Defaults to stdout; use `--write` to write to a file.

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--write` | `-w` | Write the content to the given file (stdout if omitted) | |
| `--socket-dir` | `-d` | Directory for Unix domain socket files | `/run/credagent` |
| `--config` | `-c` | Path to the configuration file | `/usr/local/etc/credagent/credctl/config.json` |

> The `<id>` argument is the SHA identifier of the protected file (visible via `credctl list`).
> The password prompt goes to `/dev/tty`, so it does not pollute stdout — safe for pipes and command substitution.

### `restore` flags

Updates the content of a protected credential; baseline metadata (path, permissions, etc.) and access rules (strategy, authorized programs, etc.) are unchanged. New content must be supplied via `--file` or `--secret` (mutually exclusive).

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--file` | `-f` | Read new content from the given file | |
| `--secret` | `-s` | Supply new content directly from the argument (note: the value appears in the process list and shell history) | |
| `--socket-dir` | `-d` | Directory for Unix domain socket files | `/run/credagent` |
| `--config` | `-c` | Path to the configuration file | `/usr/local/etc/credagent/credctl/config.json` |

> The `<id>` argument is the SHA identifier of the protected file.
> `--file` and `--secret` are mutually exclusive; exactly one must be specified.
> **Security note**: the `--secret/-s` value appears in `/proc/PID/cmdline` and shell history; for sensitive content prefer `--file/-f`.

### `release` flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--socket-dir` | `-d` | Directory for Unix domain socket files | `/run/credagent` |
| `--config` | `-c` | Path to the configuration file | `/usr/local/etc/credagent/credctl/config.json` |

> The `<id>` argument is the SHA identifier of the protected file (visible via `credctl list`), not the original file path.

### `remove` flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--socket-dir` | `-d` | Directory for Unix domain socket files | `/run/credagent` |
| `--config` | `-c` | Path to the configuration file | `/usr/local/etc/credagent/credctl/config.json` |

> The `<target_filepath>` argument is the full path of the original credential file, not the SHA identifier.

### Usage examples

```bash
# One-time-use strategy
./credctl protect --strategy ONE_TIME_USE --program-permit /usr/bin/psql --measure true /etc/psql/passwd

# Spec-verification strategy
./credctl protect --strategy SPEC_VERIFICATION --program-permit /usr/bin/psql --program-permit /usr/bin/pg_dump --measure true /etc/psql/passwd

# Basic strategy, measuring the binary
./credctl protect --strategy BASIC --program-permit /usr/bin/cat --measure true /etc/myfile.txt

# Allow the file to be modified
./credctl protect --strategy BASIC --program-permit /usr/bin/vim --measure false --writable true /etc/myfile.txt

# List all protected files
./credctl list

# List as JSON
./credctl list --json

# Show details of a protected file (including the full SHA256 list)
./credctl inspect 59524298d125

# Show details as JSON
./credctl inspect 59524298d125 --json

# Update a protected file's strategy (wholesale-replaces the authorized-program list)
./credctl update 59524298d125 --strategy ONE_TIME_USE
./credctl update 59524298d125 --program-permit /usr/bin/psql --measure true
./credctl update 59524298d125 --open-frequency 10
./credctl update 59524298d125 --writable true

# Incrementally append authorized programs (does not affect other authorized programs)
./credctl attach -p /usr/bin/pg_dump 59524298d125
./credctl attach -p /usr/bin/psql -p /usr/bin/pg_dump 59524298d125

# Remove authorized programs
./credctl detach -p /usr/bin/pg_dump 59524298d125

# Refresh SHA256 of authorized programs (use after a program is updated)
./credctl refresh -p /usr/bin/psql 59524298d125
./credctl refresh -p /usr/bin/psql -p /usr/bin/pg_dump 59524298d125

# Refresh SHA256 of all authorized programs (omit -p)
./credctl refresh 59524298d125

# Dump credential content to stdout
./credctl dump 59524298d125

# Dump credential content to a file
./credctl dump -w /tmp/config.json 59524298d125

# Update credential content from a file
./credctl restore -f /tmp/config.json 59524298d125

# Update credential content from an argument
./credctl restore -s 'new-secret-value' 59524298d125

# Combined: dump -> modify -> restore (prompts for the password twice)
./credctl restore -s "$(./credctl dump 59524298d125 | sed 's/old/new/g')" 59524298d125

# Release a protected file (by SHA id)
./credctl release 59524298d125

# Remove a protected file (by original file path)
./credctl remove /path/to/original/credential/file
```

## Configuration

CredAgent uses JSON configuration files to manage each component's settings.

### credagent config (engine/config.json)

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

#### Field reference

- **enclave.socket_dir**: directory for the Unix domain socket files.
- **enclave.master_key_file**: location of the master key file. credagent also stores the admin password file next to it.
- **enclave.baseline_file**: path of the encrypted baseline store file.
- **monitor.mount_point**: FUSE filesystem mount point.
- **credagent.api_url**: API URL of the LLM service (used for AI risk assessment; not needed for the BASIC strategy).
- **credagent.api_key**: API key for the LLM service.
- **credagent.model_name**: LLM model name to use.
- **credagent.timeout_seconds**: API request timeout, in seconds.
- **log_level**: log level (debug, info, warning, error).
- **cmdline_trusted_source**: trusted source(s) for cmdline tamper detection, comma-separated. See [cmdline tamper detection](#cmdline-tamper-detection-cmdline_trusted_source).

### credctl config (credctl/config.json)

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

#### Field reference

- **enclave.socket_dir**: directory for the Unix domain socket files.
- **monitor.mount_point**: FUSE filesystem mount point.
- **log_level**: log level (debug, info, warning, error).

### Default config file locations

- **Engine / daemon config**: `/usr/local/etc/credagent/engine/config.json`
- **Security policy**: `/usr/local/etc/credagent/engine/security.json`
- **credctl config**: `/usr/local/etc/credagent/credctl/config.json`

If no config file is explicitly specified, the program loads it from these default locations.

## Security configuration (`security.json`)

`security.json` configures the anti-attack checks the policy engine runs while attesting a process on every `open()`. Every check is opt-in; the shipped template has all of them `enabled: false` — enable the ones you need and restart `credagent`.

The top-level structure is:

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
    "interpreter_check":       { "...": "per-interpreter, see below" },
    "fd_share_check":          { "enabled": false }
  }
}
```

`cmdline_trusted_source` is a top-level field (not under `antiattack_options`) and is Linux-only; see [cmdline tamper detection](#cmdline-tamper-detection-cmdline_trusted_source).

### Checks

| Check | Detects / prevents | Sub-fields |
|---|---|---|
| `binary_check` | Verifies binary trust — path safety and ownership of the requesting process and its ancestors | `enabled`, `trusted_programs[]` |
| `ancestor_check` | Walks the ancestor process chain and verifies each ancestor up to `max_depth` | `enabled`, `max_depth` |
| `process_status_check` | Detects a tracer/debugger attached (`TracerPid`) and seccomp status | `enabled` |
| `library_injection_check` | Detects suspicious injected shared libraries (`.so` on Linux, `.dylib` on macOS) | `enabled`, `trusted_lib_paths[]` |
| `env_var_check` | Detects dynamic-linker injection via env vars — `LD_PRELOAD` / `LD_LIBRARY_PATH` / `LD_AUDIT` (Linux) and `DYLD_INSERT_LIBRARIES` (macOS). Applies to every binary, not just interpreters | `enabled`, `trusted_env{}` |
| `interpreter_check` | Per-interpreter attestation for Python/Node/Perl/Ruby/Java/PHP — trusted env, trusted scripts, executable paths | one `enabled` per interpreter; plus `trusted_env{}`, `trusted_scripts[]`, `exe_paths[]` |
| `fd_share_check` | Detects cross-process file-descriptor sharing (an unauthorized process being handed the opened fd) and blacklists offenders | `enabled` |
| `trusted_harness` | Trusted harness programs that bypass the interpreter checks | array of paths |

### `interpreter_check` structure

Each interpreter is configured independently with **one `enabled` toggle** (no finer sub-check toggles) plus trust lists:

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

- `trusted_env`: environment variables (per key) whose values are considered safe for that interpreter.
- `trusted_scripts`: entry-point scripts that are measured and allowed to run.
- `exe_paths`: realpaths of the interpreter binaries that may run trusted scripts.

### Startup summary

On startup `credagent` logs the loaded policy, e.g.:

```
Security policy loaded from security.json: enabled=[interpreter_check], disabled=[binary_check, ancestor_check, process_status_check, library_injection_check, env_var_check, fd_share_check]
```

Note: `interpreter_check` is reported as `enabled` whenever the `interpreter_check` block is present, regardless of the individual interpreter `enabled` flags — the per-interpreter `enabled` toggles control which interpreters are actually attested.

## cmdline tamper detection (`cmdline_trusted_source`)

Script interpreters (Python, Node, Ruby, Perl, etc.) can rewrite `/proc/<pid>/cmdline` at runtime, impersonating an authorized script to bypass the SHA256 check. credagent mitigates this by collecting the original command line from a **trusted source** at `execve` time and comparing it to the value read from `/proc`, detecting tampering.

Enable it by setting `cmdline_trusted_source` in `engine/config.json`:

```json
{
  "cmdline_trusted_source": "ebpf,auditd"
}
```

Supported sources (tried in configured order; the first available one wins):

| Source | How it works | Requirements |
|--------|--------------|--------------|
| `ebpf` | eBPF hook on `sys_enter_execve`; the kernel collects cmdline into a BPF hash map | Linux >= 5.2, BTF enabled (`/sys/kernel/btf/vmlinux` present), syscall tracepoints available |
| `auditd` | The Linux audit subsystem records execve argv; credagent parses the audit log in real time | auditd installed and enabled, no `task,never` rule blocking (credagent handles this automatically on startup) |

**Fallback behavior**:
- If `cmdline_trusted_source` is unset, or every configured source is unavailable, credagent reads cmdline from `/proc/<pid>/cmdline` with no tamper detection.
- Under WSL2 both eBPF and auditd are unavailable; it falls back automatically.

**auditd notes**:
- On startup, credagent scans the system for interpreter realpaths (python, perl, ruby, node, php, java) and adds execve audit rules only for those interpreters.
- Rules are tagged `-k credagent_cmdline` and do not affect other audit rules.
- If a `-a task,never` rule exists (which blocks all syscall auditing), credagent removes it to enable auditing and restores it on exit.
- credagent cleans up all the audit rules it added on exit.

**eBPF notes**:
- The eBPF bytecode (`internal/execsnoop/execsnoop_x86_bpfel.o`) and Go bindings are pre-generated and committed to the repo, so `go build` already includes eBPF support — **no extra build step needed**. `bpf2go` embeds the bytecode into the Go binary, so the compiled credagent can be shipped to other nodes, which do not need clang or any build toolchain.
- If the target node's kernel lacks BTF or the syscall tracepoints are not registered, credagent skips eBPF on startup and logs `eBPF execsnoop: syscall tracepoints not available`.

### Regenerating the eBPF bytecode

After editing the eBPF C source (`internal/execsnoop/bpf/execsnoop.c`), regenerate the bytecode and Go bindings:

```bash
# Build dependencies (only needed on the dev machine that regenerates; target nodes do not need them)
sudo apt-get install clang libbpf-dev

# Regenerate the eBPF bytecode and Go bindings
go generate ./internal/execsnoop/

# Rebuild credagent
go build -o credagent ./cmd/credagent
```

Commit the updated `execsnoop_x86_bpfel.o` and `execsnoop_x86_bpfel.go` to the repo.

## Service files

The `INSTALL` script installs the service definition and bootstraps the runtime directories. The installed files are the source of truth; this section summarizes them.

### Linux (systemd)

Installed to `/etc/systemd/system/credagent.service`. Key fields:

```ini
[Service]
Type=simple
User=root
ExecStartPre=+/usr/bin/bash -c "/usr/bin/fusermount -uz /mnt/credagent/shielded || true"
ExecStartPre=+/usr/bin/mkdir -p /mnt/credagent/shielded/
ExecStart=/usr/local/bin/credagent run --mount /mnt/credagent/shielded/ --socket-dir /run/credagent --baseline-file /var/lib/credagent/baseline.enc --config /usr/local/etc/credagent/engine/config.json
Restart=always
```

Manage with `systemctl {start,stop,status,enable,disable} credagent`; logs via `journalctl -u credagent`.

### macOS (launchd)

Installed to `/Library/LaunchDaemons/com.credagent.enclave.plist`. Key fields:

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

Manage with `launchctl {load,unload}` and `sudo launchctl list | grep credagent`; logs at `/usr/local/var/log/credagent/credagent.log`.

## Configuration precedence

CredAgent follows this precedence (highest to lowest):

1. **Command-line flags** — highest; a flag passed on the command line overrides any setting from the config file.
2. **Config file** — medium; settings read from the specified or default config file.
3. **Defaults** — lowest; used when neither a command-line flag nor the config file supplies a value.

So if the same setting is provided both as a flag and in the config file, the flag value wins; the config file value is used only when the flag is not specified.
