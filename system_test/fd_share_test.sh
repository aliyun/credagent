#!/bin/bash

# CredAgent 跨进程 fd 共享检测系统测试
# 测试目标：验证 FUSE 层能检测并拒绝跨进程 fd 共享（文件描述符传递）
# 覆盖范围：
#   - 测试1: 正常进程可以读取凭据（基线验证）
#   - 测试2: fork 后子进程继承 fd 读取应被拒绝
#   - 测试3: 被标记 untrusted 的进程再次打开应被拒绝（单进程内验证）
#   - 测试4: Unix socket 传递 fd 到无关进程应被拒绝
#   - 测试5: fd_share_check 禁用时不标记 untrusted
# 前置条件：已执行 init_test_environ.sh
# 运行要求：需要 sudo 权限

echo "=============================================="
echo "CredAgent 跨进程 fd 共享检测测试"
echo "=============================================="

# 检查 root 权限
if [ "$(id -u)" -ne 0 ]; then
    echo "错误: 此脚本需要 root 权限运行"
    echo "请使用: sudo bash $0"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---- 加载测试环境 ----
ENV_FILE="/tmp/credagent_test_env.sh"
if [ -f "$ENV_FILE" ]; then
    source "$ENV_FILE"
else
    echo "错误: 测试环境未初始化，请先运行 init_test_environ.sh"
    exit 1
fi

if [ -z "$TEST_DIR" ] || [ ! -d "$TEST_DIR" ]; then
    echo "错误: TEST_DIR 未设置或不存在"
    exit 1
fi

if [ -z "$CREDAGENT_PID" ] || ! ps -p "$CREDAGENT_PID" > /dev/null 2>&1; then
    echo "错误: credagent 进程未运行"
    exit 1
fi

PYTHON3_PATH=$(which python3 2>/dev/null)
if [ -z "$PYTHON3_PATH" ]; then
    echo "错误: python3 未安装，无法执行此测试"
    exit 1
fi

echo "测试环境验证通过"
echo "  TEST_DIR: $TEST_DIR"
echo "  MOUNT_POINT: $MOUNT_POINT"
echo "  CREDAGENT_PID: $CREDAGENT_PID"
echo "  PYTHON3_PATH: $PYTHON3_PATH"
echo ""

# ---- 测试计数器 ----
TESTS_PASSED=0
TESTS_FAILED=0

# ---- 公共文件路径 ----
SECRET_FILE="$SECRETS_DIR/fd_share_test_secret.txt"
SECRET_CONTENT="fd_share_test_secret_value_99999"
PY_NORMAL_READ="$TEST_DIR/fd_share_normal_read.py"
PY_FORK_SHARE="$TEST_DIR/fd_share_fork.py"
PY_REOPEN_TEST="$TEST_DIR/fd_share_reopen.py"
PY_SOCK_SENDER="$TEST_DIR/fd_share_sender.py"
PY_SOCK_RECEIVER="$TEST_DIR/fd_share_receiver.py"
PY_DISABLED_TEST="$TEST_DIR/fd_share_disabled_check.py"
SHA_IDENTIFIER=""

# ============================================
# 准备: 创建测试文件
# ============================================
echo "准备: 创建测试文件"

rm -f "$SECRET_FILE" "$PY_NORMAL_READ" "$PY_FORK_SHARE" "$PY_REOPEN_TEST" \
      "$PY_SOCK_SENDER" "$PY_SOCK_RECEIVER" "$PY_DISABLED_TEST" 2>/dev/null

echo "$SECRET_CONTENT" > "$SECRET_FILE"
echo "  秘密文件: $SECRET_FILE"

# 正常读取脚本
cat > "$PY_NORMAL_READ" << 'PYEOF'
import sys

target = sys.argv[1] if len(sys.argv) > 1 else None
if not target:
    print("Usage: fd_share_normal_read.py <file_path>", file=sys.stderr)
    sys.exit(1)

try:
    with open(target, "r") as f:
        content = f.read().strip()
    print(content)
except PermissionError:
    print("PERMISSION_DENIED", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
chmod +x "$PY_NORMAL_READ"
echo "  正常读取脚本: $PY_NORMAL_READ"

# fork fd 共享测试脚本
# 父进程打开文件获取 fd，fork 后子进程尝试通过继承的 fd 读取
# 注意：子进程使用 os.write(1,...) 绕过 Python 缓冲区（os._exit 不会 flush）
cat > "$PY_FORK_SHARE" << 'PYEOF'
import os
import sys

target = sys.argv[1] if len(sys.argv) > 1 else None
if not target:
    print("Usage: fd_share_fork.py <file_path>", file=sys.stderr)
    sys.exit(1)

# 父进程打开文件
try:
    fd = os.open(target, os.O_RDONLY)
except PermissionError:
    os.write(1, b"PARENT_OPEN_DENIED\n")
    sys.exit(2)
except OSError as e:
    os.write(1, f"PARENT_OPEN_ERROR:{e}\n".encode())
    sys.exit(2)

# fork 子进程
pid = os.fork()
if pid == 0:
    # 子进程: 尝试通过继承的 fd 读取
    # 使用 os.write 直接写 stdout fd，避免 os._exit 不 flush 的问题
    try:
        data = os.read(fd, 4096)
        if data:
            os.write(1, f"CHILD_READ_OK:{data.decode().strip()}\n".encode())
        else:
            os.write(1, b"CHILD_READ_EMPTY\n")
    except PermissionError:
        os.write(1, b"CHILD_READ_DENIED\n")
    except OSError as e:
        os.write(1, f"CHILD_READ_ERROR:{e}\n".encode())
    finally:
        os.close(fd)
        os._exit(0)
else:
    # 父进程: 等待子进程
    os.close(fd)
    _, status = os.waitpid(pid, 0)
    sys.exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1)
PYEOF
chmod +x "$PY_FORK_SHARE"
echo "  Fork 共享脚本: $PY_FORK_SHARE"

# 同一进程中验证 untrusted 持久性的脚本
# 流程: 打开文件 → fork 子进程读取(触发标记) → 等待 → 再次打开(验证被拒绝)
cat > "$PY_REOPEN_TEST" << 'PYEOF'
import os
import sys
import time

target = sys.argv[1] if len(sys.argv) > 1 else None
if not target:
    sys.exit(1)

# 第一次打开
try:
    fd = os.open(target, os.O_RDONLY)
except PermissionError:
    print("FIRST_OPEN_DENIED")
    sys.exit(0)
except OSError as e:
    print(f"FIRST_OPEN_ERROR:{e}")
    sys.exit(0)

# fork 子进程读取（触发 fd_share_check，标记父进程 untrusted）
pid = os.fork()
if pid == 0:
    try:
        os.read(fd, 4096)
    except:
        pass
    os.close(fd)
    os._exit(0)
else:
    os.waitpid(pid, 0)
    os.close(fd)
    # 等待确保 FUSE 完成标记
    time.sleep(0.2)

# 第二次打开 — 父进程已被标记 untrusted，应被拒绝
try:
    fd2 = os.open(target, os.O_RDONLY)
    data = os.read(fd2, 4096)
    os.close(fd2)
    print(f"REOPEN_OK:{data.decode().strip()}")
except PermissionError:
    print("REOPEN_DENIED")
except OSError as e:
    print(f"REOPEN_ERROR:{e}")
PYEOF
chmod +x "$PY_REOPEN_TEST"
echo "  Reopen 测试脚本: $PY_REOPEN_TEST"

# Unix socket fd 传递 - 发送端
cat > "$PY_SOCK_SENDER" << 'PYEOF'
import os
import sys
import socket
import array
import time

target = sys.argv[1] if len(sys.argv) > 1 else None
sock_path = sys.argv[2] if len(sys.argv) > 2 else None
if not target or not sock_path:
    print("Usage: fd_share_sender.py <file_path> <socket_path>", file=sys.stderr)
    sys.exit(1)

# 打开目标文件
try:
    fd = os.open(target, os.O_RDONLY)
except PermissionError:
    print("SENDER_OPEN_DENIED", file=sys.stderr)
    sys.exit(2)
except OSError as e:
    print(f"SENDER_OPEN_ERROR: {e}", file=sys.stderr)
    sys.exit(2)

# 创建 Unix socket 服务端，等待 receiver 连接
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    os.unlink(sock_path)
except OSError:
    pass
server.bind(sock_path)
server.listen(1)

# 写入就绪标记文件
ready_file = sock_path + ".ready"
with open(ready_file, "w") as rf:
    rf.write("ready")

# 等待连接（超时 5 秒）
server.settimeout(5)
try:
    conn, _ = server.accept()
except socket.timeout:
    print("SENDER_TIMEOUT", file=sys.stderr)
    os.close(fd)
    server.close()
    sys.exit(3)

# 通过 SCM_RIGHTS 发送 fd
fds = array.array("i", [fd])
conn.sendmsg([b"fd"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
conn.close()
os.close(fd)
server.close()

# 等待 receiver 完成
time.sleep(1)
print("SENDER_DONE")
PYEOF
chmod +x "$PY_SOCK_SENDER"
echo "  Socket 发送端: $PY_SOCK_SENDER"

# Unix socket fd 传递 - 接收端
cat > "$PY_SOCK_RECEIVER" << 'PYEOF'
import os
import sys
import socket
import array

sock_path = sys.argv[1] if len(sys.argv) > 1 else None
if not sock_path:
    print("Usage: fd_share_receiver.py <socket_path>", file=sys.stderr)
    sys.exit(1)

# 连接到 sender
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.connect(sock_path)

# 通过 SCM_RIGHTS 接收 fd
fds = array.array("i", [0])
msg, ancdata, flags, addr = client.recvmsg(64, socket.CMSG_SPACE(fds.itemsize))
for cmsg_level, cmsg_type, cmsg_data in ancdata:
    if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
        fds.frombytes(cmsg_data[:fds.itemsize])

client.close()
received_fd = fds[0]

# 尝试通过接收的 fd 读取
try:
    data = os.read(received_fd, 4096)
    if data:
        print(f"RECEIVER_READ_OK:{data.decode().strip()}")
    else:
        print("RECEIVER_READ_EMPTY")
except PermissionError:
    print("RECEIVER_READ_DENIED")
except OSError as e:
    print(f"RECEIVER_READ_ERROR:{e}")
finally:
    os.close(received_fd)
PYEOF
chmod +x "$PY_SOCK_RECEIVER"
echo "  Socket 接收端: $PY_SOCK_RECEIVER"

# fd_share_check 禁用测试脚本
cat > "$PY_DISABLED_TEST" << 'PYEOF'
import os
import sys
import time

target = sys.argv[1] if len(sys.argv) > 1 else None
if not target:
    sys.exit(1)

# 第一次打开
try:
    fd = os.open(target, os.O_RDONLY)
except PermissionError:
    print("FIRST_OPEN_DENIED")
    sys.exit(0)
except OSError as e:
    print(f"FIRST_OPEN_ERROR:{e}")
    sys.exit(0)

# fork 子进程读取（fd_share_check 禁用时不标记 untrusted）
pid = os.fork()
if pid == 0:
    try:
        os.read(fd, 4096)
    except:
        pass
    os.close(fd)
    os._exit(0)
else:
    os.waitpid(pid, 0)
    os.close(fd)
    time.sleep(0.2)

# 第二次打开 — fd_share_check 禁用，父进程未被标记，应成功
try:
    fd2 = os.open(target, os.O_RDONLY)
    data = os.read(fd2, 4096)
    os.close(fd2)
    print(f"REOPEN_OK:{data.decode().strip()}")
except PermissionError:
    print("REOPEN_DENIED")
except OSError as e:
    print(f"REOPEN_ERROR:{e}")
PYEOF
chmod +x "$PY_DISABLED_TEST"
echo "  禁用检查测试脚本: $PY_DISABLED_TEST"

echo ""

# ============================================
# protect: 保护秘密文件
# ============================================
echo "准备: 使用 credctl protect 保护秘密文件"

# 注意: 所有需要 open() FUSE 文件的脚本都必须加入 -p 列表
PROTECT_CMD=("$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" --strategy BASIC --measure false)
PROTECT_CMD+=(-p "$PY_NORMAL_READ")
PROTECT_CMD+=(-p "$PY_FORK_SHARE")
PROTECT_CMD+=(-p "$PY_REOPEN_TEST")
PROTECT_CMD+=(-p "$PY_SOCK_SENDER")
PROTECT_CMD+=(-p "$PY_DISABLED_TEST")
PROTECT_CMD+=(-i "$SECRET_FILE")

echo "  命令: ${PROTECT_CMD[*]}"
PROTECT_OUTPUT=$("${PROTECT_CMD[@]}" 2>&1)
PROTECT_RESULT=$?

echo "  输出: $PROTECT_OUTPUT"

if [ $PROTECT_RESULT -ne 0 ]; then
    echo "  ✗ protect 失败, 无法继续测试"
    exit 1
fi
echo "  ✓ protect 成功"

# 获取 SHA identifier
LIST_OUTPUT=$("$PROJECT_ROOT/credctl" list --config "$CREDCTL_CONFIG" 2>&1)
SHA_LINE=$(echo "$LIST_OUTPUT" | grep "$SECRET_FILE" | grep -oE "^[a-f0-9]+")
if [ -z "$SHA_LINE" ]; then
    SHA_LINE=$(echo "$LIST_OUTPUT" | grep -E "^[a-f0-9]+" | tail -n1 | awk '{print $1}')
fi
SHA_IDENTIFIER="$SHA_LINE"
echo "  SHA identifier: $SHA_IDENTIFIER"
echo ""

echo "=============================================="
echo "测试1: 正常进程可以读取凭据（基线验证）"
echo "=============================================="
echo ""

OUTPUT=$("$PYTHON3_PATH" "$PY_NORMAL_READ" "$SECRET_FILE" 2>&1)
RESULT=$?
echo "  返回值: $RESULT"
echo "  输出: $OUTPUT"

if [ $RESULT -eq 0 ] && [ "$OUTPUT" = "$SECRET_CONTENT" ]; then
    echo "  ✓ 正常进程成功读取凭据"
    ((TESTS_PASSED++))
else
    echo "  ✗ 正常进程无法读取凭据"
    ((TESTS_FAILED++))
fi

echo ""
echo "=============================================="
echo "测试2: fork 后子进程继承 fd 读取应被拒绝"
echo "=============================================="
echo ""
echo "  场景: 父进程(已授权)打开文件，fork 后子进程(不同PID)尝试 read"

OUTPUT=$("$PYTHON3_PATH" "$PY_FORK_SHARE" "$SECRET_FILE" 2>&1)
RESULT=$?
echo "  返回值: $RESULT"
echo "  输出: $OUTPUT"

if [[ "$OUTPUT" == *"CHILD_READ_DENIED"* ]] || [[ "$OUTPUT" == *"CHILD_READ_ERROR"* ]]; then
    echo "  ✓ 子进程通过继承 fd 读取被拒绝"
    ((TESTS_PASSED++))
elif [[ "$OUTPUT" == *"PARENT_OPEN_DENIED"* ]]; then
    echo "  ✗ 父进程打开就被拒绝（不应发生）"
    ((TESTS_FAILED++))
elif [[ "$OUTPUT" == *"CHILD_READ_OK"* ]]; then
    echo "  ✗ 子进程成功读取了凭据！fd 共享未被检测"
    ((TESTS_FAILED++))
elif [[ "$OUTPUT" == *"CHILD_READ_EMPTY"* ]]; then
    echo "  ~ 子进程读取返回空（FUSE 可能返回了空数据而非 EACCES）"
    echo "    检查 credagent 日志确认是否触发了 fd_share_check"
    ((TESTS_PASSED++))
else
    echo "  ✗ 未预期的输出"
    ((TESTS_FAILED++))
fi

echo ""
echo "=============================================="
echo "测试3: 被标记 untrusted 的进程再次打开应被拒绝"
echo "=============================================="
echo ""
echo "  场景: 同一进程打开文件 → fork 子进程读取(触发标记) → 再次 Open 验证"

OUTPUT=$("$PYTHON3_PATH" "$PY_REOPEN_TEST" "$SECRET_FILE" 2>&1)
RESULT=$?
echo "  返回值: $RESULT"
echo "  输出: $OUTPUT"

if [[ "$OUTPUT" == *"REOPEN_DENIED"* ]]; then
    echo "  ✓ 被标记 untrusted 的进程再次打开被拒绝"
    ((TESTS_PASSED++))
elif [[ "$OUTPUT" == *"FIRST_OPEN_DENIED"* ]]; then
    echo "  ✗ 第一次打开就被拒绝（脚本未在授权列表中？）"
    ((TESTS_FAILED++))
elif [[ "$OUTPUT" == *"REOPEN_OK"* ]]; then
    echo "  ✗ 被标记 untrusted 的进程仍可打开文件"
    ((TESTS_FAILED++))
else
    echo "  ✗ 未预期的输出"
    ((TESTS_FAILED++))
fi

echo ""
echo "=============================================="
echo "测试4: Unix socket 传递 fd 到无关进程应被拒绝"
echo "=============================================="
echo ""
echo "  场景: 进程A(已授权)打开文件，通过 SCM_RIGHTS 传递 fd 给进程B(不同PID)"

SOCK_PATH="/tmp/credagent_fd_share_test.sock"
rm -f "$SOCK_PATH" "${SOCK_PATH}.ready" 2>/dev/null

# 启动 sender（后台运行）
"$PYTHON3_PATH" "$PY_SOCK_SENDER" "$SECRET_FILE" "$SOCK_PATH" > /tmp/fd_share_sender_out.txt 2>&1 &
SENDER_PID=$!

# 等待 sender 就绪
WAIT_COUNT=0
while [ ! -f "${SOCK_PATH}.ready" ] && [ $WAIT_COUNT -lt 50 ]; do
    sleep 0.1
    ((WAIT_COUNT++))
done

if [ ! -f "${SOCK_PATH}.ready" ]; then
    echo "  ✗ Sender 启动超时"
    kill $SENDER_PID 2>/dev/null
    ((TESTS_FAILED++))
else
    # 启动 receiver
    RECEIVER_OUTPUT=$("$PYTHON3_PATH" "$PY_SOCK_RECEIVER" "$SOCK_PATH" 2>&1)
    RECEIVER_RESULT=$?

    # 等待 sender 完成
    wait $SENDER_PID 2>/dev/null
    SENDER_OUTPUT=$(cat /tmp/fd_share_sender_out.txt 2>/dev/null)

    echo "  Sender 输出: $SENDER_OUTPUT"
    echo "  Receiver 返回值: $RECEIVER_RESULT"
    echo "  Receiver 输出: $RECEIVER_OUTPUT"

    if [[ "$SENDER_OUTPUT" == *"SENDER_OPEN_DENIED"* ]]; then
        echo "  ✗ Sender 打开文件被拒绝（不应发生）"
        ((TESTS_FAILED++))
    elif [[ "$RECEIVER_OUTPUT" == *"RECEIVER_READ_DENIED"* ]] || [[ "$RECEIVER_OUTPUT" == *"RECEIVER_READ_ERROR"* ]]; then
        echo "  ✓ 通过 Unix socket 传递的 fd 被拒绝读取"
        ((TESTS_PASSED++))
    elif [[ "$RECEIVER_OUTPUT" == *"RECEIVER_READ_EMPTY"* ]]; then
        echo "  ~ Receiver 读取返回空数据（FUSE 可能返回了 EOF 而非 EACCES）"
        echo "    检查 credagent 日志确认是否触发了 fd_share_check"
        ((TESTS_PASSED++))
    elif [[ "$RECEIVER_OUTPUT" == *"RECEIVER_READ_OK:$SECRET_CONTENT"* ]]; then
        echo "  ✗ Receiver 成功读取了凭据内容！fd 传递未被检测"
        ((TESTS_FAILED++))
    elif [[ "$RECEIVER_OUTPUT" == *"RECEIVER_READ_OK:"* ]]; then
        echo "  ~ Receiver 读取返回了空内容（fd_share_check 可能已拦截但未返回 EACCES）"
        echo "    检查 credagent 日志确认"
        ((TESTS_PASSED++))
    else
        echo "  ✗ 未预期的输出"
        ((TESTS_FAILED++))
    fi
fi

rm -f "$SOCK_PATH" "${SOCK_PATH}.ready" /tmp/fd_share_sender_out.txt 2>/dev/null

echo ""
echo "=============================================="
echo "测试5: fd_share_check 禁用时不标记 untrusted"
echo "=============================================="
echo ""
echo "  场景: 临时禁用 fd_share_check，验证跨进程 fd 共享不标记 untrusted"

# 修改配置禁用 fd_share_check
python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    cfg = json.load(f)
cfg.setdefault('antiattack_options', {}).setdefault('fd_share_check', {})['enabled'] = False
with open(sys.argv[1], 'w') as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
" "$SECURITY_CONFIG"

if [ $? -ne 0 ]; then
    echo "  ✗ 无法修改配置文件（需要 root 权限）"
    ((TESTS_FAILED++))
else
    # 重启 credagent 使配置生效
    kill "$CREDAGENT_PID" 2>/dev/null
    sleep 2
    "$PROJECT_ROOT/credagent" run -c "$ENGINE_CONFIG" > "$CREDAGENT_LOG" 2>&1 &
    NEW_CREDAGENT_PID=$!
    sleep 2

    if ! ps -p $NEW_CREDAGENT_PID > /dev/null 2>&1; then
        echo "  ✗ credagent 重启失败"
        ((TESTS_FAILED++))
    else
        OUTPUT=$("$PYTHON3_PATH" "$PY_DISABLED_TEST" "$SECRET_FILE" 2>&1)
        RESULT=$?
        echo "  返回值: $RESULT"
        echo "  输出: $OUTPUT"

        if [[ "$OUTPUT" == *"REOPEN_OK:$SECRET_CONTENT"* ]]; then
            echo "  ✓ fd_share_check 禁用后，进程未被标记 untrusted，再次打开成功"
            ((TESTS_PASSED++))
        elif [[ "$OUTPUT" == *"REOPEN_DENIED"* ]]; then
            echo "  ✗ fd_share_check 禁用后，进程仍被标记 untrusted"
            ((TESTS_FAILED++))
        elif [[ "$OUTPUT" == *"FIRST_OPEN_DENIED"* ]]; then
            echo "  ✗ 第一次打开就被拒绝（脚本未在授权列表中？）"
            ((TESTS_FAILED++))
        else
            echo "  ✗ 未预期的输出"
            ((TESTS_FAILED++))
        fi

        # 恢复配置并重启
        kill "$NEW_CREDAGENT_PID" 2>/dev/null
        sleep 2
    fi

    # 恢复配置
    python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    cfg = json.load(f)
cfg.setdefault('antiattack_options', {}).setdefault('fd_share_check', {})['enabled'] = True
with open(sys.argv[1], 'w') as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
" "$SECURITY_CONFIG"
    # 重启 credagent 恢复默认配置
    "$PROJECT_ROOT/credagent" run -c "$ENGINE_CONFIG" > "$CREDAGENT_LOG" 2>&1 &
    CREDAGENT_PID=$!
    sleep 2

    # 更新环境变量文件中的 PID
    sed -i "s/export CREDAGENT_PID=.*/export CREDAGENT_PID=\"$CREDAGENT_PID\"/" "$ENV_FILE"
fi

# ============================================
# 清理: release 受保护文件
# ============================================
echo ""
echo "清理: 释放受保护文件"

if [ -n "$SHA_IDENTIFIER" ]; then
    if [ -L "$SECRET_FILE" ]; then
        rm -f "$SECRET_FILE"
    fi

    echo "  → 释放凭据 $SHA_IDENTIFIER (请输入管理员密码):"
    "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER"
    RELEASE_RESULT=$?

    if [ $RELEASE_RESULT -eq 0 ]; then
        echo "  ✓ release 成功"
    else
        echo "  ⚠ release 失败（不影响测试结果）"
    fi
fi

rm -f "$PY_NORMAL_READ" "$PY_FORK_SHARE" "$PY_REOPEN_TEST" \
      "$PY_SOCK_SENDER" "$PY_SOCK_RECEIVER" "$PY_DISABLED_TEST" 2>/dev/null

# ============================================
# 测试结果汇总
# ============================================
echo ""
echo "=============================================="
echo "测试结果汇总"
echo "=============================================="
echo "通过的测试: $TESTS_PASSED"
echo "失败的测试: $TESTS_FAILED"
echo "总计测试: $((TESTS_PASSED + TESTS_FAILED))"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo "所有测试通过 ✓"
    echo "=============================================="
    exit 0
else
    echo "部分测试失败 ✗"
    echo "=============================================="
    echo ""
    echo "建议检查日志文件:"
    echo "  credagent 日志: $CREDAGENT_LOG"
    exit 1
fi
