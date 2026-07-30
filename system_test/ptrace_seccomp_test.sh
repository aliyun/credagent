#!/bin/bash

# CredAgent 进程运行时安全检测测试 (Phase 1)
# 测试目标：验证 TracerPid (ptrace 附加) 和 seccomp filter 检测
# 前置条件：已执行 init_test_environ.sh
# 运行要求：需要 sudo 权限

if [ "$(id -u)" -ne 0 ]; then
    echo "错误: 此测试需要 root 权限运行，请使用 sudo 执行"
    exit 1
fi

echo "=============================================="
echo "CredAgent 进程运行时安全检测测试 (TracerPid / seccomp)"
echo "=============================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

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

echo "测试环境验证通过"
echo "  TEST_DIR: $TEST_DIR"
echo "  MOUNT_POINT: $MOUNT_POINT"
echo "  CREDAGENT_PID: $CREDAGENT_PID"
echo ""

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

SECRET_FILE="$SECRETS_DIR/ptrace_test_secret.txt"
SECRET_CONTENT="ptrace_test_secret_value_99887"
PY_SCRIPT="$TEST_DIR/ptrace_read_secret.py"

# 创建测试脚本
cat > "$PY_SCRIPT" << 'PYEOF'
import sys
try:
    with open(sys.argv[1], "r") as f:
        print(f.read().strip())
except PermissionError:
    print("PERMISSION_DENIED", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
chmod +x "$PY_SCRIPT"

# 保护凭据
rm -f "$SECRET_FILE" 2>/dev/null
echo "$SECRET_CONTENT" > "$SECRET_FILE"

"$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" \
    --strategy BASIC -p "$PY_SCRIPT" --measure false -i "$SECRET_FILE" 2>&1 | head -3
echo ""

# ============================================
# 测试1: 正常访问 — 确认基线可读
# ============================================
echo "测试1: 正常访问 — 确认基线可读"
OUTPUT=$(python3 "$PY_SCRIPT" "$SECRET_FILE" 2>&1)
RESULT=$?
if [ $RESULT -eq 0 ] && [ "$OUTPUT" = "$SECRET_CONTENT" ]; then
    echo "  ✓ 正常访问成功"
    ((TESTS_PASSED++))
else
    echo "  ✗ 正常访问失败 (返回值: $RESULT, 输出: $OUTPUT)"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试2: strace 附加后读取应被拒绝 (TracerPid != 0)
# ============================================
echo ""
echo "测试2: strace 附加进程读取凭据应被拒绝 (TracerPid 检测)"

if ! command -v strace >/dev/null 2>&1; then
    echo "  跳过（strace 未安装）"
    ((TESTS_SKIPPED++))
else
    # strace 会 ptrace 目标进程，使其 TracerPid != 0
    OUTPUT=$(strace -o /dev/null -e trace=open,openat python3 "$PY_SCRIPT" "$SECRET_FILE" 2>&1)
    RESULT=$?
    if [ $RESULT -ne 0 ] || [[ "$OUTPUT" == *"PERMISSION_DENIED"* ]] || [[ "$OUTPUT" != *"$SECRET_CONTENT"* ]]; then
        echo "  ✓ strace 附加进程被拒绝 (TracerPid 检测生效)"
        ((TESTS_PASSED++))
    else
        echo "  ✗ strace 附加进程未被拒绝，秘密被泄露！"
        echo "  输出: $OUTPUT"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试3: ltrace 附加后读取应被拒绝
# 注意：ltrace 追踪库函数调用（libc 层），python3 启动时有数万次库函数调用，
# 每次都被 ltrace 拦截，导致此测试耗时较长（可能数十秒）。这不是 FUSE 超时，
# 而是 python3 在 ltrace 下启动极慢。如需加速可改用 C 程序替代 python3。
# ============================================
echo ""
echo "测试3: ltrace 附加进程读取凭据应被拒绝（ltrace 对 python 开销大，请耐心等待）"

if ! command -v ltrace >/dev/null 2>&1; then
    echo "  跳过（ltrace 未安装）"
    ((TESTS_SKIPPED++))
else
    OUTPUT=$(ltrace -o /dev/null python3 "$PY_SCRIPT" "$SECRET_FILE" 2>&1)
    RESULT=$?
    if [ $RESULT -ne 0 ] || [[ "$OUTPUT" == *"PERMISSION_DENIED"* ]] || [[ "$OUTPUT" != *"$SECRET_CONTENT"* ]]; then
        echo "  ✓ ltrace 附加进程被拒绝"
        ((TESTS_PASSED++))
    else
        echo "  ✗ ltrace 附加进程未被拒绝，秘密被泄露！"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试4: 使用 ptrace 自定义程序附加后读取
# ============================================
echo ""
echo "测试4: 自写 ptrace 附加程序检测"

# 用 C 写一个 ptrace attach -> read 的测试程序
PTRACE_PROG="$TEST_DIR/ptrace_reader"
cat > "$TEST_DIR/ptrace_reader.c" << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file_to_read>\n", argv[0]);
        return 1;
    }
    pid_t child = fork();
    if (child == 0) {
        // Child: let parent ptrace us, then try to read the file
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);  // Wait for parent to attach
        FILE *f = fopen(argv[1], "r");
        if (!f) {
            fprintf(stderr, "PERMISSION_DENIED\n");
            return 1;
        }
        char buf[256];
        if (fgets(buf, sizeof(buf), f)) {
            // Remove trailing newline
            buf[strcspn(buf, "\n")] = 0;
            printf("%s\n", buf);
        }
        fclose(f);
        return 0;
    } else {
        // Parent: wait for child to stop, then let it continue
        int status;
        waitpid(child, &status, 0);
        ptrace(PTRACE_CONT, child, NULL, NULL);
        waitpid(child, &status, 0);
        return WEXITSTATUS(status);
    }
}
CEOF

if gcc -o "$PTRACE_PROG" "$TEST_DIR/ptrace_reader.c" 2>/dev/null; then
    OUTPUT=$("$PTRACE_PROG" "$SECRET_FILE" 2>&1)
    RESULT=$?
    if [ $RESULT -ne 0 ] || [[ "$OUTPUT" == *"PERMISSION_DENIED"* ]] || [[ "$OUTPUT" != *"$SECRET_CONTENT"* ]]; then
        echo "  ✓ ptrace TRACEME 子进程被拒绝"
        ((TESTS_PASSED++))
    else
        echo "  ✗ ptrace TRACEME 子进程未被拒绝，秘密被泄露！"
        echo "  输出: $OUTPUT"
        ((TESTS_FAILED++))
    fi
else
    echo "  跳过（gcc 编译失败）"
    ((TESTS_SKIPPED++))
fi

# ============================================
# 测试5: strace 后正常访问不受影响
# ============================================
echo ""
echo "测试5: strace 测试后正常访问仍然正常"
OUTPUT=$(python3 "$PY_SCRIPT" "$SECRET_FILE" 2>&1)
RESULT=$?
if [ $RESULT -eq 0 ] && [ "$OUTPUT" = "$SECRET_CONTENT" ]; then
    echo "  ✓ 正常访问未受影响"
    ((TESTS_PASSED++))
else
    echo "  ✗ 正常访问受到影响 (误报)"
    echo "  输出: $OUTPUT"
    ((TESTS_FAILED++))
fi

# ============================================
# 清理
# ============================================
echo ""
echo "清理: 释放受保护文件"
if [ -L "$SECRET_FILE" ]; then
    SHA_ID=$(readlink "$SECRET_FILE" | xargs basename)
    rm -f "$SECRET_FILE"
    echo "  → 释放凭据 $SHA_ID (请输入管理员密码):"
    "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_ID"
fi

rm -f "$PY_SCRIPT" "$PTRACE_PROG" "$TEST_DIR/ptrace_reader.c" 2>/dev/null

# 汇总
echo ""
echo "=============================================="
echo "测试结果汇总"
echo "=============================================="
echo "  通过: $TESTS_PASSED"
echo "  失败: $TESTS_FAILED"
echo "  跳过: $TESTS_SKIPPED"
echo "  总计: $((TESTS_PASSED + TESTS_FAILED))"
echo ""
if [ $TESTS_FAILED -gt 0 ]; then
    echo "存在失败的测试! ✗"
    exit 1
else
    echo "全部通过 ✓"
fi
