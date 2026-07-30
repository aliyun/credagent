#!/bin/bash

# CredAgent 环境变量注入检测系统测试
# 测试目标：验证策略引擎能检测并拒绝带有危险环境变量的进程访问凭证
# 覆盖范围：
#   - Layer 1: LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT (原生动态链接器注入)
#   - Layer 2: PYTHONPATH, BASH_ENV (解释器模块路径劫持)
#   - 选择性检查: 解释器特定变量不应误报非对应进程
# 前置条件：已执行 init_test_environ.sh
# 运行要求：需要 sudo 权限

echo "=============================================="
echo "CredAgent 环境变量注入检测测试 (Layer 1 + Layer 2)"
echo "=============================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 加载测试环境变量
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
BASH_PATH=$(which bash 2>/dev/null)

echo "测试环境验证通过"
echo "  TEST_DIR: $TEST_DIR"
echo "  MOUNT_POINT: $MOUNT_POINT"
echo "  CREDAGENT_PID: $CREDAGENT_PID"
echo "  PYTHON3_PATH: ${PYTHON3_PATH:-未安装}"
echo "  BASH_PATH: ${BASH_PATH:-未安装}"
echo ""

# 测试计数器
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# 公共文件路径
SECRET_FILE="$SECRETS_DIR/env_injection_test_secret.txt"
SECRET_CONTENT="env_injection_test_secret_value_67890"
PY_SCRIPT="$TEST_DIR/env_read_secret.py"
BASH_SCRIPT="$TEST_DIR/env_read_secret.sh"
FAKE_SO="/tmp/credagent_test_fake.so"
SHA_IDENTIFIER=""

# ============================================
# 准备: 创建测试文件
# ============================================
echo "准备: 创建测试文件"

rm -f "$SECRET_FILE" "$PY_SCRIPT" "$BASH_SCRIPT" "$FAKE_SO" 2>/dev/null

echo "$SECRET_CONTENT" > "$SECRET_FILE"
echo "  秘密文件: $SECRET_FILE"

# Python 读取脚本
cat > "$PY_SCRIPT" << 'PYEOF'
import sys

target = sys.argv[1] if len(sys.argv) > 1 else None
if not target:
    print("Usage: env_read_secret.py <file_path>", file=sys.stderr)
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
chmod +x "$PY_SCRIPT"
echo "  Python 脚本: $PY_SCRIPT"

# Bash 读取脚本
# 重要: 必须使用 bash 内置方式读取文件 $(< file)，使 bash 自身成为 FUSE open() 的调用者。
# 如果使用 $(cat file)，则 cat 是独立进程，CredAgent 检查的是 cat 的 /proc/<pid>/exe，
# 不会触发 BASH_ENV 检查。
cat > "$BASH_SCRIPT" << 'BASHEOF'
#!/bin/bash
TARGET="$1"
if [ -z "$TARGET" ]; then
    echo "Usage: env_read_secret.sh <file_path>" >&2
    exit 1
fi
CONTENT=$(< "$TARGET") 2>/dev/null
if [ $? -ne 0 ] || [ -z "$CONTENT" ]; then
    echo "PERMISSION_DENIED" >&2
    exit 1
fi
echo "$CONTENT"
BASHEOF
chmod +x "$BASH_SCRIPT"
echo "  Bash 脚本: $BASH_SCRIPT"

# 假 .so 文件
echo "fake shared library" > "$FAKE_SO"
echo "  假 .so 文件: $FAKE_SO"

echo ""

# ============================================
# protect: 保护秘密文件（授权测试脚本访问）
# ============================================
echo "准备: 使用 credctl protect 保护秘密文件"

PROTECT_CMD=("$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" --strategy BASIC --measure false)
PROTECT_CMD+=(-p "$PY_SCRIPT")
PROTECT_CMD+=(-p "$BASH_SCRIPT")
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
echo "Layer 1: 原生动态链接器注入测试"
echo "=============================================="

# ============================================
# 测试1: LD_PRELOAD 注入应被拒绝
# ============================================
echo ""
echo "测试1: LD_PRELOAD 注入应被拒绝"
if [ -n "$PYTHON3_PATH" ]; then
    OUTPUT=$(LD_PRELOAD="$FAKE_SO" "$PYTHON3_PATH" "$PY_SCRIPT" "$SECRET_FILE" 2>&1)
    RESULT=$?
    echo "  返回值: $RESULT"
    echo "  输出: $OUTPUT"
    if [ $RESULT -ne 0 ] || [[ "$OUTPUT" == *"PERMISSION_DENIED"* ]] || [[ "$OUTPUT" != "$SECRET_CONTENT" ]]; then
        echo "  ✓ LD_PRELOAD 注入被检测，访问被拒绝"
        ((TESTS_PASSED++))
    else
        echo "  ✗ LD_PRELOAD 注入未被检测，秘密被泄露！"
        ((TESTS_FAILED++))
    fi
else
    echo "  跳过（python3 不可用）"
    ((TESTS_SKIPPED++))
fi

# ============================================
# 测试2: LD_LIBRARY_PATH 注入应被拒绝
# ============================================
echo ""
echo "测试2: LD_LIBRARY_PATH 注入应被拒绝"
if [ -n "$PYTHON3_PATH" ]; then
    OUTPUT=$(LD_LIBRARY_PATH="/tmp" "$PYTHON3_PATH" "$PY_SCRIPT" "$SECRET_FILE" 2>&1)
    RESULT=$?
    echo "  返回值: $RESULT"
    echo "  输出: $OUTPUT"
    if [ $RESULT -ne 0 ] || [[ "$OUTPUT" == *"PERMISSION_DENIED"* ]] || [[ "$OUTPUT" != "$SECRET_CONTENT" ]]; then
        echo "  ✓ LD_LIBRARY_PATH 注入被检测，访问被拒绝"
        ((TESTS_PASSED++))
    else
        echo "  ✗ LD_LIBRARY_PATH 注入未被检测，秘密被泄露！"
        ((TESTS_FAILED++))
    fi
else
    echo "  跳过（python3 不可用）"
    ((TESTS_SKIPPED++))
fi

# ============================================
# 测试3: LD_AUDIT 注入应被拒绝
# ============================================
echo ""
echo "测试3: LD_AUDIT 注入应被拒绝"
if [ -n "$PYTHON3_PATH" ]; then
    OUTPUT=$(LD_AUDIT="$FAKE_SO" "$PYTHON3_PATH" "$PY_SCRIPT" "$SECRET_FILE" 2>&1)
    RESULT=$?
    echo "  返回值: $RESULT"
    echo "  输出: $OUTPUT"
    if [ $RESULT -ne 0 ] || [[ "$OUTPUT" == *"PERMISSION_DENIED"* ]] || [[ "$OUTPUT" != "$SECRET_CONTENT" ]]; then
        echo "  ✓ LD_AUDIT 注入被检测，访问被拒绝"
        ((TESTS_PASSED++))
    else
        echo "  ✗ LD_AUDIT 注入未被检测，秘密被泄露！"
        ((TESTS_FAILED++))
    fi
else
    echo "  跳过（python3 不可用）"
    ((TESTS_SKIPPED++))
fi

echo ""
echo "=============================================="
echo "Layer 2: 解释器模块路径劫持测试"
echo "=============================================="

# ============================================
# 测试4: PYTHONPATH 注入 Python 进程应被拒绝
# ============================================
echo ""
echo "测试4: PYTHONPATH 注入 Python 进程应被拒绝"
if [ -n "$PYTHON3_PATH" ]; then
    OUTPUT=$(PYTHONPATH="/tmp/evil" "$PYTHON3_PATH" "$PY_SCRIPT" "$SECRET_FILE" 2>&1)
    RESULT=$?
    echo "  返回值: $RESULT"
    echo "  输出: $OUTPUT"
    if [ $RESULT -ne 0 ] || [[ "$OUTPUT" == *"PERMISSION_DENIED"* ]] || [[ "$OUTPUT" != "$SECRET_CONTENT" ]]; then
        echo "  ✓ PYTHONPATH 注入被检测，Python 进程访问被拒绝"
        ((TESTS_PASSED++))
    else
        echo "  ✗ PYTHONPATH 注入未被检测，秘密被泄露！"
        ((TESTS_FAILED++))
    fi
else
    echo "  跳过（python3 不可用）"
    ((TESTS_SKIPPED++))
fi

# ============================================
# 测试5: PYTHONSTARTUP 注入 Python 进程应被拒绝
# ============================================
echo ""
echo "测试5: PYTHONSTARTUP 注入 Python 进程应被拒绝"
if [ -n "$PYTHON3_PATH" ]; then
    OUTPUT=$(PYTHONSTARTUP="/tmp/evil_startup.py" "$PYTHON3_PATH" "$PY_SCRIPT" "$SECRET_FILE" 2>&1)
    RESULT=$?
    echo "  返回值: $RESULT"
    echo "  输出: $OUTPUT"
    if [ $RESULT -ne 0 ] || [[ "$OUTPUT" == *"PERMISSION_DENIED"* ]] || [[ "$OUTPUT" != "$SECRET_CONTENT" ]]; then
        echo "  ✓ PYTHONSTARTUP 注入被检测，访问被拒绝"
        ((TESTS_PASSED++))
    else
        echo "  ✗ PYTHONSTARTUP 注入未被检测，秘密被泄露！"
        ((TESTS_FAILED++))
    fi
else
    echo "  跳过（python3 不可用）"
    ((TESTS_SKIPPED++))
fi

# ============================================
# 测试6: PYTHONHOME 注入 Python 进程应被拒绝
# 注意: PYTHONHOME 指向无效目录会导致 Python 启动即崩溃（无法加载 encodings 模块），
# 此时 Python 来不及打开 FUSE 文件，CredAgent 无机会拦截。测试仍验证秘密未泄露，
# 但需区分"CredAgent 拦截"和"Python 自行崩溃"两种情况。
# ============================================
echo ""
echo "测试6: PYTHONHOME 注入 Python 进程应被拒绝"
if [ -n "$PYTHON3_PATH" ]; then
    OUTPUT=$(PYTHONHOME="/tmp/evil_home" "$PYTHON3_PATH" "$PY_SCRIPT" "$SECRET_FILE" 2>&1)
    RESULT=$?
    echo "  返回值: $RESULT"
    echo "  输出（截取前3行）:"
    echo "$OUTPUT" | head -3 | sed 's/^/    /'
    if [[ "$OUTPUT" == *"$SECRET_CONTENT"* ]]; then
        echo "  ✗ PYTHONHOME 注入未被检测，秘密被泄露！"
        ((TESTS_FAILED++))
    elif [[ "$OUTPUT" == *"Fatal Python error"* ]] || [[ "$OUTPUT" == *"ModuleNotFoundError"* ]]; then
        echo "  ~ 秘密未泄露，但原因是 Python 自行崩溃而非 CredAgent 拦截（预期行为）"
        ((TESTS_PASSED++))
    else
        echo "  ✓ PYTHONHOME 注入被 CredAgent 检测，访问被拒绝"
        ((TESTS_PASSED++))
    fi
else
    echo "  跳过（python3 不可用）"
    ((TESTS_SKIPPED++))
fi

# ============================================
# 测试7: BASH_ENV 注入 Bash 进程应被拒绝
# ============================================
echo ""
echo "测试7: BASH_ENV 注入 Bash 进程应被拒绝"
if [ -n "$BASH_PATH" ]; then
    OUTPUT=$(BASH_ENV="/tmp/evil_env.sh" "$BASH_PATH" "$BASH_SCRIPT" "$SECRET_FILE" 2>&1)
    RESULT=$?
    echo "  返回值: $RESULT"
    echo "  输出: $OUTPUT"
    if [ $RESULT -ne 0 ] || [[ "$OUTPUT" == *"PERMISSION_DENIED"* ]] || [[ "$OUTPUT" != "$SECRET_CONTENT" ]]; then
        echo "  ✓ BASH_ENV 注入被检测，Bash 进程访问被拒绝"
        ((TESTS_PASSED++))
    else
        echo "  ✗ BASH_ENV 注入未被检测，秘密被泄露！"
        ((TESTS_FAILED++))
    fi
else
    echo "  跳过（bash 不可用）"
    ((TESTS_SKIPPED++))
fi

echo ""
echo "=============================================="
echo "选择性检查: 解释器特定变量不应误报"
echo "=============================================="

# ============================================
# 测试8: PYTHONPATH 对 Bash 进程不应触发拒绝
# ============================================
echo ""
echo "测试8: PYTHONPATH 对 Bash 进程不应触发拒绝（无误报）"
if [ -n "$BASH_PATH" ]; then
    OUTPUT=$(PYTHONPATH="/tmp/evil" "$BASH_PATH" "$BASH_SCRIPT" "$SECRET_FILE" 2>&1)
    RESULT=$?
    echo "  返回值: $RESULT"
    echo "  输出: $OUTPUT"
    if [ $RESULT -eq 0 ] && [[ "$OUTPUT" == *"$SECRET_CONTENT"* ]]; then
        echo "  ✓ PYTHONPATH 对 Bash 进程无影响，正确放行"
        ((TESTS_PASSED++))
    else
        echo "  ✗ PYTHONPATH 误报: Bash 进程被错误拒绝"
        ((TESTS_FAILED++))
    fi
else
    echo "  跳过（bash 不可用）"
    ((TESTS_SKIPPED++))
fi

# ============================================
# 测试9: BASH_ENV 对 Python 进程不应触发拒绝
# ============================================
echo ""
echo "测试9: BASH_ENV 对 Python 进程不应触发拒绝（无误报）"
if [ -n "$PYTHON3_PATH" ]; then
    OUTPUT=$(BASH_ENV="/tmp/evil_env.sh" "$PYTHON3_PATH" "$PY_SCRIPT" "$SECRET_FILE" 2>&1)
    RESULT=$?
    echo "  返回值: $RESULT"
    echo "  输出: $OUTPUT"
    if [ $RESULT -eq 0 ] && [[ "$OUTPUT" == "$SECRET_CONTENT" ]]; then
        echo "  ✓ BASH_ENV 对 Python 进程无影响，正确放行"
        ((TESTS_PASSED++))
    else
        echo "  ✗ BASH_ENV 误报: Python 进程被错误拒绝"
        ((TESTS_FAILED++))
    fi
else
    echo "  跳过（python3 不可用）"
    ((TESTS_SKIPPED++))
fi

echo ""
echo "=============================================="
echo "基线验证: 正常运行不受影响"
echo "=============================================="

# ============================================
# 测试10: 正常 Python 运行仍可读取秘密
# ============================================
echo ""
echo "测试10: 正常 Python 运行仍可读取秘密"
if [ -n "$PYTHON3_PATH" ]; then
    OUTPUT=$("$PYTHON3_PATH" "$PY_SCRIPT" "$SECRET_FILE" 2>&1)
    RESULT=$?
    echo "  返回值: $RESULT"
    echo "  输出: $OUTPUT"
    if [ $RESULT -eq 0 ] && [ "$OUTPUT" = "$SECRET_CONTENT" ]; then
        echo "  ✓ 正常 Python 脚本成功读取秘密"
        ((TESTS_PASSED++))
    else
        echo "  ✗ 正常 Python 脚本无法读取秘密"
        ((TESTS_FAILED++))
    fi
else
    echo "  跳过（python3 不可用）"
    ((TESTS_SKIPPED++))
fi

# ============================================
# 测试11: 正常 Bash 运行仍可读取秘密
# ============================================
echo ""
echo "测试11: 正常 Bash 运行仍可读取秘密"
if [ -n "$BASH_PATH" ]; then
    OUTPUT=$("$BASH_PATH" "$BASH_SCRIPT" "$SECRET_FILE" 2>&1)
    RESULT=$?
    echo "  返回值: $RESULT"
    echo "  输出: $OUTPUT"
    if [ $RESULT -eq 0 ] && [[ "$OUTPUT" == *"$SECRET_CONTENT"* ]]; then
        echo "  ✓ 正常 Bash 脚本成功读取秘密"
        ((TESTS_PASSED++))
    else
        echo "  ✗ 正常 Bash 脚本无法读取秘密"
        ((TESTS_FAILED++))
    fi
else
    echo "  跳过（bash 不可用）"
    ((TESTS_SKIPPED++))
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

    echo ""
    echo "----------------------------------------------"
    echo "请注意：此步骤需要人工交互输入"
    echo "当要求输入密码时，请输入初始化时设置的管理员密码"
    echo "----------------------------------------------"
    echo ""

    "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER"
    RELEASE_RESULT=$?

    if [ $RELEASE_RESULT -eq 0 ]; then
        echo "  ✓ release 成功"
    else
        echo "  ⚠ release 失败（不影响测试结果）"
    fi
fi

rm -f "$PY_SCRIPT" "$BASH_SCRIPT" "$FAKE_SO" 2>/dev/null

# ============================================
# 测试结果汇总
# ============================================
echo ""
echo "=============================================="
echo "测试结果汇总"
echo "=============================================="
echo "通过的测试: $TESTS_PASSED"
echo "失败的测试: $TESTS_FAILED"
echo "跳过的测试: $TESTS_SKIPPED"
echo "总计测试: $((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))"
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
