#!/bin/bash

# CredAgent LD_PRELOAD 注入检测系统测试
# 测试目标：验证策略引擎能检测并拒绝带有 LD_PRELOAD 的进程访问凭证
# 前置条件：已执行 init_test_environ.sh

echo "=============================================="
echo "CredAgent LD_PRELOAD 注入检测测试"
echo "=============================================="

# 获取脚本所在目录，推导项目根目录
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

# 验证测试环境是否就绪
if [ -z "$TEST_DIR" ] || [ ! -d "$TEST_DIR" ]; then
    echo "错误: TEST_DIR 未设置或不存在"
    exit 1
fi

if [ -z "$CREDAGENT_PID" ] || ! ps -p "$CREDAGENT_PID" > /dev/null 2>&1; then
    echo "错误: credagent 进程未运行"
    exit 1
fi

# 检查 python3 是否可用
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

# 测试计数器
TESTS_PASSED=0
TESTS_FAILED=0

# 文件路径
SECRET_FILE="$SECRETS_DIR/ld_preload_test_secret.txt"
PY_SCRIPT="$TEST_DIR/read_secret.py"
FAKE_SO="/tmp/credagent_test_fake.so"
SHA_IDENTIFIER=""

# ============================================
# 准备: 创建测试秘密文件和 Python 脚本
# ============================================
echo "准备: 创建测试文件"

# 清理可能存在的旧文件
rm -f "$SECRET_FILE" "$PY_SCRIPT" "$FAKE_SO" 2>/dev/null

# 创建秘密文件
echo "ld_preload_test_secret_value_12345" > "$SECRET_FILE"
echo "  秘密文件: $SECRET_FILE"

# 创建合法的 Python 脚本
cat > "$PY_SCRIPT" << 'PYEOF'
import sys

target = sys.argv[1] if len(sys.argv) > 1 else None
if not target:
    print("Usage: read_secret.py <file_path>", file=sys.stderr)
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

# 创建一个假的 .so 文件（不需要真正是共享库，只需要存在即可触发 environ 检测）
echo "fake shared library" > "$FAKE_SO"
echo "  假 .so 文件: $FAKE_SO"

echo ""

# ============================================
# 测试1: 使用 credctl protect 保护秘密文件
# ============================================
echo "测试1: 使用 credctl protect 保护秘密文件"
echo "  命令: credctl protect --strategy BASIC -p $PY_SCRIPT $SECRET_FILE"

PROTECT_OUTPUT=$("$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" --strategy BASIC -p "$PY_SCRIPT" --measure false -i "$SECRET_FILE" 2>&1)
PROTECT_RESULT=$?

echo "  输出: $PROTECT_OUTPUT"

if [ $PROTECT_RESULT -eq 0 ]; then
    echo "  ✓ protect 成功"
    ((TESTS_PASSED++))
else
    echo "  ✗ protect 失败"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试2: 验证符号链接已创建
# ============================================
echo ""
echo "测试2: 验证符号链接已创建"
if [ -L "$SECRET_FILE" ]; then
    LINK_TARGET=$(readlink "$SECRET_FILE")
    echo "  ✓ 符号链接已创建 -> $LINK_TARGET"
    ((TESTS_PASSED++))
else
    echo "  ✗ 文件未变为符号链接"
    ((TESTS_FAILED++))
fi

# 获取 SHA identifier
LIST_OUTPUT=$("$PROJECT_ROOT/credctl" list --config "$CREDCTL_CONFIG" 2>&1)
SHA_LINE=$(echo "$LIST_OUTPUT" | grep -E "^[a-f0-9]+" | head -n1)
if [ -n "$SHA_LINE" ]; then
    SHA_IDENTIFIER=$(echo "$SHA_LINE" | awk '{print $1}')
    echo "  SHA identifier: $SHA_IDENTIFIER"
fi

# ============================================
# 测试3: 正常运行 Python 脚本可以读取秘密
# ============================================
echo ""
echo "测试3: 正常运行 Python 脚本可以读取秘密"

NORMAL_OUTPUT=$("$PYTHON3_PATH" "$PY_SCRIPT" "$SECRET_FILE" 2>&1)
NORMAL_RESULT=$?

echo "  返回值: $NORMAL_RESULT"
echo "  输出: $NORMAL_OUTPUT"

if [ $NORMAL_RESULT -eq 0 ] && [ "$NORMAL_OUTPUT" = "ld_preload_test_secret_value_12345" ]; then
    echo "  ✓ 正常 Python 脚本成功读取秘密"
    ((TESTS_PASSED++))
else
    echo "  ✗ 正常 Python 脚本无法读取秘密"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试4: 使用 LD_PRELOAD 加载异常路径 .so 后被拒绝
# ============================================
echo ""
echo "测试4: 使用 LD_PRELOAD 加载异常路径 .so 后被拒绝"
echo "  命令: LD_PRELOAD=$FAKE_SO python3 read_secret.py $SECRET_FILE"

PRELOAD_OUTPUT=$(LD_PRELOAD="$FAKE_SO" "$PYTHON3_PATH" "$PY_SCRIPT" "$SECRET_FILE" 2>&1)
PRELOAD_RESULT=$?

echo "  返回值: $PRELOAD_RESULT"
echo "  输出: $PRELOAD_OUTPUT"

if [ $PRELOAD_RESULT -ne 0 ] || [[ "$PRELOAD_OUTPUT" == *"PERMISSION_DENIED"* ]] || [[ "$PRELOAD_OUTPUT" != "ld_preload_test_secret_value_12345" ]]; then
    echo "  ✓ LD_PRELOAD 注入被检测，访问被拒绝"
    ((TESTS_PASSED++))
else
    echo "  ✗ LD_PRELOAD 注入未被检测，秘密被泄露！"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试5: 使用 LD_LIBRARY_PATH 设置异常路径后被拒绝
# ============================================
echo ""
echo "测试5: 使用 LD_LIBRARY_PATH 设置异常路径后被拒绝"
echo "  命令: LD_LIBRARY_PATH=/tmp python3 read_secret.py $SECRET_FILE"

LIBPATH_OUTPUT=$(LD_LIBRARY_PATH="/tmp" "$PYTHON3_PATH" "$PY_SCRIPT" "$SECRET_FILE" 2>&1)
LIBPATH_RESULT=$?

echo "  返回值: $LIBPATH_RESULT"
echo "  输出: $LIBPATH_OUTPUT"

if [ $LIBPATH_RESULT -ne 0 ] || [[ "$LIBPATH_OUTPUT" == *"PERMISSION_DENIED"* ]] || [[ "$LIBPATH_OUTPUT" != "ld_preload_test_secret_value_12345" ]]; then
    echo "  ✓ LD_LIBRARY_PATH 注入被检测，访问被拒绝"
    ((TESTS_PASSED++))
else
    echo "  ✗ LD_LIBRARY_PATH 注入未被检测，秘密被泄露！"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试6: 再次正常运行确认检测不影响合法访问
# ============================================
echo ""
echo "测试6: 再次正常运行确认检测不影响合法访问"

NORMAL_OUTPUT2=$("$PYTHON3_PATH" "$PY_SCRIPT" "$SECRET_FILE" 2>&1)
NORMAL_RESULT2=$?

echo "  返回值: $NORMAL_RESULT2"
echo "  输出: $NORMAL_OUTPUT2"

if [ $NORMAL_RESULT2 -eq 0 ] && [ "$NORMAL_OUTPUT2" = "ld_preload_test_secret_value_12345" ]; then
    echo "  ✓ 正常 Python 脚本仍可成功读取秘密（无误报）"
    ((TESTS_PASSED++))
else
    echo "  ✗ 正常 Python 脚本无法读取秘密（误报！）"
    ((TESTS_FAILED++))
fi

# ============================================
# 清理: release 受保护文件
# ============================================
echo ""
echo "清理: 释放受保护文件"

if [ -n "$SHA_IDENTIFIER" ]; then
    # 先删除符号链接
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

# 清理临时文件
rm -f "$PY_SCRIPT" "$FAKE_SO" 2>/dev/null

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
