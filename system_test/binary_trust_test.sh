#!/bin/bash

# CredAgent 二进制/脚本路径信任检测测试 (Phase 2C + 2H)
# 测试目标：验证 unsafe location、non-root owned、group/other writable 的检测
# 前置条件：已执行 init_test_environ.sh
# 运行要求：需要 sudo 权限

if [ "$(id -u)" -ne 0 ]; then
    echo "错误: 此测试需要 root 权限运行，请使用 sudo 执行"
    exit 1
fi

echo "=============================================="
echo "CredAgent 二进制/脚本路径信任检测测试"
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

# 确定非 root 测试用户
if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
    TEST_USER="$SUDO_USER"
else
    TEST_USER=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1; exit}' /etc/passwd)
fi
TEST_UID=$(id -u "$TEST_USER" 2>/dev/null)

echo "测试环境验证通过"
echo "  TEST_DIR: $TEST_DIR"
echo "  TEST_USER: ${TEST_USER:-无} (uid=${TEST_UID:-?})"
echo ""

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

SECRET_FILE="$SECRETS_DIR/trust_test_secret.txt"
SECRET_CONTENT="trust_test_secret_value_44556"

# 辅助函数
expect_denied() {
    local desc="$1"; local output="$2"; local result="$3"
    if [ "$result" -ne 0 ] || [[ "$output" == *"PERMISSION_DENIED"* ]] || [[ "$output" != *"$SECRET_CONTENT"* ]]; then
        echo "  ✓ $desc"
        ((TESTS_PASSED++))
    else
        echo "  ✗ $desc — 未被拒绝！输出: $output"
        ((TESTS_FAILED++))
    fi
}

expect_allowed() {
    local desc="$1"; local output="$2"; local result="$3"
    if [ "$result" -eq 0 ] && [[ "$output" == *"$SECRET_CONTENT"* ]]; then
        echo "  ✓ $desc"
        ((TESTS_PASSED++))
    else
        echo "  ✗ $desc — 被错误拒绝。输出: $output"
        ((TESTS_FAILED++))
    fi
}

# ============================================
echo "=============================================="
echo "测试组1: 二进制在不安全路径 (binary in unsafe location)"
echo "=============================================="

# 将 cat 复制到 /tmp 下
UNSAFE_CAT="$TEST_DIR/unsafe_cat"
cp /bin/cat "$UNSAFE_CAT"
chmod 755 "$UNSAFE_CAT"

# 保护凭据，授权 /bin/cat（安全路径）
rm -f "$SECRET_FILE" 2>/dev/null
echo "$SECRET_CONTENT" > "$SECRET_FILE"
"$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" \
    --strategy BASIC -p /bin/cat --measure true "$SECRET_FILE" >/dev/null 2>&1

echo ""
echo "测试1a: /bin/cat (系统路径) — 应允许"
OUTPUT=$(/bin/cat "$SECRET_FILE" 2>&1)
expect_allowed "/bin/cat 正常访问" "$OUTPUT" "$?"

echo ""
echo "测试1b: /tmp/.../unsafe_cat (不安全路径，即使是 cat 的副本) — 应被拒绝"
OUTPUT=$("$UNSAFE_CAT" "$SECRET_FILE" 2>&1)
expect_denied "unsafe 路径二进制被拒绝" "$OUTPUT" "$?"

# 释放
if [ -L "$SECRET_FILE" ]; then
    SHA_ID=$(readlink "$SECRET_FILE" | xargs basename)
    rm -f "$SECRET_FILE"
    echo "  → 释放凭据 $SHA_ID (请输入管理员密码):"
    "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_ID"
fi

# ============================================
echo ""
echo "=============================================="
echo "测试组2: 脚本在不安全路径 (script in unsafe location)"
echo "=============================================="

# 创建一个在 /tmp 下的 Python 脚本（未被 trusted）
UNSAFE_SCRIPT="$TEST_DIR/unsafe_script.py"
cat > "$UNSAFE_SCRIPT" << 'PYEOF'
import sys
try:
    with open(sys.argv[1], "r") as f:
        print(f.read().strip())
except PermissionError:
    print("PERMISSION_DENIED", file=sys.stderr)
    sys.exit(1)
PYEOF
chmod +x "$UNSAFE_SCRIPT"

# 创建一个被信任的脚本
SAFE_SCRIPT="$TEST_DIR/safe_script.py"
cp "$UNSAFE_SCRIPT" "$SAFE_SCRIPT"

# 保护凭据，只授权 safe_script
rm -f "$SECRET_FILE" 2>/dev/null
echo "$SECRET_CONTENT" > "$SECRET_FILE"
"$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" \
    --strategy BASIC -p "$SAFE_SCRIPT" --measure false -i "$SECRET_FILE" >/dev/null 2>&1

echo ""
echo "测试2a: 授权脚本 (在 TrustedPrograms 中) — 应允许"
OUTPUT=$(python3 "$SAFE_SCRIPT" "$SECRET_FILE" 2>&1)
expect_allowed "授权脚本正常访问" "$OUTPUT" "$?"

echo ""
echo "测试2b: 未授权脚本 (同目录但未在 -p 中) — 应被拒绝"
OUTPUT=$(python3 "$UNSAFE_SCRIPT" "$SECRET_FILE" 2>&1)
expect_denied "未授权脚本被拒绝 (script in unsafe location)" "$OUTPUT" "$?"

# 释放
if [ -L "$SECRET_FILE" ]; then
    SHA_ID=$(readlink "$SECRET_FILE" | xargs basename)
    rm -f "$SECRET_FILE"
    echo "  → 释放凭据 $SHA_ID (请输入管理员密码):"
    "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_ID"
fi

# ============================================
echo ""
echo "=============================================="
echo "测试组3: 非 root 所有 / group-writable 二进制"
echo "=============================================="

if [ -z "$TEST_USER" ]; then
    echo "  跳过（无法确定非 root 测试用户）"
    ((TESTS_SKIPPED++))
else
    # 创建一个 user-owned 的 cat 副本在非 unsafe 路径
    USERBIN_DIR="/opt/credagent_test_userbin"
    mkdir -p "$USERBIN_DIR"

    USER_CAT="$USERBIN_DIR/user_cat"
    cp /bin/cat "$USER_CAT"
    chown "$TEST_USER" "$USER_CAT"
    chmod 755 "$USER_CAT"

    GW_CAT="$USERBIN_DIR/gw_cat"
    cp /bin/cat "$GW_CAT"
    chown root "$GW_CAT"
    chmod 775 "$GW_CAT"  # group writable

    # 保护凭据，授权 /bin/cat（不授权 user_cat/gw_cat）
    # user_cat/gw_cat 不在系统 PATH，不在 TrustedPrograms，不在 unsafe prefix，
    # 会进入 Step 5 checkPathNodeChain: user_cat 非 root-owned 被拒; gw_cat mode=775 被拒。
    rm -f "$SECRET_FILE" 2>/dev/null
    echo "$SECRET_CONTENT" > "$SECRET_FILE"
    "$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" \
        --strategy BASIC -p /bin/cat --measure true "$SECRET_FILE" >/dev/null 2>&1

    echo ""
    echo "测试3a: 非 root 所有的二进制 ($USER_CAT, owner=$TEST_USER) — 应被拒绝"
    OUTPUT=$("$USER_CAT" "$SECRET_FILE" 2>&1)
    expect_denied "non-root owned 二进制被拒绝" "$OUTPUT" "$?"

    echo ""
    echo "测试3b: group-writable 二进制 ($GW_CAT, mode=775) — 应被拒绝"
    OUTPUT=$("$GW_CAT" "$SECRET_FILE" 2>&1)
    expect_denied "group-writable 二进制被拒绝" "$OUTPUT" "$?"

    # 测试3c: 将 user_cat 加入 TrustedPrograms 后应允许
    # 释放当前凭据并重新保护（加入 user_cat 到 -p）
    chown root "$USER_CAT"
    chmod 755 "$USER_CAT"
    if [ -L "$SECRET_FILE" ]; then
        SHA_ID=$(readlink "$SECRET_FILE" | xargs basename)
        rm -f "$SECRET_FILE"
        echo "  → 释放凭据 $SHA_ID (请输入管理员密码):"
        "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_ID"
    fi
    echo "$SECRET_CONTENT" > "$SECRET_FILE"
    "$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" \
        --strategy BASIC -p "$USER_CAT" --measure false "$SECRET_FILE" >/dev/null 2>&1

    echo ""
    echo "测试3c: 加入 TrustedPrograms 后 — 应允许"
    OUTPUT=$("$USER_CAT" "$SECRET_FILE" 2>&1)
    expect_allowed "加入信任列表后正常访问" "$OUTPUT" "$?"

    # 释放
    if [ -L "$SECRET_FILE" ]; then
        SHA_ID=$(readlink "$SECRET_FILE" | xargs basename)
        rm -f "$SECRET_FILE"
        echo "  → 释放凭据 $SHA_ID (请输入管理员密码):"
    "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_ID"
    fi

    # 测试3d: 二进制 root-owned 但父目录 user-owned — 应被拒绝
    # 父目录可写意味着攻击者可以删除并替换二进制
    USERDIR="$USERBIN_DIR/user_dir"
    mkdir -p "$USERDIR"
    chown "$TEST_USER" "$USERDIR"
    chmod 755 "$USERDIR"

    SNEAKY_CAT="$USERDIR/sneaky_cat"
    cp /bin/cat "$SNEAKY_CAT"
    chown root "$SNEAKY_CAT"
    chmod 755 "$SNEAKY_CAT"

    if [ -L "$SECRET_FILE" ]; then
        SHA_ID=$(readlink "$SECRET_FILE" | xargs basename)
        rm -f "$SECRET_FILE"
        echo "  → 释放凭据 $SHA_ID (请输入管理员密码):"
        "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_ID"
    fi
    echo "$SECRET_CONTENT" > "$SECRET_FILE"
    "$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" \
        --strategy BASIC -p /bin/cat --measure true "$SECRET_FILE" >/dev/null 2>&1

    echo ""
    echo "测试3d: 二进制 root-owned 但父目录 user-owned ($SNEAKY_CAT) — 应被拒绝"
    OUTPUT=$("$SNEAKY_CAT" "$SECRET_FILE" 2>&1)
    expect_denied "父目录非root-owned的二进制被拒绝" "$OUTPUT" "$?"

    # 释放
    if [ -L "$SECRET_FILE" ]; then
        SHA_ID=$(readlink "$SECRET_FILE" | xargs basename)
        rm -f "$SECRET_FILE"
        echo "  → 释放凭据 $SHA_ID (请输入管理员密码):"
        "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_ID"
    fi

    # 清理
    rm -rf "$USERBIN_DIR"
fi

# ============================================
echo ""
echo "=============================================="
echo "测试组4: python -c / bash -c (inline exec) 作为祖先进程"
echo "=============================================="

# 保护凭据，授权 /bin/cat
rm -f "$SECRET_FILE" 2>/dev/null
echo "$SECRET_CONTENT" > "$SECRET_FILE"
"$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" \
    --strategy BASIC -p /bin/cat --measure true "$SECRET_FILE" >/dev/null 2>&1

echo ""
echo "测试4a: python3 -c '...cat...' 作为祖先 — 应被拒绝 (inline exec)"
OUTPUT=$(python3 -c "import subprocess,sys; r=subprocess.run(['cat','$SECRET_FILE'],capture_output=True,text=True); print(r.stdout); sys.exit(r.returncode)" 2>&1)
expect_denied "python -c 祖先被拒绝" "$OUTPUT" "$?"

echo ""
echo "测试4b: bash -c 'cat ...' — bash -c 作为祖先应允许"
# bash -c 只是命令分发器，子进程 cat 会被独立检查。
# 与 python -c 不同：python -c 进程自身执行代码并访问凭据，
# 而 bash -c 的子进程才是真正的访问者，子进程有完整的安全检查。
OUTPUT=$(bash -c "cat '$SECRET_FILE'; true" 2>&1)
expect_allowed "bash -c 祖先允许 (子进程独立验证)" "$OUTPUT" "$?"

# 释放
if [ -L "$SECRET_FILE" ]; then
    SHA_ID=$(readlink "$SECRET_FILE" | xargs basename)
    rm -f "$SECRET_FILE"
    echo "  → 释放凭据 $SHA_ID (请输入管理员密码):"
    "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_ID"
fi

# ============================================
echo ""
echo "=============================================="
echo "测试组5: root-owned 脚本作为祖先 (无需显式 trusted_scripts)"
echo "=============================================="

# 创建一个 root-owned 的 wrapper script 在安全路径
SAFE_WRAPPER_DIR="/opt/credagent_test_scripts"
mkdir -p "$SAFE_WRAPPER_DIR"
SAFE_WRAPPER="$SAFE_WRAPPER_DIR/wrapper.sh"
cat > "$SAFE_WRAPPER" << 'SHEOF'
#!/bin/bash
# Wrapper that invokes cat on the argument
cat "$1"
SHEOF
chown root "$SAFE_WRAPPER"
chmod 755 "$SAFE_WRAPPER"
chown root "$SAFE_WRAPPER_DIR"
chmod 755 "$SAFE_WRAPPER_DIR"

rm -f "$SECRET_FILE" 2>/dev/null
echo "$SECRET_CONTENT" > "$SECRET_FILE"
"$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" \
    --strategy BASIC -p /bin/cat --measure true "$SECRET_FILE" >/dev/null 2>&1

echo ""
echo "测试5a: root-owned 脚本 (/opt/.../wrapper.sh) 作为祖先 — 应允许"
echo "  (脚本不在 trusted_scripts 中，但 root-owned + 路径链安全)"
OUTPUT=$(bash "$SAFE_WRAPPER" "$SECRET_FILE" 2>&1)
expect_allowed "root-owned 安全路径脚本作祖先自动信任" "$OUTPUT" "$?"

# 创建一个 user-owned 的 wrapper — 应被拒绝
if [ -n "$TEST_USER" ]; then
    USER_WRAPPER="$SAFE_WRAPPER_DIR/user_wrapper.sh"
    cp "$SAFE_WRAPPER" "$USER_WRAPPER"
    chown "$TEST_USER" "$USER_WRAPPER"
    chmod 755 "$USER_WRAPPER"

    echo ""
    echo "测试5b: user-owned 脚本作为祖先 — 应被拒绝"
    OUTPUT=$(bash "$USER_WRAPPER" "$SECRET_FILE" 2>&1)
    expect_denied "user-owned 脚本祖先被拒绝" "$OUTPUT" "$?"

    rm -f "$USER_WRAPPER"
fi

# 释放
if [ -L "$SECRET_FILE" ]; then
    SHA_ID=$(readlink "$SECRET_FILE" | xargs basename)
    rm -f "$SECRET_FILE"
    echo "  → 释放凭据 $SHA_ID (请输入管理员密码):"
    "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_ID"
fi

rm -rf "$SAFE_WRAPPER_DIR"

# 清理
rm -f "$UNSAFE_CAT" "$UNSAFE_SCRIPT" "$SAFE_SCRIPT" 2>/dev/null

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
