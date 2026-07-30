#!/bin/bash

# CredAgent 依赖风险检查系统测试
# 测试目标：验证 credctl protect 对脚本依赖路径的安全检查
# 前置条件：已执行 init_test_environ.sh
# 注意：本测试需要 root 权限运行（sudo），且依赖 SUDO_USER 变量来模拟普通用户文件

echo "=============================================="
echo "CredAgent 依赖风险检查测试"
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

# 确定非 root 测试用户 (用于模拟普通用户文件)
if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
    TEST_USER="$SUDO_USER"
else
    # 尝试找一个 uid >= 1000 的普通用户
    TEST_USER=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1; exit}' /etc/passwd)
fi

if [ -z "$TEST_USER" ]; then
    echo "错误: 无法确定非 root 测试用户"
    echo "  请使用 'sudo bash $0' 运行（SUDO_USER 会自动设置）"
    exit 1
fi

TEST_UID=$(id -u "$TEST_USER")
TEST_GID=$(id -g "$TEST_USER")

echo "测试环境验证通过"
echo "  TEST_DIR: $TEST_DIR"
echo "  MOUNT_POINT: $MOUNT_POINT"
echo "  CREDAGENT_PID: $CREDAGENT_PID"
echo "  TEST_USER: $TEST_USER (uid=$TEST_UID)"
echo ""

# 测试计数器
TESTS_PASSED=0
TESTS_FAILED=0

# 测试目录
DEP_TEST_DIR="$TEST_DIR/dep_risk_test"
mkdir -p "$DEP_TEST_DIR"

# 辅助函数: 创建用户所属文件
create_user_file() {
    local path="$1"
    local content="$2"
    echo "$content" > "$path"
    chown "$TEST_USER:$TEST_GID" "$path"
}

# 辅助函数: 创建用户所属目录
create_user_dir() {
    local path="$1"
    mkdir -p "$path"
    chown "$TEST_USER:$TEST_GID" "$path"
}

# 辅助函数: 重建凭据文件 (root 所有)
reset_secret_file() {
    rm -f "$SECRET_FILE" 2>/dev/null
    echo "SECRET_KEY=test-dep-risk-12345" > "$SECRET_FILE"
}

# ============================================
# 准备测试环境
# ============================================
echo "准备: 创建测试脚本和依赖结构"
echo ""

# 创建 Python 项目结构 (模拟普通用户可写)
PYAPP_DIR="$DEP_TEST_DIR/pyapp"
create_user_dir "$PYAPP_DIR"
create_user_dir "$PYAPP_DIR/packages"

create_user_file "$PYAPP_DIR/main.py" 'import sys
from packages import helper

def main():
    if len(sys.argv) < 2:
        print("usage: main.py <credential_path>")
        sys.exit(1)
    with open(sys.argv[1]) as f:
        data = f.read()
    result = helper.process(data)
    print(f"Processed: {result}")

if __name__ == "__main__":
    main()'

create_user_file "$PYAPP_DIR/packages/__init__.py" ""
create_user_file "$PYAPP_DIR/packages/helper.py" 'def process(data):
    return f"length={len(data)}"'

# 创建 __pycache__ 目录 (模拟 pyc 注入场景)
create_user_dir "$PYAPP_DIR/packages/__pycache__"
create_user_file "$PYAPP_DIR/packages/__pycache__/helper.cpython-311.pyc" "fake pyc content"

# 创建 Shell 项目结构 (模拟普通用户可写)
SHAPP_DIR="$DEP_TEST_DIR/shapp"
create_user_dir "$SHAPP_DIR"

create_user_file "$SHAPP_DIR/main.sh" '#!/bin/bash
source ./config.sh
cat "$1"'
chmod +x "$SHAPP_DIR/main.sh"

create_user_file "$SHAPP_DIR/config.sh" '# Configuration
export APP_NAME="test"'

# 凭据文件 (root 所有)
SECRET_FILE="$DEP_TEST_DIR/secret_cred.txt"
reset_secret_file

echo "  Python 项目: $PYAPP_DIR/main.py (owner: $TEST_USER)"
echo "  Shell 项目: $SHAPP_DIR/main.sh (owner: $TEST_USER)"
echo "  凭据文件: $SECRET_FILE (owner: root)"
echo ""

# ============================================
# 测试1: Python 脚本 — 可写依赖被拒绝
# ============================================
echo "测试1: Python 脚本 — 可写依赖应被拒绝"

PROTECT_OUTPUT=$("$PROJECT_ROOT/credctl" protect \
    --config "$CREDCTL_CONFIG" \
    --strategy BASIC \
    --program-permit "$PYAPP_DIR/main.py" \
    --measure true \
    "$SECRET_FILE" 2>&1)
PROTECT_RESULT=$?

if [ $PROTECT_RESULT -ne 0 ]; then
    if echo "$PROTECT_OUTPUT" | grep -q "\[RISK\]"; then
        echo "  ✓ 正确拒绝: 检测到依赖风险"
        ((TESTS_PASSED++))
    else
        echo "  ✗ 命令失败但未输出风险报告"
        echo "  输出: $PROTECT_OUTPUT"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 命令应该失败但成功了"
    echo "  输出: $PROTECT_OUTPUT"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试2: 验证风险报告包含 __pycache__ 信息
# ============================================
echo ""
echo "测试2: 验证风险报告包含 __pycache__ 信息"

if echo "$PROTECT_OUTPUT" | grep -qi "pycache\|__pycache__"; then
    echo "  ✓ 风险报告中包含 __pycache__ 警告"
    ((TESTS_PASSED++))
else
    echo "  ✗ 风险报告中未提及 __pycache__"
    echo "  输出: $PROTECT_OUTPUT"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试3: 验证风险报告包含 chattr 修复建议
# ============================================
echo ""
echo "测试3: 验证风险报告包含 chattr 修复建议"

if echo "$PROTECT_OUTPUT" | grep -q "chattr"; then
    echo "  ✓ 风险报告中包含 chattr 修复建议"
    ((TESTS_PASSED++))
else
    echo "  ✗ 风险报告中未包含 chattr 修复建议"
    echo "  输出: $PROTECT_OUTPUT"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试4: 验证风险报告包含依赖文件路径
# ============================================
echo ""
echo "测试4: 验证风险报告包含依赖文件路径"

if echo "$PROTECT_OUTPUT" | grep -q "helper.py"; then
    echo "  ✓ 风险报告中包含 helper.py 依赖路径"
    ((TESTS_PASSED++))
else
    echo "  ✗ 风险报告中未包含 helper.py 路径"
    echo "  输出: $PROTECT_OUTPUT"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试5: --ignore-risk 跳过检查
# ============================================
echo ""
echo "测试5: --ignore-risk (-i) 应跳过检查并成功保护"

reset_secret_file

PROTECT_OUTPUT=$("$PROJECT_ROOT/credctl" protect \
    --config "$CREDCTL_CONFIG" \
    --strategy BASIC \
    --program-permit "$PYAPP_DIR/main.py" \
    --measure true \
    --ignore-risk \
    "$SECRET_FILE" 2>&1)
PROTECT_RESULT=$?

if [ $PROTECT_RESULT -eq 0 ]; then
    echo "  ✓ --ignore-risk 成功跳过检查并保护凭据"
    ((TESTS_PASSED++))
    # 释放凭据 (需要交互输入密码)
    if [ -L "$SECRET_FILE" ]; then
        SHA_ID=$(readlink "$SECRET_FILE" | xargs basename)
        rm -f "$SECRET_FILE"
        echo "  → 释放凭据 $SHA_ID (请输入管理员密码):"
        "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_ID"
    fi
else
    echo "  ✗ --ignore-risk 仍然失败"
    echo "  输出: $PROTECT_OUTPUT"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试6: -i 短标志同样有效
# ============================================
echo ""
echo "测试6: -i 短标志同样有效"

reset_secret_file

PROTECT_OUTPUT=$("$PROJECT_ROOT/credctl" protect \
    --config "$CREDCTL_CONFIG" \
    --strategy BASIC \
    --program-permit "$PYAPP_DIR/main.py" \
    --measure true \
    -i \
    "$SECRET_FILE" 2>&1)
PROTECT_RESULT=$?

if [ $PROTECT_RESULT -eq 0 ]; then
    echo "  ✓ -i 短标志成功跳过检查"
    ((TESTS_PASSED++))
    # 释放凭据 (需要交互输入密码)
    if [ -L "$SECRET_FILE" ]; then
        SHA_ID=$(readlink "$SECRET_FILE" | xargs basename)
        rm -f "$SECRET_FILE"
        echo "  → 释放凭据 $SHA_ID (请输入管理员密码):"
        "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_ID"
    fi
else
    echo "  ✗ -i 短标志失败"
    echo "  输出: $PROTECT_OUTPUT"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试7: Shell 脚本 — 可写 source 依赖被拒绝
# ============================================
echo ""
echo "测试7: Shell 脚本 — 可写 source 依赖应被拒绝"

reset_secret_file

PROTECT_OUTPUT=$("$PROJECT_ROOT/credctl" protect \
    --config "$CREDCTL_CONFIG" \
    --strategy BASIC \
    --program-permit "$SHAPP_DIR/main.sh" \
    --measure true \
    "$SECRET_FILE" 2>&1)
PROTECT_RESULT=$?

if [ $PROTECT_RESULT -ne 0 ]; then
    if echo "$PROTECT_OUTPUT" | grep -q "\[RISK\]"; then
        echo "  ✓ Shell 脚本正确拒绝: 检测到可写依赖"
        ((TESTS_PASSED++))
    else
        echo "  ✗ Shell 脚本失败但未输出风险报告"
        echo "  输出: $PROTECT_OUTPUT"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ Shell 脚本应该失败但成功了"
    echo "  输出: $PROTECT_OUTPUT"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试8: Native 二进制 — 不做依赖检查
# ============================================
echo ""
echo "测试8: Native 二进制 (如 /bin/cat) 不做依赖检查，直接通过"

reset_secret_file

PROTECT_OUTPUT=$("$PROJECT_ROOT/credctl" protect \
    --config "$CREDCTL_CONFIG" \
    --strategy BASIC \
    --program-permit /bin/cat \
    --measure true \
    "$SECRET_FILE" 2>&1)
PROTECT_RESULT=$?

if [ $PROTECT_RESULT -eq 0 ]; then
    echo "  ✓ Native 二进制无依赖检查，直接保护成功"
    ((TESTS_PASSED++))
    # 释放凭据 (需要交互输入密码)
    if [ -L "$SECRET_FILE" ]; then
        SHA_ID=$(readlink "$SECRET_FILE" | xargs basename)
        rm -f "$SECRET_FILE"
        echo "  → 释放凭据 $SHA_ID (请输入管理员密码):"
        "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_ID"
    fi
else
    echo "  ✗ Native 二进制保护失败"
    echo "  输出: $PROTECT_OUTPUT"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试9: chattr +i 后应通过检查
# ============================================
echo ""
echo "测试9: chattr +i 设置不可变后应通过依赖检查"

reset_secret_file

# 检测文件系统是否支持 chattr +i (tmpfs 不支持)
if chattr +i "$PYAPP_DIR/main.py" 2>/dev/null; then
    chattr -i "$PYAPP_DIR/main.py" 2>/dev/null

    # 对脚本和依赖设置 immutable
    chattr +i "$PYAPP_DIR/main.py"
    chattr +i "$PYAPP_DIR/packages/__init__.py"
    chattr +i "$PYAPP_DIR/packages/helper.py"
    # 删除 __pycache__ 并锁定目录
    rm -rf "$PYAPP_DIR/packages/__pycache__"
    chattr +i "$PYAPP_DIR/packages"

    PROTECT_OUTPUT=$("$PROJECT_ROOT/credctl" protect \
        --config "$CREDCTL_CONFIG" \
        --strategy BASIC \
        --program-permit "$PYAPP_DIR/main.py" \
        --measure true \
        "$SECRET_FILE" 2>&1)
    PROTECT_RESULT=$?

    # 恢复 chattr (无论测试结果如何)
    chattr -i "$PYAPP_DIR/packages" 2>/dev/null
    chattr -i "$PYAPP_DIR/packages/helper.py" 2>/dev/null
    chattr -i "$PYAPP_DIR/packages/__init__.py" 2>/dev/null
    chattr -i "$PYAPP_DIR/main.py" 2>/dev/null

    if [ $PROTECT_RESULT -eq 0 ]; then
        echo "  ✓ chattr +i 后依赖检查通过，保护成功"
        ((TESTS_PASSED++))
        # 释放凭据 (需要交互输入密码)
        if [ -L "$SECRET_FILE" ]; then
            SHA_ID=$(readlink "$SECRET_FILE" | xargs basename)
            rm -f "$SECRET_FILE"
            echo "  → 释放凭据 $SHA_ID (请输入管理员密码):"
            "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_ID"
        fi
    else
        echo "  ✗ chattr +i 后仍失败"
        echo "  输出: $PROTECT_OUTPUT"
        ((TESTS_FAILED++))
    fi
else
    echo "  ⊘ 跳过: 文件系统不支持 chattr +i (tmpfs)"
    echo "    提示: 将 TEST_DIR 设置为 ext4/xfs 路径以启用此测试"
fi

# ============================================
# 测试10: attach 命令同样受依赖检查保护
# ============================================
echo ""
echo "测试10: credctl attach 同样受依赖检查保护"

# 重建 __pycache__ (测试9删除了)
create_user_dir "$PYAPP_DIR/packages/__pycache__"
create_user_file "$PYAPP_DIR/packages/__pycache__/helper.cpython-311.pyc" "fake pyc"

# 先用 native 二进制保护一个凭据
reset_secret_file
PROTECT_OUTPUT=$("$PROJECT_ROOT/credctl" protect \
    --config "$CREDCTL_CONFIG" \
    --strategy BASIC \
    --program-permit /bin/cat \
    --measure true \
    "$SECRET_FILE" 2>&1)

if [ -L "$SECRET_FILE" ]; then
    SHA_ID=$(readlink "$SECRET_FILE" | xargs basename)
else
    SHA_ID=""
fi

if [ -n "$SHA_ID" ]; then
    # 尝试 attach 一个有风险的 Python 脚本 (不需要密码即可被拒绝)
    ATTACH_OUTPUT=$("$PROJECT_ROOT/credctl" attach \
        --config "$CREDCTL_CONFIG" \
        --program-permit "$PYAPP_DIR/main.py" \
        "$SHA_ID" 2>&1)
    ATTACH_RESULT=$?

    if [ $ATTACH_RESULT -ne 0 ]; then
        if echo "$ATTACH_OUTPUT" | grep -q "\[RISK\]"; then
            echo "  ✓ attach 正确拒绝有风险的脚本"
            ((TESTS_PASSED++))
        else
            echo "  ✗ attach 失败但原因不是依赖风险"
            echo "  输出: $ATTACH_OUTPUT"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ attach 应该拒绝但成功了"
        ((TESTS_FAILED++))
    fi

    # 释放凭据 (需要交互输入密码)
    if [ -L "$SECRET_FILE" ]; then
        SHA_ID=$(readlink "$SECRET_FILE" | xargs basename)
        rm -f "$SECRET_FILE"
        echo "  → 释放凭据 $SHA_ID (请输入管理员密码):"
        "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_ID"
    fi
else
    echo "  ⊘ 跳过: 前置 protect 失败"
fi

# ============================================
# 测试11: 无依赖的简单脚本 — 脚本自身不检查(有SHA256度量保护)
# ============================================
echo ""
echo "测试11: 无依赖的简单 Python 脚本 — 脚本自身有度量保护，应通过"

SIMPLE_SCRIPT="$DEP_TEST_DIR/simple.py"
create_user_file "$SIMPLE_SCRIPT" 'import sys
with open(sys.argv[1]) as f:
    print(f.read())'

reset_secret_file

PROTECT_OUTPUT=$("$PROJECT_ROOT/credctl" protect \
    --config "$CREDCTL_CONFIG" \
    --strategy BASIC \
    --program-permit "$SIMPLE_SCRIPT" \
    --measure true \
    "$SECRET_FILE" 2>&1)
PROTECT_RESULT=$?

if [ $PROTECT_RESULT -eq 0 ]; then
    echo "  ✓ 无依赖脚本通过 (脚本自身由 SHA256 度量保护)"
    ((TESTS_PASSED++))
    # 释放凭据 (需要交互输入密码)
    if [ -L "$SECRET_FILE" ]; then
        SHA_ID=$(readlink "$SECRET_FILE" | xargs basename)
        rm -f "$SECRET_FILE"
        echo "  → 释放凭据 $SHA_ID (请输入管理员密码):"
        "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_ID"
    fi
else
    echo "  ✗ 无依赖脚本不应被拒绝"
    echo "  输出: $PROTECT_OUTPUT"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试12: 非脚本文件 (ELF binary 拷贝) 不触发检查
# ============================================
echo ""
echo "测试12: 非脚本二进制文件不触发依赖检查"

CUSTOM_BIN="$DEP_TEST_DIR/myapp"
cp /bin/cat "$CUSTOM_BIN"

reset_secret_file

PROTECT_OUTPUT=$("$PROJECT_ROOT/credctl" protect \
    --config "$CREDCTL_CONFIG" \
    --strategy BASIC \
    --program-permit "$CUSTOM_BIN" \
    --measure true \
    "$SECRET_FILE" 2>&1)
PROTECT_RESULT=$?

if [ $PROTECT_RESULT -eq 0 ]; then
    echo "  ✓ 非脚本二进制文件不触发依赖检查，保护成功"
    ((TESTS_PASSED++))
    # 释放凭据 (需要交互输入密码)
    if [ -L "$SECRET_FILE" ]; then
        SHA_ID=$(readlink "$SECRET_FILE" | xargs basename)
        rm -f "$SECRET_FILE"
        echo "  → 释放凭据 $SHA_ID (请输入管理员密码):"
        "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_ID"
    fi
else
    echo "  ✗ 非脚本文件保护失败"
    echo "  输出: $PROTECT_OUTPUT"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试13: 验证风险报告显示正确的 owner 名称
# ============================================
echo ""
echo "测试13: 验证风险报告显示正确的 owner 名称"

reset_secret_file

PROTECT_OUTPUT=$("$PROJECT_ROOT/credctl" protect \
    --config "$CREDCTL_CONFIG" \
    --strategy BASIC \
    --program-permit "$PYAPP_DIR/main.py" \
    --measure true \
    "$SECRET_FILE" 2>&1)

if echo "$PROTECT_OUTPUT" | grep -q "owner: $TEST_USER"; then
    echo "  ✓ 风险报告正确显示 owner: $TEST_USER"
    ((TESTS_PASSED++))
else
    echo "  ✗ 风险报告未正确显示 owner"
    echo "  期望包含: owner: $TEST_USER"
    echo "  实际输出: $(echo "$PROTECT_OUTPUT" | grep 'owner:' | head -3)"
    ((TESTS_FAILED++))
fi

# ============================================
# 清理
# ============================================
echo ""
echo "清理测试目录..."
rm -rf "$DEP_TEST_DIR" 2>/dev/null

# ============================================
# 测试结果汇总
# ============================================
echo ""
echo "=============================================="
echo "依赖风险检查测试结果"
echo "=============================================="
echo "  通过: $TESTS_PASSED"
echo "  失败: $TESTS_FAILED"
echo "  总计: $((TESTS_PASSED + TESTS_FAILED))"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo "所有测试通过! ✓"
    exit 0
else
    echo "存在失败的测试! ✗"
    exit 1
fi
