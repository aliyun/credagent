#!/bin/bash

# CredAgent cmdline 篡改仿冒测试
# 测试目标：验证不同 cmdline_trusted_source 配置下，脚本类程序篡改 /proc/<pid>/cmdline
#           能否绕过 SHA256 校验
# 攻击原理：脚本程序（如 Python）覆写自身 argv 内存区域，将 cmdline 伪装成合法授权脚本，
#           使策略引擎从篡改后的 cmdline 提取到错误的脚本路径，绕过 SHA256 校验。
# 测试场景：
#   1. cmdline_trusted_source: []        — 降级模式，篡改可绕过
#   2. cmdline_trusted_source: ["ebpf"]  — eBPF 模式，篡改应被拦截（需系统支持）
#   3. cmdline_trusted_source: ["auditd"]— auditd 模式，篡改应被拦截（需系统支持）
# 前置条件：已执行 init_test_environ.sh，需要 sudo 权限（重启 credagent）

echo "=============================================="
echo "CredAgent cmdline 篡改仿冒检测测试（脚本类程序）"
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

# 检查 root 权限（重启 credagent 需要）
if [ "$(id -u)" -ne 0 ]; then
    echo "错误: 此脚本需要 root 权限运行（需重启 credagent）"
    echo "请使用: sudo bash $0"
    exit 1
fi

PYTHON3_PATH=$(which python3 2>/dev/null)

if [ -z "$PYTHON3_PATH" ]; then
    echo "错误: python3 未安装，无法执行测试"
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
TESTS_SKIPPED=0

# 公共文件路径
SECRET_FILE="$SECRETS_DIR/cmdline_tamper_test_secret.txt"
SECRET_CONTENT="cmdline_tamper_test_secret_value_13579"
PY_NORMAL_SCRIPT="$TEST_DIR/cmdline_normal_reader.py"
PY_TAMPER_SCRIPT="$TEST_DIR/cmdline_tamper.py"
PY_LEGIT_SCRIPT="$TEST_DIR/cmdline_legit_script.py"
SHA_IDENTIFIER=""

# ============================================
# 辅助函数：重启 credagent 并等待就绪
# 参数: $1 = cmdline_trusted_source JSON 数组（如 '[]', '["ebpf"]'）
# ============================================
restart_credagent_with_source() {
    local source_value="$1"
    echo "  重启 credagent (cmdline_trusted_source: $source_value)..."

    # 修改配置
    python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    cfg = json.load(f)
cfg['cmdline_trusted_source'] = json.loads(sys.argv[2])
with open(sys.argv[1], 'w') as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
" "$SECURITY_CONFIG" "$source_value"

    # 停止当前进程
    if [ -n "$CREDAGENT_PID" ] && ps -p "$CREDAGENT_PID" > /dev/null 2>&1; then
        kill "$CREDAGENT_PID" 2>/dev/null || true
        local wait_count=0
        while ps -p "$CREDAGENT_PID" > /dev/null 2>&1 && [ $wait_count -lt 10 ]; do
            sleep 1
            ((wait_count++))
        done
        if ps -p "$CREDAGENT_PID" > /dev/null 2>&1; then
            echo "  警告: credagent 未能在 10 秒内退出，强制终止"
            kill -9 "$CREDAGENT_PID" 2>/dev/null || true
            sleep 1
        fi
    fi

    # 确保 FUSE 已卸载
    if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        fusermount -uz "$MOUNT_POINT" 2>/dev/null || true
        sleep 1
    fi

    # 重新启动
    CREDAGENT_LOG="$LOG_DIR/credagent.log"
    "$PROJECT_ROOT/credagent" run -c "$ENGINE_CONFIG" > "$CREDAGENT_LOG" 2>&1 &
    CREDAGENT_PID=$!
    sleep 8

    if ! ps -p "$CREDAGENT_PID" > /dev/null 2>&1; then
        echo "  ✗ credagent 重启失败"
        echo "  日志:"
        tail -20 "$CREDAGENT_LOG"
        return 1
    fi

    if ! mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        echo "  ✗ FUSE 挂载点未就绪"
        return 1
    fi

    # 更新环境变量文件中的 PID
    sed -i "s/^export CREDAGENT_PID=.*/export CREDAGENT_PID=\"$CREDAGENT_PID\"/" "$ENV_FILE"

    echo "  ✓ credagent 重启完成 (PID: $CREDAGENT_PID)"
    return 0
}

# ============================================
# 辅助函数：检测 cmdline 可信来源是否实际生效
# 参数: $1 = 期望的来源名 (ebpf/auditd)
# 返回: 0=生效, 1=未生效
# ============================================
check_source_active() {
    local source_name="$1"
    if grep -q "Cmdline trusted source active: $source_name" "$CREDAGENT_LOG" 2>/dev/null; then
        return 0
    fi
    return 1
}

# ============================================
# 辅助函数：执行篡改测试并判定结果
# 参数: $1=场景描述, $2=是否期望拦截 (expect_block/expect_bypass/detect_capability)
# ============================================
run_tamper_test() {
    local description="$1"
    local expectation="$2"

    FAKE_CMDLINE="$PYTHON3_PATH $PY_LEGIT_SCRIPT $SECRET_FILE"
    OUTPUT=$("$PYTHON3_PATH" "$PY_TAMPER_SCRIPT" "$FAKE_CMDLINE" "$SECRET_FILE" 2>&1)
    RESULT=$?

    echo "  伪造 cmdline: $FAKE_CMDLINE"
    echo "  返回值: $RESULT"
    echo "  输出: $OUTPUT"

    if [[ "$OUTPUT" == *"TAMPER_FAILED"* ]]; then
        echo "  跳过（ctypes 篡改失败，可能缺少权限）"
        ((TESTS_SKIPPED++))
        return
    fi

    local tamper_succeeded=false
    if [ $RESULT -eq 0 ] && [[ "$OUTPUT" == "$SECRET_CONTENT" ]]; then
        tamper_succeeded=true
    fi

    case "$expectation" in
        expect_bypass)
            if [ "$tamper_succeeded" = true ]; then
                echo "  ✓ $description: 篡改成功绕过（降级模式，符合预期）"
                ((TESTS_PASSED++))
            else
                echo "  ✗ $description: 篡改未能绕过，但降级模式下应可绕过"
                echo "    可能有其他策略拦截了访问"
                ((TESTS_FAILED++))
            fi
            ;;
        expect_block)
            if [ "$tamper_succeeded" = false ]; then
                echo "  ✓ $description: 篡改被拦截"
                ((TESTS_PASSED++))
            else
                echo "  ✗ $description: 篡改未被拦截，秘密被泄露！"
                ((TESTS_FAILED++))
            fi
            ;;
        detect_capability)
            # 用于可信来源可能不可用的场景
            if [ "$tamper_succeeded" = false ]; then
                echo "  ✓ $description: 篡改被拦截"
                ((TESTS_PASSED++))
            else
                echo "  ~ $description: 篡改未被拦截（可信来源可能初始化失败）"
                ((TESTS_SKIPPED++))
            fi
            ;;
    esac
}

# ============================================
# 准备: 创建测试脚本
# ============================================
echo "准备: 创建测试脚本"

# 非授权读取脚本（内容与合法脚本不同，SHA256 不同）
cat > "$PY_NORMAL_SCRIPT" << 'PYEOF'
import sys
import os
target = sys.argv[1] if len(sys.argv) > 1 else None
if not target:
    print("Usage: cmdline_normal_reader.py <file>", file=sys.stderr)
    sys.exit(1)
try:
    with open(target, 'r') as f:
        print(f.read().strip())
except PermissionError:
    print("PERMISSION_DENIED", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
chmod +x "$PY_NORMAL_SCRIPT"
echo "  非授权读取脚本: $PY_NORMAL_SCRIPT"

# 合法脚本（用于仿冒目标，内容与正常脚本相同）
cat > "$PY_LEGIT_SCRIPT" << 'PYEOF'
import sys
try:
    with open(sys.argv[1], 'r') as f:
        print(f.read().strip())
except PermissionError:
    print("PERMISSION_DENIED", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
chmod +x "$PY_LEGIT_SCRIPT"
echo "  合法脚本（仿冒目标）: $PY_LEGIT_SCRIPT"

# 篡改脚本：通过 ctypes 覆写 argv 内存区域，将 cmdline 伪装成合法脚本
cat > "$PY_TAMPER_SCRIPT" << 'PYEOF'
import sys
import ctypes

def tamper_cmdline(new_cmdline_str):
    """Overwrite /proc/self/cmdline by writing to the argv memory area.
    Parses arg_start/arg_end from /proc/self/stat (fields 48/49)."""
    try:
        with open('/proc/self/stat', 'r') as f:
            stat_content = f.read()

        # comm field can contain any character; find last ')'
        idx = stat_content.rfind(')')
        if idx < 0:
            return False
        fields = stat_content[idx + 2:].split()
        # fields[0]=state(field3), fields[1]=ppid(field4), ...
        # arg_start=field48 -> fields[45], arg_end=field49 -> fields[46]
        arg_start = int(fields[45])
        arg_end = int(fields[46])
        arg_len = arg_end - arg_start

        if arg_len <= 0:
            return False

        parts = new_cmdline_str.split(' ')
        fake = b'\x00'.join(p.encode('utf-8') for p in parts) + b'\x00'
        if len(fake) > arg_len:
            fake = fake[:arg_len]

        libc = ctypes.CDLL('libc.so.6', use_errno=True)
        libc.memmove(ctypes.c_void_p(arg_start), fake, len(fake))
        remaining = arg_len - len(fake)
        if remaining > 0:
            libc.memset(ctypes.c_void_p(arg_start + len(fake)), 0, remaining)

        return True
    except Exception as e:
        print(f"TAMPER_FAILED: {e}", file=sys.stderr)
        return False

if len(sys.argv) < 3:
    print("Usage: cmdline_tamper.py <fake_cmdline> <file_to_read>", file=sys.stderr)
    sys.exit(1)

fake_cmdline = sys.argv[1]
file_to_read = sys.argv[2]

if not tamper_cmdline(fake_cmdline):
    print("TAMPER_FAILED", file=sys.stderr)
    sys.exit(2)

try:
    with open(file_to_read, 'r') as f:
        print(f.read().strip())
except PermissionError:
    print("PERMISSION_DENIED", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
chmod +x "$PY_TAMPER_SCRIPT"
echo "  篡改脚本: $PY_TAMPER_SCRIPT"

# ============================================
# 准备: 创建并保护秘密文件
# ============================================
echo ""
echo "准备: 创建并保护秘密文件"

rm -f "$SECRET_FILE" 2>/dev/null
echo "$SECRET_CONTENT" > "$SECRET_FILE"
echo "  秘密文件: $SECRET_FILE"

# 授权合法脚本访问，measure=true 度量脚本完整性
PROTECT_CMD=("$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" --strategy BASIC)
PROTECT_CMD+=(--program-permit "$PY_LEGIT_SCRIPT" --measure true)
PROTECT_CMD+=("$SECRET_FILE")

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

# ============================================
# 测试1: 基线 — 合法脚本正常读取
# ============================================
echo ""
echo "=============================================="
echo "测试1: 基线 — 合法脚本正常读取（无篡改）"
echo "=============================================="
OUTPUT=$("$PYTHON3_PATH" "$PY_LEGIT_SCRIPT" "$SECRET_FILE" 2>&1)
RESULT=$?
echo "  返回值: $RESULT"
echo "  输出: $OUTPUT"
if [ $RESULT -eq 0 ] && [ "$OUTPUT" = "$SECRET_CONTENT" ]; then
    echo "  ✓ 合法脚本正常读取成功"
    ((TESTS_PASSED++))
else
    echo "  ✗ 合法脚本正常读取失败（基线异常）"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试2: 非授权脚本直接访问应被拒绝
# ============================================
echo ""
echo "=============================================="
echo "测试2: 非授权脚本直接访问应被拒绝（SHA256 不匹配）"
echo "=============================================="
OUTPUT=$("$PYTHON3_PATH" "$PY_NORMAL_SCRIPT" "$SECRET_FILE" 2>&1)
RESULT=$?
echo "  返回值: $RESULT"
echo "  输出: $OUTPUT"
if [ $RESULT -ne 0 ] || [[ "$OUTPUT" == *"PERMISSION_DENIED"* ]] || [[ "$OUTPUT" != "$SECRET_CONTENT" ]]; then
    echo "  ✓ 非授权脚本被拒绝（SHA256 校验生效）"
    ((TESTS_PASSED++))
else
    echo "  ✗ 非授权脚本意外获得访问权限！"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试3: cmdline_trusted_source: [] — 篡改应可绕过
# init 默认配置即为 []，直接测试
# ============================================
echo ""
echo "=============================================="
echo "测试3: cmdline_trusted_source: [] — 降级模式，篡改应可绕过"
echo "=============================================="

# 确认当前配置
echo "  当前配置确认:"
CURRENT_SOURCE=$(python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    cfg = json.load(f)
print(json.dumps(cfg.get('cmdline_trusted_source', [])))
" "$SECURITY_CONFIG")
echo "  cmdline_trusted_source = $CURRENT_SOURCE"

run_tamper_test "降级模式([])" "expect_bypass"

# ============================================
# 测试4: cmdline_trusted_source: ["ebpf"] — eBPF 模式
# ============================================
echo ""
echo "=============================================="
echo "测试4: cmdline_trusted_source: [\"ebpf\"] — eBPF 模式"
echo "=============================================="

if ! restart_credagent_with_source '["ebpf"]'; then
    echo "  ✗ credagent 重启失败，跳过 eBPF 测试"
    ((TESTS_SKIPPED++))
else
    # 检查 eBPF 是否实际加载成功
    if check_source_active "ebpf"; then
        echo "  eBPF 可信来源已激活"
        # 先验证合法脚本仍可正常访问
        LEGIT_OUTPUT=$("$PYTHON3_PATH" "$PY_LEGIT_SCRIPT" "$SECRET_FILE" 2>&1)
        LEGIT_RESULT=$?
        if [ $LEGIT_RESULT -eq 0 ] && [ "$LEGIT_OUTPUT" = "$SECRET_CONTENT" ]; then
            echo "  ✓ eBPF 模式下合法脚本正常读取"
        else
            echo "  ⚠ eBPF 模式下合法脚本读取异常 (返回值: $LEGIT_RESULT, 输出: $LEGIT_OUTPUT)"
        fi
        # 篡改测试：期望被拦截
        run_tamper_test "eBPF 模式" "expect_block"
    else
        echo "  eBPF 可信来源未能激活（系统可能不支持 eBPF）"
        # 仍然运行测试，但结果仅作参考
        run_tamper_test "eBPF 模式(未激活)" "detect_capability"
    fi
fi

# ============================================
# 测试5: cmdline_trusted_source: ["auditd"] — auditd 模式
# ============================================
echo ""
echo "=============================================="
echo "测试5: cmdline_trusted_source: [\"auditd\"] — auditd 模式"
echo "=============================================="

if ! restart_credagent_with_source '["auditd"]'; then
    echo "  ✗ credagent 重启失败，跳过 auditd 测试"
    ((TESTS_SKIPPED++))
else
    if check_source_active "auditd"; then
        echo "  auditd 可信来源已激活"
        # 先验证合法脚本仍可正常访问
        LEGIT_OUTPUT=$("$PYTHON3_PATH" "$PY_LEGIT_SCRIPT" "$SECRET_FILE" 2>&1)
        LEGIT_RESULT=$?
        if [ $LEGIT_RESULT -eq 0 ] && [ "$LEGIT_OUTPUT" = "$SECRET_CONTENT" ]; then
            echo "  ✓ auditd 模式下合法脚本正常读取"
        else
            echo "  ⚠ auditd 模式下合法脚本读取异常 (返回值: $LEGIT_RESULT, 输出: $LEGIT_OUTPUT)"
        fi
        # 篡改测试：期望被拦截
        run_tamper_test "auditd 模式" "expect_block"
    else
        echo "  auditd 可信来源未能激活（系统可能未安装/运行 auditd）"
        run_tamper_test "auditd 模式(未激活)" "detect_capability"
    fi
fi

# ============================================
# 恢复：重启 credagent 为默认配置 []
# ============================================
echo ""
echo "恢复: 重启 credagent 为默认配置 (cmdline_trusted_source: [])"
if ! restart_credagent_with_source '[]'; then
    echo "  ⚠ 恢复默认配置失败，后续测试可能受影响"
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

rm -f "$PY_NORMAL_SCRIPT" "$PY_TAMPER_SCRIPT" "$PY_LEGIT_SCRIPT" 2>/dev/null

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
