#!/bin/bash

# CredAgent 凭据写入系统测试
# 测试目标：验证授权程序对受保护凭据的写入（tee覆盖/追加、dd写入、truncate截断）、
#          非授权程序写入拦截、writable=false 写入拦截、动态 update writable 属性、
#          release 后恢复最终写入内容
# 前置条件：已执行 init_test_environ.sh

echo "=============================================="
echo "CredAgent 凭据写入测试"
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

echo "测试环境验证通过"
echo "  TEST_DIR: $TEST_DIR"
echo "  MOUNT_POINT: $MOUNT_POINT"
echo "  CREDAGENT_PID: $CREDAGENT_PID"
echo ""

# 测试计数器
TESTS_PASSED=0
TESTS_FAILED=0

# 存储变量
SHA_WRITABLE=""
SHA_READONLY=""
WRITABLE_FILE="$SECRETS_DIR/write_test_secret.txt"
READONLY_FILE="$SECRETS_DIR/readonly_test_secret.txt"
ORIGINAL_CONTENT="original secret content for write test"
READONLY_CONTENT="readonly secret content for test"

# 授权程序（用于可写文件）
PROG_TEE="/usr/bin/tee"
PROG_DD="/bin/dd"
PROG_CAT="/bin/cat"
PROG_TRUNCATE="/usr/bin/truncate"

# ============================================
# Part A: writable=true 正常写入路径
# ============================================
echo "====== Part A: writable=true 正常写入路径 ======"
echo ""

# ============================================
# 测试1: 创建可写测试文件并保护
# ============================================
echo "测试1: 创建可写测试文件并保护（writable=true）"

# 清理可能存在的旧文件或符号链接
if [ -L "$WRITABLE_FILE" ] || [ -f "$WRITABLE_FILE" ]; then
    rm -f "$WRITABLE_FILE"
fi

echo "$ORIGINAL_CONTENT" > "$WRITABLE_FILE"
chmod 666 "$WRITABLE_FILE"

echo "执行命令: credctl protect --strategy BASIC -p $PROG_TEE -p $PROG_DD -p $PROG_CAT -p $PROG_TRUNCATE --writable true --measure true $WRITABLE_FILE"

PROTECT_OUTPUT=$("$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" \
    --strategy BASIC \
    -p "$PROG_TEE" -p "$PROG_DD" -p "$PROG_CAT" -p "$PROG_TRUNCATE" \
    --writable true --measure true "$WRITABLE_FILE" 2>&1)
PROTECT_RESULT=$?

echo "protect 输出: $PROTECT_OUTPUT"

if [ $PROTECT_RESULT -eq 0 ]; then
    echo "  ✓ credctl protect (writable=true) 执行成功"
    ((TESTS_PASSED++))
else
    echo "  ✗ credctl protect (writable=true) 执行失败"
    ((TESTS_FAILED++))
fi

# 提取 SHA
LIST_OUTPUT=$("$PROJECT_ROOT/credctl" list --config "$CREDCTL_CONFIG" 2>&1)
SHA_LINE=$(echo "$LIST_OUTPUT" | grep "$WRITABLE_FILE" | head -n1)
if [ -z "$SHA_LINE" ]; then
    SHA_LINE=$(echo "$LIST_OUTPUT" | grep -E "^[a-f0-9]+" | head -n1)
fi
SHA_WRITABLE=$(echo "$SHA_LINE" | awk '{print $1}')
echo "  可写文件 SHA: $SHA_WRITABLE"

# ============================================
# 测试2: 验证符号链接创建
# ============================================
echo ""
echo "测试2: 验证符号链接创建"
if [ -L "$WRITABLE_FILE" ]; then
    LINK_TARGET=$(readlink "$WRITABLE_FILE")
    echo "  ✓ 符号链接已创建 -> $LINK_TARGET"
    ((TESTS_PASSED++))
else
    echo "  ✗ 符号链接未创建"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试3: 授权程序读取原始内容
# ============================================
echo ""
echo "测试3: 授权程序(cat)读取原始内容"
CAT_CONTENT=$(cat "$WRITABLE_FILE" 2>&1)
CAT_RESULT=$?

if [ $CAT_RESULT -eq 0 ] && [ "$CAT_CONTENT" = "$ORIGINAL_CONTENT" ]; then
    echo "  ✓ cat 读取原始内容正确"
    ((TESTS_PASSED++))
else
    echo "  ✗ cat 读取原始内容失败"
    echo "    期望: '$ORIGINAL_CONTENT'"
    echo "    实际: '$CAT_CONTENT'"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试4: tee 覆盖写入
# ============================================
echo ""
echo "测试4: tee 覆盖写入"
NEW_CONTENT="tee overwrite content 12345"
echo "$NEW_CONTENT" | tee "$WRITABLE_FILE" > /dev/null 2>&1
TEE_RESULT=$?

if [ $TEE_RESULT -eq 0 ]; then
    # 读取验证
    VERIFY=$(cat "$WRITABLE_FILE" 2>&1)
    if [ "$VERIFY" = "$NEW_CONTENT" ]; then
        echo "  ✓ tee 覆盖写入成功，内容验证正确"
        ((TESTS_PASSED++))
    else
        echo "  ✗ tee 覆盖写入后内容不正确"
        echo "    期望: '$NEW_CONTENT'"
        echo "    实际: '$VERIFY'"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ tee 覆盖写入返回非零: $TEE_RESULT"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试5: dd 写入
# ============================================
echo ""
echo "测试5: dd 写入"
DD_CONTENT="dd written content 67890"
echo "$DD_CONTENT" | dd of="$WRITABLE_FILE" 2>/dev/null
DD_RESULT=$?

if [ $DD_RESULT -eq 0 ]; then
    VERIFY=$(cat "$WRITABLE_FILE" 2>&1)
    if [ "$VERIFY" = "$DD_CONTENT" ]; then
        echo "  ✓ dd 写入成功，内容验证正确"
        ((TESTS_PASSED++))
    else
        echo "  ✗ dd 写入后内容不正确"
        echo "    期望: '$DD_CONTENT'"
        echo "    实际: '$VERIFY'"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ dd 写入返回非零: $DD_RESULT"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试6: tee -a 追加写入
# ============================================
echo ""
echo "测试6: tee -a 追加写入"
# 先写入基础内容
BASE_CONTENT="base content"
echo "$BASE_CONTENT" | tee "$WRITABLE_FILE" > /dev/null 2>&1

APPEND_CONTENT="appended line"
echo "$APPEND_CONTENT" | tee -a "$WRITABLE_FILE" > /dev/null 2>&1
APPEND_RESULT=$?

if [ $APPEND_RESULT -eq 0 ]; then
    VERIFY=$(cat "$WRITABLE_FILE" 2>&1)
    EXPECTED=$(printf "%s\n%s" "$BASE_CONTENT" "$APPEND_CONTENT")
    if [ "$VERIFY" = "$EXPECTED" ]; then
        echo "  ✓ tee -a 追加写入成功，内容验证正确"
        ((TESTS_PASSED++))
    else
        echo "  ✗ tee -a 追加写入后内容不正确"
        echo "    期望: '$EXPECTED'"
        echo "    实际: '$VERIFY'"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ tee -a 追加写入返回非零: $APPEND_RESULT"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试7: truncate -s 0 截断为空（Setattr 路径）
# ============================================
echo ""
echo "测试7: truncate -s 0 截断为空（Setattr 路径）"

# 先确保文件有内容
echo "content before truncate" | tee "$WRITABLE_FILE" > /dev/null 2>&1

truncate -s 0 "$WRITABLE_FILE" 2>&1
TRUNC_RESULT=$?

if [ $TRUNC_RESULT -eq 0 ]; then
    VERIFY=$(cat "$WRITABLE_FILE" 2>&1)
    if [ -z "$VERIFY" ]; then
        echo "  ✓ truncate -s 0 成功，文件内容为空"
        ((TESTS_PASSED++))
    else
        echo "  ✗ truncate -s 0 后文件内容非空"
        echo "    实际内容: '$VERIFY'"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ truncate -s 0 返回非零: $TRUNC_RESULT"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试8: truncate 后重新写入
# ============================================
echo ""
echo "测试8: truncate 后重新写入"
RECOVERED_CONTENT="recovered after truncate"
echo "$RECOVERED_CONTENT" | tee "$WRITABLE_FILE" > /dev/null 2>&1
TEE_RESULT=$?

if [ $TEE_RESULT -eq 0 ]; then
    VERIFY=$(cat "$WRITABLE_FILE" 2>&1)
    if [ "$VERIFY" = "$RECOVERED_CONTENT" ]; then
        echo "  ✓ truncate 后重新写入成功"
        ((TESTS_PASSED++))
    else
        echo "  ✗ truncate 后重新写入内容不正确"
        echo "    期望: '$RECOVERED_CONTENT'"
        echo "    实际: '$VERIFY'"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ truncate 后重新写入失败: $TEE_RESULT"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试9: 大内容写入（>4KB）
# ============================================
echo ""
echo "测试9: 大内容写入（>4KB）"
# 生成 8KB 可打印内容
LARGE_CONTENT=$(dd if=/dev/urandom bs=1024 count=8 2>/dev/null | base64)
LARGE_SIZE=${#LARGE_CONTENT}

echo "$LARGE_CONTENT" | tee "$WRITABLE_FILE" > /dev/null 2>&1
TEE_RESULT=$?

if [ $TEE_RESULT -eq 0 ]; then
    VERIFY=$(cat "$WRITABLE_FILE" 2>&1)
    VERIFY_SIZE=${#VERIFY}
    if [ "$VERIFY_SIZE" -gt 4096 ]; then
        if [ "$VERIFY" = "$LARGE_CONTENT" ]; then
            echo "  ✓ 大内容写入成功 (${VERIFY_SIZE} 字节)，完整性验证通过"
            ((TESTS_PASSED++))
        else
            echo "  ✗ 大内容写入后内容不一致 (写入 ${LARGE_SIZE} 字节, 读回 ${VERIFY_SIZE} 字节)"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ 读回内容过小 (${VERIFY_SIZE} 字节, 期望 > 4096)"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 大内容写入失败: $TEE_RESULT"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试10: 多次连续写入
# ============================================
echo ""
echo "测试10: 多次连续写入"
ALL_PASSED=true
for i in 1 2 3 4 5; do
    ITER_CONTENT="iteration $i content $(date +%s%N)"
    echo "$ITER_CONTENT" | tee "$WRITABLE_FILE" > /dev/null 2>&1
    VERIFY=$(cat "$WRITABLE_FILE" 2>&1)
    if [ "$VERIFY" != "$ITER_CONTENT" ]; then
        echo "  ✗ 第 $i 次写入后内容不正确"
        echo "    期望: '$ITER_CONTENT'"
        echo "    实际: '$VERIFY'"
        ALL_PASSED=false
        break
    fi
done

if [ "$ALL_PASSED" = true ]; then
    echo "  ✓ 5次连续写入全部成功，每次读回均正确"
    ((TESTS_PASSED++))
else
    ((TESTS_FAILED++))
fi

# 记录最终写入内容，用于后续 release 验证
FINAL_WRITABLE_CONTENT=$(cat "$WRITABLE_FILE" 2>&1)

# ============================================
# Part B: 安全拦截 — 非授权 / 只读场景
# ============================================
echo ""
echo "====== Part B: 安全拦截 ======"
echo ""

# ============================================
# 测试11: 非授权程序写入被拒绝
# ============================================
echo "测试11: 非授权程序写入被拒绝"
# python3 不在授权列表中
PYTHON_WRITE_OUTPUT=$(python3 -c "
try:
    f = open('$WRITABLE_FILE', 'w')
    f.write('hacked')
    f.close()
    print('WRITE_OK')
except PermissionError:
    print('PERMISSION_DENIED')
except OSError as e:
    print(f'OS_ERROR: {e}')
" 2>&1)

if [[ "$PYTHON_WRITE_OUTPUT" == *"PERMISSION_DENIED"* ]] || [[ "$PYTHON_WRITE_OUTPUT" == *"OS_ERROR"* ]]; then
    echo "  ✓ 非授权程序(python3)写入被拒绝: $PYTHON_WRITE_OUTPUT"
    ((TESTS_PASSED++))
else
    echo "  ✗ 非授权程序(python3)写入未被拦截: $PYTHON_WRITE_OUTPUT"
    ((TESTS_FAILED++))
fi

# 验证文件内容未被篡改
VERIFY=$(cat "$WRITABLE_FILE" 2>&1)
if [ "$VERIFY" = "$FINAL_WRITABLE_CONTENT" ]; then
    echo "  ✓ 文件内容未被篡改"
else
    echo "  ✗ 文件内容被篡改！"
    echo "    期望: '$FINAL_WRITABLE_CONTENT'"
    echo "    实际: '$VERIFY'"
fi

# ============================================
# 测试12: 非授权程序读取被拒绝
# ============================================
echo ""
echo "测试12: 非授权程序读取被拒绝"
GREP_OUTPUT=$(grep "content" "$WRITABLE_FILE" 2>&1)
GREP_RESULT=$?

if [ $GREP_RESULT -ne 0 ] || [[ "$GREP_OUTPUT" != *"content"* ]]; then
    echo "  ✓ 非授权程序(grep)读取被拒绝"
    ((TESTS_PASSED++))
else
    echo "  ✗ 非授权程序(grep)读取未被拦截"
    echo "    grep 输出: $GREP_OUTPUT"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试13-14: writable=false 文件写入被拒绝 + 读取正常
# ============================================
echo ""
echo "测试13: 创建 writable=false 文件并验证写入被拒绝"

# 清理可能存在的旧文件
if [ -L "$READONLY_FILE" ] || [ -f "$READONLY_FILE" ]; then
    rm -f "$READONLY_FILE"
fi

echo "$READONLY_CONTENT" > "$READONLY_FILE"
chmod 666 "$READONLY_FILE"

# protect 不带 --writable true（默认 writable=false）
PROTECT_RO_OUTPUT=$("$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" \
    --strategy BASIC \
    -p "$PROG_TEE" -p "$PROG_CAT" \
    --measure true "$READONLY_FILE" 2>&1)
PROTECT_RO_RESULT=$?

if [ $PROTECT_RO_RESULT -ne 0 ]; then
    echo "  ✗ writable=false 文件 protect 失败: $PROTECT_RO_OUTPUT"
    ((TESTS_FAILED++))
else
    # 提取 SHA
    LIST_RO=$("$PROJECT_ROOT/credctl" list --config "$CREDCTL_CONFIG" 2>&1)
    SHA_RO_LINE=$(echo "$LIST_RO" | grep "$READONLY_FILE" | head -n1)
    if [ -z "$SHA_RO_LINE" ]; then
        # 如果按路径没找到，取第二个条目（第一个是 writable 文件）
        SHA_RO_LINE=$(echo "$LIST_RO" | grep -E "^[a-f0-9]+" | grep -v "$SHA_WRITABLE" | head -n1)
    fi
    SHA_READONLY=$(echo "$SHA_RO_LINE" | awk '{print $1}')
    echo "  只读文件 SHA: $SHA_READONLY"

    # 授权程序(tee)尝试写入 writable=false 文件
    echo "unauthorized write attempt" | tee "$READONLY_FILE" > /dev/null 2>&1
    TEE_RO_RESULT=$?

    if [ $TEE_RO_RESULT -ne 0 ]; then
        echo "  ✓ writable=false 文件，授权程序(tee)写入被拒绝"
        ((TESTS_PASSED++))
    else
        # tee 可能返回 0 但内容未改变（取决于实现），验证内容
        VERIFY_RO=$(cat "$READONLY_FILE" 2>&1)
        if [ "$VERIFY_RO" = "$READONLY_CONTENT" ]; then
            echo "  ✓ writable=false 文件内容未被修改（写入被忽略）"
            ((TESTS_PASSED++))
        else
            echo "  ✗ writable=false 文件内容被修改"
            echo "    期望: '$READONLY_CONTENT'"
            echo "    实际: '$VERIFY_RO'"
            ((TESTS_FAILED++))
        fi
    fi
fi

echo ""
echo "测试14: writable=false 文件读取正常"
if [ -L "$READONLY_FILE" ]; then
    CAT_RO=$(cat "$READONLY_FILE" 2>&1)
    CAT_RO_RESULT=$?

    if [ $CAT_RO_RESULT -eq 0 ] && [ "$CAT_RO" = "$READONLY_CONTENT" ]; then
        echo "  ✓ writable=false 文件，授权程序(cat)读取正常"
        ((TESTS_PASSED++))
    else
        echo "  ✗ writable=false 文件读取异常"
        echo "    期望: '$READONLY_CONTENT'"
        echo "    实际: '$CAT_RO' (返回值: $CAT_RO_RESULT)"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 只读文件符号链接不存在"
    ((TESTS_FAILED++))
fi

# ============================================
# Part C: 动态修改 writable 属性
# ============================================
echo ""
echo "====== Part C: 动态修改 writable 属性 ======"
echo ""

# ============================================
# 测试15: update writable=true
# ============================================
echo "测试15: update writable=false -> writable=true"

if [ -z "$SHA_READONLY" ]; then
    echo "  ✗ 无法获取只读文件 SHA，跳过 update 测试"
    ((TESTS_FAILED++))
else
    echo ""
    echo "----------------------------------------------"
    echo "请注意：此步骤需要人工交互输入"
    echo "当要求输入密码时，请输入初始化时设置的管理员密码"
    echo "----------------------------------------------"
    echo ""

    UPDATE_OUTPUT=$("$PROJECT_ROOT/credctl" update --config "$CREDCTL_CONFIG" \
        "$SHA_READONLY" --writable true 2>&1)
    UPDATE_RESULT=$?

    echo "update 输出: $UPDATE_OUTPUT"

    if [ $UPDATE_RESULT -eq 0 ]; then
        echo "  ✓ update writable=true 执行成功"
        ((TESTS_PASSED++))
    else
        echo "  ✗ update writable=true 执行失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试16: update 后写入变为允许
# ============================================
echo ""
echo "测试16: update 后写入变为允许"

if [ -L "$READONLY_FILE" ]; then
    UPDATED_CONTENT="content after update writable=true"
    echo "$UPDATED_CONTENT" | tee "$READONLY_FILE" > /dev/null 2>&1
    TEE_UPDATED_RESULT=$?

    if [ $TEE_UPDATED_RESULT -eq 0 ]; then
        VERIFY_UPDATED=$(cat "$READONLY_FILE" 2>&1)
        if [ "$VERIFY_UPDATED" = "$UPDATED_CONTENT" ]; then
            echo "  ✓ update writable=true 后写入成功，内容验证正确"
            ((TESTS_PASSED++))
        else
            echo "  ✗ update writable=true 后写入内容不正确"
            echo "    期望: '$UPDATED_CONTENT'"
            echo "    实际: '$VERIFY_UPDATED'"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ update writable=true 后写入仍然被拒绝: $TEE_UPDATED_RESULT"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 只读文件符号链接不存在，无法测试"
    ((TESTS_FAILED++))
fi

# 记录最终内容用于 release 验证
FINAL_READONLY_CONTENT=$(cat "$READONLY_FILE" 2>&1)

# ============================================
# Part D: 清理与 release 验证
# ============================================
echo ""
echo "====== Part D: 清理与 release 验证 ======"
echo ""

# ============================================
# 测试17: release 可写文件
# ============================================
echo "测试17: release 可写文件"

if [ -z "$SHA_WRITABLE" ]; then
    echo "  ✗ 无法获取可写文件 SHA，跳过 release"
    ((TESTS_FAILED++))
else
    if [ -L "$WRITABLE_FILE" ]; then
        rm -f "$WRITABLE_FILE"
    fi

    echo ""
    echo "----------------------------------------------"
    echo "请注意：此步骤需要人工交互输入"
    echo "当要求输入密码时，请输入初始化时设置的管理员密码"
    echo "----------------------------------------------"
    echo ""

    "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_WRITABLE"
    RELEASE_W_RESULT=$?

    if [ $RELEASE_W_RESULT -eq 0 ]; then
        echo "  ✓ release 可写文件成功"
        ((TESTS_PASSED++))
    else
        echo "  ✗ release 可写文件失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试18: release 后内容为最终写入值
# ============================================
echo ""
echo "测试18: release 后内容为最终写入值"
if [ -f "$WRITABLE_FILE" ] && [ ! -L "$WRITABLE_FILE" ]; then
    RESTORED=$(cat "$WRITABLE_FILE")
    if [ "$RESTORED" = "$FINAL_WRITABLE_CONTENT" ]; then
        echo "  ✓ release 后文件内容 = 最终写入值"
        ((TESTS_PASSED++))
    else
        echo "  ✗ release 后内容不正确"
        echo "    期望: '$FINAL_WRITABLE_CONTENT'"
        echo "    实际: '$RESTORED'"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 文件未正确还原为普通文件"
    if [ -L "$WRITABLE_FILE" ]; then
        echo "    仍然是符号链接"
    elif [ ! -f "$WRITABLE_FILE" ]; then
        echo "    文件不存在"
    fi
    ((TESTS_FAILED++))
fi

# ============================================
# 测试19: release 原只读文件（已 update 为 writable）
# ============================================
echo ""
echo "测试19: release 原只读文件"

if [ -z "$SHA_READONLY" ]; then
    echo "  ✗ 无法获取只读文件 SHA，跳过 release"
    ((TESTS_FAILED++))
else
    if [ -L "$READONLY_FILE" ]; then
        rm -f "$READONLY_FILE"
    fi

    echo ""
    echo "----------------------------------------------"
    echo "请注意：此步骤需要人工交互输入"
    echo "当要求输入密码时，请输入初始化时设置的管理员密码"
    echo "----------------------------------------------"
    echo ""

    "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_READONLY"
    RELEASE_RO_RESULT=$?

    if [ $RELEASE_RO_RESULT -eq 0 ]; then
        echo "  ✓ release 原只读文件成功"
        ((TESTS_PASSED++))
    else
        echo "  ✗ release 原只读文件失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试20: release 后内容为最终写入值
# ============================================
echo ""
echo "测试20: release 后原只读文件内容验证"
if [ -f "$READONLY_FILE" ] && [ ! -L "$READONLY_FILE" ]; then
    RESTORED_RO=$(cat "$READONLY_FILE")
    if [ "$RESTORED_RO" = "$FINAL_READONLY_CONTENT" ]; then
        echo "  ✓ release 后原只读文件内容 = 最终写入值"
        ((TESTS_PASSED++))
    else
        echo "  ✗ release 后内容不正确"
        echo "    期望: '$FINAL_READONLY_CONTENT'"
        echo "    实际: '$RESTORED_RO'"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 文件未正确还原为普通文件"
    ((TESTS_FAILED++))
fi

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
