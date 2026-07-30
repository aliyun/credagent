#!/bin/bash

# CredAgent dump/restore 功能系统测试
# 测试目标：验证 credctl dump 和 credctl restore 命令功能
#   - dump 导出凭据内容到 stdout 或文件，不修改 baseline
#   - restore 从文件或参数更新凭据内容，不修改 baseline 元数据和规则
# 前置条件：已执行 init_test_environ.sh
# 运行要求：需要 sudo 权限

echo "=============================================="
echo "CredAgent Dump/Restore 功能测试"
echo "=============================================="

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

echo "测试环境验证通过"
echo "  TEST_DIR: $TEST_DIR"
echo "  MOUNT_POINT: $MOUNT_POINT"
echo "  CREDAGENT_PID: $CREDAGENT_PID"
echo ""

# ---- 测试计数器 ----
TESTS_PASSED=0
TESTS_FAILED=0

# ---- 准备测试文件 ----
SECRET_FILE="$SECRETS_DIR/dump_restore_test_secret.txt"
SECRET_CONTENT="dump-restore-original-content-12345"
SHA_IDENTIFIER=""

# 清理可能存在的旧文件或符号链接
if [ -L "$SECRET_FILE" ] || [ -f "$SECRET_FILE" ]; then
    rm -f "$SECRET_FILE"
fi

echo -n "$SECRET_CONTENT" > "$SECRET_FILE"

# ---- 保护凭据 ----
echo "准备: 使用 credctl protect 保护测试文件"
PROTECT_OUTPUT=$("$PROJECT_ROOT/credctl" protect \
    --config "$CREDCTL_CONFIG" \
    --strategy BASIC \
    --program-permit /bin/cat \
    --measure true \
    "$SECRET_FILE" 2>&1)
PROTECT_RESULT=$?

if [ $PROTECT_RESULT -ne 0 ]; then
    echo "错误: credctl protect 失败: $PROTECT_OUTPUT"
    exit 1
fi

# 提取 SHA identifier
if [ -L "$SECRET_FILE" ]; then
    SHA_IDENTIFIER=$(readlink "$SECRET_FILE" | xargs basename)
    echo "  凭据已保护, SHA: $SHA_IDENTIFIER"
else
    echo "错误: protect 后文件不是符号链接"
    exit 1
fi
echo ""

# ============================================
# 测试1: credctl dump 输出到 stdout
# ============================================
echo "测试1: credctl dump 输出到 stdout"
echo ""
echo "----------------------------------------------"
echo "请注意：此步骤需要人工交互输入"
echo "当要求输入密码时，请输入初始化时设置的管理员密码"
echo "----------------------------------------------"
echo ""

DUMP_STDOUT=$("$PROJECT_ROOT/credctl" dump --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER")
DUMP_RESULT=$?

if [ $DUMP_RESULT -eq 0 ] && [ "$DUMP_STDOUT" = "$SECRET_CONTENT" ]; then
    echo "  ✓ dump 到 stdout 成功，内容正确"
    ((TESTS_PASSED++))
else
    echo "  ✗ dump 到 stdout 失败"
    echo "    期望: '$SECRET_CONTENT'"
    echo "    实际: '$DUMP_STDOUT'"
    echo "    返回值: $DUMP_RESULT"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试2: dump 后 baseline 仍存在
# ============================================
echo ""
echo "测试2: dump 后 baseline 仍存在"
LIST_OUTPUT=$("$PROJECT_ROOT/credctl" list --config "$CREDCTL_CONFIG" 2>&1)

if [[ "$LIST_OUTPUT" == *"$SHA_IDENTIFIER"* ]]; then
    echo "  ✓ dump 后 baseline 仍存在"
    ((TESTS_PASSED++))
else
    echo "  ✗ dump 后 baseline 丢失"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试3: dump 后 FUSE 读取仍正常
# ============================================
echo ""
echo "测试3: dump 后 FUSE 读取仍正常"
FUSE_CONTENT=$(cat "$SECRET_FILE" 2>&1)
FUSE_RESULT=$?

if [ $FUSE_RESULT -eq 0 ] && [ "$FUSE_CONTENT" = "$SECRET_CONTENT" ]; then
    echo "  ✓ dump 后 FUSE 读取正常，内容一致"
    ((TESTS_PASSED++))
else
    echo "  ✗ dump 后 FUSE 读取异常"
    echo "    期望: '$SECRET_CONTENT'"
    echo "    实际: '$FUSE_CONTENT'"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试4: credctl dump --write 输出到文件
# ============================================
echo ""
echo "测试4: credctl dump --write 输出到文件"
DUMP_FILE="/tmp/credagent_dump_test_output.txt"
rm -f "$DUMP_FILE"

echo ""
echo "----------------------------------------------"
echo "请注意：此步骤需要人工交互输入"
echo "当要求输入密码时，请输入初始化时设置的管理员密码"
echo "----------------------------------------------"
echo ""

"$PROJECT_ROOT/credctl" dump --config "$CREDCTL_CONFIG" -w "$DUMP_FILE" "$SHA_IDENTIFIER"
DUMP_WRITE_RESULT=$?

if [ $DUMP_WRITE_RESULT -eq 0 ] && [ -f "$DUMP_FILE" ]; then
    DUMP_FILE_CONTENT=$(cat "$DUMP_FILE")
    if [ "$DUMP_FILE_CONTENT" = "$SECRET_CONTENT" ]; then
        echo "  ✓ dump --write 成功，文件内容正确"
        ((TESTS_PASSED++))
    else
        echo "  ✗ dump --write 文件内容不匹配"
        echo "    期望: '$SECRET_CONTENT'"
        echo "    实际: '$DUMP_FILE_CONTENT'"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ dump --write 失败 (返回值: $DUMP_WRITE_RESULT)"
    ((TESTS_FAILED++))
fi
rm -f "$DUMP_FILE"

# ============================================
# 测试5: credctl restore --file 从文件恢复
# ============================================
echo ""
echo "测试5: credctl restore --file 从文件恢复"
RESTORE_FILE="/tmp/credagent_restore_test_input.txt"
RESTORED_CONTENT="restored-content-from-file-67890"
echo -n "$RESTORED_CONTENT" > "$RESTORE_FILE"

echo ""
echo "----------------------------------------------"
echo "请注意：此步骤需要人工交互输入"
echo "当要求输入密码时，请输入初始化时设置的管理员密码"
echo "----------------------------------------------"
echo ""

"$PROJECT_ROOT/credctl" restore --config "$CREDCTL_CONFIG" -f "$RESTORE_FILE" "$SHA_IDENTIFIER"
RESTORE_RESULT=$?

if [ $RESTORE_RESULT -eq 0 ]; then
    echo "  ✓ restore --file 命令执行成功"
    ((TESTS_PASSED++))
else
    echo "  ✗ restore --file 命令执行失败"
    ((TESTS_FAILED++))
fi
rm -f "$RESTORE_FILE"

# ============================================
# 测试6: restore 后 FUSE 读取内容已更新
# ============================================
echo ""
echo "测试6: restore 后通过 FUSE 读取内容已更新"
FUSE_AFTER_RESTORE=$(cat "$SECRET_FILE" 2>&1)
FUSE_AFTER_RESULT=$?

if [ $FUSE_AFTER_RESULT -eq 0 ] && [ "$FUSE_AFTER_RESTORE" = "$RESTORED_CONTENT" ]; then
    echo "  ✓ restore 后 FUSE 读取到更新后的内容"
    ((TESTS_PASSED++))
else
    echo "  ✗ restore 后 FUSE 内容未更新"
    echo "    期望: '$RESTORED_CONTENT'"
    echo "    实际: '$FUSE_AFTER_RESTORE'"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试7: restore 后 dump 内容一致
# ============================================
echo ""
echo "测试7: restore 后 dump 内容与 restore 输入一致"
echo ""
echo "----------------------------------------------"
echo "请注意：此步骤需要人工交互输入"
echo "当要求输入密码时，请输入初始化时设置的管理员密码"
echo "----------------------------------------------"
echo ""

DUMP_AFTER_RESTORE=$("$PROJECT_ROOT/credctl" dump --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER")
DUMP_AFTER_RESULT=$?

if [ $DUMP_AFTER_RESULT -eq 0 ] && [ "$DUMP_AFTER_RESTORE" = "$RESTORED_CONTENT" ]; then
    echo "  ✓ restore 后 dump 内容一致"
    ((TESTS_PASSED++))
else
    echo "  ✗ restore 后 dump 内容不一致"
    echo "    期望: '$RESTORED_CONTENT'"
    echo "    实际: '$DUMP_AFTER_RESTORE'"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试8: restore --secret 从参数恢复
# ============================================
echo ""
echo "测试8: credctl restore --secret 从参数恢复"
SECRET_ARG_CONTENT="secret-from-argument-abcdef"

echo ""
echo "----------------------------------------------"
echo "请注意：此步骤需要人工交互输入"
echo "当要求输入密码时，请输入初始化时设置的管理员密码"
echo "----------------------------------------------"
echo ""

"$PROJECT_ROOT/credctl" restore --config "$CREDCTL_CONFIG" -s "$SECRET_ARG_CONTENT" "$SHA_IDENTIFIER"
RESTORE_SECRET_RESULT=$?

if [ $RESTORE_SECRET_RESULT -eq 0 ]; then
    echo "  ✓ restore --secret 命令执行成功"
    ((TESTS_PASSED++))
else
    echo "  ✗ restore --secret 命令执行失败"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试9: restore --secret 后 FUSE 内容已更新
# ============================================
echo ""
echo "测试9: restore --secret 后通过 FUSE 读取内容已更新"
FUSE_AFTER_SECRET=$(cat "$SECRET_FILE" 2>&1)
FUSE_AFTER_SECRET_RESULT=$?

if [ $FUSE_AFTER_SECRET_RESULT -eq 0 ] && [ "$FUSE_AFTER_SECRET" = "$SECRET_ARG_CONTENT" ]; then
    echo "  ✓ restore --secret 后 FUSE 读取到更新后的内容"
    ((TESTS_PASSED++))
else
    echo "  ✗ restore --secret 后 FUSE 内容未更新"
    echo "    期望: '$SECRET_ARG_CONTENT'"
    echo "    实际: '$FUSE_AFTER_SECRET'"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试10: restore 不改变 baseline 元数据和规则
# ============================================
echo ""
echo "测试10: restore 后 baseline 元数据和规则未变"
INSPECT_OUTPUT=$("$PROJECT_ROOT/credctl" inspect --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER" 2>&1)
INSPECT_RESULT=$?

if [ $INSPECT_RESULT -eq 0 ]; then
    # 验证 strategy 和 permitted_program 未变
    if [[ "$INSPECT_OUTPUT" == *"strategy: BASIC"* ]] && [[ "$INSPECT_OUTPUT" == *"/bin/cat"* ]]; then
        echo "  ✓ restore 后 strategy 和 permitted_program 未变"
        ((TESTS_PASSED++))
    else
        echo "  ✗ restore 后元数据被意外修改"
        echo "    inspect 输出:"
        echo "$INSPECT_OUTPUT"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ inspect 失败"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试11: dump + sed + restore 组合用法
# ============================================
echo ""
echo "测试11: dump + sed + restore 组合用法"
echo "  先 restore 一个已知内容，然后通过 dump | sed | restore 修改"

# 先设置一个已知内容
KNOWN_CONTENT="user=admin password=old123"
echo ""
echo "----------------------------------------------"
echo "请注意：此步骤需要人工交互输入（共需输入 3 次密码）"
echo "当要求输入密码时，请输入初始化时设置的管理员密码"
echo "----------------------------------------------"
echo ""

"$PROJECT_ROOT/credctl" restore --config "$CREDCTL_CONFIG" -s "$KNOWN_CONTENT" "$SHA_IDENTIFIER"

# 使用 dump | sed | restore 组合
MODIFIED=$("$PROJECT_ROOT/credctl" dump --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER" | sed 's/password=old123/password=new456/g')
SED_RESULT=$?

if [ $SED_RESULT -ne 0 ] || [ -z "$MODIFIED" ]; then
    echo "  ✗ dump | sed 失败"
    ((TESTS_FAILED++))
else
    "$PROJECT_ROOT/credctl" restore --config "$CREDCTL_CONFIG" -s "$MODIFIED" "$SHA_IDENTIFIER"
    COMBO_RESULT=$?

    if [ $COMBO_RESULT -eq 0 ]; then
        # 验证 FUSE 读取到修改后的内容
        FUSE_COMBO=$(cat "$SECRET_FILE" 2>&1)
        EXPECTED_COMBO="user=admin password=new456"
        if [ "$FUSE_COMBO" = "$EXPECTED_COMBO" ]; then
            echo "  ✓ dump + sed + restore 组合用法成功"
            ((TESTS_PASSED++))
        else
            echo "  ✗ 组合用法后内容不正确"
            echo "    期望: '$EXPECTED_COMBO'"
            echo "    实际: '$FUSE_COMBO'"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ restore 阶段失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试12: dump 错误密码应失败
# ============================================
echo ""
echo "测试12: dump 使用错误密码应失败"
echo ""
echo "----------------------------------------------"
echo "请注意：此步骤需要人工交互输入"
echo "当要求输入密码时，请输入一个【错误的密码】"
echo "----------------------------------------------"
echo ""

"$PROJECT_ROOT/credctl" dump --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER" > /dev/null
DUMP_WRONG_RESULT=$?

if [ $DUMP_WRONG_RESULT -ne 0 ]; then
    echo "  ✓ 错误密码被正确拒绝"
    ((TESTS_PASSED++))
else
    echo "  ✗ 错误密码未被拒绝"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试13: restore 错误密码应失败
# ============================================
echo ""
echo "测试13: restore 使用错误密码应失败"
echo ""
echo "----------------------------------------------"
echo "请注意：此步骤需要人工交互输入"
echo "当要求输入密码时，请输入一个【错误的密码】"
echo "----------------------------------------------"
echo ""

"$PROJECT_ROOT/credctl" restore --config "$CREDCTL_CONFIG" -s "should-not-work" "$SHA_IDENTIFIER"
RESTORE_WRONG_RESULT=$?

if [ $RESTORE_WRONG_RESULT -ne 0 ]; then
    echo "  ✓ 错误密码被正确拒绝"
    ((TESTS_PASSED++))

    # 验证内容未被修改
    FUSE_UNCHANGED=$(cat "$SECRET_FILE" 2>&1)
    if [ "$FUSE_UNCHANGED" = "user=admin password=new456" ]; then
        echo "  ✓ 错误密码 restore 后内容未被修改"
        ((TESTS_PASSED++))
    else
        echo "  ✗ 错误密码 restore 后内容被意外修改"
        echo "    实际: '$FUSE_UNCHANGED'"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 错误密码未被拒绝"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试14: restore 缺少 --file 和 --secret 应失败
# ============================================
echo ""
echo "测试14: restore 缺少 --file 和 --secret 应失败"
RESTORE_NO_INPUT=$("$PROJECT_ROOT/credctl" restore --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER" 2>&1)
RESTORE_NO_INPUT_RESULT=$?

if [ $RESTORE_NO_INPUT_RESULT -ne 0 ]; then
    echo "  ✓ 缺少输入源被正确拒绝"
    ((TESTS_PASSED++))
else
    echo "  ✗ 缺少输入源未被拒绝"
    ((TESTS_FAILED++))
fi

# ============================================
# 清理: 释放凭据
# ============================================
echo ""
echo "清理: 释放测试凭据"
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
    echo "  ✓ 凭据释放成功"
else
    echo "  ⚠ 凭据释放失败，可能需要手动清理 (SHA: $SHA_IDENTIFIER)"
fi

# ============================================
# 测试结果汇总
# ============================================
echo ""
echo "=============================================="
echo "测试结果汇总"
echo "=============================================="
echo "  通过: $TESTS_PASSED"
echo "  失败: $TESTS_FAILED"
echo "  总计: $((TESTS_PASSED + TESTS_FAILED))"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo "全部通过 ✓"
    echo "=============================================="
    exit 0
else
    echo "存在失败的测试 ✗"
    echo "=============================================="
    echo ""
    echo "建议检查日志文件:"
    echo "  credagent 日志: $CREDAGENT_LOG"
    exit 1
fi
