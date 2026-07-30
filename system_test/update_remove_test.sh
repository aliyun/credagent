#!/bin/bash

# CredAgent update/remove 功能系统测试
# 测试目标：验证 credctl update 和 remove 命令功能
# 前置条件：已执行 init_test_environ.sh

echo "=============================================="
echo "CredAgent Update/Remove 功能测试"
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
SHA_IDENTIFIER=""
SECRET_FILE="$SECRETS_DIR/test_update_remove.txt"

# ============================================
# 测试1: 创建并保护测试文件
# ============================================
echo "测试1: 创建并保护测试文件"

# 清理可能存在的旧文件或符号链接
if [ -L "$SECRET_FILE" ] || [ -f "$SECRET_FILE" ]; then
    echo "  清理已存在的文件/符号链接: $SECRET_FILE"
    rm -f "$SECRET_FILE"
fi

echo "secret content for update/remove test" > "$SECRET_FILE"

if [ -f "$SECRET_FILE" ] && [ ! -L "$SECRET_FILE" ]; then
    echo "  ✓ 测试文件已创建: $SECRET_FILE"
    
    # 保护文件
    PROTECT_OUTPUT=$("$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" --strategy BASIC --program-permit /bin/cat --measure true "$SECRET_FILE" 2>&1)
    PROTECT_RESULT=$?
    
    if [ $PROTECT_RESULT -eq 0 ]; then
        echo "  ✓ 文件已保护"
        ((TESTS_PASSED++))
    else
        echo "  ✗ 文件保护失败: $PROTECT_OUTPUT"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 测试文件创建失败"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试2: 获取 SHA identifier
# ============================================
echo ""
echo "测试2: 获取 SHA identifier"

LIST_OUTPUT=$("$PROJECT_ROOT/credctl" list --config "$CREDCTL_CONFIG" 2>&1)

echo "list 输出:"
echo "$LIST_OUTPUT"

# 从 list 输出提取 SHA identifier
SHA_LINE=$(echo "$LIST_OUTPUT" | grep -E "^[a-f0-9]+" | head -n1)
if [ -n "$SHA_LINE" ]; then
    SHA_IDENTIFIER=$(echo "$SHA_LINE" | awk '{print $1}')
    echo "  ✓ SHA identifier: $SHA_IDENTIFIER"
    ((TESTS_PASSED++))
else
    echo "  ✗ 无法获取 SHA identifier"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试3: 更新 strategy
# ============================================
echo ""
echo "测试3: 更新 strategy (BASIC -> ONE_TIME_USE)"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过测试"
    ((TESTS_FAILED++))
else
    echo ""
    echo "----------------------------------------------"
    echo "请注意：此步骤需要人工交互输入"
    echo "当要求输入密码时，请输入初始化时设置的管理员密码"
    echo "----------------------------------------------"
    echo ""
    
    UPDATE_OUTPUT=$("$PROJECT_ROOT/credctl" update --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER" --strategy ONE_TIME_USE 2>&1)
    UPDATE_RESULT=$?
    
    echo "update 输出:"
    echo "$UPDATE_OUTPUT"
    
    if [ $UPDATE_RESULT -eq 0 ]; then
        if [[ "$UPDATE_OUTPUT" == *"Successfully updated"* ]] && [[ "$UPDATE_OUTPUT" == *"ONE_TIME_USE"* ]]; then
            echo "  ✓ strategy 更新成功"
            ((TESTS_PASSED++))
        else
            echo "  ✗ strategy 更新输出格式不正确"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ strategy 更新失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试4: 验证 strategy 更新生效
# ============================================
echo ""
echo "测试4: 验证 strategy 更新生效 (inspect)"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过测试"
    ((TESTS_FAILED++))
else
    INSPECT_OUTPUT=$("$PROJECT_ROOT/credctl" inspect --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER" 2>&1)
    
    echo "inspect 输出:"
    echo "$INSPECT_OUTPUT"
    
    if [[ "$INSPECT_OUTPUT" == *"strategy: ONE_TIME_USE"* ]]; then
        echo "  ✓ strategy 已更新为 ONE_TIME_USE"
        ((TESTS_PASSED++))
    else
        echo "  ✗ strategy 未正确更新"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试5: 更新 open-frequency
# ============================================
echo ""
echo "测试5: 更新 open-frequency"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过测试"
    ((TESTS_FAILED++))
else
    echo ""
    echo "----------------------------------------------"
    echo "请注意：此步骤需要人工交互输入"
    echo "当要求输入密码时，请输入初始化时设置的管理员密码"
    echo "----------------------------------------------"
    echo ""
    
    UPDATE_OUTPUT=$("$PROJECT_ROOT/credctl" update --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER" --open-frequency 5 2>&1)
    UPDATE_RESULT=$?
    
    echo "update 输出:"
    echo "$UPDATE_OUTPUT"
    
    if [ $UPDATE_RESULT -eq 0 ]; then
        if [[ "$UPDATE_OUTPUT" == *"Successfully updated"* ]] && [[ "$UPDATE_OUTPUT" == *"max open count: 5"* ]]; then
            echo "  ✓ open-frequency 更新成功"
            ((TESTS_PASSED++))
        else
            echo "  ✗ open-frequency 更新输出格式不正确"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ open-frequency 更新失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试6: 验证 open-frequency 更新生效
# ============================================
echo ""
echo "测试6: 验证 open-frequency 更新生效 (inspect)"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过测试"
    ((TESTS_FAILED++))
else
    INSPECT_OUTPUT=$("$PROJECT_ROOT/credctl" inspect --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER" 2>&1)
    
    echo "inspect 输出:"
    echo "$INSPECT_OUTPUT"
    
    if [[ "$INSPECT_OUTPUT" == *"open_frequency: 5"* ]]; then
        echo "  ✓ open-frequency 已更新为 5"
        ((TESTS_PASSED++))
    else
        echo "  ✗ open-frequency 未正确更新"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试7: 更新 program-permit (with measure)
# ============================================
echo ""
echo "测试7: 更新 program-permit (with measure=true)"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过测试"
    ((TESTS_FAILED++))
else
    echo ""
    echo "----------------------------------------------"
    echo "请注意：此步骤需要人工交互输入"
    echo "当要求输入密码时，请输入初始化时设置的管理员密码"
    echo "----------------------------------------------"
    echo ""
    
    UPDATE_OUTPUT=$("$PROJECT_ROOT/credctl" update --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER" --program-permit /bin/cat --measure true 2>&1)
    UPDATE_RESULT=$?
    
    echo "update 输出:"
    echo "$UPDATE_OUTPUT"
    
    if [ $UPDATE_RESULT -eq 0 ]; then
        if [[ "$UPDATE_OUTPUT" == *"Successfully updated"* ]] && [[ "$UPDATE_OUTPUT" == *"allowed binaries"* ]]; then
            echo "  ✓ program-permit 更新成功"
            ((TESTS_PASSED++))
        else
            echo "  ✗ program-permit 更新输出格式不正确"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ program-permit 更新失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试8: 更新 writable
# ============================================
echo ""
echo "测试8: 更新 writable (true)"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过测试"
    ((TESTS_FAILED++))
else
    echo ""
    echo "----------------------------------------------"
    echo "请注意：此步骤需要人工交互输入"
    echo "当要求输入密码时，请输入初始化时设置的管理员密码"
    echo "----------------------------------------------"
    echo ""
    
    UPDATE_OUTPUT=$("$PROJECT_ROOT/credctl" update --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER" --writable true 2>&1)
    UPDATE_RESULT=$?
    
    echo "update 输出:"
    echo "$UPDATE_OUTPUT"
    
    if [ $UPDATE_RESULT -eq 0 ]; then
        if [[ "$UPDATE_OUTPUT" == *"Successfully updated"* ]] && [[ "$UPDATE_OUTPUT" == *"writable: true"* ]]; then
            echo "  ✓ writable 更新成功"
            ((TESTS_PASSED++))
        else
            echo "  ✗ writable 更新输出格式不正确"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ writable 更新失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试9: 验证 writable 更新生效
# ============================================
echo ""
echo "测试9: 验证 writable 更新生效 (inspect)"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过测试"
    ((TESTS_FAILED++))
else
    INSPECT_OUTPUT=$("$PROJECT_ROOT/credctl" inspect --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER" 2>&1)
    
    echo "inspect 输出:"
    echo "$INSPECT_OUTPUT"
    
    if [[ "$INSPECT_OUTPUT" == *"writable: true"* ]]; then
        echo "  ✓ writable 已更新为 true"
        ((TESTS_PASSED++))
    else
        echo "  ✗ writable 未正确更新"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试10: remove 命令测试
# ============================================
echo ""
echo "测试10: remove 命令测试"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过测试"
    ((TESTS_FAILED++))
else
    echo "使用 SHA identifier: $SHA_IDENTIFIER"
    
    # 先删除符号链接（如果存在）
    if [ -L "$SECRET_FILE" ]; then
        echo "  删除符号链接: $SECRET_FILE"
        rm -f "$SECRET_FILE"
    fi
    
    echo ""
    echo "----------------------------------------------"
    echo "请注意：此步骤需要人工交互输入"
    echo "当要求输入密码时，请输入初始化时设置的管理员密码"
    echo "----------------------------------------------"
    echo ""
    
    REMOVE_OUTPUT=$("$PROJECT_ROOT/credctl" remove --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER" 2>&1)
    REMOVE_RESULT=$?
    
    echo "remove 输出:"
    echo "$REMOVE_OUTPUT"
    
    if [ $REMOVE_RESULT -eq 0 ]; then
        if [[ "$REMOVE_OUTPUT" == *"Successfully removed"* ]]; then
            echo "  ✓ remove 命令执行成功"
            ((TESTS_PASSED++))
        else
            echo "  ✗ remove 输出格式不正确"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ remove 命令执行失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试11: 验证文件已从 enclave 移除
# ============================================
echo ""
echo "测试11: 验证文件已从 enclave 移除 (list)"

LIST_OUTPUT_AFTER=$("$PROJECT_ROOT/credctl" list --config "$CREDCTL_CONFIG" 2>&1)

echo "list 输出（remove 后）:"
echo "$LIST_OUTPUT_AFTER"

if [[ "$LIST_OUTPUT_AFTER" == *"Total Count: 0"* ]] || [[ "$LIST_OUTPUT_AFTER" != *"$SHA_IDENTIFIER"* ]]; then
    echo "  ✓ 文件已从 enclave 移除"
    ((TESTS_PASSED++))
else
    echo "  ✗ 文件仍然存在于 enclave 中"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试12: 验证原文件未恢复（remove 不恢复文件）
# ============================================
echo ""
echo "测试12: 验证原文件未恢复（remove 不恢复文件）"

if [ ! -f "$SECRET_FILE" ] && [ ! -L "$SECRET_FILE" ]; then
    echo "  ✓ 原文件未恢复（符合 remove 行为）"
    ((TESTS_PASSED++))
else
    echo "  ✗ 原文件意外存在"
    if [ -L "$SECRET_FILE" ]; then
        echo "    文件类型: 符号链接"
    else
        echo "    文件类型: 普通文件"
    fi
    ((TESTS_FAILED++))
fi

# ============================================
# 测试13: 验证挂载点虚拟文件已删除
# ============================================
echo ""
echo "测试13: 验证挂载点虚拟文件已删除"

if [ -n "$SHA_IDENTIFIER" ]; then
    VIRTUAL_FILE="$MOUNT_POINT/$SHA_IDENTIFIER"
    if [ ! -f "$VIRTUAL_FILE" ]; then
        echo "  ✓ 挂载点虚拟文件已删除"
        ((TESTS_PASSED++))
    else
        echo "  ✗ 挂载点虚拟文件仍然存在"
        ((TESTS_FAILED++))
    fi
else
    echo "  - 跳过测试：SHA identifier 未知"
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