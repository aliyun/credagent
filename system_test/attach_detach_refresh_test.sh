#!/bin/bash

# CredAgent attach / detach / refresh 功能系统测试
# 测试目标：验证 credctl attach、detach、refresh 命令功能
#   - attach: 追加授权程序（含 SHA256），已存在则 Skip 并给出 refresh 提示
#   - detach: 按程序路径逐对删除授权程序及其 SHA256
#   - refresh: 刷新已授权程序的 SHA256，未授权程序报 not_authorized 并给出 attach 提示
# 前置条件：已执行 init_test_environ.sh

echo "=============================================="
echo "CredAgent Attach / Detach / Refresh 功能测试"
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
SECRET_FILE="$SECRETS_DIR/test_attach_detach_refresh.txt"

# 授权程序
PROGRAM_CAT="/bin/cat"
PROGRAM_HEAD="/usr/bin/head"
PROGRAM_GREP="/usr/bin/grep"
PROGRAM_NOT_IN_LIST="/usr/bin/awk"

# ============================================
# 测试1: 创建并保护测试文件（初始仅授权 cat）
# ============================================
echo "测试1: 创建并保护测试文件（初始仅授权 cat）"

# 清理可能存在的旧文件或符号链接
if [ -L "$SECRET_FILE" ] || [ -f "$SECRET_FILE" ]; then
    echo "  清理已存在的文件/符号链接: $SECRET_FILE"
    rm -f "$SECRET_FILE"
fi

echo "attach detach refresh test secret value" > "$SECRET_FILE"

if [ -f "$SECRET_FILE" ] && [ ! -L "$SECRET_FILE" ]; then
    echo "  ✓ 测试文件已创建: $SECRET_FILE"

    PROTECT_OUTPUT=$("$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" \
        --strategy BASIC \
        -p "$PROGRAM_CAT" \
        --measure true \
        "$SECRET_FILE" 2>&1)
    PROTECT_RESULT=$?

    echo "  protect 输出: $PROTECT_OUTPUT"

    if [ $PROTECT_RESULT -eq 0 ]; then
        echo "  ✓ 文件已保护（授权程序: cat）"
        ((TESTS_PASSED++))
    else
        echo "  ✗ 文件保护失败"
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

SHA_LINE=$(echo "$LIST_OUTPUT" | grep -E "^[a-f0-9]+" | tail -n1)
if [ -n "$SHA_LINE" ]; then
    SHA_IDENTIFIER=$(echo "$SHA_LINE" | awk '{print $1}')
    echo "  ✓ SHA identifier: $SHA_IDENTIFIER"
    ((TESTS_PASSED++))
else
    echo "  ✗ 无法获取 SHA identifier"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试3: attach 追加新程序（head 和 grep）
# ============================================
echo ""
echo "测试3: attach 追加新程序（head 和 grep）"

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

    ATTACH_OUTPUT=$("$PROJECT_ROOT/credctl" attach --config "$CREDCTL_CONFIG" \
        -p "$PROGRAM_HEAD" \
        -p "$PROGRAM_GREP" \
        "$SHA_IDENTIFIER" 2>&1)
    ATTACH_RESULT=$?

    echo "attach 输出:"
    echo "$ATTACH_OUTPUT"

    if [ $ATTACH_RESULT -eq 0 ]; then
        if [[ "$ATTACH_OUTPUT" == *"Added (2)"* ]]; then
            echo "  ✓ attach 成功追加 2 个新程序"
            ((TESTS_PASSED++))
        else
            echo "  ✗ attach 输出格式不正确（期望 'Added (2)'）"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ attach 执行失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试4: 验证 inspect 包含所有三个授权程序
# ============================================
echo ""
echo "测试4: 验证 attach 后 inspect 包含全部三个授权程序"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过测试"
    ((TESTS_FAILED++))
else
    INSPECT_OUTPUT=$("$PROJECT_ROOT/credctl" inspect --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER" 2>&1)
    echo "inspect 输出:"
    echo "$INSPECT_OUTPUT"

    if [[ "$INSPECT_OUTPUT" == *"$PROGRAM_CAT"* ]] && \
       [[ "$INSPECT_OUTPUT" == *"$PROGRAM_HEAD"* ]] && \
       [[ "$INSPECT_OUTPUT" == *"$PROGRAM_GREP"* ]]; then
        echo "  ✓ inspect 显示了所有三个授权程序 (cat, head, grep)"
        ((TESTS_PASSED++))
    else
        echo "  ✗ inspect 未完整显示所有授权程序"
        ((TESTS_FAILED++))
    fi

    # 验证 program_sha256 数量与程序数量一致（计数 JSON 中 64 字符十六进制字符串）
    INSPECT_JSON=$("$PROJECT_ROOT/credctl" inspect --config "$CREDCTL_CONFIG" --json "$SHA_IDENTIFIER" 2>&1)
    SHA256_COUNT=$(echo "$INSPECT_JSON" | grep -oE '[0-9a-f]{64}' | wc -l)
    if [ "$SHA256_COUNT" -eq 3 ]; then
        echo "  ✓ program_sha256 有 3 个条目，与授权程序数量一致"
        ((TESTS_PASSED++))
    else
        echo "  ✗ program_sha256 条目数为 $SHA256_COUNT（期望 3）"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试5: 验证新追加的程序（head, grep）可访问文件
# ============================================
echo ""
echo "测试5: 验证新追加的程序（head, grep）可访问文件"

if [ -L "$SECRET_FILE" ]; then
    HEAD_OUTPUT=$(head -n1 "$SECRET_FILE" 2>&1)
    HEAD_RESULT=$?
    if [ $HEAD_RESULT -eq 0 ] && [[ "$HEAD_OUTPUT" == *"attach detach refresh test secret value"* ]]; then
        echo "  ✓ head（新增授权）可以访问文件"
        ((TESTS_PASSED++))
    else
        echo "  ✗ head 无法访问文件，输出: $HEAD_OUTPUT"
        ((TESTS_FAILED++))
    fi

    GREP_OUTPUT=$(grep "secret" "$SECRET_FILE" 2>&1)
    GREP_RESULT=$?
    if [ $GREP_RESULT -eq 0 ] && [[ "$GREP_OUTPUT" == *"secret"* ]]; then
        echo "  ✓ grep（新增授权）可以访问文件"
        ((TESTS_PASSED++))
    else
        echo "  ✗ grep 无法访问文件，输出: $GREP_OUTPUT"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 符号链接不存在，跳过访问测试"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试6: attach 重复追加已存在的程序（cat）—— 验证 Skipped 及 refresh 提示
# ============================================
echo ""
echo "测试6: attach 重复追加已存在的程序 cat（应显示 Skipped 及 refresh 提示）"

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

    ATTACH_DUP_OUTPUT=$("$PROJECT_ROOT/credctl" attach --config "$CREDCTL_CONFIG" \
        -p "$PROGRAM_CAT" \
        "$SHA_IDENTIFIER" 2>&1)
    ATTACH_DUP_RESULT=$?

    echo "attach（重复）输出:"
    echo "$ATTACH_DUP_OUTPUT"

    if [ $ATTACH_DUP_RESULT -eq 0 ]; then
        if [[ "$ATTACH_DUP_OUTPUT" == *"Skipped (1)"* ]]; then
            echo "  ✓ attach 正确报告已存在的程序为 Skipped"
            ((TESTS_PASSED++))
        else
            echo "  ✗ attach 未正确报告 Skipped"
            ((TESTS_FAILED++))
        fi

        if [[ "$ATTACH_DUP_OUTPUT" == *"credctl refresh"* ]]; then
            echo "  ✓ attach 输出中包含了 refresh 提示"
            ((TESTS_PASSED++))
        else
            echo "  ✗ attach 输出中缺少 refresh 提示"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ attach（重复）执行失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试7: detach 删除 grep
# ============================================
echo ""
echo "测试7: detach 删除 grep"

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

    DETACH_OUTPUT=$("$PROJECT_ROOT/credctl" detach --config "$CREDCTL_CONFIG" \
        -p "$PROGRAM_GREP" \
        "$SHA_IDENTIFIER" 2>&1)
    DETACH_RESULT=$?

    echo "detach 输出:"
    echo "$DETACH_OUTPUT"

    if [ $DETACH_RESULT -eq 0 ]; then
        if [[ "$DETACH_OUTPUT" == *"Removed (1)"* ]] && [[ "$DETACH_OUTPUT" == *"$PROGRAM_GREP"* ]]; then
            echo "  ✓ detach 成功删除 grep"
            ((TESTS_PASSED++))
        else
            echo "  ✗ detach 输出格式不正确（期望 'Removed (1)' 含 grep 路径）"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ detach 执行失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试8: 验证 detach 后 inspect 不再包含 grep
# ============================================
echo ""
echo "测试8: 验证 detach 后 inspect 不再包含 grep"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过测试"
    ((TESTS_FAILED++))
else
    INSPECT_OUTPUT=$("$PROJECT_ROOT/credctl" inspect --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER" 2>&1)
    echo "inspect 输出（detach 后）:"
    echo "$INSPECT_OUTPUT"

    if [[ "$INSPECT_OUTPUT" != *"$PROGRAM_GREP"* ]]; then
        echo "  ✓ inspect 不再显示已删除的 grep"
        ((TESTS_PASSED++))
    else
        echo "  ✗ inspect 仍然显示已删除的 grep"
        ((TESTS_FAILED++))
    fi

    if [[ "$INSPECT_OUTPUT" == *"$PROGRAM_CAT"* ]] && [[ "$INSPECT_OUTPUT" == *"$PROGRAM_HEAD"* ]]; then
        echo "  ✓ inspect 仍然显示保留的 cat 和 head"
        ((TESTS_PASSED++))
    else
        echo "  ✗ inspect 未正确保留 cat 和 head"
        ((TESTS_FAILED++))
    fi

    # 验证 SHA256 数量也减少为 2
    INSPECT_JSON=$("$PROJECT_ROOT/credctl" inspect --config "$CREDCTL_CONFIG" --json "$SHA_IDENTIFIER" 2>&1)
    SHA256_COUNT=$(echo "$INSPECT_JSON" | grep -oE '[0-9a-f]{64}' | wc -l)
    if [ "$SHA256_COUNT" -eq 2 ]; then
        echo "  ✓ program_sha256 减少为 2 个条目，与授权程序数量一致"
        ((TESTS_PASSED++))
    else
        echo "  ✗ program_sha256 条目数为 $SHA256_COUNT（期望 2）"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试9: 验证 detach 后 grep 无法访问文件，head 仍可访问
# ============================================
echo ""
echo "测试9: 验证 detach 后访问权限变化"

if [ -L "$SECRET_FILE" ]; then
    GREP_OUTPUT=$(grep "secret" "$SECRET_FILE" 2>&1)
    GREP_RESULT=$?
    if [ $GREP_RESULT -ne 0 ] || [[ "$GREP_OUTPUT" != *"secret"* ]]; then
        echo "  ✓ grep（已撤销授权）无法访问文件"
        ((TESTS_PASSED++))
    else
        echo "  ✗ grep（已撤销授权）意外仍能访问文件"
        ((TESTS_FAILED++))
    fi

    HEAD_OUTPUT=$(head -n1 "$SECRET_FILE" 2>&1)
    HEAD_RESULT=$?
    if [ $HEAD_RESULT -eq 0 ] && [[ "$HEAD_OUTPUT" == *"attach detach refresh test secret value"* ]]; then
        echo "  ✓ head（仍在授权列表）可以访问文件"
        ((TESTS_PASSED++))
    else
        echo "  ✗ head 无法访问文件，输出: $HEAD_OUTPUT"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 符号链接不存在，跳过访问测试"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试10: detach 后重新 attach（re-attach grep，验证访问恢复）
# ============================================
echo ""
echo "测试10: detach 后重新 attach grep（验证访问恢复）"

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

    REATTACH_OUTPUT=$("$PROJECT_ROOT/credctl" attach --config "$CREDCTL_CONFIG" \
        -p "$PROGRAM_GREP" \
        "$SHA_IDENTIFIER" 2>&1)
    REATTACH_RESULT=$?

    echo "re-attach 输出:"
    echo "$REATTACH_OUTPUT"

    if [ $REATTACH_RESULT -eq 0 ]; then
        if [[ "$REATTACH_OUTPUT" == *"Added (1)"* ]]; then
            echo "  ✓ re-attach grep 成功（Added (1)）"
            ((TESTS_PASSED++))
        else
            echo "  ✗ re-attach 输出格式不正确（期望 'Added (1)'）"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ re-attach 执行失败"
        ((TESTS_FAILED++))
    fi

    # 验证 grep 访问恢复
    if [ -L "$SECRET_FILE" ]; then
        GREP_REATTACH_OUTPUT=$(grep "secret" "$SECRET_FILE" 2>&1)
        GREP_REATTACH_RESULT=$?
        if [ $GREP_REATTACH_RESULT -eq 0 ] && [[ "$GREP_REATTACH_OUTPUT" == *"secret"* ]]; then
            echo "  ✓ re-attach 后 grep 可以重新访问文件"
            ((TESTS_PASSED++))
        else
            echo "  ✗ re-attach 后 grep 仍然无法访问文件"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ 符号链接不存在，跳过访问验证"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试11: 混合 attach（已存在程序 + 新程序，验证 Added/Skipped 计数）
# ============================================
echo ""
echo "测试11: 混合 attach（已存在 grep + 新增 awk，验证 Added/Skipped 计数）"

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

    MIXED_OUTPUT=$("$PROJECT_ROOT/credctl" attach --config "$CREDCTL_CONFIG" \
        -p "$PROGRAM_GREP" \
        -p "$PROGRAM_NOT_IN_LIST" \
        "$SHA_IDENTIFIER" 2>&1)
    MIXED_RESULT=$?

    echo "混合 attach 输出:"
    echo "$MIXED_OUTPUT"

    if [ $MIXED_RESULT -eq 0 ]; then
        if [[ "$MIXED_OUTPUT" == *"Added (1)"* ]]; then
            echo "  ✓ 混合 attach 正确报告新增 1 个程序（awk）"
            ((TESTS_PASSED++))
        else
            echo "  ✗ 混合 attach 未正确报告 Added (1)"
            ((TESTS_FAILED++))
        fi

        if [[ "$MIXED_OUTPUT" == *"Skipped (1)"* ]]; then
            echo "  ✓ 混合 attach 正确报告跳过 1 个已存在程序（grep）"
            ((TESTS_PASSED++))
        else
            echo "  ✗ 混合 attach 未正确报告 Skipped (1)"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ 混合 attach 执行失败"
        ((TESTS_FAILED++))
    fi

    # 验证现在有 4 个授权程序
    INSPECT_JSON=$("$PROJECT_ROOT/credctl" inspect --config "$CREDCTL_CONFIG" --json "$SHA_IDENTIFIER" 2>&1)
    SHA256_COUNT=$(echo "$INSPECT_JSON" | grep -oE '[0-9a-f]{64}' | wc -l)
    if [ "$SHA256_COUNT" -eq 4 ]; then
        echo "  ✓ 混合 attach 后共有 4 个授权程序 (cat, head, grep, awk)"
        ((TESTS_PASSED++))
    else
        echo "  ✗ 混合 attach 后 program_sha256 条目数为 $SHA256_COUNT（期望 4）"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试12: detach 多个程序（同时删除 grep 和 awk）
# ============================================
echo ""
echo "测试12: detach 多个程序（同时删除 grep 和 awk）"

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

    DETACH_MULTI_OUTPUT=$("$PROJECT_ROOT/credctl" detach --config "$CREDCTL_CONFIG" \
        -p "$PROGRAM_GREP" \
        -p "$PROGRAM_NOT_IN_LIST" \
        "$SHA_IDENTIFIER" 2>&1)
    DETACH_MULTI_RESULT=$?

    echo "detach 多个程序输出:"
    echo "$DETACH_MULTI_OUTPUT"

    if [ $DETACH_MULTI_RESULT -eq 0 ]; then
        if [[ "$DETACH_MULTI_OUTPUT" == *"Removed (2)"* ]]; then
            echo "  ✓ detach 成功删除 2 个程序"
            ((TESTS_PASSED++))
        else
            echo "  ✗ detach 输出格式不正确（期望 'Removed (2)'）"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ detach 多个程序执行失败"
        ((TESTS_FAILED++))
    fi

    # 验证现在只剩 2 个授权程序 (cat, head)
    INSPECT_JSON=$("$PROJECT_ROOT/credctl" inspect --config "$CREDCTL_CONFIG" --json "$SHA_IDENTIFIER" 2>&1)
    SHA256_COUNT=$(echo "$INSPECT_JSON" | grep -oE '[0-9a-f]{64}' | wc -l)
    if [ "$SHA256_COUNT" -eq 2 ]; then
        echo "  ✓ detach 多个程序后剩余 2 个授权程序 (cat, head)"
        ((TESTS_PASSED++))
    else
        echo "  ✗ detach 后 program_sha256 条目数为 $SHA256_COUNT（期望 2）"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试13: refresh 不指定 -p（刷新全部授权程序）
# ============================================
echo ""
echo "测试13: refresh 不指定 -p（刷新全部授权程序）"

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

    REFRESH_ALL_OUTPUT=$("$PROJECT_ROOT/credctl" refresh --config "$CREDCTL_CONFIG" \
        "$SHA_IDENTIFIER" 2>&1)
    REFRESH_ALL_RESULT=$?

    echo "refresh（全部）输出:"
    echo "$REFRESH_ALL_OUTPUT"

    if [ $REFRESH_ALL_RESULT -eq 0 ]; then
        if [[ "$REFRESH_ALL_OUTPUT" == *"2 已刷新"* ]]; then
            echo "  ✓ refresh 不指定 -p 成功刷新全部 2 个授权程序"
            ((TESTS_PASSED++))
        else
            echo "  ✗ refresh 输出格式不正确（期望 '2 已刷新'）"
            ((TESTS_FAILED++))
        fi

        # 验证每个程序都有 [刷新] 记录
        REFRESH_COUNT=$(echo "$REFRESH_ALL_OUTPUT" | grep -c "刷新" || true)
        if [ "$REFRESH_COUNT" -ge 2 ]; then
            echo "  ✓ refresh 输出中包含了每个程序的刷新记录"
            ((TESTS_PASSED++))
        else
            echo "  ✗ refresh 输出中刷新记录数不足（找到 $REFRESH_COUNT，期望 >= 2）"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ refresh（全部）执行失败"
        ((TESTS_FAILED++))
    fi

    # 验证刷新后仍可访问
    if [ -L "$SECRET_FILE" ]; then
        CAT_OUTPUT=$(cat "$SECRET_FILE" 2>&1)
        CAT_RESULT=$?
        if [ $CAT_RESULT -eq 0 ] && [[ "$CAT_OUTPUT" == *"attach detach refresh test secret value"* ]]; then
            echo "  ✓ refresh 全部后 cat 仍可访问文件"
            ((TESTS_PASSED++))
        else
            echo "  ✗ refresh 全部后 cat 无法访问文件，输出: $CAT_OUTPUT"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ 符号链接不存在，跳过访问验证"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试14: detach 不存在的程序（not_found 分支）
# ============================================
echo ""
echo "测试14: detach 不在授权列表中的程序（$PROGRAM_NOT_IN_LIST）"

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

    DETACH_NF_OUTPUT=$("$PROJECT_ROOT/credctl" detach --config "$CREDCTL_CONFIG" \
        -p "$PROGRAM_NOT_IN_LIST" \
        "$SHA_IDENTIFIER" 2>&1)
    DETACH_NF_RESULT=$?

    echo "detach（不存在程序）输出:"
    echo "$DETACH_NF_OUTPUT"

    if [ $DETACH_NF_RESULT -eq 0 ]; then
        if [[ "$DETACH_NF_OUTPUT" == *"Not found (1)"* ]] && [[ "$DETACH_NF_OUTPUT" == *"$PROGRAM_NOT_IN_LIST"* ]]; then
            echo "  ✓ detach 正确报告未授权的程序为 Not found"
            ((TESTS_PASSED++))
        else
            echo "  ✗ detach 未正确报告 Not found"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ detach 执行失败（期望成功并报告 not_found）"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试15: refresh 刷新已授权程序 SHA256（cat 和 head）
# ============================================
echo ""
echo "测试15: refresh 刷新 cat 和 head 的 SHA256"

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

    REFRESH_OUTPUT=$("$PROJECT_ROOT/credctl" refresh --config "$CREDCTL_CONFIG" \
        -p "$PROGRAM_CAT" \
        -p "$PROGRAM_HEAD" \
        "$SHA_IDENTIFIER" 2>&1)
    REFRESH_RESULT=$?

    echo "refresh 输出:"
    echo "$REFRESH_OUTPUT"

    if [ $REFRESH_RESULT -eq 0 ]; then
        if [[ "$REFRESH_OUTPUT" == *"2 已刷新"* ]]; then
            echo "  ✓ refresh 成功刷新 2 个程序的 SHA256"
            ((TESTS_PASSED++))
        else
            echo "  ✗ refresh 输出格式不正确（期望 '2 已刷新'）"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ refresh 执行失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试16: 验证 refresh 后 inspect program_sha256 仍有 2 个条目
# ============================================
echo ""
echo "测试16: 验证 refresh 后 program_sha256 条目数不变"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过测试"
    ((TESTS_FAILED++))
else
    INSPECT_JSON=$("$PROJECT_ROOT/credctl" inspect --config "$CREDCTL_CONFIG" --json "$SHA_IDENTIFIER" 2>&1)
    SHA256_COUNT=$(echo "$INSPECT_JSON" | grep -oE '[0-9a-f]{64}' | wc -l)
    if [ "$SHA256_COUNT" -eq 2 ]; then
        echo "  ✓ refresh 后 program_sha256 仍有 2 个条目"
        ((TESTS_PASSED++))
    else
        echo "  ✗ refresh 后 program_sha256 条目数为 $SHA256_COUNT（期望 2）"
        ((TESTS_FAILED++))
    fi

    # 验证刷新后授权程序仍可访问文件
    if [ -L "$SECRET_FILE" ]; then
        CAT_OUTPUT=$(cat "$SECRET_FILE" 2>&1)
        CAT_RESULT=$?
        if [ $CAT_RESULT -eq 0 ] && [[ "$CAT_OUTPUT" == *"attach detach refresh test secret value"* ]]; then
            echo "  ✓ refresh 后 cat 仍可访问文件（measure 验证通过）"
            ((TESTS_PASSED++))
        else
            echo "  ✗ refresh 后 cat 无法访问文件，输出: $CAT_OUTPUT"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ 符号链接不存在，跳过访问验证"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试17: refresh 未授权程序（not_authorized 分支）
# ============================================
echo ""
echo "测试17: refresh 不在授权列表中的程序 grep（not_authorized 分支）"

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

    REFRESH_NA_OUTPUT=$("$PROJECT_ROOT/credctl" refresh --config "$CREDCTL_CONFIG" \
        -p "$PROGRAM_GREP" \
        "$SHA_IDENTIFIER" 2>&1)
    REFRESH_NA_RESULT=$?

    echo "refresh（未授权程序）输出:"
    echo "$REFRESH_NA_OUTPUT"

    if [ $REFRESH_NA_RESULT -eq 0 ]; then
        if [[ "$REFRESH_NA_OUTPUT" == *"未授权"* ]] && [[ "$REFRESH_NA_OUTPUT" == *"$PROGRAM_GREP"* ]]; then
            echo "  ✓ refresh 正确报告未授权的程序"
            ((TESTS_PASSED++))
        else
            echo "  ✗ refresh 未正确报告未授权程序"
            ((TESTS_FAILED++))
        fi

        if [[ "$REFRESH_NA_OUTPUT" == *"credctl attach"* ]]; then
            echo "  ✓ refresh 输出中包含了 attach 提示"
            ((TESTS_PASSED++))
        else
            echo "  ✗ refresh 输出中缺少 attach 提示"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ refresh 执行失败（期望成功并报告未授权）"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试18: 清理 —— remove 保护文件
# ============================================
echo ""
echo "测试18: 清理 —— remove 保护文件"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过清理"
    ((TESTS_FAILED++))
else
    # 先删除符号链接
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
            echo "  ✓ remove 清理成功"
            ((TESTS_PASSED++))
        else
            echo "  ✗ remove 输出格式不正确"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ remove 执行失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试19: 验证文件已从 enclave 移除
# ============================================
echo ""
echo "测试19: 验证文件已从 enclave 移除 (list)"

LIST_AFTER=$("$PROJECT_ROOT/credctl" list --config "$CREDCTL_CONFIG" 2>&1)
echo "list 输出（remove 后）:"
echo "$LIST_AFTER"

if [[ "$LIST_AFTER" == *"Total Count: 0"* ]] || [[ "$LIST_AFTER" != *"$SHA_IDENTIFIER"* ]]; then
    echo "  ✓ 文件已从 enclave 移除"
    ((TESTS_PASSED++))
else
    echo "  ✗ 文件仍然存在于 enclave 中"
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
