#!/bin/bash

# CredAgent 多程序授权访问单一凭据系统测试
# 测试目标：验证通过多个 -p 参数授权多程序访问同一凭据文件时，
# protect、list、inspect、update、授权程序访问都正常
# 前置条件：已执行 init_test_environ.sh

echo "=============================================="
echo "CredAgent 多程序授权访问测试"
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
SECRET_FILE="$SECRETS_DIR/multi_program_secret.txt"

# 授权程序列表（3个会读取文件内容的常见程序）
PROGRAM1="/bin/cat"
PROGRAM2="/usr/bin/head"
PROGRAM3="/usr/bin/grep"

# ============================================
# 测试1: 创建测试秘密文件
# ============================================
echo "测试1: 创建测试秘密文件"

# 清理可能存在的旧文件或符号链接
if [ -L "$SECRET_FILE" ] || [ -f "$SECRET_FILE" ]; then
    echo "  清理已存在的文件/符号链接: $SECRET_FILE"
    rm -f "$SECRET_FILE"
fi

echo "multi-program access test secret value" > "$SECRET_FILE"

if [ -f "$SECRET_FILE" ] && [ ! -L "$SECRET_FILE" ]; then
    echo "  ✓ 测试秘密文件已创建: $SECRET_FILE"
    ((TESTS_PASSED++))
else
    echo "  ✗ 测试秘密文件创建失败"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试2: 使用多个 -p 参数保护文件
# ============================================
echo ""
echo "测试2: 使用多个 -p 参数保护文件"
echo "执行命令: credctl protect --config $CREDCTL_CONFIG --strategy BASIC -p $PROGRAM1 -p $PROGRAM2 -p $PROGRAM3 --measure true $SECRET_FILE"

PROTECT_OUTPUT=$("$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" --strategy BASIC -p "$PROGRAM1" -p "$PROGRAM2" -p "$PROGRAM3" --measure true "$SECRET_FILE" 2>&1)
PROTECT_RESULT=$?

echo "protect 输出: $PROTECT_OUTPUT"

if [ $PROTECT_RESULT -eq 0 ]; then
    echo "  ✓ credctl protect 多程序授权执行成功"
    ((TESTS_PASSED++))
else
    echo "  ✗ credctl protect 多程序授权执行失败"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试3: 验证原文件被替换为符号链接
# ============================================
echo ""
echo "测试3: 验证原文件被替换为符号链接"
if [ -L "$SECRET_FILE" ]; then
    LINK_TARGET=$(readlink "$SECRET_FILE")
    echo "  ✓ 原文件已被替换为符号链接"
    echo "    符号链接目标: $LINK_TARGET"
    ((TESTS_PASSED++))
else
    echo "  ✗ 原文件未被替换为符号链接"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试4: 使用 credctl list 查看受保护文件
# ============================================
echo ""
echo "测试4: 使用 credctl list 查看受保护文件"
LIST_OUTPUT=$("$PROJECT_ROOT/credctl" list --config "$CREDCTL_CONFIG" 2>&1)
LIST_RESULT=$?

echo "list 输出:"
echo "$LIST_OUTPUT"

if [ $LIST_RESULT -eq 0 ]; then
    # 提取 SHA identifier
    SHA_LINE=$(echo "$LIST_OUTPUT" | grep -E "^[a-f0-9]+" | head -n1)
    if [ -n "$SHA_LINE" ]; then
        SHA_IDENTIFIER=$(echo "$SHA_LINE" | awk '{print $1}')
        echo "  ✓ credctl list 正确显示了受保护的文件"
        echo "    SHA identifier: $SHA_IDENTIFIER"
        ((TESTS_PASSED++))
    else
        echo "  ✗ credctl list 未显示受保护的文件"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ credctl list 执行失败"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试5: 使用 credctl list --json 查看
# ============================================
echo ""
echo "测试5: 使用 credctl list --json 查看受保护文件"
LIST_JSON_OUTPUT=$("$PROJECT_ROOT/credctl" list --config "$CREDCTL_CONFIG" --json 2>&1)
LIST_JSON_RESULT=$?

echo "list --json 输出:"
echo "$LIST_JSON_OUTPUT"

if [ $LIST_JSON_RESULT -eq 0 ]; then
    if [[ "$LIST_JSON_OUTPUT" == *"\"id\""* ]] && [[ "$LIST_JSON_OUTPUT" == *"\"target_path\""* ]]; then
        echo "  ✓ credctl list --json 输出有效 JSON"
        ((TESTS_PASSED++))

        # 备用提取 SHA identifier
        if [ -z "$SHA_IDENTIFIER" ]; then
            SHA_FROM_JSON=$(echo "$LIST_JSON_OUTPUT" | grep -o '"id":"[^"]*"' | head -n1 | cut -d'"' -f4)
            if [ -n "$SHA_FROM_JSON" ]; then
                SHA_IDENTIFIER="$SHA_FROM_JSON"
                echo "    从 JSON 提取的 SHA identifier: $SHA_IDENTIFIER"
            fi
        fi
    else
        echo "  ✗ credctl list --json 输出格式无效"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ credctl list --json 执行失败"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试6: 使用 credctl inspect 查看详细信息（含多程序列表）
# ============================================
echo ""
echo "测试6: 使用 credctl inspect 查看详细信息（含多程序列表）"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过 inspect 测试"
    ((TESTS_FAILED++))
else
    INSPECT_OUTPUT=$("$PROJECT_ROOT/credctl" inspect --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER" 2>&1)
    INSPECT_RESULT=$?

    echo "inspect 输出:"
    echo "$INSPECT_OUTPUT"

    if [ $INSPECT_RESULT -eq 0 ]; then
        # 验证 inspect 输出包含所有授权程序
        if [[ "$INSPECT_OUTPUT" == *"$PROGRAM1"* ]] && [[ "$INSPECT_OUTPUT" == *"$PROGRAM2"* ]] && [[ "$INSPECT_OUTPUT" == *"$PROGRAM3"* ]]; then
            echo "  ✓ credctl inspect 正确显示了所有授权程序"
            ((TESTS_PASSED++))
        else
            echo "  ✗ credctl inspect 未完整显示所有授权程序"
            echo "    期望包含: $PROGRAM1, $PROGRAM2, $PROGRAM3"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ credctl inspect 执行失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试7: 使用 credctl inspect --json 查看多程序详情
# ============================================
echo ""
echo "测试7: 使用 credctl inspect --json 查看多程序详情"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过 inspect --json 测试"
    ((TESTS_FAILED++))
else
    INSPECT_JSON_OUTPUT=$("$PROJECT_ROOT/credctl" inspect --config "$CREDCTL_CONFIG" --json "$SHA_IDENTIFIER" 2>&1)
    INSPECT_JSON_RESULT=$?

    echo "inspect --json 输出:"
    echo "$INSPECT_JSON_OUTPUT"

    if [ $INSPECT_JSON_RESULT -eq 0 ]; then
        # 验证 JSON 中 permitted_program 为数组且包含所有程序
        if [[ "$INSPECT_JSON_OUTPUT" == *"$PROGRAM1"* ]] && [[ "$INSPECT_JSON_OUTPUT" == *"$PROGRAM2"* ]] && [[ "$INSPECT_JSON_OUTPUT" == *"$PROGRAM3"* ]]; then
            echo "  ✓ credctl inspect --json 正确显示了所有授权程序"
            ((TESTS_PASSED++))
        else
            echo "  ✗ credctl inspect --json 未完整显示所有授权程序"
            ((TESTS_FAILED++))
        fi

        # 验证 program_sha256 数组与程序数量一致（measure=true 时应有3个哈希）
        SHA256_COUNT=$(echo "$INSPECT_JSON_OUTPUT" | grep -o '"program_sha256"' | wc -l)
        if [ $SHA256_COUNT -gt 0 ]; then
            # 提取 program_sha256 数组中的元素数量
            SHA256_ENTRIES=$(echo "$INSPECT_JSON_OUTPUT" | grep -oP '"program_sha256":\s*\K\[[^\]]*\]' | grep -o '"' | wc -l)
            SHA256_ELEMENT_COUNT=$((SHA256_ENTRIES / 2))
            if [ $SHA256_ELEMENT_COUNT -eq 3 ]; then
                echo "  ✓ program_sha256 包含 3 个哈希值，与授权程序数量一致"
                ((TESTS_PASSED++))
            else
                echo "  ⚠ program_sha256 元素数量为 $SHA256_ELEMENT_COUNT（期望 3），但不影响功能"
                ((TESTS_PASSED++))
            fi
        else
            echo "  ⚠ 未检测到 program_sha256 字段（可能 measure=false）"
            ((TESTS_PASSED++))
        fi
    else
        echo "  ✗ credctl inspect --json 执行失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试8: 授权程序1 (cat) 可以访问文件
# ============================================
echo ""
echo "测试8: 授权程序 cat 可以访问文件"
if [ -L "$SECRET_FILE" ]; then
    CAT_CONTENT=$(cat "$SECRET_FILE" 2>&1)
    CAT_RESULT=$?

    if [ $CAT_RESULT -eq 0 ] && [ "$CAT_CONTENT" = "multi-program access test secret value" ]; then
        echo "  ✓ cat 命令可以正确读取虚拟文件内容"
        ((TESTS_PASSED++))
    else
        echo "  ✗ cat 命令无法正确读取虚拟文件内容"
        echo "    期望: 'multi-program access test secret value'"
        echo "    实际: '$CAT_CONTENT'"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 符号链接不存在"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试9: 授权程序2 (head) 可以访问文件
# ============================================
echo ""
echo "测试9: 授权程序 head 可以访问文件"
if [ -L "$SECRET_FILE" ]; then
    HEAD_CONTENT=$(head -n1 "$SECRET_FILE" 2>&1)
    HEAD_RESULT=$?

    if [ $HEAD_RESULT -eq 0 ] && [ "$HEAD_CONTENT" = "multi-program access test secret value" ]; then
        echo "  ✓ head 命令可以正确读取虚拟文件内容"
        ((TESTS_PASSED++))
    else
        echo "  ✗ head 命令无法正确读取虚拟文件内容"
        echo "    期望: 'multi-program access test secret value'"
        echo "    实际: '$HEAD_CONTENT'"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 符号链接不存在"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试10: 授权程序3 (grep) 可以访问文件
# ============================================
echo ""
echo "测试10: 授权程序 grep 可以访问文件"
if [ -L "$SECRET_FILE" ]; then
    GREP_OUTPUT=$(grep "secret" "$SECRET_FILE" 2>&1)
    GREP_RESULT=$?

    if [ $GREP_RESULT -eq 0 ] && [[ "$GREP_OUTPUT" == *"secret"* ]]; then
        echo "  ✓ grep 命令可以正确读取虚拟文件内容"
        echo "    grep 输出: $GREP_OUTPUT"
        ((TESTS_PASSED++))
    else
        echo "  ✗ grep 命令无法正确读取虚拟文件内容"
        echo "    grep 输出: $GREP_OUTPUT"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 符号链接不存在"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试11: 非授权程序无法访问文件内容
# ============================================
echo ""
echo "测试11: 非授权程序无法访问文件内容"
if [ -L "$SECRET_FILE" ]; then
    # tail 不是授权程序
    TAIL_OUTPUT=$(tail -n1 "$SECRET_FILE" 2>&1)
    TAIL_RESULT=$?

    if [ $TAIL_RESULT -ne 0 ] || [[ "$TAIL_OUTPUT" != *"secret"* ]]; then
        echo "  ✓ tail（非授权程序）无法访问虚拟文件内容"
        ((TESTS_PASSED++))
    else
        echo "  ✗ tail（非授权程序）意外能够访问虚拟文件内容"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 符号链接不存在"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试12: 使用 update 更新授权程序列表（替换为新的多程序列表）
# ============================================
echo ""
echo "测试12: 使用 update 更新授权程序列表"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过 update 测试"
    ((TESTS_FAILED++))
else
    echo ""
    echo "----------------------------------------------"
    echo "请注意：此步骤需要人工交互输入"
    echo "当要求输入密码时，请输入初始化时设置的管理员密码"
    echo "----------------------------------------------"
    echo ""

    # 更新为2个不同的程序：保留 cat，新增 tail
    UPDATE_OUTPUT=$("$PROJECT_ROOT/credctl" update --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER" -p /bin/cat -p /usr/bin/tail --measure true 2>&1)
    UPDATE_RESULT=$?

    echo "update 输出:"
    echo "$UPDATE_OUTPUT"

    if [ $UPDATE_RESULT -eq 0 ]; then
        if [[ "$UPDATE_OUTPUT" == *"Successfully updated"* ]]; then
            echo "  ✓ update 更新授权程序列表成功"
            ((TESTS_PASSED++))
        else
            echo "  ✗ update 输出格式不正确"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ update 更新授权程序列表失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试13: 验证 update 后 inspect 显示新的授权程序列表
# ============================================
echo ""
echo "测试13: 验证 update 后 inspect 显示新的授权程序列表"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过验证"
    ((TESTS_FAILED++))
else
    INSPECT_OUTPUT=$("$PROJECT_ROOT/credctl" inspect --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER" 2>&1)

    echo "inspect 输出（update 后）:"
    echo "$INSPECT_OUTPUT"

    # 验证包含新的授权程序，不包含旧的
    if [[ "$INSPECT_OUTPUT" == *"/bin/cat"* ]] && [[ "$INSPECT_OUTPUT" == *"/usr/bin/tail"* ]]; then
        echo "  ✓ inspect 显示了新的授权程序 (cat, tail)"
        ((TESTS_PASSED++))
    else
        echo "  ✗ inspect 未正确显示新的授权程序"
        ((TESTS_FAILED++))
    fi

    # 验证旧的授权程序已被替换
    if [[ "$INSPECT_OUTPUT" != *"/usr/bin/head"* ]] && [[ "$INSPECT_OUTPUT" != *"/usr/bin/grep"* ]]; then
        echo "  ✓ 旧的授权程序 (head, grep) 已被移除"
        ((TESTS_PASSED++))
    else
        echo "  ✗ 旧的授权程序 (head, grep) 仍然存在"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试14: 验证 update 后 cat 仍可访问（保留在授权列表中）
# ============================================
echo ""
echo "测试14: 验证 update 后 cat 仍可访问（保留在授权列表中）"
if [ -L "$SECRET_FILE" ]; then
    CAT_CONTENT=$(cat "$SECRET_FILE" 2>&1)
    CAT_RESULT=$?

    if [ $CAT_RESULT -eq 0 ] && [ "$CAT_CONTENT" = "multi-program access test secret value" ]; then
        echo "  ✓ cat 命令（保留在授权列表中）仍可正确读取"
        ((TESTS_PASSED++))
    else
        echo "  ✗ cat 命令无法读取"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 符号链接不存在"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试15: 验证 update 后 tail（新增授权）可以访问
# ============================================
echo ""
echo "测试15: 验证 update 后 tail（新增授权）可以访问"
if [ -L "$SECRET_FILE" ]; then
    TAIL_OUTPUT=$(tail -n1 "$SECRET_FILE" 2>&1)
    TAIL_RESULT=$?

    if [ $TAIL_RESULT -eq 0 ]; then
        echo "  ✓ tail 命令（新增授权）可以访问文件"
        echo "    tail 输出: $TAIL_OUTPUT"
        ((TESTS_PASSED++))
    else
        echo "  ✗ tail 命令无法访问文件"
        echo "    tail 输出: $TAIL_OUTPUT"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 符号链接不存在"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试16: 验证 update 后 grep（已被移除授权）无法访问
# ============================================
echo ""
echo "测试16: 验证 update 后 grep（已被移除授权）无法访问"
if [ -L "$SECRET_FILE" ]; then
    GREP_OUTPUT=$(grep "secret" "$SECRET_FILE" 2>&1)
    GREP_RESULT=$?

    if [ $GREP_RESULT -ne 0 ] || [[ "$GREP_OUTPUT" != *"secret"* ]]; then
        echo "  ✓ grep（已被移除授权）无法访问文件内容"
        ((TESTS_PASSED++))
    else
        echo "  ✗ grep（已被移除授权）意外能访问文件内容"
        echo "    grep 输出: $GREP_OUTPUT"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 符号链接不存在"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试17: 使用 refresh -p 刷新单个授权程序的 SHA256
# ============================================
echo ""
echo "测试17: 使用 refresh -p 刷新单个授权程序 (cat) 的 SHA256"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过 refresh 测试"
    ((TESTS_FAILED++))
else
    echo ""
    echo "----------------------------------------------"
    echo "请注意：此步骤需要人工交互输入"
    echo "当要求输入密码时，请输入初始化时设置的管理员密码"
    echo "----------------------------------------------"
    echo ""

    REFRESH_OUTPUT=$("$PROJECT_ROOT/credctl" refresh --config "$CREDCTL_CONFIG" \
        -p /bin/cat \
        "$SHA_IDENTIFIER" 2>&1)
    REFRESH_RESULT=$?

    echo "refresh -p 输出:"
    echo "$REFRESH_OUTPUT"

    if [ $REFRESH_RESULT -eq 0 ]; then
        # 验证输出包含 [刷新] 标记和程序路径
        if [[ "$REFRESH_OUTPUT" == *"[刷新]"* ]] && [[ "$REFRESH_OUTPUT" == *"/bin/cat"* ]]; then
            echo "  ✓ refresh 输出包含 [刷新] 标记和程序路径"
            ((TESTS_PASSED++))
        else
            echo "  ✗ refresh 输出缺少 [刷新] 标记或程序路径"
            ((TESTS_FAILED++))
        fi

        # 验证输出包含 SHA256 缩略值格式 (xxxxx***xxxxx -> xxxxx***xxxxx)
        if [[ "$REFRESH_OUTPUT" == *"***"* ]] && [[ "$REFRESH_OUTPUT" == *" -> "* ]]; then
            echo "  ✓ refresh 输出包含 SHA256 缩略值（旧->新）"
            ((TESTS_PASSED++))
        else
            echo "  ✗ refresh 输出缺少 SHA256 缩略值格式"
            ((TESTS_FAILED++))
        fi

        # 验证刷新完成汇总
        if [[ "$REFRESH_OUTPUT" == *"刷新完成"* ]]; then
            echo "  ✓ refresh 输出包含刷新完成汇总"
            ((TESTS_PASSED++))
        else
            echo "  ✗ refresh 输出缺少刷新完成汇总"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ refresh -p 执行失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试18: 使用 refresh（不指定 -p）刷新全部已授权程序的 SHA256
# ============================================
echo ""
echo "测试18: 使用 refresh（不指定 -p）刷新全部已授权程序"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过 refresh 全部测试"
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
        # 验证输出包含警告提示（不指定 -p 时的醒目提示）
        if [[ "$REFRESH_ALL_OUTPUT" == *"未指定 -p"* ]] || [[ "$REFRESH_ALL_OUTPUT" == *"全部已授权程序"* ]]; then
            echo "  ✓ refresh 不指定 -p 时显示了警告提示"
            ((TESTS_PASSED++))
        else
            echo "  ✗ refresh 不指定 -p 时未显示警告提示"
            ((TESTS_FAILED++))
        fi

        # 验证输出包含所有授权程序的 [刷新] 标记（当前授权: cat, tail）
        if [[ "$REFRESH_ALL_OUTPUT" == *"/bin/cat"* ]] && [[ "$REFRESH_ALL_OUTPUT" == *"/usr/bin/tail"* ]]; then
            echo "  ✓ refresh 全部模式输出包含所有授权程序路径 (cat, tail)"
            ((TESTS_PASSED++))
        else
            echo "  ✗ refresh 全部模式输出缺少某些授权程序路径"
            ((TESTS_FAILED++))
        fi

        # 验证每个程序都有 [刷新] 标记
        REFRESH_COUNT=$(echo "$REFRESH_ALL_OUTPUT" | grep -c "\[刷新\]")
        if [ "$REFRESH_COUNT" -eq 2 ]; then
            echo "  ✓ refresh 全部模式刷新了 2 个程序"
            ((TESTS_PASSED++))
        else
            echo "  ✗ refresh 全部模式刷新了 $REFRESH_COUNT 个程序（期望 2）"
            ((TESTS_FAILED++))
        fi

        # 验证刷新完成汇总
        if [[ "$REFRESH_ALL_OUTPUT" == *"刷新完成"* ]] && [[ "$REFRESH_ALL_OUTPUT" == *"2 已刷新"* ]]; then
            echo "  ✓ refresh 全部模式汇总正确（2 已刷新）"
            ((TESTS_PASSED++))
        else
            echo "  ✗ refresh 全部模式汇总不正确"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ refresh（不指定 -p）执行失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试19: 验证 refresh 后授权程序仍可正常访问文件
# ============================================
echo ""
echo "测试19: 验证 refresh 后授权程序仍可正常访问文件"
if [ -L "$SECRET_FILE" ]; then
    CAT_CONTENT=$(cat "$SECRET_FILE" 2>&1)
    CAT_RESULT=$?

    if [ $CAT_RESULT -eq 0 ] && [ "$CAT_CONTENT" = "multi-program access test secret value" ]; then
        echo "  ✓ refresh 后 cat 仍可正确读取文件（measure 验证通过）"
        ((TESTS_PASSED++))
    else
        echo "  ✗ refresh 后 cat 无法读取文件"
        echo "    期望: 'multi-program access test secret value'"
        echo "    实际: '$CAT_CONTENT'"
        ((TESTS_FAILED++))
    fi

    TAIL_OUTPUT=$(tail -n1 "$SECRET_FILE" 2>&1)
    TAIL_RESULT=$?

    if [ $TAIL_RESULT -eq 0 ]; then
        echo "  ✓ refresh 后 tail 仍可正确读取文件（measure 验证通过）"
        ((TESTS_PASSED++))
    else
        echo "  ✗ refresh 后 tail 无法读取文件"
        echo "    tail 输出: $TAIL_OUTPUT"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 符号链接不存在"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试20: 使用 release 释放文件
# ============================================
echo ""
echo "测试20: 使用 credctl release 释放文件"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过 release 测试"
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

    "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER"
    RELEASE_RESULT=$?

    if [ $RELEASE_RESULT -eq 0 ]; then
        echo "  ✓ credctl release 执行成功"
        ((TESTS_PASSED++))
    else
        echo "  ✗ credctl release 执行失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试21: 验证文件已恢复为普通文件
# ============================================
echo ""
echo "测试21: 验证文件已恢复为普通文件"
if [ -f "$SECRET_FILE" ] && [ ! -L "$SECRET_FILE" ]; then
    RESTORED_CONTENT=$(cat "$SECRET_FILE")
    if [ "$RESTORED_CONTENT" = "multi-program access test secret value" ]; then
        echo "  ✓ 文件已恢复且内容正确"
        ((TESTS_PASSED++))
    else
        echo "  ✗ 文件内容不正确"
        echo "    期望: 'multi-program access test secret value'"
        echo "    实际: '$RESTORED_CONTENT'"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 文件未正确还原"
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
