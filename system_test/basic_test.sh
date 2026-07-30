#!/bin/bash

# CredAgent 基本功能系统测试
# 测试目标：验证 credctl protect/release/list 基本功能
# 前置条件：已执行 init_test_environ.sh

echo "=============================================="
echo "CredAgent 基本功能测试"
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
SECRET_FILE="$SECRETS_DIR/test_secret.txt"

# ============================================
# 测试1: 验证 FUSE 挂载点可访问
# ============================================
echo "测试1: 验证 FUSE 挂载点"
if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
    echo "  ✓ FUSE 挂载点已挂载"
    ((TESTS_PASSED++))
else
    echo "  ✗ FUSE 挂载点未挂载"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试2: 创建测试秘密文件
# ============================================
echo ""
echo "测试2: 创建测试秘密文件"

# 清理可能存在的旧文件或符号链接（来自之前的测试运行）
if [ -L "$SECRET_FILE" ] || [ -f "$SECRET_FILE" ]; then
    echo "  清理已存在的文件/符号链接: $SECRET_FILE"
    rm -f "$SECRET_FILE"
fi

echo "this is a secret value for testing" > "$SECRET_FILE"

if [ -f "$SECRET_FILE" ] && [ ! -L "$SECRET_FILE" ]; then
    echo "  ✓ 测试秘密文件已创建: $SECRET_FILE"
    ((TESTS_PASSED++))
else
    echo "  ✗ 测试秘密文件创建失败"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试3: 使用 credctl protect 保护文件
# ============================================
echo ""
echo "测试3: 使用 credctl protect 保护文件"
echo "执行命令: credctl protect --config $CREDCTL_CONFIG --strategy BASIC --program-permit /bin/cat --measure true $SECRET_FILE"

PROTECT_OUTPUT=$("$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" --strategy BASIC --program-permit /bin/cat --measure true "$SECRET_FILE" 2>&1)
PROTECT_RESULT=$?

echo "protect 输出: $PROTECT_OUTPUT"

if [ $PROTECT_RESULT -eq 0 ]; then
    echo "  ✓ credctl protect 执行成功"
    ((TESTS_PASSED++))
else
    echo "  ✗ credctl protect 执行失败"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试4: 验证原文件被替换为符号链接
# ============================================
echo ""
echo "测试4: 验证原文件被替换为符号链接"
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
# 测试5: 使用 credctl list 查看受保护文件并获取 SHA
# ============================================
echo ""
echo "测试5: 使用 credctl list 查看受保护文件"
LIST_OUTPUT=$("$PROJECT_ROOT/credctl" list --config "$CREDCTL_CONFIG" 2>&1)
LIST_RESULT=$?

echo "list 输出:"
echo "$LIST_OUTPUT"

if [ $LIST_RESULT -eq 0 ]; then
    if [[ "$LIST_OUTPUT" == *"Total Count: 1"* ]] || [[ "$LIST_OUTPUT" == *"Total Count: "* && "$LIST_OUTPUT" != *"Total Count: 0"* ]]; then
        echo "  ✓ credctl list 正确显示了受保护的文件"
        ((TESTS_PASSED++))
        
        # 从 list 输出提取 SHA identifier
        # list 输出格式中 SHA 在第一列
        SHA_LINE=$(echo "$LIST_OUTPUT" | grep -E "^[a-f0-9]+" | head -n1)
        if [ -n "$SHA_LINE" ]; then
            SHA_IDENTIFIER=$(echo "$SHA_LINE" | awk '{print $1}')
            echo "  从 list 提取的 SHA identifier: $SHA_IDENTIFIER"
        fi
    else
        echo "  ✗ credctl list 未显示受保护的文件"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ credctl list 执行失败"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试5b: 使用 credctl list --json 测试 JSON 输出
# ============================================
echo ""
echo "测试5b: 使用 credctl list --json 测试 JSON 输出"
LIST_JSON_OUTPUT=$("$PROJECT_ROOT/credctl" list --config "$CREDCTL_CONFIG" --json 2>&1)
LIST_JSON_RESULT=$?

echo "list --json 输出:"
echo "$LIST_JSON_OUTPUT"

if [ $LIST_JSON_RESULT -eq 0 ]; then
    # 验证 JSON 格式是否有效（JSON 数组包含 id 和 target_path 字段）
    if [[ "$LIST_JSON_OUTPUT" == *"\"id\""* ]] && [[ "$LIST_JSON_OUTPUT" == *"\"target_path\""* ]]; then
        echo "  ✓ credctl list --json 输出有效的 JSON 格式"
        ((TESTS_PASSED++))
        
        # 从 JSON 提取 SHA identifier（备用）
        if [ -z "$SHA_IDENTIFIER" ]; then
            # 尝试从 JSON 提取第一个文件的 id
            SHA_FROM_JSON=$(echo "$LIST_JSON_OUTPUT" | grep -o '"id":"[^"]*"' | head -n1 | cut -d'"' -f4)
            if [ -n "$SHA_FROM_JSON" ]; then
                SHA_IDENTIFIER="$SHA_FROM_JSON"
                echo "  从 JSON 提取的 SHA identifier: $SHA_IDENTIFIER"
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
# 测试6: 使用 cat 通过符号链接读取虚拟文件内容
# ============================================
echo ""
echo "测试6: 使用 cat 通过符号链接读取虚拟文件内容"
if [ -L "$SECRET_FILE" ]; then
    # 通过符号链接读取（应该触发 FUSE 验证）
    CAT_CONTENT=$(cat "$SECRET_FILE" 2>&1)
    CAT_RESULT=$?
    
    echo "cat 输出: $CAT_CONTENT"
    echo "cat 返回值: $CAT_RESULT"
    
    if [ $CAT_RESULT -eq 0 ] && [ "$CAT_CONTENT" = "this is a secret value for testing" ]; then
        echo "  ✓ cat 命令可以正确读取虚拟文件内容"
        ((TESTS_PASSED++))
    else
        echo "  ✗ cat 命令无法正确读取虚拟文件内容"
        echo "    期望: 'this is a secret value for testing'"
        echo "    实际: '$CAT_CONTENT'"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 符号链接不存在"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试7: 验证非授权程序无法访问文件内容
# ============================================
echo ""
echo "测试7: 验证非授权程序无法访问文件内容（FUSE 限制）"
if [ -L "$SECRET_FILE" ]; then
    # 使用 grep 尝试访问（grep 不是授权程序）
    GREP_OUTPUT=$(grep "secret" "$SECRET_FILE" 2>&1)
    GREP_RESULT=$?
    
    echo "grep 输出: $GREP_OUTPUT"
    echo "grep 返回值: $GREP_RESULT"
    
    # grep 应该失败或无法读取内容
    if [ $GREP_RESULT -ne 0 ] || [[ "$GREP_OUTPUT" != *"secret"* ]]; then
        echo "  ✓ grep 命令无法访问虚拟文件内容（符合预期）"
        ((TESTS_PASSED++))
    else
        echo "  ✗ grep 命令意外能够访问虚拟文件内容"
        ((TESTS_FAILED++))
    fi
else
    echo "  - 跳过测试：符号链接不存在"
fi

# ============================================
# 测试8: 使用 credctl inspect 查看文件详细信息
# ============================================
echo ""
echo "测试8: 使用 credctl inspect 查看文件详细信息"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过 inspect 测试"
    ((TESTS_FAILED++))
else
    echo "使用 SHA identifier: $SHA_IDENTIFIER"
    
    INSPECT_OUTPUT=$("$PROJECT_ROOT/credctl" inspect --config "$CREDCTL_CONFIG" "$SHA_IDENTIFIER" 2>&1)
    INSPECT_RESULT=$?
    
    echo "inspect 输出:"
    echo "$INSPECT_OUTPUT"
    
    if [ $INSPECT_RESULT -eq 0 ]; then
        # 验证 inspect 输出包含关键信息（使用小写字段名）
        if [[ "$INSPECT_OUTPUT" == *"target_path:"* ]] && [[ "$INSPECT_OUTPUT" == *"strategy:"* ]]; then
            echo "  ✓ credctl inspect 正确显示了文件详细信息"
            ((TESTS_PASSED++))
        else
            echo "  ✗ credctl inspect 输出格式不完整"
            ((TESTS_FAILED++))
        fi
    else
        echo "  ✗ credctl inspect 执行失败"
        ((TESTS_FAILED++))
    fi
fi

# ============================================
# 测试9: 使用 credctl release 释放文件
# ============================================
echo ""
echo "测试9: 使用 credctl release 释放文件"

if [ -z "$SHA_IDENTIFIER" ]; then
    echo "  ✗ 无法获取 SHA identifier，跳过 release 测试"
    ((TESTS_FAILED++))
else
    echo "使用 SHA identifier: $SHA_IDENTIFIER"
    
    # 重要：先删除符号链接，否则 release 写入文件时会因符号链接指向 FUSE 而失败
    if [ -L "$SECRET_FILE" ]; then
        echo "  删除符号链接: $SECRET_FILE"
        rm -f "$SECRET_FILE"
        if [ ! -e "$SECRET_FILE" ]; then
            echo "  ✓ 符号链接已删除"
        else
            echo "  ⚠ 符号链接删除失败，尝试继续"
        fi
    fi
    
    echo ""
    echo "----------------------------------------------"
    echo "请注意：此步骤需要人工交互输入"
    echo "当要求输入密码时，请输入初始化时设置的管理员密码"
    echo "----------------------------------------------"
    echo ""
    
    # 执行 release 命令（需要人工输入密码）
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
# 测试10: 验证文件已恢复为普通文件
# ============================================
echo ""
echo "测试10: 验证文件已恢复为普通文件"
if [ -f "$SECRET_FILE" ] && [ ! -L "$SECRET_FILE" ]; then
    echo "  ✓ 文件已从虚拟文件还原为普通文件"
    ((TESTS_PASSED++))
    
    # 验证内容
    RESTORED_CONTENT=$(cat "$SECRET_FILE")
    if [ "$RESTORED_CONTENT" = "this is a secret value for testing" ]; then
        echo "  ✓ 文件内容正确还原"
        ((TESTS_PASSED++))
    else
        echo "  ✗ 文件内容未正确还原"
        echo "    期望: 'this is a secret value for testing'"
        echo "    实际: '$RESTORED_CONTENT'"
        ((TESTS_FAILED++))
    fi
else
    echo "  ✗ 文件未正确还原"
    if [ -L "$SECRET_FILE" ]; then
        echo "    文件仍然是符号链接"
    elif [ ! -f "$SECRET_FILE" ]; then
        echo "    文件不存在"
    fi
    ((TESTS_FAILED++))
fi

# ============================================
# 测试11: 验证释放后文件不再显示在 list 中
# ============================================
echo ""
echo "测试11: 验证释放后文件不再显示在 list 中"
LIST_OUTPUT_AFTER=$("$PROJECT_ROOT/credctl" list --config "$CREDCTL_CONFIG" 2>&1)

echo "list 输出（释放后）:"
echo "$LIST_OUTPUT_AFTER"

if [[ "$LIST_OUTPUT_AFTER" == *"Total Count: 0"* ]] || [[ "$LIST_OUTPUT_AFTER" != *"$SHA_IDENTIFIER"* ]]; then
    echo "  ✓ 释放的文件不再显示在 list 中"
    ((TESTS_PASSED++))
else
    echo "  ✗ 释放的文件仍然显示在 list 中"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试12: 验证挂载点虚拟文件已删除
# ============================================
echo ""
echo "测试12: 验证挂载点虚拟文件已删除"
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