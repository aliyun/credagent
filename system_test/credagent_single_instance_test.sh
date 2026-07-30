#!/bin/bash

# CredAgent 单例模式系统测试用例
# 测试目标：验证当第一个 credagent 实例正在运行并监听 socket 文件时，
# 第二个尝试监听相同 socket 文件的 credagent 实例会报错并退出
# 
# 前置条件：已执行 init_test_environ.sh

# 测试计数器
TESTS_PASSED=0
TESTS_FAILED=0

echo "=============================================="
echo "CredAgent 单例模式系统测试"
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

if [ -z "$SOCKET_DIR" ] || [ ! -d "$SOCKET_DIR" ]; then
    echo "错误: SOCKET_DIR 未设置或不存在"
    exit 1
fi

echo "测试环境验证通过"
echo "  TEST_DIR: $TEST_DIR"
echo "  SOCKET_DIR: $SOCKET_DIR"
echo "  ENGINE_CONFIG: $ENGINE_CONFIG"
echo "  CREDAGENT_PID: $CREDAGENT_PID"
echo ""

# ============================================
# 测试1: 验证第一个 credagent 实例正在运行
# ============================================
echo "测试1: 验证第一个 credagent 实例正在运行"
if ps -p "$CREDAGENT_PID" > /dev/null 2>&1; then
    echo "  ✓ 第一个 credagent 实例正在运行 (PID: $CREDAGENT_PID)"
    ((TESTS_PASSED++))
else
    echo "  ✗ 第一个 credagent 实例未运行"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试2: 验证 socket 文件已创建
# ============================================
echo ""
echo "测试2: 验证 socket 文件已创建"
ENCLAVE_SOCKET_PATH="$SOCKET_DIR/enclave.sock"

if [ -S "$ENCLAVE_SOCKET_PATH" ]; then
    echo "  ✓ enclave.sock 文件已创建"
    ((TESTS_PASSED++))
else
    echo "  ✗ enclave.sock 文件未创建"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试3: 尝试启动第二个 credagent 实例（应该失败并退出）
# ============================================
echo ""
echo "测试3: 尝试启动第二个 credagent 实例（应该失败并退出）"
SECOND_LOG="$LOG_DIR/credagent_second_instance.log"
timeout 15s "$PROJECT_ROOT/credagent" run --config "$ENGINE_CONFIG" > "$SECOND_LOG" 2>&1 || SECOND_START_RESULT=$?

if [ ${SECOND_START_RESULT:-0} -ne 0 ]; then
    echo "  ✓ 第二个 credagent 实例启动失败，符合预期 (exit code: ${SECOND_START_RESULT})"
    ((TESTS_PASSED++))
else
    echo "  ✗ 第二个 credagent 实例意外成功启动，单例模式失效"
    echo "  日志内容:"
    cat "$SECOND_LOG"
    ((TESTS_FAILED++))
    pkill -u "$USER" -f "credagent.*run" 2>/dev/null || true
fi

# ============================================
# 测试4: 验证第一个实例仍在运行
# ============================================
echo ""
echo "测试4: 验证第一个实例仍在运行"
if ps -p "$CREDAGENT_PID" > /dev/null 2>&1; then
    echo "  ✓ 第一个 credagent 实例仍在运行"
    ((TESTS_PASSED++))
else
    echo "  ✗ 第一个 credagent 实例已停止运行"
    ((TESTS_FAILED++))
fi

# ============================================
# 测试5: 终止第一个实例后，重新启动 credagent 应该成功
# ============================================
echo ""
echo "测试5: 终止第一个实例后，重新启动 credagent 应该成功"

# 终止第一个实例
kill "$CREDAGENT_PID" 2>/dev/null
sleep 2

# 确认第一个实例已停止
if ps -p "$CREDAGENT_PID" > /dev/null 2>&1; then
    kill -9 "$CREDAGENT_PID" 2>/dev/null
    sleep 1
fi

if ps -p "$CREDAGENT_PID" > /dev/null 2>&1; then
    echo "  ✗ 无法终止第一个 credagent 实例"
    ((TESTS_FAILED++))
else
    echo "  ✓ 第一个 credagent 实例已终止"
    ((TESTS_PASSED++))

    # 重新启动 credagent
    RESTART_LOG="$LOG_DIR/credagent_restart.log"
    "$PROJECT_ROOT/credagent" run --config "$ENGINE_CONFIG" > "$RESTART_LOG" 2>&1 &
    RESTART_PID=$!
    sleep 2

    if ps -p "$RESTART_PID" > /dev/null 2>&1; then
        echo "  ✓ 重新启动 credagent 成功 (PID: $RESTART_PID)"
        ((TESTS_PASSED++))
    else
        echo "  ✗ 重新启动 credagent 失败"
        echo "  日志内容:"
        cat "$RESTART_LOG"
        ((TESTS_FAILED++))
    fi
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
    echo "  第二实例日志: $SECOND_LOG"
    exit 1
fi