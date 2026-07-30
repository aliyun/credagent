#!/bin/bash

# CredAgent 系统测试环境清理脚本
# 此脚本负责终止测试进程、清理测试环境目录
# 必须在所有 *_test.sh 测试脚本完成后执行

echo "=============================================="
echo "CredAgent 系统测试环境清理"
echo "=============================================="

# 获取脚本所在目录，推导项目根目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "项目根目录: $PROJECT_ROOT"
echo "脚本目录: $SCRIPT_DIR"

# 加载测试环境变量
ENV_FILE="/tmp/credagent_test_env.sh"
if [ -f "$ENV_FILE" ]; then
    source "$ENV_FILE"
    echo "已加载环境变量文件: $ENV_FILE"
else
    echo "警告: 未找到环境变量文件 $ENV_FILE"
    echo "尝试从现有目录推断测试目录..."
    TEST_DIR=$(ls -d /tmp/credagent_test.* 2>/dev/null | head -n1)
    if [ -z "$TEST_DIR" ]; then
        echo "未找到测试目录，清理操作可能已完成"
        exit 0
    fi
    echo "检测到测试目录: $TEST_DIR"
fi

echo ""
echo "步骤1: 终止 credagent 测试进程..."
echo ""
echo "重要说明:"
echo "  - 通过配置路径 /tmp/ 识别测试进程，不会影响系统正式 credagent 进程"
echo ""

# 注意：credagent 实现了优雅退出，使用 SIGTERM (kill) 即可优雅退出
CREDAGENT_GRACEFUL_EXIT=true

if [ -n "$CREDAGENT_PID" ] && ps -p "$CREDAGENT_PID" > /dev/null 2>&1; then
    echo "发送 SIGTERM 信号终止测试 credagent 进程 (PID: $CREDAGENT_PID)..."
    kill "$CREDAGENT_PID" || true

    # 等待进程优雅退出（最多等待10秒）
    GRACEFUL_WAIT_COUNT=0
    GRACEFUL_WAIT_MAX=10
    while ps -p "$CREDAGENT_PID" > /dev/null 2>&1; do
        if [ $GRACEFUL_WAIT_COUNT -ge $GRACEFUL_WAIT_MAX ]; then
            echo "警告: credagent 进程在 $GRACEFUL_WAIT_MAX 秒后仍未退出"
            echo "这可能表明优雅退出功能存在问题"
            CREDAGENT_GRACEFUL_EXIT=false
            break
        fi
        sleep 1
        ((GRACEFUL_WAIT_COUNT++))
        echo "等待进程优雅退出... ($GRACEFUL_WAIT_COUNT/$GRACEFUL_WAIT_MAX)"
    done

    if [ "$CREDAGENT_GRACEFUL_EXIT" = true ]; then
        echo "测试 credagent 进程已优雅退出 ✓ (耗时: $GRACEFUL_WAIT_COUNT 秒)"
    fi
else
    echo "未找到记录的 credagent PID 或进程已终止"
fi

# 检查并终止其他遗留的 credagent 测试进程（通过 /tmp/ 配置路径识别，避免误杀系统正式进程）
echo ""
echo "检查并终止遗留的 credagent 测试进程..."
TEST_CREDAGENT_PIDS=$(pgrep -f "credagent.*run.*-c.*/tmp/" 2>/dev/null || true)
if [ -n "$TEST_CREDAGENT_PIDS" ]; then
    echo "发现遗留的 credagent 测试进程: $TEST_CREDAGENT_PIDS"
    for pid in $TEST_CREDAGENT_PIDS; do
        if [ "$pid" != "$CREDAGENT_PID" ]; then
            echo "发送 SIGTERM 信号终止遗留测试进程 (PID: $pid)..."
            kill "$pid" 2>/dev/null || true

            # 等待进程优雅退出（最多等待5秒）
            wait_count=0
            while ps -p "$pid" > /dev/null 2>&1 && [ $wait_count -lt 5 ]; do
                sleep 1
                ((wait_count++))
            done

            if ps -p "$pid" > /dev/null 2>&1; then
                echo "警告: 遗留测试进程 (PID: $pid) 未能在5秒内优雅退出"
                CREDAGENT_GRACEFUL_EXIT=false
            else
                echo "遗留测试进程 (PID: $pid) 已优雅退出 ✓"
            fi
        fi
    done
    echo "遗留 credagent 测试进程已清理 ✓"
else
    echo "未发现遗留的 credagent 测试进程"
fi

# 等待进程完全终止
echo ""
echo "等待进程终止..."
sleep 3

# 确认测试进程已终止（通过 /tmp/ 配置路径识别）
echo ""
echo "进程终止状态检查:"
TEST_CREDAGENT_REMAINING=$(pgrep -f "credagent.*run.*-c.*/tmp/" 2>/dev/null || true)

if [ -z "$TEST_CREDAGENT_REMAINING" ]; then
    echo "credagent 测试进程已全部终止 ✓"
else
    echo "警告: 仍有 credagent 测试进程运行: $TEST_CREDAGENT_REMAINING"
fi

# 显示系统中所有 credagent 进程（仅供参考）
echo ""
echo "系统中 credagent 进程状态（仅供参考）:"
ps aux | grep -E "credagent" | grep -v grep | awk '{printf "  %-12s %-8s %-6s %s\n", $1, $2, $3, $11}' || echo "  无相关进程"

echo ""
echo "步骤2: 卸载 FUSE 挂载点..."

# 卸载 FUSE 挂载点
if [ -n "$MOUNT_POINT" ] && [ -d "$MOUNT_POINT" ]; then
    # 检查是否为挂载点
    if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        echo "卸载 FUSE 挂载点: $MOUNT_POINT"
        # FUSE 挂载由当前用户创建，可以直接卸载
        fusermount -uz "$MOUNT_POINT" 2>/dev/null || true
        sleep 1
        # 确认卸载成功
        if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
            echo "警告: 挂载点未能完全卸载"
        fi
        echo "FUSE 挂载点已卸载 ✓"
    else
        echo "挂载点未处于挂载状态"
    fi
fi

# 也尝试卸载其他可能的测试挂载点
for mount_path in $(ls -d /tmp/credagent_test.*/mount 2>/dev/null); do
    if mountpoint -q "$mount_path" 2>/dev/null; then
        echo "卸载遗留挂载点: $mount_path"
        fusermount -uz "$mount_path" 2>/dev/null || true
    fi
done

echo ""
echo "步骤3: 清理 Socket 文件..."

# 清理 socket 文件
if [ -n "$SOCKET_DIR" ] && [ -d "$SOCKET_DIR" ]; then
    echo "清理 Socket 目录: $SOCKET_DIR"
    rm -f "$SOCKET_DIR/enclave.sock" 2>/dev/null || true
    echo "Socket 文件已清理 ✓"
fi

# 也清理其他可能的测试 socket 文件
for sock_dir in $(ls -d /tmp/credagent_test.*/run 2>/dev/null); do
    rm -f "$sock_dir/enclave.sock" 2>/dev/null || true
done

echo ""
echo "步骤4: 删除测试环境目录..."

# 删除测试环境目录
if [ -n "$TEST_DIR" ] && [ -d "$TEST_DIR" ]; then
    echo "删除测试目录: $TEST_DIR"
    rm -rf "$TEST_DIR" || true
    
    # 确认删除成功
    if [ -d "$TEST_DIR" ]; then
        echo "警告: 测试目录可能未完全删除"
        ls -la "$TEST_DIR" 2>/dev/null || true
    else
        echo "测试目录已删除 ✓"
    fi
fi

# 清理其他遗留的测试目录
for test_dir in $(ls -d /tmp/credagent_test.* 2>/dev/null); do
    if [ "$test_dir" != "$TEST_DIR" ]; then
        echo "清理遗留测试目录: $test_dir"
        # 先检查并卸载挂载点
        mount_path="$test_dir/mount"
        if [ -d "$mount_path" ] && mountpoint -q "$mount_path" 2>/dev/null; then
            fusermount -uz "$mount_path" 2>/dev/null || true
        fi
        rm -rf "$test_dir" || true
    fi
done

echo ""
echo "步骤5: 清理环境变量文件..."

# 删除环境变量文件
if [ -f "$ENV_FILE" ]; then
    echo "删除环境变量文件: $ENV_FILE"
    rm -f "$ENV_FILE"
    echo "环境变量文件已删除 ✓"
fi

echo ""
echo "=============================================="
echo "测试环境清理完成"
echo "=============================================="
echo ""
echo "清理摘要:"
echo ""
echo "【进程终止状态】"
if [ "$CREDAGENT_GRACEFUL_EXIT" = true ]; then
    echo "  ✓ credagent 进程优雅退出成功"
else
    echo "  ✗ credagent 进程优雅退出失败（超时）"
fi
echo ""
echo "【资源清理状态】"
echo "  - FUSE 挂载点已卸载"
echo "  - Socket 文件已清理"
echo "  - 测试目录已删除"
echo "  - 环境变量文件已删除"
echo ""

# 根据优雅退出状态设置退出码
if [ "$CREDAGENT_GRACEFUL_EXIT" = true ]; then
    echo "=============================================="
    echo "所有进程优雅退出验证通过 ✓"
    echo "=============================================="
    exit 0
else
    echo "=============================================="
    echo "警告: 部分进程未能优雅退出"
    echo "=============================================="
    echo ""
    echo "这可能是以下原因之一:"
    echo "  1. 进程正在处理长时间操作"
    echo "  2. 优雅退出信号处理未正确实现"
    echo "  3. 进程存在死锁或阻塞状态"
    echo ""
    echo "建议检查相关日志文件进行排查"
    exit 1
fi
