#!/bin/bash

# CredAgent 系统测试环境初始化脚本
# 此脚本负责创建测试环境目录、配置文件、启动服务进程等
# 必须在任何 *_test.sh 测试脚本之前执行

set -e

echo "=============================================="
echo "CredAgent 系统测试环境初始化"
echo "=============================================="

# 解析命令行参数
AUTO_INIT=false
for arg in "$@"; do
    case "$arg" in
        --auto-init)
            AUTO_INIT=true
            ;;
        *)
            echo "错误: 未知参数: $arg"
            echo "用法: $0 [--auto-init]"
            exit 1
            ;;
    esac
done

if [ "$AUTO_INIT" = true ]; then
    echo "模式: --auto-init (非交互式，自动生成主密钥和管理员密码)"
else
    echo "模式: 交互式 (需要手动输入管理员密码)"
fi

# 检查 root 权限（FUSE AllowOther 需要 root）
if [ "$(id -u)" -ne 0 ]; then
    echo "错误: 此脚本需要 root 权限运行"
    echo "请使用: sudo bash $0 [--auto-init]"
    exit 1
fi

# 获取脚本所在目录，推导项目根目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

echo "项目根目录: $PROJECT_ROOT"
echo "脚本目录: $SCRIPT_DIR"

# 创建测试环境目录
TEST_DIR=$(mktemp -d /tmp/credagent_test.XXXXXX)
echo "创建测试目录: $TEST_DIR"

# 创建测试环境变量文件（供其他测试脚本使用）
ENV_FILE="/tmp/credagent_test_env.sh"

# 定义测试环境变量
SOCKET_DIR="$TEST_DIR/run"
MASTER_KEY_FILE="$TEST_DIR/etc/credagent/master.key"
BASELINE_FILE="$TEST_DIR/lib/credagent/baseline.enc"
ADMIN_PASSWORD_FILE="$TEST_DIR/etc/credagent/admin_password.json"
MOUNT_POINT="$TEST_DIR/mount"
ENGINE_CONFIG="$TEST_DIR/config/engine_config.json"
SECURITY_CONFIG="$TEST_DIR/config/security.json"
CREDCTL_CONFIG="$TEST_DIR/config/credctl_config.json"
LOG_DIR="$TEST_DIR/logs"
SECRETS_DIR="$TEST_DIR/secrets"

# 创建必要的目录
echo ""
echo "步骤1: 创建目录结构..."
mkdir -p "$SOCKET_DIR"
mkdir -p "$TEST_DIR/etc/credagent"
mkdir -p "$TEST_DIR/lib/credagent"
mkdir -p "$MOUNT_POINT"
mkdir -p "$TEST_DIR/config"
mkdir -p "$LOG_DIR"
mkdir -p "$SECRETS_DIR"

# 放宽测试目录权限，方便非 root 用户调试查看日志等
chmod 777 "$TEST_DIR"
chmod 777 "$SOCKET_DIR"
chmod 777 "$TEST_DIR/config"
chmod 777 "$TEST_DIR/lib/credagent"
chmod 777 "$LOG_DIR"
chmod 777 "$SECRETS_DIR"

echo "目录创建完成:"
echo "  - Socket目录: $SOCKET_DIR"
echo "  - 配置目录: $TEST_DIR/config"
echo "  - 密钥目录: $TEST_DIR/etc/credagent"
echo "  - 基线目录: $TEST_DIR/lib/credagent"
echo "  - 挂载点: $MOUNT_POINT"
echo "  - 日志目录: $LOG_DIR"
echo "  - 秘密文件目录: $SECRETS_DIR"

# 从模板复制配置文件并替换路径
echo ""
echo "步骤2: 从模板创建配置文件..."

ENGINE_TEMPLATE="$PROJECT_ROOT/config.template/config/engine/config.json"
SECURITY_TEMPLATE="$PROJECT_ROOT/config.template/config/engine/security.json"
CREDCTL_TEMPLATE="$PROJECT_ROOT/config.template/config/credctl/config.json"

if [ ! -f "$ENGINE_TEMPLATE" ]; then
    echo "✗ 引擎配置模板不存在: $ENGINE_TEMPLATE"
    exit 1
fi
if [ ! -f "$SECURITY_TEMPLATE" ]; then
    echo "✗ 安全配置模板不存在: $SECURITY_TEMPLATE"
    exit 1
fi
if [ ! -f "$CREDCTL_TEMPLATE" ]; then
    echo "✗ credctl 配置模板不存在: $CREDCTL_TEMPLATE"
    exit 1
fi

# 复制模板
cp "$ENGINE_TEMPLATE" "$ENGINE_CONFIG"
cp "$SECURITY_TEMPLATE" "$SECURITY_CONFIG"
cp "$CREDCTL_TEMPLATE" "$CREDCTL_CONFIG"

# 替换引擎配置中的路径
sed -i "s|/run/credagent|$SOCKET_DIR|g" "$ENGINE_CONFIG"
sed -i "s|/usr/local/etc/credagent/engine/master.key|$MASTER_KEY_FILE|g" "$ENGINE_CONFIG"
sed -i "s|/var/lib/credagent/baseline.enc|$BASELINE_FILE|g" "$ENGINE_CONFIG"
sed -i "s|/mnt/credagent/shielded|$MOUNT_POINT|g" "$ENGINE_CONFIG"

# 替换 credctl 配置中的路径
sed -i "s|/run/credagent|$SOCKET_DIR|g" "$CREDCTL_CONFIG"
sed -i "s|/mnt/credagent/shielded|$MOUNT_POINT|g" "$CREDCTL_CONFIG"

chmod 644 "$ENGINE_CONFIG"
chmod 644 "$SECURITY_CONFIG"
chmod 644 "$CREDCTL_CONFIG"

# 测试环境默认不启用 cmdline_trusted_source，由各测试脚本按需开启
#
# 注意: 模板 security.json 中所有安全检查默认 enabled=false（opt-in）。
# 测试环境需要完整的反攻击检查栈来覆盖各检测场景，因此在此显式开启
# binary/ancestor/process_status/env_var 及全部解释器检查。
# library_injection_check 与 fd_share_check 保持关闭，由对应测试脚本按需开启。
#
# 注意: bash/sh 已从解释器类型中移除，不再需要 shell.trusted_scripts 配置。
python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    cfg = json.load(f)
cfg['cmdline_trusted_source'] = []
opts = cfg.setdefault('antiattack_options', {})
interp = opts.setdefault('interpreter_check', {})
# 测试环境显式开启反攻击检查（模板默认为 false）
for key in ('binary_check', 'ancestor_check', 'process_status_check', 'env_var_check'):
    opts.setdefault(key, {})['enabled'] = True
for family in ('python', 'node', 'perl', 'ruby', 'java', 'php'):
    interp.setdefault(family, {})['enabled'] = True
with open(sys.argv[1], 'w') as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
" "$SECURITY_CONFIG"

echo "引擎配置文件已创建: $ENGINE_CONFIG (来源: $ENGINE_TEMPLATE)"
echo "  注意: cmdline_trusted_source 已设为 [] (测试默认值)"
echo "credctl 配置文件已创建: $CREDCTL_CONFIG (来源: $CREDCTL_TEMPLATE)"

# 导出环境变量到环境文件（先导出，后续步骤会更新密码）
rm -f "$ENV_FILE" 2>/dev/null
cat > "$ENV_FILE" << EOF
#!/bin/bash
# CredAgent 测试环境变量
# 此文件由 init_test_environ.sh 自动生成

export TEST_DIR="$TEST_DIR"
export PROJECT_ROOT="$PROJECT_ROOT"
export SOCKET_DIR="$SOCKET_DIR"
export MASTER_KEY_FILE="$MASTER_KEY_FILE"
export BASELINE_FILE="$BASELINE_FILE"
export ADMIN_PASSWORD_FILE="$ADMIN_PASSWORD_FILE"
export MOUNT_POINT="$MOUNT_POINT"
export ENGINE_CONFIG="$ENGINE_CONFIG"
export SECURITY_CONFIG="$SECURITY_CONFIG"
export CREDCTL_CONFIG="$CREDCTL_CONFIG"
export LOG_DIR="$LOG_DIR"
export SECRETS_DIR="$SECRETS_DIR"

# 进程 PID（由后续步骤填充）
export CREDAGENT_PID=""
EOF

chmod 644 "$ENV_FILE"
echo "环境变量文件已创建: $ENV_FILE"

if [ "$AUTO_INIT" = true ]; then
echo ""
echo "步骤3: 跳过 credagent init (--auto-init 模式)"
echo "  主密钥和管理员密码将由 credagent run --auto-init 自动生成"
echo "  注意: 自动生成的管理员密码是随机且不可恢复的"
else
# 执行 credagent init 初始化（需要人工输入）
echo ""
echo "步骤3: 执行 credagent init 初始化..."
echo "----------------------------------------------"
echo "请注意：此步骤需要人工交互输入"
echo "1. 当询问是否创建主密钥文件时，请输入 'y'"
echo "2. 当要求输入管理员密码时，请输入您选择的密码"
echo "3. 当要求确认密码时，请再次输入相同的密码"
echo "----------------------------------------------"
echo ""

# 执行 credagent init
"$PROJECT_ROOT/credagent" init -c "$ENGINE_CONFIG"

echo ""
echo "credagent init 执行完成"
fi

# 检查初始化生成的文件
echo ""
echo "步骤4: 检查初始化生成的文件..."

INIT_SUCCESS=true
MISSING_ITEMS=""

# 检查主密钥文件（auto-init 模式下跳过，密钥由 credagent run --auto-init 生成）
if [ "$AUTO_INIT" = true ]; then
    echo "  - 主密钥: 跳过检查 (--auto-init，将由 credagent run 生成)"
elif [ -f "$MASTER_KEY_FILE" ]; then
    MASTER_KEY_PERMS=$(stat -c %a "$MASTER_KEY_FILE")
    if [ "$MASTER_KEY_PERMS" = "600" ]; then
        echo "✓ 主密钥文件已生成: $MASTER_KEY_FILE (权限: $MASTER_KEY_PERMS)"
    else
        echo "⚠ 主密钥文件已生成: $MASTER_KEY_FILE (权限: $MASTER_KEY_PERMS, 应为 600)"
        INIT_SUCCESS=false
        MISSING_ITEMS="$MISSING_ITEMS\n  - 主密钥文件权限不安全: $MASTER_KEY_FILE (当前: $MASTER_KEY_PERMS, 应为: 600)"
    fi
else
    echo "✗ 主密钥文件缺失: $MASTER_KEY_FILE"
    INIT_SUCCESS=false
    MISSING_ITEMS="$MISSING_ITEMS\n  - 主密钥文件: $MASTER_KEY_FILE"
fi

# 检查管理员密码文件（auto-init 模式下跳过）
if [ "$AUTO_INIT" = true ]; then
    echo "  - 管理员密码: 跳过检查 (--auto-init，将由 credagent run 生成)"
elif [ -f "$ADMIN_PASSWORD_FILE" ]; then
    ADMIN_PASS_PERMS=$(stat -c %a "$ADMIN_PASSWORD_FILE")
    if [ "$ADMIN_PASS_PERMS" = "600" ]; then
        echo "✓ 管理员密码文件已生成: $ADMIN_PASSWORD_FILE (权限: $ADMIN_PASS_PERMS)"
    else
        echo "⚠ 管理员密码文件已生成: $ADMIN_PASSWORD_FILE (权限: $ADMIN_PASS_PERMS, 应为 600)"
        INIT_SUCCESS=false
        MISSING_ITEMS="$MISSING_ITEMS\n  - 管理员密码文件权限不安全: $ADMIN_PASSWORD_FILE (当前: $ADMIN_PASS_PERMS, 应为: 600)"
    fi
else
    echo "✗ 管理员密码文件缺失: $ADMIN_PASSWORD_FILE"
    INIT_SUCCESS=false
    MISSING_ITEMS="$MISSING_ITEMS\n  - 管理员密码文件: $ADMIN_PASSWORD_FILE"
fi

# 注意: 基线文件 (baseline.enc) 是由 credagent run 命令产生的，不是 init 命令产生的
# 因此这里不检查基线文件，它将在步骤6中 credagent run 启动后自动生成

# 检查配置文件
if [ -f "$ENGINE_CONFIG" ]; then
    echo "✓ 引擎配置文件已创建: $ENGINE_CONFIG"
else
    echo "✗ 引擎配置文件缺失: $ENGINE_CONFIG"
    INIT_SUCCESS=false
    MISSING_ITEMS="$MISSING_ITEMS\n  - 引擎配置文件: $ENGINE_CONFIG"
fi

if [ -f "$CREDCTL_CONFIG" ]; then
    echo "✓ credctl 配置文件已创建: $CREDCTL_CONFIG"
else
    echo "✗ credctl 配置文件缺失: $CREDCTL_CONFIG"
    INIT_SUCCESS=false
    MISSING_ITEMS="$MISSING_ITEMS\n  - credctl 配置文件: $CREDCTL_CONFIG"
fi

# 检查目录
if [ -d "$MOUNT_POINT" ]; then
    echo "✓ 挂载点目录已创建: $MOUNT_POINT"
else
    echo "✗ 挂载点目录缺失: $MOUNT_POINT"
    INIT_SUCCESS=false
    MISSING_ITEMS="$MISSING_ITEMS\n  - 挂载点目录: $MOUNT_POINT"
fi

if [ -d "$SOCKET_DIR" ]; then
    echo "✓ Socket 目录已创建: $SOCKET_DIR"
else
    echo "✗ Socket 目录缺失: $SOCKET_DIR"
    INIT_SUCCESS=false
    MISSING_ITEMS="$MISSING_ITEMS\n  - Socket 目录: $SOCKET_DIR"
fi

# 检查二进制程序
echo ""
echo "步骤5: 检查程序二进制文件..."

for prog in credagent credctl; do
    if [ -f "$PROJECT_ROOT/$prog" ]; then
        if [ -x "$PROJECT_ROOT/$prog" ]; then
            echo "✓ 程序已编译且可执行: $prog"
        else
            echo "✗ 程序文件不可执行: $prog"
            INIT_SUCCESS=false
            MISSING_ITEMS="$MISSING_ITEMS\n  - 程序不可执行: $PROJECT_ROOT/$prog"
        fi
    else
        echo "✗ 程序文件缺失: $prog"
        INIT_SUCCESS=false
        MISSING_ITEMS="$MISSING_ITEMS\n  - 程序文件缺失: $PROJECT_ROOT/$prog"
    fi
done

# 如果初始化文件检查失败，退出
if [ "$INIT_SUCCESS" = false ]; then
    echo ""
    echo "=============================================="
    echo "错误: 初始化检查失败"
    echo "=============================================="
    echo "缺失或失败的项:"
    echo "$MISSING_ITEMS"
    echo ""
    echo "请检查上述问题后重新执行初始化脚本"
    exit 1
fi

echo ""
echo "初始化文件检查全部通过 ✓"

# 启动 credagent daemon
echo ""
echo "步骤6: 启动 credagent 服务..."
CREDAGENT_LOG="$LOG_DIR/credagent.log"

# 检查是否有已运行的 credagent 测试进程（通过 /tmp/ 配置路径识别，避免误杀系统正式进程）
TEST_PIDS=$(pgrep -f "credagent.*run.*-c.*/tmp/" 2>/dev/null || true)
if [ -n "$TEST_PIDS" ]; then
    echo "警告: 发现已运行的 credagent 测试进程 (PIDs: $TEST_PIDS)，正在终止..."
    for pid in $TEST_PIDS; do
        kill "$pid" 2>/dev/null || true
    done
    sleep 2
fi

# 启动 credagent（以当前用户身份运行，便于后续管理和清理）
# --auto-init 模式下，credagent run 会自动生成主密钥和管理员密码
RUN_ARGS="run -c $ENGINE_CONFIG"
if [ "$AUTO_INIT" = true ]; then
    RUN_ARGS="$RUN_ARGS --auto-init"
fi
"$PROJECT_ROOT/credagent" $RUN_ARGS > "$CREDAGENT_LOG" 2>&1 &
CREDAGENT_PID=$!

echo "credagent 已启动 (PID: $CREDAGENT_PID)"
echo "日志文件: $CREDAGENT_LOG"

# 等待 credagent 启动（含 FUSE 挂载）
sleep 2

# 检查 credagent 进程状态
if ps -p $CREDAGENT_PID > /dev/null 2>&1; then
    echo "✓ credagent 进程正在运行"
else
    echo "✗ credagent 进程启动失败"
    echo "日志内容:"
    cat "$CREDAGENT_LOG"
    exit 1
fi

# 放宽日志文件权限，方便非 root 用户查看
chmod 666 "$CREDAGENT_LOG" 2>/dev/null || true

# 放宽基线文件权限（credagent run 启动后生成）
chmod 666 "$BASELINE_FILE" 2>/dev/null || true

# auto-init 模式下，主密钥和管理员密码文件也是由 credagent run 生成的
# 放宽权限方便非 root 用户调试
if [ "$AUTO_INIT" = true ]; then
    chmod 666 "$MASTER_KEY_FILE" 2>/dev/null || true
    chmod 666 "$ADMIN_PASSWORD_FILE" 2>/dev/null || true
fi

# 更新环境变量文件，添加 PID
rm -f "$ENV_FILE" 2>/dev/null
cat > "$ENV_FILE" << EOF
#!/bin/bash
# CredAgent 测试环境变量
# 此文件由 init_test_environ.sh 自动生成

export TEST_DIR="$TEST_DIR"
export PROJECT_ROOT="$PROJECT_ROOT"
export SOCKET_DIR="$SOCKET_DIR"
export MASTER_KEY_FILE="$MASTER_KEY_FILE"
export BASELINE_FILE="$BASELINE_FILE"
export ADMIN_PASSWORD_FILE="$ADMIN_PASSWORD_FILE"
export MOUNT_POINT="$MOUNT_POINT"
export ENGINE_CONFIG="$ENGINE_CONFIG"
export SECURITY_CONFIG="$SECURITY_CONFIG"
export CREDCTL_CONFIG="$CREDCTL_CONFIG"
export LOG_DIR="$LOG_DIR"
export SECRETS_DIR="$SECRETS_DIR"
export CREDAGENT_LOG="$CREDAGENT_LOG"

# 进程 PID
export CREDAGENT_PID="$CREDAGENT_PID"

# 快捷命令
alias credctl-test='$PROJECT_ROOT/credctl --config $CREDCTL_CONFIG'
EOF

chmod 644 "$ENV_FILE"

# 最终就绪检查
echo ""
echo "步骤8: 最终就绪检查..."

FINAL_SUCCESS=true

# 检查 Socket 文件
ENCLAVE_SOCK="$SOCKET_DIR/enclave.sock"

if [ -S "$ENCLAVE_SOCK" ]; then
    ENCLAVE_SOCK_PERMS=$(stat -c %a "$ENCLAVE_SOCK")
    echo "✓ enclave.sock 已创建 (权限: $ENCLAVE_SOCK_PERMS)"
else
    echo "✗ enclave.sock 未创建"
    FINAL_SUCCESS=false
fi

# 检查 FUSE 挂载点
if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
    echo "✓ FUSE 挂载点已就绪: $MOUNT_POINT"
else
    echo "✗ FUSE 挂载点未就绪"
    FINAL_SUCCESS=false
fi

# 检查进程
if ps -p $CREDAGENT_PID > /dev/null 2>&1; then
    echo "✓ credagent 进程运行中 (PID: $CREDAGENT_PID)"
else
    echo "✗ credagent 进程已停止"
    FINAL_SUCCESS=false
fi

# 显示最终结果
echo ""
echo "=============================================="

if [ "$FINAL_SUCCESS" = true ]; then
    echo "测试环境初始化完成 ✓"
    echo "=============================================="
    echo ""
    echo "环境信息:"
    echo "  TEST_DIR=$TEST_DIR"
    echo "  ENGINE_CONFIG=$ENGINE_CONFIG"
    echo "  CREDCTL_CONFIG=$CREDCTL_CONFIG"
    echo "  MOUNT_POINT=$MOUNT_POINT"
    echo "  CREDAGENT_PID=$CREDAGENT_PID"
    echo ""
    echo "日志文件:"
    echo "  credagent: $CREDAGENT_LOG"
    echo ""
    echo "使用方法:"
    echo "  1. 在测试脚本中执行: source /tmp/credagent_test_env.sh"
    echo "  2. 运行测试脚本: ./xxx_test.sh"
    echo "  3. 测试完成后执行: ./destruct_test_environ.sh"
    echo ""
    echo "=============================================="
    exit 0
else
    echo "测试环境初始化失败 ✗"
    echo "=============================================="
    echo ""
    echo "请检查日志文件获取详细信息:"
    echo "  credagent 日志: $CREDAGENT_LOG"
    echo ""
    echo "建议执行 ./destruct_test_environ.sh 清理环境后重新初始化"
    exit 1
fi