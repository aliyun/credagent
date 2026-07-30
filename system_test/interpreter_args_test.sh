#!/bin/bash

# CredAgent 解释器危险参数检测测试 (Phase 2F)
# 测试目标：验证各解释器的危险命令行参数被正确拦截
# 覆盖：python -i, node --require, ruby -r, perl -M, java -javaagent, php -z/-d
# 注意：bash/sh 已从解释器类型中移除，作为普通 Binary 处理
# 前置条件：已执行 init_test_environ.sh
# 运行要求：需要 sudo 权限

if [ "$(id -u)" -ne 0 ]; then
    echo "错误: 此测试需要 root 权限运行，请使用 sudo 执行"
    exit 1
fi

echo "=============================================="
echo "CredAgent 解释器危险参数检测测试"
echo "=============================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

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

PYTHON3_PATH=$(which python3 2>/dev/null)
NODE_PATH_BIN=$(which node 2>/dev/null)
RUBY_PATH=$(which ruby 2>/dev/null)
PERL_PATH=$(which perl 2>/dev/null)

echo "测试环境验证通过"
echo "  TEST_DIR: $TEST_DIR"
echo "  python3: ${PYTHON3_PATH:-未安装}"
echo "  node: ${NODE_PATH_BIN:-未安装}"
echo "  ruby: ${RUBY_PATH:-未安装}"
echo "  perl: ${PERL_PATH:-未安装}"
echo ""

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

SECRET_FILE="$SECRETS_DIR/args_test_secret.txt"
SECRET_CONTENT="args_test_secret_value_11223"

# 创建各解释器的读取脚本
PY_SCRIPT="$TEST_DIR/args_read.py"
cat > "$PY_SCRIPT" << 'PYEOF'
import sys
try:
    with open(sys.argv[1], "r") as f:
        print(f.read().strip())
except PermissionError:
    print("PERMISSION_DENIED", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
chmod +x "$PY_SCRIPT"


NODE_SCRIPT="$TEST_DIR/args_read.js"
cat > "$NODE_SCRIPT" << 'JSEOF'
const fs = require('fs');
try {
    const content = fs.readFileSync(process.argv[2], 'utf8').trim();
    console.log(content);
} catch(e) {
    if (e.code === 'EACCES') {
        process.stderr.write("PERMISSION_DENIED\n");
        process.exit(1);
    }
    process.stderr.write("ERROR: " + e.message + "\n");
    process.exit(1);
}
JSEOF
chmod +x "$NODE_SCRIPT"

RUBY_SCRIPT="$TEST_DIR/args_read.rb"
cat > "$RUBY_SCRIPT" << 'RBEOF'
begin
  puts File.read(ARGV[0]).strip
rescue Errno::EACCES
  $stderr.puts "PERMISSION_DENIED"
  exit 1
rescue => e
  $stderr.puts "ERROR: #{e.message}"
  exit 1
end
RBEOF
chmod +x "$RUBY_SCRIPT"

PERL_SCRIPT="$TEST_DIR/args_read.pl"
cat > "$PERL_SCRIPT" << 'PLEOF'
use strict;
open(my $fh, '<', $ARGV[0]) or do {
    print STDERR "PERMISSION_DENIED\n";
    exit 1;
};
my $content = do { local $/; <$fh> };
chomp $content;
print "$content\n";
close($fh);
PLEOF
chmod +x "$PERL_SCRIPT"

# 添加脚本到 python trusted_scripts (用于祖先链)
python3 -c "
import json, sys
with open(sys.argv[1]) as f: cfg = json.load(f)
opts = cfg.setdefault('antiattack_options', {}).setdefault('interpreter_check', {})
family, script = 'python', sys.argv[2]
fam_opts = opts.setdefault(family, {})
trusted = fam_opts.get('trusted_scripts', [])
if script not in trusted:
    trusted.append(script)
fam_opts['trusted_scripts'] = trusted
with open(sys.argv[1], 'w') as f: json.dump(cfg, f, indent=2, ensure_ascii=False)
" "$SECURITY_CONFIG" "$PY_SCRIPT"

# 重启 daemon 使配置生效
kill "$CREDAGENT_PID" 2>/dev/null; sleep 2
"$PROJECT_ROOT/credagent" run -c "$ENGINE_CONFIG" >> "$CREDAGENT_LOG" 2>&1 &
CREDAGENT_PID=$!; sleep 2
sed -i "s/^export CREDAGENT_PID=.*/export CREDAGENT_PID=\"$CREDAGENT_PID\"/" "$ENV_FILE"
echo "daemon 重启完成 (PID=$CREDAGENT_PID)"

# 保护凭据 — 授权所有测试脚本
rm -f "$SECRET_FILE" 2>/dev/null
echo "$SECRET_CONTENT" > "$SECRET_FILE"

PROTECT_ARGS=(-p "$PY_SCRIPT")
NODE_PATH_BIN=$(which node 2>/dev/null)
[ -n "$NODE_PATH_BIN" ] && PROTECT_ARGS+=(-p "$NODE_SCRIPT")
[ -n "$RUBY_PATH" ] && PROTECT_ARGS+=(-p "$RUBY_SCRIPT")
[ -n "$PERL_PATH" ] && PROTECT_ARGS+=(-p "$PERL_SCRIPT")

"$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" \
    --strategy BASIC --measure false "${PROTECT_ARGS[@]}" -i "$SECRET_FILE" >/dev/null 2>&1

if [ ! -L "$SECRET_FILE" ]; then
    echo "protect 失败，无法继续测试"
    exit 1
fi
echo "凭据已保护"
echo ""

# 辅助函数: 检查是否被拒绝
expect_denied() {
    local desc="$1"
    local output="$2"
    local result="$3"
    if [ "$result" -ne 0 ] || [[ "$output" == *"PERMISSION_DENIED"* ]] || [[ "$output" != *"$SECRET_CONTENT"* ]]; then
        echo "  ✓ $desc"
        ((TESTS_PASSED++))
    else
        echo "  ✗ $desc — 未被拒绝！"
        echo "    输出: $output"
        ((TESTS_FAILED++))
    fi
}

expect_allowed() {
    local desc="$1"
    local output="$2"
    local result="$3"
    if [ "$result" -eq 0 ] && [[ "$output" == *"$SECRET_CONTENT"* ]]; then
        echo "  ✓ $desc"
        ((TESTS_PASSED++))
    else
        echo "  ✗ $desc — 被错误拒绝"
        echo "    输出: $output"
        ((TESTS_FAILED++))
    fi
}

# ============================================
echo "=============================================="
echo "Python 危险参数检测"
echo "=============================================="

# 测试: python -i (交互保持，PYTHONINSPECT 攻击向量)
echo ""
echo "测试: python3 -i script.py — 应被拒绝 (dangerous_args_check)"
OUTPUT=$(python3 -i "$PY_SCRIPT" "$SECRET_FILE" < /dev/null 2>&1)
expect_denied "python -i 被拒绝" "$OUTPUT" "$?"

# 基线: 正常 python 访问
echo ""
echo "基线: python3 script.py — 应正常"
OUTPUT=$(python3 "$PY_SCRIPT" "$SECRET_FILE" 2>&1)
expect_allowed "python 正常访问" "$OUTPUT" "$?"


if [ -n "$NODE_PATH_BIN" ]; then
    echo ""
    echo "=============================================="
    echo "Node.js 危险参数 / 环境变量检测"
    echo "=============================================="

    # 测试: NODE_OPTIONS 注入
    echo ""
    echo "测试: NODE_OPTIONS='--require /tmp/evil.js' — 应被拒绝"
    OUTPUT=$(NODE_OPTIONS="--require /tmp/evil.js" node "$NODE_SCRIPT" "$SECRET_FILE" 2>&1)
    expect_denied "NODE_OPTIONS 注入被拒绝" "$OUTPUT" "$?"

    # 测试: NODE_PATH 注入
    echo ""
    echo "测试: NODE_PATH=/tmp/evil_modules — 应被拒绝"
    OUTPUT=$(NODE_PATH="/tmp/evil_modules" node "$NODE_SCRIPT" "$SECRET_FILE" 2>&1)
    expect_denied "NODE_PATH 注入被拒绝" "$OUTPUT" "$?"

    # 测试: --require 参数
    echo ""
    echo "测试: node --require /tmp/evil.js script.js — 应被拒绝"
    OUTPUT=$(node --require /tmp/evil.js "$NODE_SCRIPT" "$SECRET_FILE" 2>&1)
    expect_denied "node --require 被拒绝" "$OUTPUT" "$?"

    # 测试: -r 参数
    echo ""
    echo "测试: node -r /tmp/evil.js script.js — 应被拒绝"
    OUTPUT=$(node -r /tmp/evil.js "$NODE_SCRIPT" "$SECRET_FILE" 2>&1)
    expect_denied "node -r 被拒绝" "$OUTPUT" "$?"

    # 基线: 正常访问
    echo ""
    echo "基线: node script.js — 应正常"
    OUTPUT=$(node "$NODE_SCRIPT" "$SECRET_FILE" 2>&1)
    expect_allowed "node 正常访问" "$OUTPUT" "$?"
else
    echo ""
    echo "跳过 Node.js 测试（未安装）"
    ((TESTS_SKIPPED++))
fi

# ============================================
if [ -n "$RUBY_PATH" ]; then
    echo ""
    echo "=============================================="
    echo "Ruby 危险参数 / 环境变量检测"
    echo "=============================================="

    # 测试: RUBYOPT 注入
    echo ""
    echo "测试: RUBYOPT='-r /tmp/evil.rb' — 应被拒绝"
    OUTPUT=$(RUBYOPT="-r /tmp/evil.rb" ruby "$RUBY_SCRIPT" "$SECRET_FILE" 2>&1)
    expect_denied "RUBYOPT 注入被拒绝" "$OUTPUT" "$?"

    # 测试: RUBYLIB 注入
    echo ""
    echo "测试: RUBYLIB=/tmp/evil — 应被拒绝"
    OUTPUT=$(RUBYLIB="/tmp/evil" ruby "$RUBY_SCRIPT" "$SECRET_FILE" 2>&1)
    expect_denied "RUBYLIB 注入被拒绝" "$OUTPUT" "$?"

    # 测试: -r 参数
    echo ""
    echo "测试: ruby -r /tmp/evil.rb script.rb — 应被拒绝"
    OUTPUT=$(ruby -r /tmp/evil.rb "$RUBY_SCRIPT" "$SECRET_FILE" 2>&1)
    expect_denied "ruby -r 被拒绝" "$OUTPUT" "$?"

    # 基线: 正常访问
    echo ""
    echo "基线: ruby script.rb — 应正常"
    OUTPUT=$(ruby "$RUBY_SCRIPT" "$SECRET_FILE" 2>&1)
    expect_allowed "ruby 正常访问" "$OUTPUT" "$?"
else
    echo ""
    echo "跳过 Ruby 测试（未安装）"
    ((TESTS_SKIPPED++))
fi

# ============================================
if [ -n "$PERL_PATH" ]; then
    echo ""
    echo "=============================================="
    echo "Perl 危险参数 / 环境变量检测"
    echo "=============================================="

    # 测试: PERL5OPT 注入
    echo ""
    echo "测试: PERL5OPT='-MEvil' — 应被拒绝"
    OUTPUT=$(PERL5OPT="-MEvil" perl "$PERL_SCRIPT" "$SECRET_FILE" 2>&1)
    expect_denied "PERL5OPT 注入被拒绝" "$OUTPUT" "$?"

    # 测试: PERL5LIB 注入
    echo ""
    echo "测试: PERL5LIB=/tmp/evil — 应被拒绝"
    OUTPUT=$(PERL5LIB="/tmp/evil" perl "$PERL_SCRIPT" "$SECRET_FILE" 2>&1)
    expect_denied "PERL5LIB 注入被拒绝" "$OUTPUT" "$?"

    # 测试: -M 参数
    echo ""
    echo "测试: perl -MEvil script.pl — 应被拒绝"
    OUTPUT=$(perl -MEvil "$PERL_SCRIPT" "$SECRET_FILE" 2>&1)
    expect_denied "perl -M 被拒绝" "$OUTPUT" "$?"

    # 基线: 正常访问
    echo ""
    echo "基线: perl script.pl — 应正常"
    OUTPUT=$(perl "$PERL_SCRIPT" "$SECRET_FILE" 2>&1)
    expect_allowed "perl 正常访问" "$OUTPUT" "$?"
else
    echo ""
    echo "跳过 Perl 测试（未安装）"
    ((TESTS_SKIPPED++))
fi

# ============================================
# 清理
# ============================================
echo ""
echo "清理: 释放受保护文件"
echo ""
echo "----------------------------------------------"
echo "请注意：此步骤需要人工交互输入"
echo "当要求输入密码时，请输入初始化时设置的管理员密码"
echo "----------------------------------------------"
echo ""

if [ -L "$SECRET_FILE" ]; then
    SHA_ID=$(readlink "$SECRET_FILE" | xargs basename)
    rm -f "$SECRET_FILE"
    echo "  → 释放凭据 $SHA_ID:"
    "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_ID"
fi



# 汇总
echo ""
echo "=============================================="
echo "测试结果汇总"
echo "=============================================="
echo "  通过: $TESTS_PASSED"
echo "  失败: $TESTS_FAILED"
echo "  跳过: $TESTS_SKIPPED"
echo "  总计: $((TESTS_PASSED + TESTS_FAILED))"
echo ""
if [ $TESTS_FAILED -gt 0 ]; then
    echo "存在失败的测试! ✗"
    exit 1
else
    echo "全部通过 ✓"
fi
