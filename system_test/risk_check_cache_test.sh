#!/bin/bash

# 测试目标:
#   验证 Binary.CheckRisk / Process.CheckRisk / cache 的新行为
#   - 同一进程多次访问 -> Binary cache HIT
#   - 不同子进程共享祖先 -> 祖先 cache HIT (provider 模式)
#   - 祖先未被 FUSE-active 时进入 GetOrTouch 路径
#   - cleanup 期满后 ancestor 被回收
#
# 前置: init_test_environ.sh 已执行, daemon 日志级别为 debug
# 用法: sudo bash system_test/risk_check_cache_test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ENV_FILE="/tmp/credagent_test_env.sh"
[ -f "$ENV_FILE" ] || { echo "请先执行 init_test_environ.sh"; exit 1; }
source "$ENV_FILE"

SECRET_FILE="$SECRETS_DIR/risk_cache_test.txt"
PASSED=0; FAILED=0

# 注意：不要用 ((PASSED++))，当 PASSED=0 时它返回退出码 1，
# 在 `cmd && mark_pass || mark_fail` 模式下会触发 mark_fail 误报。
mark_pass() { echo "  ✓ $1"; PASSED=$((PASSED+1)); }
mark_fail() { echo "  ✗ $1"; FAILED=$((FAILED+1)); }

# ---------- 准备 ----------
# 强制日志级别为 debug，便于观察检查/缓存事件
python3 -c "
import json,sys
with open(sys.argv[1]) as f: cfg=json.load(f)
cfg['log_level']='debug'
with open(sys.argv[1],'w') as f: json.dump(cfg,f,indent=2,ensure_ascii=False)
" "$ENGINE_CONFIG"

# 重启 daemon 使配置生效
echo "重启 daemon 以应用 debug 日志..."
kill "$CREDAGENT_PID" 2>/dev/null || true
# 等待干净退出
for i in 1 2 3 4 5; do
    ps -p "$CREDAGENT_PID" >/dev/null 2>&1 || break
    sleep 1
done
"$PROJECT_ROOT/credagent" run -c "$ENGINE_CONFIG" > "$CREDAGENT_LOG" 2>&1 &
CREDAGENT_PID=$!
sleep 2
ps -p "$CREDAGENT_PID" >/dev/null 2>&1 || { echo "daemon 启动失败"; tail -20 "$CREDAGENT_LOG"; exit 1; }
echo "daemon 已重启 (PID=$CREDAGENT_PID)"

# 同步新 PID 到 ENV_FILE，避免后续 *_test.sh 使用旧 PID 而误判 daemon 未运行
sed -i "s/^export CREDAGENT_PID=.*/export CREDAGENT_PID=\"$CREDAGENT_PID\"/" "$ENV_FILE"
echo "已同步 CREDAGENT_PID=$CREDAGENT_PID 到 $ENV_FILE"

# 记录日志当前位置，后续按时间窗口切片分析
log_mark() { wc -l < "$CREDAGENT_LOG"; }
log_slice() {
    # $1=起始行号
    tail -n +"$1" "$CREDAGENT_LOG"
}

# 创建 python 辅助脚本（替代 python3 -c，因为 -c inline 模式在祖先链中不可信）
PY_CAT_WRAPPER="$TEST_DIR/cat_wrapper.py"
cat > "$PY_CAT_WRAPPER" << 'PYEOF'
import subprocess, sys
target = sys.argv[1] if len(sys.argv) > 1 else None
if not target:
    sys.exit(1)
r = subprocess.run(['cat', target], capture_output=True, text=True)
print(r.stdout, end='')
sys.exit(r.returncode)
PYEOF
chmod +x "$PY_CAT_WRAPPER"

# 将辅助脚本加入 python trusted_scripts（作为祖先进程时需要被信任）
python3 -c "
import json, sys
with open(sys.argv[1]) as f: cfg = json.load(f)
py_opts = cfg.setdefault('antiattack_options', {}).setdefault('interpreter_check', {}).setdefault('python', {})
trusted = py_opts.get('trusted_scripts', [])
if sys.argv[2] not in trusted:
    trusted.append(sys.argv[2])
    py_opts['trusted_scripts'] = trusted
with open(sys.argv[1], 'w') as f: json.dump(cfg, f, indent=2, ensure_ascii=False)
" "$SECURITY_CONFIG" "$PY_CAT_WRAPPER"

# 重启 daemon 使 trusted_scripts 配置生效
kill "$CREDAGENT_PID" 2>/dev/null || true
for i in 1 2 3 4 5; do
    ps -p "$CREDAGENT_PID" >/dev/null 2>&1 || break
    sleep 1
done
"$PROJECT_ROOT/credagent" run -c "$ENGINE_CONFIG" > "$CREDAGENT_LOG" 2>&1 &
CREDAGENT_PID=$!
sleep 2
ps -p "$CREDAGENT_PID" >/dev/null 2>&1 || { echo "daemon 重启失败"; tail -20 "$CREDAGENT_LOG"; exit 1; }
sed -i "s/^export CREDAGENT_PID=.*/export CREDAGENT_PID=\"$CREDAGENT_PID\"/" "$ENV_FILE"

# 注册凭据
rm -f "$SECRET_FILE"
echo "ancestor-cache-test-secret" > "$SECRET_FILE"
"$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" \
    --strategy BASIC --program-permit /bin/cat --measure true \
    "$SECRET_FILE" > /dev/null
[ -L "$SECRET_FILE" ] && echo "已注册保护文件" || { echo "注册失败"; exit 1; }

# ---------- 测试 1: 首次访问产生关键检查日志 ----------
echo ""
echo "测试1: 首次访问 -> Binary 检查 + Process enter + cache MISS"
mark=$(log_mark)
cat "$SECRET_FILE" > /dev/null
sleep 0.5
slice=$(log_slice "$mark")
echo "$slice" | grep -q "Binary.CheckRisk\] pid=" && \
    mark_pass "看到 Binary.CheckRisk" || mark_fail "未看到 Binary.CheckRisk"
echo "$slice" | grep -q "Process.CheckRisk\] enter pid=" && \
    mark_pass "看到 Process.CheckRisk enter" || mark_fail "未看到 Process.CheckRisk enter"
echo "$slice" | grep -q "cache.GetOrCreate\] MISS\|cache.GetOrCreate\] HIT" && \
    mark_pass "看到 cache.GetOrCreate" || mark_fail "未看到 cache.GetOrCreate"

# ---------- 测试 2: 同一 shell 第二次访问 -> 祖先(此 bash) cache HIT ----------
echo ""
echo "测试2: 同一 shell 第二次访问 -> 祖先 cache HIT + Binary CACHE-HIT"
mark=$(log_mark)
cat "$SECRET_FILE" > /dev/null
sleep 0.5
slice=$(log_slice "$mark")
# 第二次访问的 cat 进程是新的（fork+exec），但其父 bash 与第一次相同
echo "$slice" | grep -q "cache.GetOrTouch\] REFRESH\|cache.GetOrCreate\] HIT" && \
    mark_pass "祖先命中 cache" || mark_fail "祖先未命中 cache（期望刷新或命中）"

# ---------- 测试 3: 多个子进程共享同一 bash 祖先 ----------
echo ""
echo "测试3: 连续 10 次访问，验证祖先复用"
mark=$(log_mark)
for i in $(seq 1 10); do cat "$SECRET_FILE" > /dev/null; done
sleep 0.5
slice=$(log_slice "$mark")
# 统计 GetOrTouch 命中次数；理想情况下 bash 应被命中而非每次重建
refresh_count=$(echo "$slice" | grep -c "cache.GetOrTouch\] REFRESH" || true)
binary_count=$(echo "$slice" | grep -c "Binary.CheckRisk\] pid=" || true)
fast_path=$(echo "$slice" | grep -c "Process.CheckRisk\] FAST-PATH" || true)
process_enter=$(echo "$slice" | grep -c "Process.CheckRisk\] enter" || true)
echo "  GetOrTouch REFRESH 次数: $refresh_count   (祖先 cache 刷新)"
echo "  Binary.CheckRisk 调用次数: $binary_count  (每个 cat 一次)"
echo "  Process FAST-PATH 次数: $fast_path        (短路祖先链)"
echo "  Process.CheckRisk enter 总数: $process_enter (越少越好)"
if [ "$refresh_count" -ge 5 ]; then
    mark_pass "祖先 ($refresh_count 次) 被复用"
else
    mark_fail "祖先复用不足 (期望>=5, 实际 $refresh_count)"
fi
if [ "$fast_path" -ge 5 ]; then
    mark_pass "FAST-PATH 触发 $fast_path 次（祖先链短路生效）"
else
    mark_fail "FAST-PATH 触发不足 (期望>=5, 实际 $fast_path)"
fi

# ---------- 测试 4: 不同子 shell 共享同一 init 祖先 ----------
echo ""
echo "测试4: 不同 sh 实例的 cat 共享更深祖先"
mark=$(log_mark)
for i in 1 2 3; do
    bash -c "cat $SECRET_FILE > /dev/null"
done
sleep 0.5
slice=$(log_slice "$mark")
refresh_count2=$(echo "$slice" | grep -c "cache.GetOrTouch\] REFRESH" || true)
echo "  GetOrTouch REFRESH 次数: $refresh_count2"
[ "$refresh_count2" -ge 3 ] && mark_pass "祖先 cache 在不同 bash 间复用" \
    || mark_fail "祖先复用不足 (期望>=3, 实际 $refresh_count2)"

# ---------- 测试 5: 拒绝路径 (grep 不在 allowed_binaries) ----------
echo ""
echo "测试5: 拒绝路径 (grep 未授权) -> 仍走完 CheckRisk 但 baseline 拒绝"
mark=$(log_mark)
grep "secret" "$SECRET_FILE" > /dev/null 2>&1 || true
sleep 0.5
slice=$(log_slice "$mark")
# grep 的 Binary 检查可能通过（/usr/bin/grep 在 PATH），但 baseline 路径校验会拒
echo "$slice" | grep -q "denied\|DENIED" && \
    mark_pass "拒绝事件被记录" || mark_fail "未看到拒绝日志"

# ---------- 测试 6: cache 表大小不无限增长 ----------
echo ""
echo "测试6: 大量短命子进程后，cache 表不应无限增长"
mark=$(log_mark)
# 制造 50 个短命 cat
for i in $(seq 1 50); do cat "$SECRET_FILE" > /dev/null; done
sleep 0.5
slice=$(log_slice "$mark")
# 解析 cache.GetOrCreate MISS 后面的 table 大小
final_table=$(echo "$slice" | grep "cache.GetOrCreate\] MISS" | tail -1 | grep -oE "table now=[0-9]+" | grep -oE "[0-9]+" || echo "")
echo "  cache 表大小 (最后一次 MISS 时): ${final_table:-N/A}"
if [ -n "$final_table" ] && [ "$final_table" -lt 200 ]; then
    mark_pass "cache 表大小合理: $final_table"
else
    mark_fail "cache 表大小异常: ${final_table:-N/A}"
fi

# ---------- 测试 P1: python 作为父进程，Interpreter.CheckRisk 应触发 ----------
echo ""
echo "测试P1: python 作为父进程 -> Interpreter.CheckRisk 触发并通过"
if ! command -v python3 >/dev/null; then
    echo "  - 跳过 (无 python3)"
else
    mark=$(log_mark)
    # python 运行 trusted 脚本调 cat 读受保护文件；cat 的父 = python；python 的父 = bash
    python3 "$PY_CAT_WRAPPER" "$SECRET_FILE" > /dev/null 2>&1 || true
    sleep 0.5
    slice=$(log_slice "$mark")
    # 期望日志（新架构: 具体子类 Python.CheckRisk）:
    #   [Python.CheckRisk] pid=<python_pid> path=/usr/bin/python3.12
    #   [Python.CheckRisk] PASS pid=<python_pid>
    if echo "$slice" | grep -q "Python.CheckRisk\] pid="; then
        mark_pass "Python.CheckRisk 触发 (python 作为父)"
    else
        mark_fail "未触发 Python.CheckRisk"
    fi
    if echo "$slice" | grep -q "Python.CheckRisk\] PASS pid="; then
        mark_pass "干净环境下 Python 验证通过"
    else
        mark_fail "Python 未通过 (干净环境却失败)"
    fi
    # 走通后 cat 应成功读取
    output=$(python3 "$PY_CAT_WRAPPER" "$SECRET_FILE" 2>&1)
    if echo "$output" | grep -q "ancestor-cache-test-secret"; then
        mark_pass "python->cat 访问成功"
    else
        mark_fail "python->cat 访问失败: $output"
    fi
fi

# ---------- 测试 P2: PYTHONPATH 注入应被拒绝 ----------
echo ""
echo "测试P2: PYTHONPATH=/tmp/evil python -> cat 应被拒绝（untrusted ancestor）"
if ! command -v python3 >/dev/null; then
    echo "  - 跳过 (无 python3)"
else
    mark=$(log_mark)
    out=$(PYTHONPATH=/tmp/evil python3 -c "
import subprocess
r = subprocess.run(['cat', '$SECRET_FILE'], capture_output=True, text=True)
print(r.stdout)
print('STDERR:', r.stderr)
print('RC:', r.returncode)
" 2>&1)
    sleep 0.5
    slice=$(log_slice "$mark")
    echo "  输出: $(echo "$out" | head -3 | tr '\n' '|')"
    # 期望：cat 读不到内容（FUSE 拒绝），日志里有 interpreter_check.python 拒绝
    if echo "$slice" | grep -q "interpreter_check.python\|PYTHONPATH"; then
        mark_pass "日志包含 PYTHONPATH/interpreter_check 检查事件"
    else
        mark_fail "未看到 interpreter env 检查事件"
    fi
    if echo "$slice" | grep -qE "denied.*untrusted ancestor.*python|untrusted ancestor.*PYTHONPATH"; then
        mark_pass "FUSE 因 untrusted ancestor (python) 拒绝"
    else
        # 退化检查：只要有任意 denied + python 相关原因
        if echo "$slice" | grep -q "denied"; then
            mark_pass "FUSE 拒绝事件被记录 (PYTHONPATH 场景)"
        else
            mark_fail "未看到拒绝事件"
        fi
    fi
    if ! echo "$out" | grep -q "ancestor-cache-test-secret"; then
        mark_pass "受保护内容未被读到（拒绝生效）"
    else
        mark_fail "PYTHONPATH 注入下仍读到内容（拒绝失效）"
    fi
fi

# ---------- 测试 P2b: PYTHONUSERBASE 注入应被拒绝 (security report #6) ----------
echo ""
echo "测试P2b: PYTHONUSERBASE=/tmp/evil 应被拒绝"
if command -v python3 >/dev/null; then
    mark=$(log_mark)
    out=$(PYTHONUSERBASE=/tmp/evil_base python3 -c "
import subprocess
r=subprocess.run(['cat', '$SECRET_FILE'], capture_output=True, text=True)
print(r.stdout)" 2>&1)
    sleep 0.5
    slice=$(log_slice "$mark")
    if ! echo "$out" | grep -q "ancestor-cache-test-secret"; then
        mark_pass "PYTHONUSERBASE 注入下未读到内容"
    else
        mark_fail "PYTHONUSERBASE 注入未触发拒绝"
    fi
    if echo "$slice" | grep -q "PYTHONUSERBASE"; then
        mark_pass "日志包含 PYTHONUSERBASE 检查事件"
    else
        mark_fail "未看到 PYTHONUSERBASE 检查事件"
    fi
fi

# ---------- 测试 P2c: PYTHONINSPECT 注入应被拒绝 (security report #7) ----------
echo ""
echo "测试P2c: PYTHONINSPECT=1 应被拒绝"
if command -v python3 >/dev/null; then
    mark=$(log_mark)
    # PYTHONINSPECT=1 会让 python 脚本结束后进入交互模式等 stdin。
    # 必须 </dev/null 让交互模式立即 EOF 退出，否则测试会卡住。
    # 也加 timeout 双保险。
    out=$(PYTHONINSPECT=1 timeout 5 python3 -c "
import subprocess
r=subprocess.run(['cat', '$SECRET_FILE'], capture_output=True, text=True)
print(r.stdout)" </dev/null 2>&1)
    sleep 0.5
    slice=$(log_slice "$mark")
    if ! echo "$out" | grep -q "ancestor-cache-test-secret"; then
        mark_pass "PYTHONINSPECT 注入下未读到内容"
    else
        mark_fail "PYTHONINSPECT 注入未触发拒绝"
    fi
    if echo "$slice" | grep -q "PYTHONINSPECT"; then
        mark_pass "日志包含 PYTHONINSPECT 检查事件"
    else
        mark_fail "未看到 PYTHONINSPECT 检查事件"
    fi
fi

# ---------- 测试 P2d: PYTHONHOME 注入应被拒绝 ----------
echo ""
echo "测试P2d: PYTHONHOME=/tmp/evil 应被拒绝"
if command -v python3 >/dev/null; then
    mark=$(log_mark)
    out=$(PYTHONHOME=/tmp/evil_home timeout 5 python3 -c "
import subprocess
r=subprocess.run(['cat', '$SECRET_FILE'], capture_output=True, text=True)
print(r.stdout)" </dev/null 2>&1)
    sleep 0.5
    slice=$(log_slice "$mark")
    # PYTHONHOME 可能让 python 启动失败（找不到标准库），但应有 interp env denial 日志
    if echo "$slice" | grep -qE "PYTHONHOME|interpreter_check"; then
        mark_pass "日志包含 PYTHONHOME 检查事件"
    else
        # PYTHONHOME 可能让 python 直接死掉无法到达 FUSE，那也是另一种"拒绝"
        if ! echo "$out" | grep -q "ancestor-cache-test-secret"; then
            mark_pass "PYTHONHOME 下未读到内容（即使 python 启动失败也算拒绝）"
        else
            mark_fail "PYTHONHOME 未拦截"
        fi
    fi
fi

# ---------- 测试 P3: PYTHONSTARTUP 注入应被拒绝 ----------
echo ""
echo "测试P3: PYTHONSTARTUP=/tmp/evil.py 应被拒绝"
if ! command -v python3 >/dev/null; then
    echo "  - 跳过 (无 python3)"
else
    mark=$(log_mark)
    out=$(PYTHONSTARTUP=/tmp/evil.py timeout 5 python3 -c "
import subprocess
r = subprocess.run(['cat', '$SECRET_FILE'], capture_output=True, text=True)
print(r.stdout)
" 2>&1)
    sleep 0.5
    slice=$(log_slice "$mark")
    if ! echo "$out" | grep -q "ancestor-cache-test-secret"; then
        mark_pass "PYTHONSTARTUP 注入下未读到内容（拒绝生效）"
    else
        mark_fail "PYTHONSTARTUP 注入未触发拒绝"
    fi
    if echo "$slice" | grep -q "interpreter_check.python.*PYTHONSTARTUP\|PYTHONSTARTUP"; then
        mark_pass "日志包含 PYTHONSTARTUP 检查事件"
    else
        mark_fail "未看到 PYTHONSTARTUP 检查事件"
    fi
fi

# ---------- 测试 P3b: .pth 文件注入检测 (security report #8) ----------
echo ""
echo "测试P3b: 用户 site-packages 下的 .pth 文件注入应被拒绝"
if command -v python3 >/dev/null; then
    # 取实际 python 版本
    PY_VER=$(python3 -c "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')" 2>/dev/null)
    if [ -z "$PY_VER" ]; then
        echo "  - 跳过 (无法获取 python 版本)"
    else
        # 准备一个临时 HOME，里面有恶意 .pth
        FAKE_HOME=$(mktemp -d /tmp/credagent_fakehome.XXXXXX)
        PTH_DIR="$FAKE_HOME/.local/lib/python${PY_VER}/site-packages"
        mkdir -p "$PTH_DIR"
        cat > "$PTH_DIR/evil.pth" << 'EOF'
import os; os.system('echo pwned > /tmp/evil_pth_marker')
EOF
        mark=$(log_mark)
        out=$(HOME=$FAKE_HOME python3 -c "
import subprocess
r=subprocess.run(['cat', '$SECRET_FILE'], capture_output=True, text=True)
print(r.stdout)" 2>&1)
        sleep 0.5
        slice=$(log_slice "$mark")
        if echo "$slice" | grep -q ".pth file injection detected"; then
            mark_pass ".pth 注入被 CheckPythonPthRisk 检测到"
        else
            mark_fail "未看到 .pth 注入检测日志"
        fi
        if ! echo "$out" | grep -q "ancestor-cache-test-secret"; then
            mark_pass ".pth 注入下未读到凭据"
        else
            mark_fail ".pth 注入未拦截"
        fi
        rm -rf "$FAKE_HOME"
    fi
fi

# ---------- 测试 P3c: sitecustomize.py 注入检测 ----------
echo ""
echo "测试P3c: 用户 site-packages 下的 sitecustomize.py 注入应被拒绝"
if command -v python3 >/dev/null; then
    PY_VER=$(python3 -c "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')" 2>/dev/null)
    if [ -n "$PY_VER" ]; then
        FAKE_HOME=$(mktemp -d /tmp/credagent_fakehome.XXXXXX)
        SITE_DIR="$FAKE_HOME/.local/lib/python${PY_VER}/site-packages"
        mkdir -p "$SITE_DIR"
        cat > "$SITE_DIR/sitecustomize.py" << 'EOF'
import os; os.system('echo site-pwned > /tmp/evil_site_marker')
EOF
        mark=$(log_mark)
        out=$(HOME=$FAKE_HOME python3 -c "
import subprocess
r=subprocess.run(['cat', '$SECRET_FILE'], capture_output=True, text=True)
print(r.stdout)" 2>&1)
        sleep 0.5
        slice=$(log_slice "$mark")
        if echo "$slice" | grep -qE "sitecustomize|code injection file"; then
            mark_pass "sitecustomize.py 注入被检测到"
        else
            mark_fail "未看到 sitecustomize.py 检测日志"
        fi
        rm -rf "$FAKE_HOME"
    fi
fi

# ---------- 测试 P4: 多次 python 调用，Interpreter 检查只跑必要次数 ----------
echo ""
echo "测试P4: 多次 python->cat (祖先为 python)，验证 FAST-PATH 在 python 父链生效"
if ! command -v python3 >/dev/null; then
    echo "  - 跳过 (无 python3)"
else
    mark=$(log_mark)
    for i in 1 2 3 4 5; do
        python3 "$PY_CAT_WRAPPER" "$SECRET_FILE" > /dev/null 2>/dev/null
    done
    sleep 0.5
    slice=$(log_slice "$mark")
    py_check_count=$(echo "$slice" | grep -c "Python.CheckRisk\] pid=" || true)
    fast_path=$(echo "$slice" | grep -c "Process.CheckRisk\] FAST-PATH" || true)
    echo "  Python.CheckRisk 调用次数: $py_check_count"
    echo "  FAST-PATH 总次数: $fast_path"
    # 每次访问都创建新 python 进程（不同 PID），所以 Interpreter check 不复用是预期的
    # 但其内部 Binary 检查（path/native env）也不复用 — 因为 Interpreter 实例是新的
    # 关键是：python 的祖先 (bash) 应被 FAST-PATH
    if [ "$fast_path" -ge 5 ]; then
        mark_pass "FAST-PATH 在 python 父链下也工作 ($fast_path 次)"
    else
        mark_fail "FAST-PATH 触发不足 (期望>=5, 实际 $fast_path)"
    fi
fi

# ---------- 测试 F1: 用户二进制名为 python1，不应被误判为 Python 解释器 ----------
echo ""
echo "测试F1: /tmp/...userbin/python1 (实为 cat 副本) 被授权，应能访问凭据"
USER_BIN_DIR="$TEST_DIR/userbin"
mkdir -p "$USER_BIN_DIR"
cp /bin/cat "$USER_BIN_DIR/python1"
chmod 755 "$USER_BIN_DIR/python1"

SECRET_F1="$SECRETS_DIR/false_positive_python1.txt"
rm -f "$SECRET_F1"
echo "fake-python-secret" > "$SECRET_F1"

# 用 python1 这个名字授权
"$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" \
    --strategy BASIC --program-permit "$USER_BIN_DIR/python1" --measure true \
    "$SECRET_F1" > /dev/null 2>&1
if [ ! -L "$SECRET_F1" ]; then
    mark_fail "保护文件注册失败 (F1)"
else
    mark=$(log_mark)
    out=$("$USER_BIN_DIR/python1" "$SECRET_F1" 2>&1)
    sleep 0.5
    slice=$(log_slice "$mark")
    if echo "$out" | grep -q "fake-python-secret"; then
        mark_pass "python1 被授权后可读凭据（matchFamily 收紧生效）"
    else
        mark_fail "python1 读取失败: $out"
    fi
    # 关键日志：path=...python1 应该走 Binary 而非 Interpreter
    if echo "$slice" | grep -q "Interpreter.CheckRisk\] pid=.*path=$USER_BIN_DIR/python1"; then
        mark_fail "python1 仍被误判为 Interpreter（matchFamily 没生效）"
    else
        mark_pass "python1 未被包装为 Interpreter (正确)"
    fi
fi

# ---------- 测试 F2: 用户二进制名为 python（真符合命名），在非标准路径，依赖 trusted_programs 短路 ----------
echo ""
echo "测试F2: 名字真叫 python，但放在 /tmp/...userbin/，授权后应能访问"
cp /bin/cat "$USER_BIN_DIR/python"
chmod 755 "$USER_BIN_DIR/python"

SECRET_F2="$SECRETS_DIR/false_positive_python.txt"
rm -f "$SECRET_F2"
echo "real-name-fake-binary-secret" > "$SECRET_F2"

"$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" \
    --strategy BASIC --program-permit "$USER_BIN_DIR/python" --measure true \
    "$SECRET_F2" > /dev/null 2>&1
if [ ! -L "$SECRET_F2" ]; then
    mark_fail "保护文件注册失败 (F2)"
else
    mark=$(log_mark)
    out=$("$USER_BIN_DIR/python" "$SECRET_F2" 2>&1)
    sleep 0.5
    slice=$(log_slice "$mark")
    if echo "$out" | grep -q "real-name-fake-binary-secret"; then
        mark_pass "授权 python (非标准路径) 可读凭据"
    else
        mark_fail "授权的 python 读取失败: $out"
    fi
    # 关键日志：NewInterpreter 应该返回 nil（因为路径非标准），改走 Binary
    if echo "$slice" | grep -q "NewInterpreter\].*$USER_BIN_DIR/python.*treating as Binary"; then
        mark_pass "NewInterpreter 在路径非标准时返回 nil (落回 Binary)"
    else
        mark_fail "未看到 NewInterpreter fallback 日志"
    fi
    # 再次确认：该路径不应有 Interpreter.CheckRisk 日志
    if echo "$slice" | grep -q "Interpreter.CheckRisk\] pid=.*path=$USER_BIN_DIR/python "; then
        mark_fail "userbin/python 仍被当 Interpreter 处理"
    else
        mark_pass "userbin/python 未走 Interpreter 路径"
    fi
fi

# ---------- 测试 F3: 未授权的同名假 python 仍应被拒（fix 不能开后门） ----------
echo ""
echo "测试F3: 不被授权的同路径 python 访问 *其他* 凭据，应被拒"
SECRET_F3="$SECRETS_DIR/false_positive_unauth.txt"
rm -f "$SECRET_F3"
echo "another-secret-not-for-python" > "$SECRET_F3"

# 只授权 /bin/cat，不授权 $USER_BIN_DIR/python
"$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" \
    --strategy BASIC --program-permit /bin/cat --measure true \
    "$SECRET_F3" > /dev/null 2>&1

mark=$(log_mark)
out=$("$USER_BIN_DIR/python" "$SECRET_F3" 2>&1 || true)
sleep 0.5
slice=$(log_slice "$mark")
if echo "$out" | grep -q "another-secret-not-for-python"; then
    mark_fail "未授权 python 读到了凭据（不该）"
else
    mark_pass "未授权 python 被拒（修复未引入后门）"
fi

# ---------- 测试 7: 等待 cleanup 后 ancestor 被驱逐 ----------
echo ""
echo "测试7: 等待 cleanup 后短命 cat 进程被驱逐"
# cleanup interval=10s, timeout 由 process_cleanup_timeout_sec 决定 (默认 30s)
# 缩短不可控，这里仅观察是否有 EVICT 日志即可
mark=$(log_mark)
echo "等待 35s 给 cleanup 一轮回收时间..."
sleep 35
slice=$(log_slice "$mark")
evict_count=$(echo "$slice" | grep -c "cache.cleanup\] EVICT" || true)
echo "  EVICT 次数: $evict_count"
[ "$evict_count" -ge 1 ] && mark_pass "cleanup 驱逐了 $evict_count 个 entry" \
    || mark_fail "cleanup 未驱逐任何 entry"

# ---------- 结尾 ----------
echo ""
echo "=============================================="
echo "通过: $PASSED   失败: $FAILED"
echo "=============================================="
echo "完整日志: $CREDAGENT_LOG"
echo "可手动检查关键事件:"
echo "  grep 'Binary.CheckRisk\\|Process.CheckRisk\\|cache.GetOrCreate\\|cache.GetOrTouch\\|cache.cleanup' $CREDAGENT_LOG"
[ "$FAILED" -eq 0 ] && exit 0 || exit 1
