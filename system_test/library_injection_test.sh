#!/bin/bash

# CredAgent 动态库注入检测测试 (Phase 2 - library_injection_check)
# 测试目标：验证 /proc/<pid>/maps 中检测到从不安全路径加载的 .so 时拒绝访问
# 前置条件：已执行 init_test_environ.sh
# 运行要求：需要 sudo 权限 + gcc

if [ "$(id -u)" -ne 0 ]; then
    echo "错误: 此测试需要 root 权限运行，请使用 sudo 执行"
    exit 1
fi

echo "=============================================="
echo "CredAgent 动态库注入检测测试 (library_injection_check)"
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

if ! command -v gcc >/dev/null 2>&1; then
    echo "错误: gcc 未安装，无法编译测试 .so"
    exit 1
fi

echo "测试环境验证通过"
echo "  TEST_DIR: $TEST_DIR"
echo "  CREDAGENT_PID: $CREDAGENT_PID"
echo ""

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

SECRET_FILE="$SECRETS_DIR/libinject_test_secret.txt"
SECRET_CONTENT="libinject_test_secret_value_77788"

# ============================================
# 启用 library_injection_check
# ============================================
echo "启用 library_injection_check..."

# 保存原始配置
cp "$SECURITY_CONFIG" "${SECURITY_CONFIG}.bak_libinject"

python3 -c "
import json, sys
with open(sys.argv[1]) as f: cfg = json.load(f)
opts = cfg.setdefault('antiattack_options', {})
lib_check = opts.setdefault('library_injection_check', {})
lib_check['enabled'] = True
lib_check['trusted_lib_paths'] = []
with open(sys.argv[1], 'w') as f: json.dump(cfg, f, indent=2, ensure_ascii=False)
" "$SECURITY_CONFIG"

# 重启 daemon 使配置生效
kill "$CREDAGENT_PID" 2>/dev/null; sleep 2
"$PROJECT_ROOT/credagent" run -c "$ENGINE_CONFIG" >> "$CREDAGENT_LOG" 2>&1 &
CREDAGENT_PID=$!; sleep 2
sed -i "s/^export CREDAGENT_PID=.*/export CREDAGENT_PID=\"$CREDAGENT_PID\"/" "$ENV_FILE"
echo "daemon 重启完成 (PID=$CREDAGENT_PID)"
echo ""

# ============================================
# 准备: 编译测试用的 .so 和加载程序
# ============================================

# 创建一个无害的共享库
EVIL_SO="$TEST_DIR/evil_inject.so"
cat > "$TEST_DIR/evil_inject.c" << 'CEOF'
// A trivial shared library — does nothing harmful, just exists in /proc/maps.
#include <stdio.h>
__attribute__((constructor))
void evil_init(void) {
    // no-op
}
CEOF

gcc -shared -fPIC -o "$EVIL_SO" "$TEST_DIR/evil_inject.c" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "错误: 编译 evil_inject.so 失败"
    # 恢复配置
    mv "${SECURITY_CONFIG}.bak_libinject" "$SECURITY_CONFIG"
    kill "$CREDAGENT_PID" 2>/dev/null; sleep 1
    "$PROJECT_ROOT/credagent" run -c "$ENGINE_CONFIG" >> "$CREDAGENT_LOG" 2>&1 &
    CREDAGENT_PID=$!
    sed -i "s/^export CREDAGENT_PID=.*/export CREDAGENT_PID=\"$CREDAGENT_PID\"/" "$ENV_FILE"
    exit 1
fi

# 编译一个 C 程序: 用 dlopen 加载 .so 后读取凭据文件
READER_SRC="$TEST_DIR/libinject_reader.c"
READER_BIN="$TEST_DIR/libinject_reader"
cat > "$READER_SRC" << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file> [so_to_load]\n", argv[0]);
        return 1;
    }
    // If a .so path is given, dlopen it so it appears in /proc/self/maps
    if (argc >= 3) {
        void *handle = dlopen(argv[2], RTLD_NOW);
        if (!handle) {
            fprintf(stderr, "dlopen failed: %s\n", dlerror());
            // Continue anyway — the .so won't be in maps but that's OK for test logic
        }
    }
    // Small sleep to allow FUSE handler to inspect /proc/self/maps
    usleep(10000);
    FILE *f = fopen(argv[1], "r");
    if (!f) {
        fprintf(stderr, "PERMISSION_DENIED\n");
        return 1;
    }
    char buf[256];
    if (fgets(buf, sizeof(buf), f)) {
        buf[strcspn(buf, "\n")] = 0;
        printf("%s\n", buf);
    }
    fclose(f);
    return 0;
}
CEOF

gcc -o "$READER_BIN" "$READER_SRC" -ldl 2>/dev/null
if [ $? -ne 0 ]; then
    echo "错误: 编译 libinject_reader 失败"
    mv "${SECURITY_CONFIG}.bak_libinject" "$SECURITY_CONFIG"
    kill "$CREDAGENT_PID" 2>/dev/null; sleep 1
    "$PROJECT_ROOT/credagent" run -c "$ENGINE_CONFIG" >> "$CREDAGENT_LOG" 2>&1 &
    CREDAGENT_PID=$!
    sed -i "s/^export CREDAGENT_PID=.*/export CREDAGENT_PID=\"$CREDAGENT_PID\"/" "$ENV_FILE"
    exit 1
fi

echo "编译完成: evil_inject.so, libinject_reader"
echo ""

# ============================================
# 保护凭据 — 授权 reader 二进制
# ============================================
rm -f "$SECRET_FILE" 2>/dev/null
echo "$SECRET_CONTENT" > "$SECRET_FILE"

"$PROJECT_ROOT/credctl" protect --config "$CREDCTL_CONFIG" \
    --strategy BASIC -p "$READER_BIN" --measure false "$SECRET_FILE" >/dev/null 2>&1

if [ ! -L "$SECRET_FILE" ]; then
    echo "protect 失败"
    mv "${SECURITY_CONFIG}.bak_libinject" "$SECURITY_CONFIG"
    kill "$CREDAGENT_PID" 2>/dev/null; sleep 1
    "$PROJECT_ROOT/credagent" run -c "$ENGINE_CONFIG" >> "$CREDAGENT_LOG" 2>&1 &
    CREDAGENT_PID=$!
    sed -i "s/^export CREDAGENT_PID=.*/export CREDAGENT_PID=\"$CREDAGENT_PID\"/" "$ENV_FILE"
    exit 1
fi
echo "凭据已保护"
echo ""

# 辅助函数
expect_denied() {
    local desc="$1"; local output="$2"; local result="$3"
    if [ "$result" -ne 0 ] || [[ "$output" == *"PERMISSION_DENIED"* ]] || [[ "$output" != *"$SECRET_CONTENT"* ]]; then
        echo "  ✓ $desc"
        ((TESTS_PASSED++))
    else
        echo "  ✗ $desc — 未被拒绝！输出: $output"
        ((TESTS_FAILED++))
    fi
}

expect_allowed() {
    local desc="$1"; local output="$2"; local result="$3"
    if [ "$result" -eq 0 ] && [[ "$output" == *"$SECRET_CONTENT"* ]]; then
        echo "  ✓ $desc"
        ((TESTS_PASSED++))
    else
        echo "  ✗ $desc — 被错误拒绝。输出: $output"
        ((TESTS_FAILED++))
    fi
}

# ============================================
echo "=============================================="
echo "测试1: 正常访问 — 无注入 .so"
echo "=============================================="
OUTPUT=$("$READER_BIN" "$SECRET_FILE" 2>&1)
expect_allowed "无注入时正常访问" "$OUTPUT" "$?"

# ============================================
echo ""
echo "=============================================="
echo "测试2: dlopen /tmp 下的 .so — 应被拒绝"
echo "=============================================="
OUTPUT=$("$READER_BIN" "$SECRET_FILE" "$EVIL_SO" 2>&1)
expect_denied "dlopen /tmp .so 被拒绝" "$OUTPUT" "$?"

# ============================================
echo ""
echo "=============================================="
echo "测试3: LD_PRELOAD 加载 /tmp .so — 应被拒绝"
echo "=============================================="
OUTPUT=$(LD_PRELOAD="$EVIL_SO" "$READER_BIN" "$SECRET_FILE" 2>&1)
expect_denied "LD_PRELOAD /tmp .so 被拒绝" "$OUTPUT" "$?"

# ============================================
echo ""
echo "=============================================="
echo "测试4: 将 .so 加入 trusted_lib_paths — 应允许"
echo "=============================================="

# 更新配置加入 trusted_lib_paths
python3 -c "
import json, sys
with open(sys.argv[1]) as f: cfg = json.load(f)
lib_check = cfg['antiattack_options']['library_injection_check']
lib_check['trusted_lib_paths'] = [sys.argv[2]]
with open(sys.argv[1], 'w') as f: json.dump(cfg, f, indent=2, ensure_ascii=False)
" "$SECURITY_CONFIG" "$EVIL_SO"

# 重启 daemon
kill "$CREDAGENT_PID" 2>/dev/null; sleep 2
"$PROJECT_ROOT/credagent" run -c "$ENGINE_CONFIG" >> "$CREDAGENT_LOG" 2>&1 &
CREDAGENT_PID=$!; sleep 2
sed -i "s/^export CREDAGENT_PID=.*/export CREDAGENT_PID=\"$CREDAGENT_PID\"/" "$ENV_FILE"

OUTPUT=$("$READER_BIN" "$SECRET_FILE" "$EVIL_SO" 2>&1)
expect_allowed "trusted_lib_paths 白名单放行" "$OUTPUT" "$?"

# ============================================
echo ""
echo "=============================================="
echo "测试5: 恢复后，正常访问仍然正常"
echo "=============================================="
OUTPUT=$("$READER_BIN" "$SECRET_FILE" 2>&1)
expect_allowed "正常访问仍正常 (无误报)" "$OUTPUT" "$?"

# ============================================
# 清理
# ============================================
echo ""
echo "清理: 释放凭据 + 恢复配置"

if [ -L "$SECRET_FILE" ]; then
    SHA_ID=$(readlink "$SECRET_FILE" | xargs basename)
    rm -f "$SECRET_FILE"
    echo ""
    echo "----------------------------------------------"
    echo "请注意：此步骤需要人工交互输入"
    echo "当要求输入密码时，请输入初始化时设置的管理员密码"
    echo "----------------------------------------------"
    echo ""
    "$PROJECT_ROOT/credctl" release --config "$CREDCTL_CONFIG" "$SHA_ID"
fi

# 恢复原始配置
mv "${SECURITY_CONFIG}.bak_libinject" "$SECURITY_CONFIG"

# 重启 daemon 使配置恢复
kill "$CREDAGENT_PID" 2>/dev/null; sleep 2
"$PROJECT_ROOT/credagent" run -c "$ENGINE_CONFIG" >> "$CREDAGENT_LOG" 2>&1 &
CREDAGENT_PID=$!; sleep 2
sed -i "s/^export CREDAGENT_PID=.*/export CREDAGENT_PID=\"$CREDAGENT_PID\"/" "$ENV_FILE"
echo "daemon 已恢复原始配置 (PID=$CREDAGENT_PID)"

rm -f "$EVIL_SO" "$READER_BIN" "$READER_SRC" "$TEST_DIR/evil_inject.c" 2>/dev/null

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
