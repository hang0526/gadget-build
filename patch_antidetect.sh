#!/bin/bash
# Frida Gadget Anti-Detection Patch Script
# 批量替换所有检测特征

set -e
cd "$(dirname "$0")"

echo "[*] Patching Frida detection fingerprints..."

# ===== 1. 默认端口: 27042 -> 43890, 27052 -> 43900 =====
echo "[1/10] Patching default ports..."
sed -i 's/DEFAULT_CONTROL_PORT = 27042/DEFAULT_CONTROL_PORT = 43890/' lib/base/socket.vala
sed -i 's/DEFAULT_CLUSTER_PORT = 27052/DEFAULT_CLUSTER_PORT = 43900/' lib/base/socket.vala

# ===== 2. 线程名 =====
echo "[2/10] Patching thread names..."
# gadget-glue.c: "frida-gadget" -> "gmain-svc"
sed -i 's/"frida-gadget"/"gmain-svc"/' lib/gadget/gadget-glue.c
# gadget.vala: "frida-gadget-tcp-%u" -> "pool-svc-tcp-%u"
sed -i 's/"frida-gadget-tcp-%u"/"pool-svc-tcp-%u"/' lib/gadget/gadget.vala
# gadget.vala: "frida-gadget-unix" -> "pool-svc-unix"
sed -i 's/"frida-gadget-unix"/"pool-svc-unix"/' lib/gadget/gadget.vala
# frida-glue.c: "frida-main-loop" -> "gmain-loop"
sed -i 's/"frida-main-loop"/"gmain-loop"/' src/frida-glue.c
# agent.vala: "frida-agent-emulated" -> "jit-worker"
sed -i 's/"frida-agent-emulated"/"jit-worker"/' lib/agent/agent.vala
# agent-container.vala: "frida-agent-container" -> "pool-container"
sed -i 's/"frida-agent-container"/"pool-container"/' src/agent-container.vala

# ===== 3. D-Bus 接口名: "re.frida." -> "re.mgnt." =====
echo "[3/10] Patching D-Bus interface names..."
sed -i 's/re\.frida\./re.mgnt./g' lib/base/session.vala

# ===== 4. D-Bus 对象路径: "/re/frida/" -> "/re/mgnt/" =====
echo "[4/10] Patching D-Bus object paths..."
sed -i 's|/re/frida/|/re/mgnt/|g' lib/base/session.vala

# ===== 5. D-Bus Server GUID (hex "github.com/frida") =====
echo "[5/10] Patching D-Bus GUID..."
# Original: 6769746875622e636f6d2f6672696461 = "github.com/frida"
# Replace:  6170702e696e7465726e616c2e737663 = "app.internal.svc"
sed -i 's/6769746875622e636f6d2f6672696461/6170702e696e7465726e616c2e737663/' lib/base/session.vala

# ===== 6. TLS 证书指纹 =====
echo "[6/10] Patching TLS certificate fields..."
# Organization: "Frida" -> "Android"
sed -i 's/"O", MBSTRING_ASC, (const unsigned char \*) "Frida"/"O", MBSTRING_ASC, (const unsigned char *) "Android"/' lib/base/p2p-glue.c
# Common Name: "lolcathost" -> "localhost"
sed -i 's/"lolcathost"/"localhost"/' lib/base/p2p-glue.c

# ===== 7. HTTP User-Agent / Server 头 =====
echo "[7/10] Patching HTTP headers..."
sed -i 's/"User-Agent", "Frida\/" + _version_string ()/"User-Agent", "HttpSvc\/1.0"/' lib/base/socket.vala
sed -i 's/"Server", "Frida\/" + _version_string ()/"Server", "HttpSvc\/1.0"/' lib/base/socket.vala

# ===== 8. ICE/SDP Software 属性: "Frida" -> "SvcApp" =====
echo "[8/10] Patching SDP software attribute..."
sed -i 's/set_software ("Frida")/set_software ("SvcApp")/' lib/base/session.vala
sed -i 's/set_software ("Frida")/set_software ("SvcApp")/' src/frida.vala

# ===== 9. Gadget 标识符 =====
echo "[9/10] Patching Gadget identifiers..."
# "re.frida.Gadget" -> "com.system.svchost"  (注意 session.vala 已经被上面的批量替换处理了)
sed -i 's/"re\.frida\.Gadget"/"com.system.svchost"/' lib/gadget/gadget.vala
# droidy-host-session.vala
sed -i 's/"re\.frida\.Gadget"/"com.system.svchost"/' src/droidy/droidy-host-session.vala 2>/dev/null || true
# Other re.frida identifiers in other files
sed -i 's/"re\.frida\./"re.mgnt./g' lib/netif/tunnel-interface-observer.vala 2>/dev/null || true
sed -i 's/"re\.frida\./"re.mgnt./g' server/server.vala 2>/dev/null || true
sed -i 's/"re\.frida\./"re.mgnt./g' src/barebone/qmp-client.vala 2>/dev/null || true
sed -i 's/"re\.frida\./"re.mgnt./g' src/darwin/frida-helper-types.vala 2>/dev/null || true

# ===== 10. 模块名和环境变量 =====
echo "[10/10] Patching module names & env vars..."
# unwind-sitter-glue.c: module name "Frida" -> "System"
sed -i 's/gum_darwin_module_new_from_memory ("Frida"/gum_darwin_module_new_from_memory ("System"/' lib/payload/unwind-sitter-glue.c
# gadget-glue.c: "frida_gadget_config=" -> "sys_svc_config="
sed -i 's/frida_gadget_config=/sys_svc_config=/' lib/gadget/gadget-glue.c
# gadget-glue.c: "frida_dylib_range=" -> "sys_dylib_range="
sed -i 's/frida_dylib_range=/sys_dylib_range=/' lib/gadget/gadget-glue.c
# SO/dylib library names in source strings
sed -i 's/"frida-agent-arm\.so"/"libsystem_agent-arm.so"/g' src/linux/linux-host-session.vala 2>/dev/null || true
sed -i 's/"frida-agent-arm64\.so"/"libsystem_agent-arm64.so"/g' src/linux/linux-host-session.vala 2>/dev/null || true
sed -i 's/"frida-gadget\.so"/"libsystem_svc.so"/g' src/droidy/droidy-host-session.vala 2>/dev/null || true
sed -i 's/"frida-gadget\.dylib"/"libsystem_svc.dylib"/g' src/fruity/fruity-host-session.vala 2>/dev/null || true

# ===== Build output name =====
# compat/build.py: rename output .so/.dylib/.dll
sed -i 's/AGENT_TARGET = "frida-agent"/AGENT_TARGET = "system-agent"/' compat/build.py 2>/dev/null || true
sed -i 's/GADGET_TARGET = "frida-gadget"/GADGET_TARGET = "system-svc"/' compat/build.py 2>/dev/null || true
sed -i 's/"frida-agent\./"system-agent./g' compat/build.py 2>/dev/null || true
sed -i 's/"frida-gadget\./"system-svc./g' compat/build.py 2>/dev/null || true
sed -i 's/frida-agent-arm\.so/system-agent-arm.so/g' compat/build.py 2>/dev/null || true
sed -i 's/frida-agent-arm64\.so/system-agent-arm64.so/g' compat/build.py 2>/dev/null || true

# ===== meson.build: rename library output =====
sed -i "s/'frida-agent'/'system-agent'/g" meson.build 2>/dev/null || true
sed -i "s/'frida-gadget'/'system-svc'/g" meson.build lib/gadget/meson.build 2>/dev/null || true

# ===== Logging messages: remove "Listening on" telltale =====
sed -i 's/Listening on %s TCP port %u/Service started on %s:%u/' lib/gadget/gadget.vala
sed -i "s/Listening on UNIX socket at/Service bound to/" lib/gadget/gadget.vala

echo ""
echo "[+] All patches applied successfully!"
echo ""
echo "Detection fingerprints modified:"
echo "  - Ports: 27042->43890, 27052->43900"
echo "  - Thread names: disguised as system threads (gmain-svc, pool-svc-*, gmain-loop, etc)"
echo "  - D-Bus interfaces: re.frida.* -> re.mgnt.*"
echo "  - D-Bus GUID: github.com/frida -> app.internal.svc"
echo "  - TLS cert: O=Android, CN=localhost"
echo "  - HTTP headers: Frida/x.x.x -> HttpSvc/1.0"
echo "  - SDP software: Frida -> SvcApp"
echo "  - Gadget ID: re.frida.Gadget -> com.system.svchost"
echo "  - Env vars: frida_gadget_config -> sys_svc_config"
echo "  - Library names: frida-gadget -> system-svc, frida-agent -> system-agent"
echo "  - Module name in memory: Frida -> System"
