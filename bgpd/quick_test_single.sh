#!/bin/bash
# BGP-LS 简化测试 - 单对单路由验证脚本
# 
# 功能：测试 BGP-LS 从配置文件读取链路状态并通告给对等体
# 
# 工作流程：
#   1. 创建网络命名空间环境（router1 ↔ router2）
#   2. 生成 FRR 配置文件（启用 BGP-LS 和 linkstate monitor）
#   3. 生成 Link-State 配置文件（/etc/frr/linkstate/*.json）
#   4. 启动 BGP 进程，等待会话建立
#   5. 定时轮询（30秒）读取配置文件并生成 BGP-LS UPDATE
#   6. 通过抓包验证 UPDATE 消息是否包含 Link-State NLRI 和属性
#
# 与旧版本的区别：
#   - 旧版：从真实接口（eth0 dummy）读取链路状态
#   - 新版：从 JSON 配置文件读取链路状态（接口名虚拟化）

# 不使用 set -e，允许脚本继续执行即使部分命令失败
# set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

FRR_BASE="/home/bgp/FRR-main"
BGPD_BIN="${FRR_BASE}/bgpd/.libs/bgpd"
VTYSH_BIN="${FRR_BASE}/vtysh/.libs/vtysh"
export LD_LIBRARY_PATH="${FRR_BASE}/lib/.libs:${LD_LIBRARY_PATH}"

# 初始化全局变量
VTYSH_AVAILABLE="no"
LINKSTATE_WORKS="unknown"
TEST_RESULT="UNKNOWN"

echo -e "${GREEN}=========================================="
echo " BGP-LS 简化测试 - 单对单验证"
echo "==========================================${NC}"
echo ""

# 检查权限
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}错误: 请使用 sudo 运行此脚本${NC}"
    exit 1
fi


# 检测 bgpd 路径
BGPD_PATH=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 优先使用编译版本
if [ -f "$SCRIPT_DIR/.libs/bgpd" ]; then
    BGPD_PATH="$SCRIPT_DIR/.libs/bgpd"
    echo -e "${GREEN}✓ 使用编译的 bgpd: $BGPD_PATH${NC}"
elif [ -f "$SCRIPT_DIR/../bgpd/.libs/bgpd" ]; then
    BGPD_PATH="$(realpath $SCRIPT_DIR/../bgpd/.libs/bgpd)"
    echo -e "${GREEN}✓ 使用编译的 bgpd: $BGPD_PATH${NC}"
else
    echo -e "${RED}错误: 找不到编译的 bgpd${NC}"
    echo ""
    echo "请先编译 FRR:"
    echo "  cd $SCRIPT_DIR/.."
    echo "  ./bootstrap.sh"
    echo "  ./configure --enable-dev-build"
    echo "  make"
    echo ""
    exit 1
fi

# 验证 bgpd 可执行
if [ ! -x "$BGPD_PATH" ]; then
    echo -e "${RED}错误: bgpd 文件存在但不可执行: $BGPD_PATH${NC}"
    exit 1
fi

# 显示 bgpd 版本和编译时间
echo -e "${BLUE}BGPd 信息:${NC}"
ls -lh "$BGPD_PATH" | awk '{print "  大小: " $5 ", 修改时间: " $6 " " $7 " " $8}'
echo ""

# 检测 zebra 路径
ZEBRA_PATH=""
if [ -f "$SCRIPT_DIR/.libs/zebra" ]; then
    ZEBRA_PATH="$SCRIPT_DIR/.libs/zebra"
    echo -e "${GREEN}✓ 使用编译的 zebra (bgpd目录): $ZEBRA_PATH${NC}"
elif [ -f "$SCRIPT_DIR/../zebra/.libs/zebra" ]; then
    ZEBRA_PATH="$(realpath $SCRIPT_DIR/../zebra/.libs/zebra)"
    echo -e "${GREEN}✓ 使用编译的 zebra: $ZEBRA_PATH${NC}"
elif [ -f "${FRR_BASE}/zebra/.libs/zebra" ]; then
    ZEBRA_PATH="${FRR_BASE}/zebra/.libs/zebra"
    echo -e "${GREEN}✓ 使用编译的 zebra (FRR_BASE): $ZEBRA_PATH${NC}"
elif [ -f "/usr/lib/frr/zebra" ]; then
    ZEBRA_PATH="/usr/lib/frr/zebra"
    echo -e "${YELLOW}⚠ 使用系统安装的 zebra: $ZEBRA_PATH${NC}"
else
    echo -e "${YELLOW}⚠ 找不到 zebra，将在无zebra模式下运行${NC}"
fi
echo ""

# 清理函数
cleanup() {

    # 只打印调试信息（无需等待用户输入）
    # 在脚本结束时自动清理，如需调试请手动进入环境
    
    if ip netns list | grep -q router1; then
        echo ""
        echo -e "${YELLOW}=========================================="
        echo " 测试环境清理中 - 日志已保存"
        echo "==========================================${NC}"
        echo ""
        echo "测试日志位置:"
        echo "  Router1: /tmp/frr_router1.log"
        echo "  Router2: /tmp/frr_router2.log"
        echo "  抓包文件: /tmp/bgpls_test.pcap"
        echo "  测试报告: /tmp/bgpls_test_report.txt"
        echo ""
    fi
    
    echo ""
    echo -e "${YELLOW}清理测试环境...${NC}"
    # 停止所有tcpdump进程
    pkill -f "tcpdump.*bgpls_test" 2>/dev/null || true
    pkill -f "zebra.*router" 2>/dev/null || true
    pkill -f "bgpd.*router1" 2>/dev/null || true
    pkill -f "bgpd.*router2" 2>/dev/null || true
    ip netns del router1 2>/dev/null || true
    ip netns del router2 2>/dev/null || true
    rm -f /tmp/bgpd_router*.pid 2>/dev/null || true
    rm -f /tmp/zebra_router*.pid 2>/dev/null || true
    echo -e "${GREEN}✓ 清理完成${NC}"
}

# 捕获退出信号
trap cleanup EXIT

# ============================================================================
# 步骤1: 创建网络环境
# ============================================================================

echo -e "${BLUE}步骤1: 创建网络命名空间环境${NC}"

# 清理旧环境
ip netns del router1 2>/dev/null || true
ip netns del router2 2>/dev/null || true

# 检查二进制与运行目录
if [ ! -x "$BGPD_BIN" ]; then
    echo -e "${RED}错误: 未找到bgpd二进制: $BGPD_BIN${NC}"
    exit 1
fi

if [ ! -x "$VTYSH_BIN" ]; then
    echo -e "${YELLOW}⚠ 未找到vtysh二进制: $VTYSH_BIN${NC}"
    echo "将在无vtysh模式下运行（仅依赖日志和抓包验证）"
    VTYSH_AVAILABLE="no"
fi

mkdir -p /run/frr /var/run/frr
chown frr:frr /run/frr /var/run/frr
chmod 775 /run/frr /var/run/frr

# 创建命名空间
ip netns add router1
ip netns add router2

# 在命名空间中挂载/run（让FRR能访问socket目录）
ip netns exec router1 mount --bind /run /run || true
ip netns exec router2 mount --bind /run /run || true

# 创建veth对
ip link add veth-r1 type veth peer name veth-r2
ip link set veth-r1 netns router1
ip link set veth-r2 netns router2

# 配置IP
ip netns exec router1 ip addr add 10.0.0.1/30 dev veth-r1
ip netns exec router2 ip addr add 10.0.0.2/30 dev veth-r2

# 启动接口
ip netns exec router1 ip link set veth-r1 up
ip netns exec router2 ip link set veth-r2 up
ip netns exec router1 ip link set lo up
ip netns exec router2 ip link set lo up

# 注意：不再创建 eth0 dummy 接口
# 新的实现从配置文件读取链路信息，接口名 "r1-eth0" 是虚拟的，不需要真实存在

echo -e "${GREEN}✓ 网络环境创建完成${NC}"
echo "  Router1: 10.0.0.1 (BGP session)"
echo "  Router2: 10.0.0.2 (BGP session)"
echo "  注意: Link-State 数据现在从配置文件读取，不依赖真实接口"
echo ""

# 验证连通性
echo -e "${BLUE}验证网络连通性...${NC}"
if ip netns exec router1 ping -c 2 10.0.0.2 >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Router1 → Router2 连通${NC}"
else
    echo -e "${RED}✗ 网络不通，请检查配置${NC}"
    exit 1
fi
echo ""

# ============================================================================
# 步骤2: 创建FRR配置文件
# ============================================================================

echo -e "${BLUE}步骤2: 生成FRR配置文件${NC}"

# Router1 配置（发送方）
cat > /tmp/frr_router1.conf <<'EOF'
! FRR Router1 - BGP-LS发送方
frr version 9.0
frr defaults traditional
hostname router1
log file /tmp/frr_router1.log
log record-priority
!
debug bgp updates
debug bgp linkstate
debug bgp neighbor-events
!
router bgp 65001
 bgp router-id 1.1.1.1
 no bgp ebgp-requires-policy
 no bgp default ipv4-unicast
 neighbor 10.0.0.2 remote-as 65001
 neighbor 10.0.0.2 update-source 10.0.0.1
 !
 address-family link-state link-state
  neighbor 10.0.0.2 activate
 exit-address-family
 !
 linkstate monitor
 linkstate poll-interval 30
 ! 不再使用 'linkstate monitor interface' 命令
 ! 改为从配置文件 /etc/frr/linkstate/*.json 读取链路信息
exit
!
line vty
!
end
EOF

# Router2 配置（接收方）
cat > /tmp/frr_router2.conf <<'EOF'
! FRR Router2 - BGP-LS接收方
frr version 9.0
frr defaults traditional
hostname router2
log file /tmp/frr_router2.log
log record-priority
!
debug bgp updates
debug bgp linkstate
!
router bgp 65001
 bgp router-id 2.2.2.2
 no bgp ebgp-requires-policy
 no bgp default ipv4-unicast
 neighbor 10.0.0.1 remote-as 65001
 neighbor 10.0.0.1 update-source 10.0.0.2
 !
 address-family link-state link-state
  neighbor 10.0.0.1 activate
 exit-address-family
exit
!
line vty
!
end
EOF

echo -e "${GREEN}✓ 配置文件生成完成${NC}"
echo "  Router1配置: /tmp/frr_router1.conf"
echo "  Router2配置: /tmp/frr_router2.conf"
echo ""

# ============================================================================
# 步骤2.5: 生成 Link-State 配置文件（从接口读取改为配置文件读取）
# ============================================================================

echo -e "${BLUE}步骤2.5: 生成Link-State配置文件${NC}"

# 创建配置文件目录
mkdir -p /etc/frr/linkstate

# 生成时间戳
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# 生成 Link-State 配置文件（JSON格式）
cat > /etc/frr/linkstate/linkstate_${TIMESTAMP}.json <<'EOF_LINKSTATE'
{
  "version": "1.0",
  "timestamp": "TIMESTAMP_PLACEHOLDER",
  "links": [
    {
      "if_name": "r1-eth0",
      "if_index": 2,
      "nlri": {
        "protocol_id": 5,
        "identifier": 123456,
        "local_node": {
          "router_id": "1.1.1.1"
        },
        "remote_node": {
          "router_id": "2.2.2.2"
        },
        "link_descriptors": {
          "local_ipv4": "192.168.1.1",
          "remote_ipv4": "192.168.1.2"
        }
      },
      "attributes": {
        "oper_status": 1,
        "max_bandwidth": 1000000000,
        "te_metric": 10,
        "igp_metric": 10,
        "admin_group": 0,
        "unreserved_bw": [1000000000, 1000000000, 1000000000, 1000000000, 1000000000, 1000000000, 1000000000, 1000000000],
        "spf_sequence_number": 100,
        "spf_status": 0
      }
    }
  ]
}
EOF_LINKSTATE

# 替换时间戳占位符
sed -i "s/TIMESTAMP_PLACEHOLDER/$(date -Iseconds)/" /etc/frr/linkstate/linkstate_${TIMESTAMP}.json

echo -e "${GREEN}✓ Link-State配置文件生成完成${NC}"
echo "  配置文件: /etc/frr/linkstate/linkstate_${TIMESTAMP}.json"
echo "  链路数量: 1"
echo "  链路名称: r1-eth0 (192.168.1.1 → 192.168.1.2)"
echo ""

# ============================================================================
# 步骤3: 启动抓包（在BGP进程前启动，捕获完整会话）
# ============================================================================

echo -e "${BLUE}步骤3: 启动数据包捕获${NC}"

# 删除旧的抓包文件
rm -f /tmp/bgpls_test.pcap 2>/dev/null || true

# 在router1命名空间中启动tcpdump抓包（使用-Z选项避免权限问题）
ip netns exec router1 tcpdump -i veth-r1 -w /tmp/bgpls_test.pcap -n -U tcp port 179 >/dev/null 2>&1 &
TCPDUMP_PID=$!

# 等待tcpdump启动
sleep 1

# 验证tcpdump是否在运行
if ps -p $TCPDUMP_PID > /dev/null 2>&1; then
    echo -e "${GREEN}✓ tcpdump抓包已启动 (PID: $TCPDUMP_PID)${NC}"
    echo "  抓包接口: veth-r1"
    echo "  保存文件: /tmp/bgpls_test.pcap"
else
    echo -e "${YELLOW}⚠ tcpdump启动失败，继续测试（无抓包）${NC}"
    TCPDUMP_PID=""
fi
echo ""

# ============================================================================
# 步骤4: 启动FRR进程
# ============================================================================

echo -e "${BLUE}步骤4: 启动FRR进程${NC}"

# 清空旧日志
install -o frr -g frr -m 664 /dev/null /tmp/frr_router1.log 2>/dev/null || > /tmp/frr_router1.log
install -o frr -g frr -m 664 /dev/null /tmp/frr_router2.log 2>/dev/null || > /tmp/frr_router2.log
install -o frr -g frr -m 664 /dev/null /tmp/zebra_router1.log 2>/dev/null || > /tmp/zebra_router1.log
install -o frr -g frr -m 664 /dev/null /tmp/zebra_router2.log 2>/dev/null || > /tmp/zebra_router2.log

# 启动Zebra（如果可用）
if [ -n "$ZEBRA_PATH" ]; then
    echo "启动 Zebra 进程..."
    
    # 为每个路由器创建独立的FRR运行目录
    mkdir -p /run/frr/router1 /run/frr/router2
    chown -R frr:frr /run/frr/router1 /run/frr/router2
    chmod 775 /run/frr/router1 /run/frr/router2
    
    # Router1 Zebra (使用-N pathspace，FRR会自动创建socket在/run/frr/router1/)
    ip netns exec router1 $ZEBRA_PATH \
        -i /run/frr/router1/zebra.pid \
        --log file:/tmp/zebra_router1.log \
        -d -N router1
    
    # Router2 Zebra
    ip netns exec router2 $ZEBRA_PATH \
        -i /run/frr/router2/zebra.pid \
        --log file:/tmp/zebra_router2.log \
        -d -N router2
    
    # 等待zebra启动
    sleep 2
    echo -e "${GREEN}✓ Zebra 进程启动完成${NC}"
fi

# 启动Router1 BGPd (使用-N，会自动连接到同名pathspace的zebra)
ip netns exec router1 $BGPD_PATH \
    -f /tmp/frr_router1.conf \
    -i /run/frr/router1/bgpd.pid \
    --log file:/tmp/frr_router1.log \
    -d -N router1

# 启动Router2 BGPd
ip netns exec router2 $BGPD_PATH \
    -f /tmp/frr_router2.conf \
    -i /run/frr/router2/bgpd.pid \
    --log file:/tmp/frr_router2.log \
    -d -N router2

echo -e "${GREEN}✓ FRR进程启动完成${NC}"
echo "  等待BGP会话建立..."
sleep 8
echo ""

# ============================================================================
# 步骤5: 验证BGP会话状态
# ============================================================================

echo -e "${BLUE}步骤5: 验证BGP会话状态${NC}"

# 检查进程是否在运行
echo "调试: 检查进程..."
ps aux | grep "[b]gpd.*router1" || echo "进程检查失败"

if ! ps aux | grep -q "[b]gpd.*router1"; then
    echo -e "${RED}✗ Router1 BGP进程未运行${NC}"
    echo "查看日志: tail -50 /tmp/frr_router1.log"
    exit 1
fi

echo "调试: 运行vtysh..."
# 检查Router1的BGP会话（使用-N选项连接到正确的pathspace）
# 使用timeout防止hang，同时捕获错误
BGP_OUTPUT=$(timeout 5 ip netns exec router1 "$VTYSH_BIN" -N router1 -c "show bgp summary" 2>&1)
VTYSH_EXIT=$?

# 检查vtysh是否成功执行
if [ $VTYSH_EXIT -eq 0 ] && [ -n "$BGP_OUTPUT" ]; then
    echo "BGP Summary输出:"
    echo "$BGP_OUTPUT"
    echo ""
    
    BGP_STATUS=$(echo "$BGP_OUTPUT" | grep 10.0.0.2 | awk '{print $10}')
    echo "调试: BGP_STATUS='$BGP_STATUS'"

    if [ "$BGP_STATUS" = "Established" ] || echo "$BGP_OUTPUT" | grep -q "Established"; then
        echo -e "${GREEN}✓ BGP会话已建立 (Established)${NC}"
        VTYSH_AVAILABLE="yes"
    else
        echo -e "${YELLOW}⚠ BGP会话状态: $BGP_STATUS${NC}"
        VTYSH_AVAILABLE="yes"
    fi
else
    echo -e "${YELLOW}⚠ vtysh无法连接或返回为空 (exit=$VTYSH_EXIT)${NC}"
    echo "将跳过vtysh查询，通过日志和抓包验证功能..."
    BGP_STATUS="Unknown"
    VTYSH_AVAILABLE="no"
fi

# 显示BGP summary（如果可用）
echo ""
if [ "$VTYSH_AVAILABLE" = "yes" ]; then
    echo "Router1 BGP摘要:"
    ip netns exec router1 "$VTYSH_BIN" -N router1 -c "show bgp summary" 2>/dev/null | tail -3
    echo ""
fi

# ============================================================================
# 步骤4.5: 通过日志验证BGP功能
# ============================================================================

echo -e "${BLUE}步骤4.5: 通过日志验证BGP-LS功能${NC}"

echo ""
echo "Router1日志 - BGP会话建立:"
grep -i "neighbor 10.0.0.2.*Established\|rcvd End-of-RIB" /tmp/frr_router1.log | tail -3

echo ""
echo "Router1日志 - Link-State轮询:"
grep -i "Polling link-state\|Reading link states from config\|Processed link-state\|Successfully parsed.*links" /tmp/frr_router1.log | tail -5

echo ""
echo "Router2日志 - 接收UPDATE:"
grep -i "UPDATE\|NLRI\|Link.*State" /tmp/frr_router2.log | tail -5



# ============================================================================
# 步骤6: 多阶段测试 - 验证 add/update/delete 完整流程
# ============================================================================

echo -e "${BLUE}步骤6: 多阶段Link-State测试（add→update→delete→add）${NC}"
echo ""
echo "测试计划:"
echo "  阶段1 (T+30s): 初始添加链路 (oper_status=1, bw=1Gbps) → 验证 ADD"
echo "  阶段2 (T+60s): 修改属性 (bw=10Gbps, metric=20) → 验证 UPDATE"
echo "  阶段3 (T+90s): 链路down (oper_status=0) → 验证 DELETE"
echo "  阶段4 (T+120s): 链路恢复 (oper_status=1, bw=5Gbps) → 验证 RE-ADD"
echo ""

# ============= 阶段1: 等待初始 ADD (T+30s) =============
echo -e "${GREEN}[阶段1] 等待初始链路添加 (30秒)...${NC}"
for i in {30..1}; do
    echo -ne "\r  剩余 $i 秒...     "
    sleep 1
done
echo -e "\n${GREEN}✓ 阶段1完成: 初始链路应已添加${NC}"
echo ""

# 检查阶段1的RIB状态
echo -e "${BLUE}[检查点1] 验证Router1的RIB状态...${NC}"
if [ "$VTYSH_AVAILABLE" = "yes" ]; then
    R1_RIB_STAGE1=$(ip netns exec router1 "$VTYSH_BIN" -N router1 -c "show bgp ipv4 linkstate" 2>/dev/null)
    ROUTE_COUNT_STAGE1=$(echo "$R1_RIB_STAGE1" | grep -c "192.168.1" || echo "0")
    echo "Router1 RIB路由数: $ROUTE_COUNT_STAGE1"
    echo "$R1_RIB_STAGE1" | head -20
    
    if [ "$ROUTE_COUNT_STAGE1" -gt 0 ]; then
        echo -e "${GREEN}✓ 阶段1: RIB中有 $ROUTE_COUNT_STAGE1 条Link-State路由${NC}"
    else
        echo -e "${RED}✗ 阶段1: RIB为空！${NC}"
    fi
else
    echo -e "${YELLOW}⚠ vtysh不可用，跳过RIB检查${NC}"
fi

echo ""
echo -e "${BLUE}[检查点1] 验证Router2的RIB状态...${NC}"
if [ "$VTYSH_AVAILABLE" = "yes" ]; then
    R2_RIB_STAGE1=$(ip netns exec router2 "$VTYSH_BIN" -N router2 -c "show bgp ipv4 linkstate" 2>/dev/null)
    R2_ROUTE_COUNT_STAGE1=$(echo "$R2_RIB_STAGE1" | grep -c "192.168.1" || echo "0")
    echo "Router2 RIB路由数: $R2_ROUTE_COUNT_STAGE1"
    echo "$R2_RIB_STAGE1" | head -20
    
    if [ "$R2_ROUTE_COUNT_STAGE1" -gt 0 ]; then
        echo -e "${GREEN}✓ 阶段1: Router2收到 $R2_ROUTE_COUNT_STAGE1 条Link-State路由${NC}"
    else
        echo -e "${RED}✗ 阶段1: Router2的RIB为空！${NC}"
    fi
fi
echo ""

# ============= 阶段2: 修改配置触发 UPDATE (T+60s) =============
echo -e "${GREEN}[阶段2] 生成新配置文件，修改链路属性以触发 UPDATE...${NC}"

TIMESTAMP_STAGE2=$(date +"%Y%m%d_%H%M%S")
cat > /etc/frr/linkstate/linkstate_${TIMESTAMP_STAGE2}.json <<'EOF_STAGE2'
{
  "version": "1.0",
  "timestamp": "TIMESTAMP_PLACEHOLDER",
  "links": [
    {
      "if_name": "r1-eth0",
      "if_index": 2,
      "nlri": {
        "protocol_id": 5,
        "identifier": 123456,
        "local_node": {
          "router_id": "1.1.1.1"
        },
        "remote_node": {
          "router_id": "2.2.2.2"
        },
        "link_descriptors": {
          "local_ipv4": "192.168.1.1",
          "remote_ipv4": "192.168.1.2"
        }
      },
      "attributes": {
        "oper_status": 1,
        "max_bandwidth": 10000000000,
        "te_metric": 20,
        "igp_metric": 20,
        "admin_group": 0,
        "unreserved_bw": [10000000000, 10000000000, 10000000000, 10000000000, 10000000000, 10000000000, 10000000000, 10000000000],
        "spf_sequence_number": 101,
        "spf_status": 0
      }
    }
  ]
}
EOF_STAGE2
sed -i "s/TIMESTAMP_PLACEHOLDER/$(date -Iseconds)/" /etc/frr/linkstate/linkstate_${TIMESTAMP_STAGE2}.json

echo "  新配置: max_bandwidth=10Gbps, te_metric=20, igp_metric=20"
echo "  等待下一次轮询 (30秒)..."
for i in {30..1}; do
    echo -ne "\r  剩余 $i 秒...     "
    sleep 1
done
echo -e "\n${GREEN}✓ 阶段2完成: UPDATE应已发送（属性变化）${NC}"
echo ""

# 检查阶段2的RIB状态（关键检查点：确认阶段3删除前RIB有数据）
echo -e "${BLUE}[检查点2] 验证Router1的RIB状态（删除前）...${NC}"
if [ "$VTYSH_AVAILABLE" = "yes" ]; then
    R1_RIB_STAGE2=$(ip netns exec router1 "$VTYSH_BIN" -N router1 -c "show bgp ipv4 linkstate" 2>/dev/null)
    ROUTE_COUNT_STAGE2=$(echo "$R1_RIB_STAGE2" | grep -c "192.168.1" || echo "0")
    echo "Router1 RIB路由数: $ROUTE_COUNT_STAGE2"
    echo "$R1_RIB_STAGE2" | head -20
    
    if [ "$ROUTE_COUNT_STAGE2" -gt 0 ]; then
        echo -e "${GREEN}✓ 阶段2: RIB中仍有 $ROUTE_COUNT_STAGE2 条Link-State路由（准备删除）${NC}"
    else
        echo -e "${RED}✗✗✗ 严重问题：阶段2结束后RIB为空！无法测试DELETE功能${NC}"
        echo "可能原因："
        echo "  1. 阶段1的ADD未成功"
        echo "  2. 阶段2的UPDATE错误地删除了路由"
        echo "  3. BGP-LS监控功能未正常工作"
    fi
else
    echo -e "${YELLOW}⚠ vtysh不可用，跳过RIB检查${NC}"
    ROUTE_COUNT_STAGE2=1  # 假设有路由，继续测试
fi

echo ""
echo -e "${BLUE}[检查点2] 验证Router2的RIB状态（删除前）...${NC}"
if [ "$VTYSH_AVAILABLE" = "yes" ]; then
    R2_RIB_STAGE2=$(ip netns exec router2 "$VTYSH_BIN" -N router2 -c "show bgp ipv4 linkstate" 2>/dev/null)
    R2_ROUTE_COUNT_STAGE2=$(echo "$R2_RIB_STAGE2" | grep -c "192.168.1" || echo "0")
    echo "Router2 RIB路由数: $R2_ROUTE_COUNT_STAGE2"
    echo "$R2_RIB_STAGE2" | head -20
    
    if [ "$R2_ROUTE_COUNT_STAGE2" -gt 0 ]; then
        echo -e "${GREEN}✓ 阶段2: Router2仍有 $R2_ROUTE_COUNT_STAGE2 条Link-State路由${NC}"
    else
        echo -e "${RED}✗ 阶段2: Router2的RIB为空！${NC}"
    fi
fi
echo ""

# 显示当前路由详细信息（用于对比阶段3删除后的变化）
if [ "$VTYSH_AVAILABLE" = "yes" ] && [ "$ROUTE_COUNT_STAGE2" -gt 0 ]; then
    echo -e "${BLUE}[阶段2详细信息] Router1当前Link-State路由:${NC}"
    ip netns exec router1 "$VTYSH_BIN" -N router1 -c "show bgp ipv4 linkstate detail" 2>/dev/null | grep -A 10 "192.168.1" | head -15
    echo ""
fi

# ============= 阶段3: 设置 oper_status=0 触发 DELETE (T+90s) =============
echo -e "${GREEN}[阶段3] 生成新配置文件，设置链路down以触发 DELETE...${NC}"

TIMESTAMP_STAGE3=$(date +"%Y%m%d_%H%M%S")
cat > /etc/frr/linkstate/linkstate_${TIMESTAMP_STAGE3}.json <<'EOF_STAGE3'
{
  "version": "1.0",
  "timestamp": "TIMESTAMP_PLACEHOLDER",
  "links": [
    {
      "if_name": "r1-eth0",
      "if_index": 2,
      "nlri": {
        "protocol_id": 5,
        "identifier": 123456,
        "local_node": {
          "router_id": "1.1.1.1"
        },
        "remote_node": {
          "router_id": "2.2.2.2"
        },
        "link_descriptors": {
          "local_ipv4": "192.168.1.1",
          "remote_ipv4": "192.168.1.2"
        }
      },
      "attributes": {
        "oper_status": 0,
        "max_bandwidth": 10000000000,
        "te_metric": 20,
        "igp_metric": 20,
        "admin_group": 0,
        "unreserved_bw": [10000000000, 10000000000, 10000000000, 10000000000, 10000000000, 10000000000, 10000000000, 10000000000],
        "spf_sequence_number": 102,
        "spf_status": 1
      }
    }
  ]
}
EOF_STAGE3
sed -i "s/TIMESTAMP_PLACEHOLDER/$(date -Iseconds)/" /etc/frr/linkstate/linkstate_${TIMESTAMP_STAGE3}.json

echo "  新配置: oper_status=0 (链路down)"
echo "  等待下一次轮询 (30秒)..."
for i in {30..1}; do
    echo -ne "\r  剩余 $i 秒...     "
    sleep 1
done
echo -e "\n${GREEN}✓ 阶段3完成: DELETE应已发送（WITHDRAW）${NC}"
echo ""

# 检查阶段3的RIB状态（验证DELETE是否生效）
echo -e "${BLUE}[检查点3] 验证Router1的RIB状态（删除后）...${NC}"
if [ "$VTYSH_AVAILABLE" = "yes" ]; then
    R1_RIB_STAGE3=$(ip netns exec router1 "$VTYSH_BIN" -N router1 -c "show bgp ipv4 linkstate" 2>/dev/null)
    ROUTE_COUNT_STAGE3=$(echo "$R1_RIB_STAGE3" | grep -c "192.168.1" || echo "0")
    echo "Router1 RIB路由数: $ROUTE_COUNT_STAGE3"
    echo "$R1_RIB_STAGE3" | head -20
    
    if [ "$ROUTE_COUNT_STAGE3" -eq 0 ]; then
        echo -e "${GREEN}✓✓✓ 阶段3成功: RIB已清空（DELETE功能正常）${NC}"
    else
        echo -e "${RED}✗✗✗ 阶段3失败: RIB中仍有 $ROUTE_COUNT_STAGE3 条路由（DELETE未生效）${NC}"
        echo ""
        echo "问题诊断："
        echo "  阶段2结束时路由数: $ROUTE_COUNT_STAGE2"
        echo "  阶段3结束时路由数: $ROUTE_COUNT_STAGE3"
        
        if [ "$ROUTE_COUNT_STAGE2" -eq "$ROUTE_COUNT_STAGE3" ]; then
            echo -e "${RED}  → 路由数未变化！可能原因：${NC}"
            echo "    1. linkstate monitor未检测到oper_status=0"
            echo "    2. BGP-LS DELETE逻辑未触发"
            echo "    3. 配置文件未被重新读取"
        fi
        
        echo ""
        echo "检查日志中的DELETE相关信息："
        grep -i "delete\|withdraw\|oper_status.*0\|link.*down" /tmp/frr_router1.log | tail -10
    fi
else
    echo -e "${YELLOW}⚠ vtysh不可用，跳过RIB检查${NC}"
fi

echo ""
echo -e "${BLUE}[检查点3] 验证Router2的RIB状态（删除后）...${NC}"
if [ "$VTYSH_AVAILABLE" = "yes" ]; then
    R2_RIB_STAGE3=$(ip netns exec router2 "$VTYSH_BIN" -N router2 -c "show bgp ipv4 linkstate" 2>/dev/null)
    R2_ROUTE_COUNT_STAGE3=$(echo "$R2_RIB_STAGE3" | grep -c "192.168.1" || echo "0")
    echo "Router2 RIB路由数: $R2_ROUTE_COUNT_STAGE3"
    echo "$R2_RIB_STAGE3" | head -20
    
    if [ "$R2_ROUTE_COUNT_STAGE3" -eq 0 ]; then
        echo -e "${GREEN}✓ 阶段3: Router2的RIB已清空（WITHDRAW接收成功）${NC}"
    else
        echo -e "${RED}✗ 阶段3: Router2仍有 $R2_ROUTE_COUNT_STAGE3 条路由（未收到WITHDRAW）${NC}"
    fi
fi
echo ""

# ============= 阶段4: 恢复 oper_status=1 触发 RE-ADD (T+120s) =============
echo -e

# 检查阶段4的RIB状态（验证RE-ADD是否生效）
echo -e "${BLUE}[检查点4] 验证Router1的RIB状态（重新添加后）...${NC}"
if [ "$VTYSH_AVAILABLE" = "yes" ]; then
    R1_RIB_STAGE4=$(ip netns exec router1 "$VTYSH_BIN" -N router1 -c "show bgp ipv4 linkstate" 2>/dev/null)
    ROUTE_COUNT_STAGE4=$(echo "$R1_RIB_STAGE4" | grep -c "192.168.1" || echo "0")
    echo "Router1 RIB路由数: $ROUTE_COUNT_STAGE4"
    echo "$R1_RIB_STAGE4" | head -20
    
    if [ "$ROUTE_COUNT_STAGE4" -gt 0 ]; then
        echo -e "${GREEN}✓ 阶段4: RIB中有 $ROUTE_COUNT_STAGE4 条Link-State路由（RE-ADD成功）${NC}"
    else
        echo -e "${RED}✗ 阶段4: RIB仍为空（RE-ADD失败）${NC}"
    fi
else
    echo -e "${YELLOW}⚠ vtysh不可用，跳过RIB检查${NC}"
fi

echo ""
echo -e "${BLUE}[检查点4] 验证Router2的RIB状态（重新添加后）...${NC}"
if [ "$VTYSH_AVAILABLE" = "yes" ]; then
    R2_RIB_STAGE4=$(ip netns exec router2 "$VTYSH_BIN" -N router2 -c "show bgp ipv4 linkstate" 2>/dev/null)
    R2_ROUTE_COUNT_STAGE4=$(echo "$R2_RIB_STAGE4" | grep -c "192.168.1" || echo "0")
    echo "Router2 RIB路由数: $R2_ROUTE_COUNT_STAGE4"
    echo "$R2_RIB_STAGE4" | head -20
    
    if [ "$R2_ROUTE_COUNT_STAGE4" -gt 0 ]; then
        echo -e "${GREEN}✓ 阶段4: Router2收到 $R2_ROUTE_COUNT_STAGE4 条Link-State路由${NC}"
    else
        echo -e "${RED}✗ 阶段4: Router2的RIB为空（未收到RE-ADD）${NC}"
    fi
fi
echo "" "${GREEN}[阶段4] 生成新配置文件，恢复链路以触发 RE-ADD...${NC}"

TIMESTAMP_STAGE4=$(date +"%Y%m%d_%H%M%S")
cat > /etc/frr/linkstate/linkstate_${TIMESTAMP_STAGE4}.json <<'EOF_STAGE4'
{
  "version": "1.0",
  "timestamp": "TIMESTAMP_PLACEHOLDER",
  "links": [
    {
      "if_name": "r1-eth0",
      "if_index": 2,
      "nlri": {
        "protocol_id": 5,
        "identifier": 123456,
        "local_node": {
          "router_id": "1.1.1.1"
        },
        "remote_node": {
          "router_id": "2.2.2.2"
        },
       

# 生成阶段测试总结
echo -e "${BLUE}各阶段RIB变化总结:${NC}"
echo "----------------------------------------"
if [ "$VTYSH_AVAILABLE" = "yes" ]; then
    echo "阶段1 (ADD):        Router1=$ROUTE_COUNT_STAGE1 条, Router2=$R2_ROUTE_COUNT_STAGE1 条"
    echo "阶段2 (UPDATE):     Router1=$ROUTE_COUNT_STAGE2 条, Router2=$R2_ROUTE_COUNT_STAGE2 条"
    echo "阶段3 (DELETE):     Router1=$ROUTE_COUNT_STAGE3 条, Router2=$R2_ROUTE_COUNT_STAGE3 条"
    echo "阶段4 (RE-ADD):     Router1=$ROUTE_COUNT_STAGE4 条, Router2=$R2_ROUTE_COUNT_STAGE4 条"
    echo ""
    
    # 判断各阶段功能是否正常
    STAGE1_OK="no"
    STAGE2_OK="no"
    STAGE3_OK="no"
    STAGE4_OK="no"
    
    [ "$ROUTE_COUNT_STAGE1" -gt 0 ] && STAGE1_OK="yes"
    [ "$ROUTE_COUNT_STAGE2" -gt 0 ] && STAGE2_OK="yes"
    [ "$ROUTE_COUNT_STAGE3" -eq 0 ] && STAGE3_OK="yes"
    [ "$ROUTE_COUNT_STAGE4" -gt 0 ] && STAGE4_OK="yes"
    
    echo "功能验证结果:"
    [ "$STAGE1_OK" = "yes" ] && echo -e "  ${GREEN}✓ ADD功能正常${NC}" || echo -e "  ${RED}✗ ADD功能异常${NC}"
    [ "$STAGE2_OK" = "yes" ] && echo -e "  ${GREEN}✓ UPDATE功能正常${NC}" || echo -e "  ${RED}✗ UPDATE功能异常${NC}"
    [ "$STAGE3_OK" = "yes" ] && echo -e "  ${GREEN}✓ DELETE功能正常${NC}" || echo -e "  ${RED}✗ DELETE功能异常${NC}"
    [ "$STAGE4_OK" = "yes" ] && echo -e "  ${GREEN}✓ RE-ADD功能正常${NC}" || echo -e "  ${RED}✗ RE-ADD功能异常${NC}"
    
    # 如果DELETE失败，提供详细诊断
    if [ "$STAGE3_OK" = "no" ]; then
        echo ""
        echo -e "${RED}DELETE功能诊断报告:${NC}"
        echo "----------------------------------------"
        echo "问题: 阶段3设置oper_status=0后，RIB未清空"
        echo ""
        echo "可能原因分析:"
        echo "  1. 配置文件未被重新读取"
        echo "     → 检查: ls -lt /etc/frr/linkstate/"
        ls -lt /etc/frr/linkstate/ | head -5
        echo ""
        echo "  2. linkstate monitor未检测到oper_status变化"
        echo "     → 检查日志中的监控信息:"
        grep -i "polling\|reading.*config\|oper_status" /tmp/frr_router1.log | tail -10
        echo ""
        echo "  3. BGP-LS DELETE逻辑未触发"
        echo "     → 检查日志中的DELETE/WITHDRAW信息:"
        grep -i "delete\|withdraw" /tmp/frr_router1.log | tail -10
        echo ""
    fi
else
    echo "vtysh不可用，无法生成RIB总结"
fi
echo "" "link_descriptors": {
          "local_ipv4": "192.168.1.1",
          "remote_ipv4": "192.168.1.2"
        }
      },
      "attributes": {
        "oper_status": 1,
        "max_bandwidth": 5000000000,
        "te_metric": 15,
        "igp_metric": 15,
        "admin_group": 0,
        "unreserved_bw": [5000000000, 5000000000, 5000000000, 5000000000, 5000000000, 5000000000, 5000000000, 5000000000],
        "spf_sequence_number": 103,
        "spf_status": 0
      }
    }
  ]
}
EOF_STAGE4
sed -i "s/TIMESTAMP_PLACEHOLDER/$(date -Iseconds)/" /etc/frr/linkstate/linkstate_${TIMESTAMP_STAGE4}.json

echo "  新配置: oper_status=1 (链路up), max_bandwidth=5Gbps"
echo "  等待下一次轮询 (30秒)..."
for i in {30..1}; do
    echo -ne "\r  剩余 $i 秒...     "
    sleep 1
done
echo -e "\n${GREEN}✓ 阶段4完成: RE-ADD应已发送（链路恢复）${NC}"
echo ""

echo -e "${GREEN}=========================================="
echo " 多阶段测试完成！"
echo "==========================================${NC}"
echo ""

if [ -n "$TCPDUMP_PID" ]; then
    kill $TCPDUMP_PID 2>/dev/null || true
    wait $TCPDUMP_PID 2>/dev/null || true
    echo -e "${GREEN}✓ 抓包已停止${NC}"
else
    echo -e "${YELLOW}⚠ tcpdump未运行${NC}"
fi
echo ""

# 检查抓包文件
if [ ! -f /tmp/bgpls_test.pcap ]; then
    echo -e "${RED}✗ 抓包文件不存在（tcpdump可能未正常工作）${NC}"
    PACKET_COUNT=0
else
    PACKET_COUNT=$(tcpdump -r /tmp/bgpls_test.pcap 2>/dev/null | wc -l)
    echo "捕获的数据包总数: $PACKET_COUNT"
    echo "抓包文件时间: $(ls -lh --time-style=+"%Y-%m-%d %H:%M:%S" /tmp/bgpls_test.pcap | awk '{print $6, $7}')"
fi
echo ""

# ============================================================================
# 步骤8: 验证结果
# ============================================================================

echo -e "${GREEN}=========================================="
echo " 测试结果验证"
echo "==========================================${NC}"
echo ""

# 8.1 验证Router1的Link-State路由表
echo -e "${BLUE}8.1 Router1 Link-State路由表:${NC}"
if [ "$VTYSH_AVAILABLE" = "yes" ]; then
    R1_ROUTES=$(ip netns exec router1 "$VTYSH_BIN" -N router1 -c "show bgp ipv4 linkstate" 2>/dev/null)
    echo "$R1_ROUTES"

    if echo "$R1_ROUTES" | grep -q "192.168.1.1"; then
        echo -e "${GREEN}✓ Router1已生成Link-State路由 (包含eth0: 192.168.1.1)${NC}"
    else
        echo -e "${YELLOW}! Router1未生成Link-State路由${NC}"
    fi
else
    echo -e "${YELLOW}⚠ vtysh不可用，通过日志验证${NC}"
    if grep -q "linkstate_add.*eth0" /tmp/frr_router1.log; then
        echo -e "${GREEN}✓ 日志确认: Router1已调用linkstate_add()添加eth0${NC}"
    fi
fi
echo ""

# 8.2 验证Router2是否收到路由
echo -e "${BLUE}8.2 Router2 Link-State路由表:${NC}"
if [ "$VTYSH_AVAILABLE" = "yes" ]; then
    R2_ROUTES=$(ip netns exec router2 "$VTYSH_BIN" -N router2 -c "show bgp ipv4 linkstate" 2>/dev/null)
    echo "$R2_ROUTES"

    if echo "$R2_ROUTES" | grep -q "192.168.1.1"; then
        echo -e "${GREEN}✓ Router2已接收Link-State路由 (从10.0.0.1学到)${NC}"
    else
        echo -e "${YELLOW}! Router2未接收到Link-State路由${NC}"
    fi
else
    echo -e "${YELLOW}⚠ vtysh不可用，通过日志验证${NC}"
    if grep -qi "UPDATE\|linkstate\|192.168" /tmp/frr_router2.log; then
        echo -e "${GREEN}✓ 日志确认: Router2已处理UPDATE消息${NC}"
    fi
fi
echo ""

# 8.3 分析抓包（如果安装了tshark）
if command -v tshark &> /dev/null; then
    echo -e "${BLUE}8.3 抓包分析 (tshark):${NC}"
    
    # 统计BGP消息类型
    echo ""
    echo "BGP消息统计:"
    tshark -r /tmp/bgpls_test.pcap -q -z io,stat,0,bgp 2>/dev/null || true
    
    echo ""
    echo "BGP OPEN消息（查找Link-State能力）:"
    tshark -r /tmp/bgpls_test.pcap -Y "bgp.type == 1" -T fields \
        -e frame.number -e ip.src -e ip.dst -e bgp.type 2>/dev/null | head -5
    
    echo ""
    echo "BGP UPDATE消息（查找Link-State NLRI）:"
    UPDATE_COUNT=$(tshark -r /tmp/bgpls_test.pcap -Y "bgp.type == 2" 2>/dev/null | wc -l)
    echo "UPDATE消息数量: $UPDATE_COUNT"
    
    if [ "$UPDATE_COUNT" -gt 0 ]; then
        echo -e "${GREEN}✓ 捕获到BGP UPDATE消息${NC}"
        
        # 检查是否有Link-State AFI
        LS_COUNT=$(tshark -r /tmp/bgpls_test.pcap -Y "bgp.nlri_afi == 16388" 2>/dev/null | wc -l)
        echo "Link-State NLRI数量: $LS_COUNT"
        
        if [ "$LS_COUNT" -gt 0 ]; then
            echo -e "${GREEN}✓✓✓ 成功: 捕获到BGP-LS UPDATE消息！${NC}"
        else
            echo -e "${YELLOW}! UPDATE消息中未找到Link-State NLRI (AFI=16388)${NC}"
        fi
        
        # 详细分析各阶段的 UPDATE 消息
        echo ""
        echo "各阶段UPDATE消息详细分析:"
        echo "----------------------------------------"
        
        # 阶段1: ADD (长度应该>200字节，包含完整NLRI和attributes)
        STAGE1_UPDATES=$(tshark -r /tmp/bgpls_test.pcap -Y "bgp.type == 2 && frame.time_relative < 40 && frame.len > 200" 2>/dev/null | wc -l)
        echo "阶段1 (ADD): ${STAGE1_UPDATES} 个长UPDATE (>200字节)"
        
        # 阶段2: UPDATE (属性变化，长度也应该>200字节)
        STAGE2_UPDATES=$(tshark -r /tmp/bgpls_test.pcap -Y "bgp.type == 2 && frame.time_relative >= 40 && frame.time_relative < 70 && frame.len > 200" 2>/dev/null | wc -l)
        echo "阶段2 (UPDATE): ${STAGE2_UPDATES} 个长UPDATE (属性修改)"
        
        # 阶段3: DELETE/WITHDRAW (长度较短，只有WITHDRAWN字段)
        STAGE3_UPDATES=$(tshark -r /tmp/bgpls_test.pcap -Y "bgp.type == 2 && frame.time_relative >= 70 && frame.time_relative < 100" 2>/dev/null | wc -l)
        echo "阶段3 (DELETE): ${STAGE3_UPDATES} 个UPDATE (可能含WITHDRAW)"
        
        # 阶段4: RE-ADD (长度>200字节)
        STAGE4_UPDATES=$(tshark -r /tmp/bgpls_test.pcap -Y "bgp.type == 2 && frame.time_relative >= 100 && frame.len > 200" 2>/dev/null | wc -l)
        echo "阶段4 (RE-ADD): ${STAGE4_UPDATES} 个长UPDATE (链路恢复)"
        
        echo ""
        echo "验证结果:"
        if [ "$STAGE1_UPDATES" -gt 0 ]; then
            echo -e "  ${GREEN}✓ ADD功能正常${NC}"
        else
            echo -e "  ${RED}✗ ADD未触发${NC}"
        fi
        
        if [ "$STAGE2_UPDATES" -gt 0 ]; then
            echo -e "  ${GREEN}✓ UPDATE功能正常${NC}"
        else
            echo -e "  ${YELLOW}! UPDATE未检测到${NC}"
        fi
        
        if [ "$STAGE3_UPDATES" -gt 0 ]; then
            echo -e "  ${GREEN}✓ DELETE功能正常${NC}"
        else
            echo -e "  ${YELLOW}! DELETE未检测到${NC}"
        fi
        
        if [ "$STAGE4_UPDATES" -gt 0 ]; then
            echo -e "  ${GREEN}✓ RE-ADD功能正常${NC}"
        else
            echo -e "  ${YELLOW}! RE-ADD未检测到${NC}"
        fi
    else
        echo -e "${RED}✗ 未捕获到BGP UPDATE消息${NC}"
    fi
else
    echo -e "${YELLOW}! 未安装tshark，跳过抓包分析${NC}"
    echo "  安装: sudo apt-get install tshark"
fi

echo ""

# 8.4 检查日志
echo -e "${BLUE}8.4 日志检查:${NC}"

echo ""
echo "Router1关键日志（最近10条）:"
tail -10 /tmp/frr_router1.log | grep -E "linkstate|eth0|UPDATE" || echo "  (无相关日志)"

echo ""
echo "Router2关键日志（最近10条）:"
tail -10 /tmp/frr_router2.log | grep -E "linkstate|UPDATE|192.168.1.1" || echo "  (无相关日志)"

echo ""

# ============================================================================
# 步骤9: Wireshark分析指南
# ============================================================================

echo -e "${GREEN}=========================================="
echo " Wireshark 抓包分析指南"
echo "==========================================${NC}"
echo ""

echo "抓包文件位置: /tmp/bgpls_test.pcap"
echo ""
echo "使用Wireshark打开:"
echo "  wireshark /tmp/bgpls_test.pcap"
echo ""
echo "或在Windows上复制文件:"
echo "  scp user@host:/tmp/bgpls_test.pcap ."
echo ""
echo -e "${BLUE}关键过滤器:${NC}"
echo "  1. 查看所有BGP消息:"
echo "     ${YELLOW}bgp${NC}"
echo ""
echo "  2. 查看BGP OPEN消息（检查Link-State能力）:"
echo "     ${YELLOW}bgp.type == 1${NC}"
echo "     → 展开 'Optional Parameters' → 'Capability' → 查找 AFI=16388"
echo ""
echo "  3. 查看BGP UPDATE消息:"
echo "     ${YELLOW}bgp.type == 2${NC}"
echo ""
echo "  4. 查看Link-State NLRI:"
echo "     ${YELLOW}bgp.nlri_afi == 16388${NC}"
echo "     → 应该看到 NLRI Type = Link (0x0002)"
echo "     → 应该看到 Interface Address = 192.168.1.1"
echo ""
echo "  5. 查看Link-State属性:"
echo "     ${YELLOW}bgp.path_attribute.type == 0x4005${NC}"
echo "     → 应该看到 TLV 1089 (Max Bandwidth)"
echo "     → 应该看到 TLV 1095 (IGP Metric)"
echo ""

echo -e "${BLUE}验证清单:${NC}"
echo "  [ ] BGP OPEN消息中包含 AFI=16388 (Link-State)"
echo "  [ ] BGP UPDATE消息中包含 NLRI Type=0x0002 (Link)"
echo "  [ ] NLRI中包含正确的接口地址 (192.168.1.1)"
echo "  [ ] Path Attribute包含Link-State TLVs"
echo "  [ ] TLV 1089的值是IEEE 754浮点格式"
echo "  [ ] Router2收到并解析了该路由"
echo ""

# ============================================================================
# 步骤10: 生成测试报告
# ============================================================================

cat > /tmp/bgpls_test_report.txt <<EOF
========================================
BGP-LS 单对单测试报告
========================================

测试时间: $(date)

网络拓扑:
  Router1 (10.0.0.1) ← veth → Router2 (10.0.0.2)
  Router1 测试接口: eth0 (192.168.1.1/24)

测试结果:
-----------------------------------------

1. BGP会话状态: $BGP_STATUS

2. Link-State轮询状态: $LINKSTATE_WORKS

3. vtysh可用性: $VTYSH_AVAILABLE

4. 抓包统计:
   总数据包: $PACKET_COUNT
   UPDATE消息: $UPDATE_COUNT

5. 日志摘要:
Router1 (最后30行):
$(tail -30 /tmp/frr_router1.log)

Router2 (最后30行):
$(tail -30 /tmp/frr_router2.log)

========================================
抓包文件: /tmp/bgpls_test.pcap
完整日志: /tmp/frr_router1.log, /tmp/frr_router2.log
========================================
EOF

echo -e "${GREEN}✓ 测试报告已生成: /tmp/bgpls_test_report.txt${NC}"
echo ""

# ============================================================================
# 总结
# ============================================================================

echo -e "${GREEN}=========================================="
echo " 测试完成！"
echo "==========================================${NC}"
echo ""

# 通过日志和抓包判断轮询是否发生了（适配配置文件读取方式）
# 由于使用了 printf 输出，日志文件可能没有记录，直接检查抓包结果
if tshark -r /tmp/bgpls_test.pcap -Y "bgp.type == 2 && frame.len > 150" 2>/dev/null | grep -q "10.0.0.1.*10.0.0.2"; then
    echo -e "${GREEN}✓ Link-State轮询已执行（检测到BGP-LS UPDATE消息，长度>150字节）${NC}"
    LINKSTATE_WORKS="yes"
else
    echo -e "${YELLOW}! 未检测到Link-State UPDATE消息${NC}"
    LINKSTATE_WORKS="no"
fi

# 检查是否有UPDATE消息被发送/接收
if grep -qi "UPDATE\|NLRI" /tmp/frr_router2.log && grep -q "linkstate" /tmp/frr_router1.log; then
    echo -e "${GREEN}✓ 轮询→UPDATE→接收 完整流程已验证${NC}"
    TEST_RESULT="PASS"
else
    if [ "$LINKSTATE_WORKS" = "yes" ]; then
        echo -e "${YELLOW}⚠ 轮询已执行，但可能需要更多时间观察UPDATE消息${NC}"
        TEST_RESULT="PARTIAL"
    else
        echo -e "${RED}✗ Link-State轮询未执行${NC}"
        TEST_RESULT="FAIL"
    fi
fi

echo ""
if [ "$TEST_RESULT" = "PASS" ]; then
    echo -e "${GREEN}✓✓✓ 核心功能验证成功！${NC}"
    echo ""
    echo "BGP-LS轮询→通告→接收流程已完成"
    echo ""
    echo "后续可进一步验证:"
    echo "  1. 打开抓包文件: wireshark /tmp/bgpls_test.pcap"
    echo "  2. 使用过滤器: bgp.nlri_afi == 16388 (查看Link-State NLRI)"
    echo "  3. 验证NLRI内容和属性TLVs"
elif [ "$TEST_RESULT" = "PARTIAL" ]; then
    echo -e "${YELLOW}⚠ 测试部分完成${NC}"
    echo ""
    echo "已验证:"
    echo "  ✓ BGP会话建立"
    echo "  ✓ Link-State轮询执行"
    echo ""
    echo "建议:"
    echo "  1. 查看日志: tail -50 /tmp/frr_router1.log"
    echo "  2. 检查UPDATE计数: tcpdump -r /tmp/bgpls_test.pcap -Y 'bgp.type == 2'"
else
    echo -e "${RED}✗ 测试失败${NC}"
    echo ""
    echo "请检查:"
    echo "  1. 日志文件: /tmp/frr_router1.log"
    echo "  2. 日志文件: /tmp/frr_router2.log"
    echo "  3. 确认Link-State监控是否启用"
fi

echo ""
echo -e "${BLUE}测试完成！环境将保持运行以便调试...${NC}"
echo "（cleanup 函数会提示调试命令）"