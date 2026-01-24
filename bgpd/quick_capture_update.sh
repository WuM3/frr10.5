#!/bin/bash
# 快速测试 - 捕获BGP UPDATE消息

set -e

echo "=== 快速测试：延长抓包时间以捕获UPDATE ==="

# 清理旧环境
sudo ip netns del router1 2>/dev/null || true
sudo ip netns del router2 2>/dev/null || true
sudo killall bgpd zebra 2>/dev/null || true
sleep 1

# 创建网络命名空间
sudo ip netns add router1
sudo ip netns add router2

# 创建veth对
sudo ip link add veth1 type veth peer name veth2
sudo ip link set veth1 netns router1
sudo ip link set veth2 netns router2

# 配置router1
sudo ip netns exec router1 ip addr add 10.0.0.1/24 dev veth1
sudo ip netns exec router1 ip link set veth1 up
sudo ip netns exec router1 ip link set lo up
sudo ip netns exec router1 ip addr add 192.168.1.1/24 dev lo

# 配置router2
sudo ip netns exec router2 ip addr add 10.0.0.2/24 dev veth2
sudo ip netns exec router2 ip link set veth2 up
sudo ip netns exec router2 ip link set lo up

# 创建FRR配置目录
sudo mkdir -p /run/frr/router1 /run/frr/router2
sudo chown -R frr:frr /run/frr/

# 生成router1配置（增加轮询间隔到5秒以更快触发）
cat > /tmp/frr_router1.conf << 'EOF'
frr defaults traditional
hostname router1
log file /tmp/frr_router1.log debugging
log commands
debug bgp neighbor-events
debug bgp updates in
debug bgp updates out
debug bgp zebra
!
router bgp 65001
 bgp router-id 10.0.0.1
 bgp log-neighbor-changes
 no bgp ebgp-requires-policy
 neighbor 10.0.0.2 remote-as 65001
 !
 address-family link-state link-state
  neighbor 10.0.0.2 activate
  neighbor 10.0.0.2 route-reflector-client
  linkstate-enable
 exit-address-family
 !
 linkstate monitor
 linkstate poll-interval 10
!
line vty
!
EOF

# 生成router2配置
cat > /tmp/frr_router2.conf << 'EOF'
frr defaults traditional
hostname router2
log file /tmp/frr_router2.log debugging
log commands
debug bgp neighbor-events
debug bgp updates in
debug bgp updates out
!
router bgp 65001
 bgp router-id 10.0.0.2
 bgp log-neighbor-changes
 no bgp ebgp-requires-policy
 neighbor 10.0.0.1 remote-as 65001
 !
 address-family link-state link-state
  neighbor 10.0.0.1 activate
 exit-address-family
!
line vty
!
EOF

# 启动zebra
sudo ip netns exec router1 /home/bgp/FRR-main/zebra/.libs/zebra \
  -f /tmp/frr_router1.conf -i /run/frr/router1/zebra.pid -d -N router1

sudo ip netns exec router2 /home/bgp/FRR-main/zebra/.libs/zebra \
  -f /tmp/frr_router2.conf -i /run/frr/router2/zebra.pid -d -N router2

sleep 2

# 启动抓包 - 60秒以确保捕获轮询触发的UPDATE
echo "启动抓包（60秒）..."
sudo timeout 60 ip netns exec router1 tcpdump -i veth1 -w /tmp/bgpls_capture.pcap port 179 &
TCPDUMP_PID=$!

sleep 2

# 启动bgpd
echo "启动BGP守护进程..."
sudo ip netns exec router1 /home/bgp/FRR-main/bgpd/.libs/bgpd \
  -f /tmp/frr_router1.conf -i /run/frr/router1/bgpd.pid -d -N router1

sudo ip netns exec router2 /home/bgp/FRR-main/bgpd/.libs/bgpd \
  -f /tmp/frr_router2.conf -i /run/frr/router2/bgpd.pid -d -N router2

echo "等待BGP建立连接和轮询触发（45秒）..."
sleep 45

echo "停止抓包..."
sudo kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true

# 分析抓包结果
echo ""
echo "=== 抓包分析 ==="
echo "总BGP消息数："
tshark -r /tmp/bgpls_capture.pcap -Y "bgp" 2>/dev/null | wc -l

echo ""
echo "UPDATE消息数："
tshark -r /tmp/bgpls_capture.pcap -Y "bgp.type == 2" 2>/dev/null | wc -l

echo ""
echo "MP_REACH_NLRI数："
tshark -r /tmp/bgpls_capture.pcap -Y "bgp.mp_reach_nlri" 2>/dev/null | wc -l

echo ""
echo "Link-State NLRI数："
tshark -r /tmp/bgpls_capture.pcap -Y "bgp.ls_nlri" 2>/dev/null | wc -l

echo ""
echo "=== 详细UPDATE消息 ==="
tshark -r /tmp/bgpls_capture.pcap -Y "bgp.type == 2" -V 2>/dev/null | grep -E "Frame|UPDATE|MP_REACH|MP_UNREACH|Link-State|AFI|SAFI" | head -50

echo ""
echo "=== Router1日志中的关键信息 ==="
grep -E "send UPDATE|Link-State|bgp_linkstate_poll_callback" /tmp/frr_router1.log | tail -20

echo ""
echo "抓包文件: /tmp/bgpls_capture.pcap"
echo "日志文件: /tmp/frr_router1.log"

# 清理
echo ""
echo "清理环境..."
sudo killall bgpd zebra 2>/dev/null || true
sleep 1
sudo ip netns del router1 2>/dev/null || true
sudo ip netns del router2 2>/dev/null || true

echo "完成！"
