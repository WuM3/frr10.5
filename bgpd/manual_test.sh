#!/bin/bash
# 手动测试 - 延长抓包时间
echo "========================================"
echo " 手动测试 BGP-LS UPDATE (peer_self版本)"
echo "========================================"

# 清理之前的环境
sudo ip netns del router1 2>/dev/null
sudo ip netns del router2 2>/dev/null
sleep 1

# 创建网络环境
sudo ip netns add router1
sudo ip netns add router2
sudo ip link add veth-r1 type veth peer name veth-r2
sudo ip link set veth-r1 netns router1
sudo ip link set veth-r2 netns router2
sudo ip netns exec router1 ip addr add 10.0.0.1/24 dev veth-r1
sudo ip netns exec router2 ip addr add 10.0.0.2/24 dev veth-r2
sudo ip netns exec router1 ip link set veth-r1 up
sudo ip netns exec router2 ip link set veth-r2 up
sudo ip netns exec router1 ip link set lo up
sudo ip netns exec router2 ip link set lo up

# 添加测试接口
sudo ip netns exec router1 ip link add r1-eth0 type dummy
sudo ip netns exec router1 ip addr add 192.168.1.1/24 dev r1-eth0
sudo ip netns exec router1 ip link set r1-eth0 up

echo "✓ 网络环境创建完成"

# 生成配置文件
cat > /tmp/frr_router1.conf << 'FRRCONF'
frr defaults traditional
hostname router1
log file /tmp/frr_router1.log debugging
debug bgp updates
debug bgp zebra
!
router bgp 65001
 bgp router-id 1.1.1.1
 no bgp ebgp-requires-policy
 neighbor 10.0.0.2 remote-as 65001
 !
 address-family link-state link-state
  neighbor 10.0.0.2 activate
 exit-address-family
!
linkstate-monitor interface r1-eth0
linkstate-set-poll-interval 15
line vty
!
FRRCONF

cat > /tmp/frr_router2.conf << 'FRRCONF'
frr defaults traditional
hostname router2
log file /tmp/frr_router2.log debugging
debug bgp updates
debug bgp zebra
!
router bgp 65001
 bgp router-id 2.2.2.2
 no bgp ebgp-requires-policy
 neighbor 10.0.0.1 remote-as 65001
 !
 address-family link-state link-state
  neighbor 10.0.0.1 activate
 exit-address-family
!
line vty
!
FRRCONF

echo "✓ 配置文件生成完成"

# 启动抓包（延长到60秒）
sudo timeout 60 tcpdump -i veth-r1 -w /tmp/bgpls_manual.pcap tcp port 179 &
TCPDUMP_PID=$!
sleep 2
echo "✓ tcpdump抓包已启动 (PID: $TCPDUMP_PID, 持续60秒)"

# 启动Zebra
sudo ip netns exec router1 /home/bgp/FRR-main/zebra/.libs/zebra -f /tmp/frr_router1.conf -i /run/frr/router1/zebra.pid -d -N router1 2>&1 | grep -v "MPLS"
sudo ip netns exec router2 /home/bgp/FRR-main/zebra/.libs/zebra -f /tmp/frr_router2.conf -i /run/frr/router2/zebra.pid -d -N router2 2>&1 | grep -v "MPLS"
sleep 2

# 创建linkstate配置目录
sudo mkdir -p /etc/frr/linkstate
sudo cat > /etc/frr/linkstate/linkstate_20260123_002849.json << 'JSONCONF'
{
  "links": [
    {
      "if_name": "r1-eth0",
      "local_router_id": "1.1.1.1",
      "remote_router_id": "2.2.2.2",
      "local_ipv4": "192.168.1.1",
      "remote_ipv4": "192.168.1.2",
      "max_link_bw": 1000.0,
      "igp_metric": 10,
      "admin_status": 1,
      "oper_status": 1
    }
  ]
}
JSONCONF

echo "✓ linkstate配置文件创建完成"

# 启动BGPd
sudo ip netns exec router1 /home/bgp/FRR-main/bgpd/.libs/bgpd -f /tmp/frr_router1.conf -i /run/frr/router1/bgpd.pid -d -N router1
sudo ip netns exec router2 /home/bgp/FRR-main/bgpd/.libs/bgpd -f /tmp/frr_router2.conf -i /run/frr/router2/bgpd.pid -d -N router2
sleep 5

echo "✓ FRR进程启动完成"
echo ""
echo "等待BGP会话建立和轮询触发（60秒）..."
sleep 60

echo ""
echo "✓ 测试完成，分析结果："
echo ""

# 分析日志
echo "Router1 发送的 UPDATE:"
grep "send UPDATE.*Link" /tmp/frr_router1.log | tail -5

echo ""
echo "Router2 接收的消息:"
grep -E "rcvd UPDATE|rcvd.*link-state" /tmp/frr_router2.log | tail -5

echo ""
echo "抓包分析:"
tshark -r /tmp/bgpls_manual.pcap -Y "bgp.type == 2" 2>/dev/null | wc -l | xargs echo "UPDATE消息总数:"
tshark -r /tmp/bgpls_manual.pcap -Y "bgp.type == 2" -V 2>/dev/null | grep -E "MP_REACH|MP_UNREACH|Link-State NLRI" | head -10

echo ""
echo "=========================================="
echo "抓包文件: /tmp/bgpls_manual.pcap"
echo "Router1日志: /tmp/frr_router1.log"
echo "Router2日志: /tmp/frr_router2.log"
echo "=========================================="

# 清理
sudo pkill -9 -f "bgpd.*router1"
sudo pkill -9 -f "bgpd.*router2"
sudo pkill -9 -f "zebra.*router1"
sudo pkill -9 -f "zebra.*router2"
sudo ip netns del router1 2>/dev/null
sudo ip netns del router2 2>/dev/null

