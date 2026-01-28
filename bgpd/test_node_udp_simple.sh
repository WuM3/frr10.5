#!/bin/bash

# 简化测试：手动调用UDP发送，无需配置文件命令

set -e

echo "========================================="
echo "Simplified Node UDP Test"
echo "========================================="

# 1. 清理环境
echo "[1] Cleaning up..."
sudo ip netns del ns1 2>/dev/null || true
sudo ip netns del ns2 2>/dev/null || true
sudo rm -f /tmp/bgpls_simple.pcap

# 2. 创建网络命名空间
echo "[2] Creating network namespaces..."
sudo ip netns add ns1
sudo ip netns add ns2
sudo ip link add veth1 type veth peer name veth2
sudo ip link set veth1 netns ns1
sudo ip link set veth2 netns ns2
sudo ip netns exec ns1 ip addr add 10.0.0.1/24 dev veth1
sudo ip netns exec ns2 ip addr add 10.0.0.2/24 dev veth2
sudo ip netns exec ns1 ip link set veth1 up
sudo ip netns exec ns2 ip link set veth2 up
sudo ip netns exec ns1 ip link set lo up
sudo ip netns exec ns2 ip link set lo up

# 3. 在ns1中启动BGP (AS 65001)
echo "[3] Starting BGP in ns1..."
sudo ip netns exec ns1 bash -c "cat > /tmp/frr_ns1.conf" << 'EOF'
hostname ns1-router
log file /tmp/bgpd_ns1.log debugging
!
debug bgp updates
!
router bgp 65001
  bgp router-id 10.0.0.1
  no bgp ebgp-requires-policy
  neighbor 10.0.0.2 remote-as 65002
  !
  address-family ipv4 unicast
    neighbor 10.0.0.2 activate
  exit-address-family
  !
  address-family ipv4 linkstate
    neighbor 10.0.0.2 activate
  exit-address-family
!
line vty
!
EOF

sudo ip netns exec ns1 /home/bgp/FRR-main/bgpd/bgpd \
    -f /tmp/frr_ns1.conf \
    -i /tmp/bgpd_ns1.pid \
    -z /tmp/zserv_ns1.sock \
    -d -u root -g root &

sleep 3

# 4. 在ns2中启动BGP + tcpdump
echo "[4] Starting BGP in ns2 and tcpdump..."
sudo ip netns exec ns2 bash -c "cat > /tmp/frr_ns2.conf" << 'EOF'
hostname ns2-router
log file /tmp/bgpd_ns2.log debugging
!
router bgp 65002
  bgp router-id 10.0.0.2
  no bgp ebgp-requires-policy
  neighbor 10.0.0.1 remote-as 65001
  !
  address-family ipv4 unicast
    neighbor 10.0.0.1 activate
  exit-address-family
  !
  address-family ipv4 linkstate
    neighbor 10.0.0.1 activate
  exit-address-family
!
line vty
!
EOF

sudo ip netns exec ns2 tcpdump -i veth2 -w /tmp/bgpls_simple.pcap \
    -s 0 tcp port 179 2>/dev/null &
TCPDUMP_PID=$!

sudo ip netns exec ns2 /home/bgp/FRR-main/bgpd/bgpd \
    -f /tmp/frr_ns2.conf \
    -i /tmp/bgpd_ns2.pid \
    -z /tmp/zserv_ns2.sock \
    -d -u root -g root &

sleep 5

# 5. 使用vtysh手动启动UDP服务器
echo "[5] Manually starting UDP server via vtysh..."
sudo ip netns exec ns1 vtysh -c "conf t" -c "router bgp 65001" -c "linkstate-udp-server start" 2>/dev/null || true
sleep 2

# 检查UDP端口是否监听
echo "Checking if UDP port 9999 is listening in ns1..."
sudo ip netns exec ns1 ss -ulnp | grep 9999 || echo "UDP port 9999 not found"

# 6. 准备Node JSON数据
echo "[6] Preparing Node JSON data..."
cat > /tmp/node_data.json << 'EOF'
{
  "nodes": [
    {
      "node_name": "TestNode_R1",
      "nlri": {
        "protocol_id": 5,
        "identifier": 1001,
        "local_node_descriptors": {
          "asn": 65001,
          "bgpls_id": 100,
          "ospf_area_id": 0,
          "router_id": "10.0.0.1"
        }
      },
      "attributes": {
        "node_flags": 192,
        "te_router_id": "10.0.0.1",
        "sr_capabilities": {
          "flags": 96,
          "srgb_base": 16000,
          "srgb_range": 8000
        },
        "sr_algorithms": [0, 1],
        "sr_local_block": {
          "srlb_base": 15000,
          "srlb_range": 1000
        },
        "srms_preference": 100,
        "oper_status": 1
      }
    }
  ]
}
EOF

# 7. 通过UDP发送Node数据
echo "[7] Sending Node data via UDP..."
sudo ip netns exec ns1 bash -c "nc -u -w1 127.0.0.1 9999 < /tmp/node_data.json" || echo "Failed to send UDP data"
sleep 3

echo ""
echo "[8] Checking logs..."
echo "--- ns1 log (UDP processing) ---"
tail -20 /tmp/bgpd_ns1.log | grep -i "udp\|node\|TestNode" || echo "No relevant logs found"

# 8. 停止tcpdump
echo ""
echo "[9] Stopping tcpdump..."
sudo kill $TCPDUMP_PID 2>/dev/null || true
sleep 2

# 9. 分析pcap
echo "[10] Analyzing pcap..."
if [ -f /tmp/bgpls_simple.pcap ]; then
    echo "Total packets:"
    sudo tshark -r /tmp/bgpls_simple.pcap 2>&1 | wc -l
    
    echo ""
    echo "BGP UPDATE messages:"
    sudo tshark -r /tmp/bgpls_simple.pcap -Y "bgp.type == 2" 2>&1 | cat
fi

# 10. 清理
echo ""
echo "[11] Cleaning up..."
sudo pkill -f "bgpd.*ns1" || true
sudo pkill -f "bgpd.*ns2" || true
sleep 2
sudo ip netns del ns1 2>/dev/null || true
sudo ip netns del ns2 2>/dev/null || true

echo ""
echo "Test completed!"
echo "Check /tmp/bgpd_ns1.log for detailed logs"
