#!/bin/bash

# 测试通过UDP发送Node信息 - 使用linkstate monitor命令

set -e

echo "========================================="
echo "Node UDP Test with JSON Field Mapping"
echo "========================================="

# 1. 清理环境
echo "[1] Cleaning up..."
sudo ip netns del ns1 2>/dev/null || true
sudo ip netns del ns2 2>/dev/null || true
sudo rm -f /tmp/node_udp_test.pcap

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

# 3. 在ns1中启动BGP (带linkstate monitor)
echo "[3] Starting BGP in ns1 with linkstate monitor..."
sudo ip netns exec ns1 bash -c "cat > /tmp/ns1_bgpd.conf" << 'EOF'
hostname ns1-router
log file /tmp/ns1_bgpd.log debugging
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
  address-family link-state link-state
    neighbor 10.0.0.2 activate
  exit-address-family
  !
  linkstate monitor
!
line vty
!
EOF

sudo ip netns exec ns1 /home/bgp/FRR-main/bgpd/bgpd \
    -f /tmp/ns1_bgpd.conf \
    -i /tmp/ns1_bgpd.pid \
    -z /tmp/zserv_ns1.sock \
    -d -u root -g root &

sleep 3

# 4. 在ns2中启动BGP + tcpdump
echo "[4] Starting BGP in ns2 and tcpdump..."
sudo ip netns exec ns2 bash -c "cat > /tmp/ns2_bgpd.conf" << 'EOF'
hostname ns2-router
log file /tmp/ns2_bgpd.log debugging
!
debug bgp updates
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
  address-family link-state link-state
    neighbor 10.0.0.1 activate
  exit-address-family
!
line vty
!
EOF

sudo ip netns exec ns2 tcpdump -i veth2 -w /tmp/node_udp_test.pcap \
    -s 0 tcp port 179 2>/dev/null &
TCPDUMP_PID=$!

sudo ip netns exec ns2 /home/bgp/FRR-main/bgpd/bgpd \
    -f /tmp/ns2_bgpd.conf \
    -i /tmp/ns2_bgpd.pid \
    -z /tmp/zserv_ns2.sock \
    -d -u root -g root &

sleep 3

# 5. 检查UDP端口
echo "[5] Checking UDP port 9999..."
sudo ip netns exec ns1 ss -uln | grep 9999 || echo "UDP port 9999 not found"

# 6. 等待BGP会话建立
echo "[6] Waiting for BGP session..."
for i in {1..15}; do
    if grep -q "Established" /tmp/ns1_bgpd.log 2>/dev/null; then
        echo "BGP session established!"
        break
    fi
    sleep 1
done

# 7. 准备Node JSON数据
echo "[7] Preparing Node JSON data..."
cat > /tmp/node_test_input.json << 'EOF'
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

echo "Input JSON:"
cat /tmp/node_test_input.json
echo ""

# 8. 通过UDP发送Node数据
echo "[8] Sending Node data via UDP to 127.0.0.1:9999..."
sudo ip netns exec ns1 bash -c "nc -u -w1 127.0.0.1 9999 < /tmp/node_test_input.json"
sleep 3

# 9. 检查日志
echo ""
echo "[9] Checking logs for node processing..."
if grep -q "TestNode_R1" /tmp/ns1_bgpd.log; then
    echo "✓ Node TestNode_R1 found in log"
    grep "TestNode_R1" /tmp/ns1_bgpd.log | head -3
else
    echo "✗ Node not found in log"
fi

# 10. 停止tcpdump
echo ""
echo "[10] Stopping tcpdump..."
sudo kill $TCPDUMP_PID 2>/dev/null || true
sleep 2

# 11. 分析BGP UPDATE消息
echo "[11] Analyzing BGP UPDATE messages..."
if [ -f /tmp/node_udp_test.pcap ]; then
    # 查找UPDATE消息
    UPDATE_FRAMES=$(sudo tshark -r /tmp/node_udp_test.pcap -Y "bgp.type == 2 && bgp.mp_reach_nlri" -T fields -e frame.number 2>/dev/null | head -1)
    
    if [ -n "$UPDATE_FRAMES" ]; then
        echo "Found BGP UPDATE with Node NLRI in frame: $UPDATE_FRAMES"
        echo ""
        
        # 提取详细信息
        sudo tshark -r /tmp/node_udp_test.pcap -Y "frame.number == $UPDATE_FRAMES" -V 2>/dev/null > /tmp/node_update_detail.txt
        
        echo "=== Node NLRI (Local Node Descriptors) ==="
        grep -E "Protocol-ID|Identifier|Autonomous System|BGP-LS Identifier|OSPF Area|Router-ID" /tmp/node_update_detail.txt | head -10
        
        echo ""
        echo "=== Node Attributes (TLV 1024-1037) ==="
        grep -E "Type Code: 102[4-9]|Type Code: 103[0-7]|Node Flag|TE Router ID|SR Capabilit|Algorithm|Local Block|SRMS" /tmp/node_update_detail.txt | head -15
        
    else
        echo "No BGP UPDATE with Node NLRI found"
        echo "All BGP messages:"
        sudo tshark -r /tmp/node_udp_test.pcap -Y "bgp" 2>/dev/null | head -20
    fi
fi

# 12. 生成字段对应表
echo ""
echo "========================================="
echo "JSON to BGP-LS Field Mapping"
echo "========================================="
cat << 'TABLE'

┌─────────────────────────────────────────────────────────────────────┐
│ NLRI (Node NLRI) - RFC 7752 Section 3.2                            │
├─────────────────────────────────────────────────────────────────────┤
│ JSON Path                          → BGP-LS Encoding                │
├────────────────────────────────────┬────────────────────────────────┤
│ nlri.protocol_id: 5                │ Protocol-ID: 0x05 (OSPF v2)   │
│ nlri.identifier: 1001              │ Identifier: 0x00000000000003E9│
│ nlri.local_node_descriptors.asn    │ Sub-TLV 512: 0x0000FDE9        │
│                                    │   (65001 in 4 bytes)           │
│ nlri.local_node_descriptors.       │ Sub-TLV 513: 0x00000064        │
│   bgpls_id: 100                    │   (BGP-LS ID in 4 bytes)       │
│ nlri.local_node_descriptors.       │ Sub-TLV 514: 0x00000000        │
│   ospf_area_id: 0                  │   (OSPF Area in 4 bytes)       │
│ nlri.local_node_descriptors.       │ Sub-TLV 515: 0x0A000001        │
│   router_id: "10.0.0.1"            │   (10.0.0.1 in 4 bytes)        │
└────────────────────────────────────┴────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ Path Attributes (Node Attributes) - RFC 9085                        │
├─────────────────────────────────────────────────────────────────────┤
│ JSON Path                          → BGP-LS TLV Encoding            │
├────────────────────────────────────┬────────────────────────────────┤
│ attributes.node_flags: 192         │ TLV 1024: 0xC0                 │
│   (0xC0 = 0b11000000)              │   Bit 6=1 (Router)             │
│                                    │   Bit 7=1 (V6-capable)         │
├────────────────────────────────────┼────────────────────────────────┤
│ attributes.te_router_id:           │ TLV 1028: 0x0A000001           │
│   "10.0.0.1"                       │   (IPv4 address 4 bytes)       │
├────────────────────────────────────┼────────────────────────────────┤
│ attributes.sr_capabilities.flags:  │ TLV 1034:                      │
│   96 (0x60 = 0b01100000)           │   Flags: 0x60                  │
│                                    │     Bit 1=1 (I-flag: IPv4)     │
│                                    │     Bit 2=1 (V-flag: IPv6)     │
│ attributes.sr_capabilities.        │   SR Range Sub-TLV:            │
│   srgb_base: 16000                 │     Flags: 0x00                │
│   srgb_range: 8000                 │     Range: 8000 (3 bytes)      │
│                                    │     SID/Label: 16000 (3 bytes) │
├────────────────────────────────────┼────────────────────────────────┤
│ attributes.sr_algorithms: [0, 1]   │ TLV 1035:                      │
│                                    │   Algorithm 0: SPF             │
│                                    │   Algorithm 1: Strict SPF      │
├────────────────────────────────────┼────────────────────────────────┤
│ attributes.sr_local_block.         │ TLV 1036:                      │
│   srlb_base: 15000                 │   SR Range Sub-TLV:            │
│   srlb_range: 1000                 │     Range: 1000 (3 bytes)      │
│                                    │     SID/Label: 15000 (3 bytes) │
├────────────────────────────────────┼────────────────────────────────┤
│ attributes.srms_preference: 100    │ TLV 1037: 0x64                 │
└────────────────────────────────────┴────────────────────────────────┘

TABLE

# 13. 清理
echo ""
echo "[12] Cleaning up..."
sudo pkill -f "bgpd.*ns1" || true
sudo pkill -f "bgpd.*ns2" || true
sleep 2
sudo ip netns del ns1 2>/dev/null || true
sudo ip netns del ns2 2>/dev/null || true

echo ""
echo "========================================="
echo "Test Completed!"
echo "========================================="
echo "Files:"
echo "  - Input JSON: /tmp/node_test_input.json"
echo "  - Pcap file: /tmp/node_udp_test.pcap"
echo "  - Detailed dump: /tmp/node_update_detail.txt"
echo "  - ns1 log: /tmp/ns1_bgpd.log"
echo "  - ns2 log: /tmp/ns2_bgpd.log"
echo ""
echo "Manual inspection:"
echo "  sudo tshark -r /tmp/node_udp_test.pcap -V | less"
