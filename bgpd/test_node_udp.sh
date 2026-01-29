#!/bin/bash

# 测试通过UDP发送Node信息到BGP-LS
# 验证JSON字段与BGP UPDATE报文的对应关系

set -e

echo "========================================="
echo "Node UDP Test - Field Mapping Analysis"
echo "========================================="

# 1. 清理环境
echo "[1] Cleaning up..."
sudo ip netns del ns1 2>/dev/null || true
sudo ip netns del ns2 2>/dev/null || true
sudo rm -f /tmp/bgpls_node_udp.pcap
sudo rm -f /tmp/bgpls_node_udp_detail.txt

# 2. 创建网络命名空间和veth对
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
debug bgp neighbor-events
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

# 4. 在ns2中启动BGP + tcpdump (详细解码)
echo "[4] Starting BGP in ns2 and tcpdump..."
sudo ip netns exec ns2 bash -c "cat > /tmp/frr_ns2.conf" << 'EOF'
hostname ns2-router
log file /tmp/bgpd_ns2.log debugging
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
  address-family ipv4 linkstate
    neighbor 10.0.0.1 activate
  exit-address-family
!
line vty
!
EOF

# 启动tcpdump（抓取详细信息）
sudo ip netns exec ns2 tcpdump -i veth2 -w /tmp/bgpls_node_udp.pcap \
    -s 0 tcp port 179 2>/dev/null &
TCPDUMP_PID=$!

sudo ip netns exec ns2 /home/bgp/FRR-main/bgpd/bgpd \
    -f /tmp/frr_ns2.conf \
    -i /tmp/bgpd_ns2.pid \
    -z /tmp/zserv_ns2.sock \
    -d -u root -g root &

sleep 5

# 5. 准备测试用的Node JSON数据
echo "[5] Preparing Node JSON data..."
cat > /tmp/node_test_data.json << 'EOF'
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

echo "Node JSON data prepared:"
cat /tmp/node_test_data.json
echo ""

# 6. 通过UDP发送Node数据
echo "[6] Sending Node data via UDP to 127.0.0.1:9999..."
sudo ip netns exec ns1 bash -c "nc -u -w1 127.0.0.1 9999 < /tmp/node_test_data.json"
sleep 3

# 7. 停止tcpdump
echo "[7] Stopping tcpdump..."
sudo kill $TCPDUMP_PID 2>/dev/null || true
sleep 2

# 8. 解析pcap文件 - 提取BGP UPDATE详细信息
echo "[8] Analyzing BGP UPDATE messages..."
echo "========================================="

if [ -f /tmp/bgpls_node_udp.pcap ]; then
    # 查找BGP UPDATE帧号
    UPDATE_FRAMES=$(sudo tshark -r /tmp/bgpls_node_udp.pcap -Y "bgp.update" -T fields -e frame.number 2>/dev/null)
    
    if [ -n "$UPDATE_FRAMES" ]; then
        echo "Found BGP UPDATE in frames: $UPDATE_FRAMES"
        echo ""
        
        for FRAME in $UPDATE_FRAMES; do
            echo "========================================="
            echo "Analyzing Frame $FRAME"
            echo "========================================="
            
            # 提取详细的BGP-LS字段
            sudo tshark -r /tmp/bgpls_node_udp.pcap -Y "frame.number==$FRAME" -V 2>/dev/null | \
                grep -A 200 "Border Gateway Protocol - UPDATE Message" > /tmp/bgpls_node_udp_detail.txt
            
            # 提取关键字段
            echo ""
            echo ">>> NLRI Information (Node Descriptors):"
            grep -E "Protocol-ID|Identifier|Autonomous System|BGP-LS Identifier|OSPF Area|IGP Router-ID" /tmp/bgpls_node_udp_detail.txt | head -20
            
            echo ""
            echo ">>> Path Attributes (Node Attributes):"
            grep -E "Type Code.*102[4-9]|Type Code.*103[0-7]|Node Flag Bits|TE Router ID|Capabilities|Algorithm|Local Block|SRMS Preference" /tmp/bgpls_node_udp_detail.txt | head -30
            
            echo ""
        done
    else
        echo "No BGP UPDATE messages found in pcap file"
    fi
    
    echo ""
    echo "========================================="
    echo "Detailed packet dump saved to: /tmp/bgpls_node_udp_detail.txt"
fi

# 9. 显示日志中的处理信息
echo ""
echo "========================================="
echo "[9] Checking ns1 log for UDP processing..."
echo "========================================="
if grep -q "Node TestNode_R1" /tmp/bgpd_ns1.log 2>/dev/null; then
    echo "✓ Node TestNode_R1 found in log"
    grep "Node TestNode_R1" /tmp/bgpd_ns1.log | tail -5
else
    echo "✗ Node TestNode_R1 not found in log"
fi

if grep -q "nodestate_add" /tmp/bgpd_ns1.log 2>/dev/null; then
    echo "✓ nodestate_add called"
    grep "nodestate_add" /tmp/bgpd_ns1.log | tail -3
else
    echo "✗ nodestate_add not called"
fi

# 10. 生成字段映射表
echo ""
echo "========================================="
echo "[10] JSON to BGP-LS Field Mapping"
echo "========================================="
cat << 'MAPPING'

╔══════════════════════════════════════════════════════════════════════════════════
║ NLRI (Node Descriptors) - Protocol-ID=5, Length=37 bytes
╠══════════════════════════════════════════════════════════════════════════════════
║ JSON Field                         │ BGP-LS TLV          │ Value
║────────────────────────────────────┼─────────────────────┼──────────────────────
║ nlri.protocol_id                   │ Protocol-ID (1B)    │ 5 (OSPF v2)
║ nlri.identifier                    │ Identifier (8B)     │ 1001 (0x03E9)
║ nlri.local_node_descriptors:       │                     │
║   .asn                             │ Sub-TLV 512 (4B)    │ 65001 (0x0000FDE9)
║   .bgpls_id                        │ Sub-TLV 513 (4B)    │ 100 (0x00000064)
║   .ospf_area_id                    │ Sub-TLV 514 (4B)    │ 0 (0x00000000)
║   .router_id                       │ Sub-TLV 515 (4B)    │ 10.0.0.1 (0x0A000001)
╚══════════════════════════════════════════════════════════════════════════════════

╔══════════════════════════════════════════════════════════════════════════════════
║ Path Attributes (Node Attributes) - Length=57-58 bytes
╠══════════════════════════════════════════════════════════════════════════════════
║ JSON Field                         │ BGP-LS TLV          │ Value
║────────────────────────────────────┼─────────────────────┼──────────────────────
║ attributes.node_flags              │ TLV 1024 (1B)       │ 192 (0xC0)
║                                    │   Bit 0: Overload   │   0
║                                    │   Bit 1: Attached   │   0
║                                    │   Bit 2: External   │   0
║                                    │   Bit 3: ABR        │   0
║                                    │   Bit 6: Router     │   1
║                                    │   Bit 7: V6         │   1
║────────────────────────────────────┼─────────────────────┼──────────────────────
║ attributes.te_router_id            │ TLV 1028 (4B)       │ 10.0.0.1 (0x0A000001)
║────────────────────────────────────┼─────────────────────┼──────────────────────
║ attributes.sr_capabilities:        │ TLV 1034            │
║   .flags                           │   Flags (1B)        │ 96 (0x60)
║                                    │     I-flag (Bit 1)  │   1
║                                    │     V-flag (Bit 2)  │   1
║   .srgb_base                       │   Range TLV (3B)    │ 16000 (0x003E80)
║   .srgb_range                      │   Range TLV (3B)    │ 8000 (0x001F40)
║────────────────────────────────────┼─────────────────────┼──────────────────────
║ attributes.sr_algorithms           │ TLV 1035            │
║   [0]                              │   Algorithm 0       │ SPF
║   [1]                              │   Algorithm 1       │ Strict SPF
║────────────────────────────────────┼─────────────────────┼──────────────────────
║ attributes.sr_local_block:         │ TLV 1036            │
║   .srlb_base                       │   Range TLV (3B)    │ 15000 (0x003A98)
║   .srlb_range                      │   Range TLV (3B)    │ 1000 (0x0003E8)
║────────────────────────────────────┼─────────────────────┼──────────────────────
║ attributes.srms_preference         │ TLV 1037 (1B)       │ 100 (0x64)
╚══════════════════════════════════════════════════════════════════════════════════

Total BGP UPDATE Message Size:
  - Marker: 16 bytes (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
  - Length: 2 bytes (e.g., 0x00E5 = 229 bytes)
  - Type: 1 byte (0x02 = UPDATE)
  - Withdrawn Routes Length: 2 bytes (0x0000)
  - Total Path Attribute Length: 2 bytes
  - MP_REACH_NLRI (AFI=16388, SAFI=71):
      - NLRI: 37 bytes (Node Descriptors)
      - Path Attributes: ~57 bytes (Node Attributes TLVs)

MAPPING

# 11. 使用tshark导出十六进制对比
echo ""
echo "========================================="
echo "[11] Hexadecimal Dump for Verification"
echo "========================================="
if [ -f /tmp/bgpls_node_udp.pcap ]; then
    UPDATE_FRAME=$(sudo tshark -r /tmp/bgpls_node_udp.pcap -Y "bgp.update" -T fields -e frame.number 2>/dev/null | head -1)
    if [ -n "$UPDATE_FRAME" ]; then
        echo "Frame $UPDATE_FRAME Hex Dump (BGP payload):"
        sudo tshark -r /tmp/bgpls_node_udp.pcap -Y "frame.number==$UPDATE_FRAME" -T fields -e bgp.update 2>/dev/null | head -1
    fi
fi

# 12. 清理
echo ""
echo "========================================="
echo "[12] Cleaning up..."
echo "========================================="
sudo pkill -f "bgpd.*ns1" || true
sudo pkill -f "bgpd.*ns2" || true
sleep 2
sudo ip netns del ns1 2>/dev/null || true
sudo ip netns del ns2 2>/dev/null || true

echo ""
echo "========================================="
echo "Test Completed!"
echo "========================================="
echo "Files generated:"
echo "  - JSON input: /tmp/node_test_data.json"
echo "  - Pcap file: /tmp/bgpls_node_udp.pcap"
echo "  - Detailed dump: /tmp/bgpls_node_udp_detail.txt"
echo "  - ns1 log: /tmp/bgpd_ns1.log"
echo "  - ns2 log: /tmp/bgpd_ns2.log"
echo ""
echo "To manually inspect the pcap:"
echo "  sudo tshark -r /tmp/bgpls_node_udp.pcap -V | less"
echo ""
echo "To check specific TLV values:"
echo "  sudo tshark -r /tmp/bgpls_node_udp.pcap -Y 'bgp.update' -V | grep -A5 'TLV 103'"
