#!/bin/bash

# 测试node配置文件定期轮询功能
# 验证从nodestate_*.json文件读取并通过BGP-LS分发节点信息

set -e

echo "========================================="
echo "Node Config File Polling Test"
echo "========================================="

# 1. 清理环境
echo "[1] Cleaning up..."
sudo ip netns del ns1 2>/dev/null || true
sudo ip netns del ns2 2>/dev/null || true
sudo rm -f /tmp/bgpls_node_poll_test.pcap
sudo rm -f /home/bgp/FRR-main/linkstate_config/nodestate_*.json

# 2. 创建网络命名空间和veth对
echo "[2] Creating network namespaces and veth pair..."
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
echo "[3] Starting BGP in ns1 (AS 65001)..."
sudo ip netns exec ns1 bash -c "cat > /tmp/frr_ns1.conf" << 'EOF'
hostname ns1-router
log file /tmp/bgpd_ns1.log debugging
!
debug bgp updates
debug bgp neighbor-events
debug bgp keepalives
debug bgp bmp
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
linkstate-polling interval 10
!
line vty
!
EOF

# 启动bgpd (ns1)
sudo ip netns exec ns1 /home/bgp/FRR-main/bgpd/bgpd \
    -f /tmp/frr_ns1.conf \
    -i /tmp/bgpd_ns1.pid \
    -z /tmp/zserv_ns1.sock \
    -d -u root -g root &

sleep 3

# 4. 在ns2中启动BGP (AS 65002) + tcpdump
echo "[4] Starting BGP in ns2 (AS 65002) and tcpdump..."
sudo ip netns exec ns2 bash -c "cat > /tmp/frr_ns2.conf" << 'EOF'
hostname ns2-router
log file /tmp/bgpd_ns2.log debugging
!
debug bgp updates
debug bgp neighbor-events
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

# 启动tcpdump在ns2抓包
sudo ip netns exec ns2 tcpdump -i veth2 -w /tmp/bgpls_node_poll_test.pcap \
    tcp port 179 2>/dev/null &
TCPDUMP_PID=$!

# 启动bgpd (ns2)
sudo ip netns exec ns2 /home/bgp/FRR-main/bgpd/bgpd \
    -f /tmp/frr_ns2.conf \
    -i /tmp/bgpd_ns2.pid \
    -z /tmp/zserv_ns2.sock \
    -d -u root -g root &

sleep 5

# 5. 准备node配置文件 (带时间戳)
echo "[5] Creating node config file with 2 nodes..."
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
sudo bash -c "cat > /home/bgp/FRR-main/linkstate_config/nodestate_${TIMESTAMP}.json" << 'EOF'
{
  "nodes": [
    {
      "node_name": "R1",
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
    },
    {
      "node_name": "R2",
      "nlri": {
        "protocol_id": 5,
        "identifier": 1001,
        "local_node_descriptors": {
          "asn": 65001,
          "bgpls_id": 100,
          "ospf_area_id": 0,
          "router_id": "10.0.0.2"
        }
      },
      "attributes": {
        "node_flags": 192,
        "te_router_id": "10.0.0.2",
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

echo "Node config file created: /home/bgp/FRR-main/linkstate_config/nodestate_${TIMESTAMP}.json"

# 6. 等待第一次轮询（10秒）+ 额外缓冲
echo "[6] Waiting for first poll cycle (10 sec + 5 sec buffer)..."
sleep 15

# 7. 检查ns1日志
echo "[7] Checking ns1 BGP log for node processing..."
if grep -q "Node R1 is UP" /tmp/bgpd_ns1.log 2>/dev/null; then
    echo "✓ Node R1 processed successfully"
else
    echo "✗ Node R1 not found in logs"
fi

if grep -q "Node R2 is UP" /tmp/bgpd_ns1.log 2>/dev/null; then
    echo "✓ Node R2 processed successfully"
else
    echo "✗ Node R2 not found in logs"
fi

# 8. 更新配置文件 - 修改R1的SRGB
echo "[8] Updating R1 node config (changing SRGB)..."
TIMESTAMP2=$(date +"%Y%m%d_%H%M%S")
sleep 1  # 确保时间戳不同
sudo bash -c "cat > /home/bgp/FRR-main/linkstate_config/nodestate_${TIMESTAMP2}.json" << 'EOF'
{
  "nodes": [
    {
      "node_name": "R1",
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
          "srgb_base": 20000,
          "srgb_range": 10000
        },
        "sr_algorithms": [0, 1, 2],
        "sr_local_block": {
          "srlb_base": 15000,
          "srlb_range": 1000
        },
        "srms_preference": 200,
        "oper_status": 1
      }
    },
    {
      "node_name": "R2",
      "nlri": {
        "protocol_id": 5,
        "identifier": 1001,
        "local_node_descriptors": {
          "asn": 65001,
          "bgpls_id": 100,
          "ospf_area_id": 0,
          "router_id": "10.0.0.2"
        }
      },
      "attributes": {
        "node_flags": 192,
        "te_router_id": "10.0.0.2",
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

echo "Updated config file created: /home/bgp/FRR-main/linkstate_config/nodestate_${TIMESTAMP2}.json"

# 9. 等待第二次轮询
echo "[9] Waiting for second poll cycle (10 sec + 5 sec buffer)..."
sleep 15

# 10. 删除R1节点 (设置oper_status=0)
echo "[10] Deleting R1 node (oper_status=0)..."
TIMESTAMP3=$(date +"%Y%m%d_%H%M%S")
sleep 1
sudo bash -c "cat > /home/bgp/FRR-main/linkstate_config/nodestate_${TIMESTAMP3}.json" << 'EOF'
{
  "nodes": [
    {
      "node_name": "R1",
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
        "oper_status": 0
      }
    },
    {
      "node_name": "R2",
      "nlri": {
        "protocol_id": 5,
        "identifier": 1001,
        "local_node_descriptors": {
          "asn": 65001,
          "bgpls_id": 100,
          "ospf_area_id": 0,
          "router_id": "10.0.0.2"
        }
      },
      "attributes": {
        "node_flags": 192,
        "te_router_id": "10.0.0.2",
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

echo "Delete config file created: /home/bgp/FRR-main/linkstate_config/nodestate_${TIMESTAMP3}.json"

# 11. 等待第三次轮询
echo "[11] Waiting for third poll cycle (10 sec + 5 sec buffer)..."
sleep 15

# 12. 停止tcpdump
echo "[12] Stopping tcpdump..."
sudo kill $TCPDUMP_PID 2>/dev/null || true
sleep 2

# 13. 分析pcap文件
echo "[13] Analyzing pcap file for BGP UPDATE messages..."
if [ -f /tmp/bgpls_node_poll_test.pcap ]; then
    echo "BGP UPDATE messages (Node NLRI):"
    sudo tshark -r /tmp/bgpls_node_poll_test.pcap \
        -Y "bgp.update" \
        -T fields -e frame.number -e bgp.update.nlri -e bgp.mp_reach_nlri.ipv4_nlri 2>/dev/null || true
    
    echo ""
    echo "Total BGP UPDATE count:"
    sudo tshark -r /tmp/bgpls_node_poll_test.pcap \
        -Y "bgp.update" 2>/dev/null | wc -l
fi

# 14. 清理
echo "[14] Cleaning up..."
sudo pkill -f "bgpd.*ns1" || true
sudo pkill -f "bgpd.*ns2" || true
sleep 2
sudo ip netns del ns1 2>/dev/null || true
sudo ip netns del ns2 2>/dev/null || true

echo ""
echo "========================================="
echo "Test completed!"
echo "========================================="
echo "Log files:"
echo "  - ns1: /tmp/bgpd_ns1.log"
echo "  - ns2: /tmp/bgpd_ns2.log"
echo "Pcap file: /tmp/bgpls_node_poll_test.pcap"
echo ""
echo "Expected results:"
echo "  - 2 BGP UPDATEs for initial ADD (R1, R2)"
echo "  - 1 BGP UPDATE for R1 modification"
echo "  - 1 BGP WITHDRAW for R1 deletion"
echo "  Total: ~4 BGP UPDATE messages"
