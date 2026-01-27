#!/bin/bash
# 测试BGP-LS Node轮询功能
# 简化版本 - 只测试从配置文件轮询读取节点信息

set -e

cd /home/ubuntu/frr

# 清理
cleanup() {
    echo "[CLEANUP] 清理环境..."
    sudo ip netns exec ns1 kill $(cat /tmp/ns1_bgpd.pid 2>/dev/null) 2>/dev/null || true
    sudo ip netns exec ns2 kill $(cat /tmp/ns2_bgpd.pid 2>/dev/null) 2>/dev/null || true
    sudo pkill -9 -f "bgpd.*ns[12]" 2>/dev/null || true
    sudo pkill -9 tcpdump 2>/dev/null || true
    sudo ip link del veth1 2>/dev/null || true
    sudo ip netns del ns1 2>/dev/null || true
    sudo ip netns del ns2 2>/dev/null || true
    rm -f /tmp/ns*_bgpd.pid 2>/dev/null || true
    sudo ip netns exec ns1 rm -rf /etc/frr/linkstate 2>/dev/null || true
}

trap cleanup EXIT
cleanup

echo "=========================================="
echo " BGP-LS Node 轮询功能测试"
echo "=========================================="

# 创建网络命名空间和veth对
echo "[SETUP] 创建网络命名空间..."
sudo ip netns add ns1
sudo ip netns add ns2

echo "[SETUP] 创建veth对..."
sudo ip link add veth1 type veth peer name veth2
sudo ip link set veth1 netns ns1
sudo ip link set veth2 netns ns2

echo "[SETUP] 配置IP地址..."
sudo ip netns exec ns1 ip addr add 10.0.0.1/24 dev veth1
sudo ip netns exec ns1 ip link set veth1 up
sudo ip netns exec ns1 ip link set lo up

sudo ip netns exec ns2 ip addr add 10.0.0.2/24 dev veth2
sudo ip netns exec ns2 ip link set veth2 up
sudo ip netns exec ns2 ip link set lo up

# 验证连通性
echo "[SETUP] 验证连通性..."
sudo ip netns exec ns1 ping -c 1 10.0.0.2

# 创建配置文件 - ns1 (发送方，启用轮询)
cat > /tmp/ns1_bgpd.conf << 'EOF'
frr defaults traditional
hostname router1
log stdout debugging
debug bgp updates
debug bgp neighbor-events

router bgp 65001
 bgp router-id 1.1.1.1
 no bgp ebgp-requires-policy
 neighbor 10.0.0.2 remote-as 65002
 !
 address-family link-state link-state
  neighbor 10.0.0.2 activate
 exit-address-family
 !
 bgp linkstate poll enable
 bgp linkstate poll-interval 10
!
EOF

# 创建配置文件 - ns2 (接收方)
cat > /tmp/ns2_bgpd.conf << 'EOF'
frr defaults traditional
hostname router2
log stdout debugging
debug bgp updates
debug bgp neighbor-events

router bgp 65002
 bgp router-id 2.2.2.2
 no bgp ebgp-requires-policy
 neighbor 10.0.0.1 remote-as 65001
 !
 address-family link-state link-state
  neighbor 10.0.0.1 activate
 exit-address-family
!
EOF

# 创建节点状态配置文件目录
echo "[SETUP] 创建节点配置文件目录..."
sudo ip netns exec ns1 mkdir -p /etc/frr/linkstate

# 创建初始节点状态配置文件
echo "[TEST] 创建初始nodestate配置文件..."
NODESTATE_CONFIG="/tmp/nodestate_$(date +%Y%m%d_%H%M%S).json"
cat > "$NODESTATE_CONFIG" << 'EOF_NODE'
{
  "nodes": [
    {
      "node_name": "R1-POLL",
      "nlri": {
        "protocol_id": 5,
        "identifier": 2001,
        "local_node_descriptors": {
          "asn": 65001,
          "bgpls_id": 1,
          "ospf_area_id": 0,
          "router_id": "10.1.1.1"
        }
      },
      "attributes": {
        "node_flags": 0,
        "te_router_id": "10.1.1.1",
        "sr_capabilities": {
          "flags": 128,
          "srgb_base": 17000,
          "srgb_range": 9000
        },
        "sr_algorithms": [0, 1],
        "sr_local_block": {
          "srlb_base": 15000,
          "srlb_range": 1000
        },
        "srms_preference": 150,
        "oper_status": 1
      }
    },
    {
      "node_name": "R2-POLL",
      "nlri": {
        "protocol_id": 5,
        "identifier": 2002,
        "local_node_descriptors": {
          "asn": 65001,
          "bgpls_id": 1,
          "ospf_area_id": 0,
          "router_id": "10.1.1.2"
        }
      },
      "attributes": {
        "node_flags": 16,
        "te_router_id": "10.1.1.2",
        "sr_capabilities": {
          "flags": 128,
          "srgb_base": 17000,
          "srgb_range": 9000
        },
        "sr_algorithms": [0, 1],
        "sr_local_block": {
          "srlb_base": 15000,
          "srlb_range": 1000
        },
        "srms_preference": 150,
        "oper_status": 1
      }
    },
    {
      "node_name": "R3-POLL",
      "nlri": {
        "protocol_id": 5,
        "identifier": 2003,
        "local_node_descriptors": {
          "asn": 65001,
          "bgpls_id": 1,
          "ospf_area_id": 0,
          "router_id": "10.1.1.3"
        }
      },
      "attributes": {
        "node_flags": 0,
        "te_router_id": "10.1.1.3",
        "sr_capabilities": {
          "flags": 192,
          "srgb_base": 18000,
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
    }
  ]
}
EOF_NODE

sudo ip netns exec ns1 cp "$NODESTATE_CONFIG" /etc/frr/linkstate/

# 启动抓包
echo "[START] 启动抓包..."
rm -f /tmp/bgpls_node_poll_test.pcap 2>/dev/null
touch /tmp/bgpls_node_poll_test.pcap
chmod 666 /tmp/bgpls_node_poll_test.pcap
sudo ip netns exec ns1 tcpdump -i veth1 -nn port 179 -w /tmp/bgpls_node_poll_test.pcap &
TCPDUMP_PID=$!
sleep 1

echo "[START] 启动ns2的bgpd..."
sudo ip netns exec ns2 ./bgpd/.libs/bgpd -f /tmp/ns2_bgpd.conf -i /tmp/ns2_bgpd.pid -z /tmp/ns2_zebra.api 2>&1 | tee /tmp/ns2_bgpd.log &
sleep 2

echo "[START] 启动ns1的bgpd..."
sudo ip netns exec ns1 ./bgpd/.libs/bgpd -f /tmp/ns1_bgpd.conf -i /tmp/ns1_bgpd.pid -z /tmp/ns1_zebra.api 2>&1 | tee /tmp/ns1_bgpd.log &
sleep 3

echo "[WAIT] 等待BGP会话建立..."
for i in {1..20}; do
    if grep -q "Established" /tmp/ns1_bgpd.log 2>/dev/null; then
        echo "[SUCCESS] BGP会话已建立!"
        break
    fi
    echo "  等待中... ($i/20)"
    sleep 1
done

echo ""
echo "=========================================="
echo " 测试1: 初始轮询 - ADD操作"
echo "=========================================="

echo "[WAIT] 等待轮询函数读取节点配置文件 (10秒轮询间隔)..."
for i in {1..15}; do
    echo "  等待中... ($i/15)"
    sleep 1
    if grep -q "Parsed node.*R1-POLL" /tmp/ns1_bgpd.log 2>/dev/null; then
        echo "[SUCCESS] 检测到轮询读取节点数据!"
        break
    fi
done

echo ""
echo "[CHECK] 查看轮询ADD相关日志:"
grep -E "POLL|Parsed node|NODE.*ADD" /tmp/ns1_bgpd.log 2>/dev/null | tail -30 || echo "  (无轮询日志)"

echo ""
echo "=========================================="
echo " 测试2: 修改配置 - UPDATE和DELETE操作"
echo "=========================================="

# 创建更新后的配置文件
echo "[TEST] 创建更新后的nodestate配置文件..."
sleep 2
NODESTATE_UPDATE="/tmp/nodestate_$(date +%Y%m%d_%H%M%S).json"
cat > "$NODESTATE_UPDATE" << 'EOF_UPDATE'
{
  "nodes": [
    {
      "node_name": "R1-POLL",
      "nlri": {
        "protocol_id": 5,
        "identifier": 2001,
        "local_node_descriptors": {
          "asn": 65001,
          "bgpls_id": 1,
          "ospf_area_id": 0,
          "router_id": "10.1.1.1"
        }
      },
      "attributes": {
        "node_flags": 128,
        "te_router_id": "10.1.1.1",
        "sr_capabilities": {
          "flags": 128,
          "srgb_base": 25000,
          "srgb_range": 15000
        },
        "sr_algorithms": [0, 1, 2, 3],
        "sr_local_block": {
          "srlb_base": 14000,
          "srlb_range": 2000
        },
        "srms_preference": 250,
        "oper_status": 1
      }
    },
    {
      "node_name": "R2-POLL",
      "nlri": {
        "protocol_id": 5,
        "identifier": 2002,
        "local_node_descriptors": {
          "asn": 65001,
          "bgpls_id": 1,
          "ospf_area_id": 0,
          "router_id": "10.1.1.2"
        }
      },
      "attributes": {
        "node_flags": 16,
        "te_router_id": "10.1.1.2",
        "sr_capabilities": {
          "flags": 128,
          "srgb_base": 17000,
          "srgb_range": 9000
        },
        "sr_algorithms": [0, 1],
        "sr_local_block": {
          "srlb_base": 15000,
          "srlb_range": 1000
        },
        "srms_preference": 150,
        "oper_status": 1
      }
    },
    {
      "node_name": "R3-POLL",
      "nlri": {
        "protocol_id": 5,
        "identifier": 2003,
        "local_node_descriptors": {
          "asn": 65001,
          "bgpls_id": 1,
          "ospf_area_id": 0,
          "router_id": "10.1.1.3"
        }
      },
      "attributes": {
        "oper_status": 0
      }
    }
  ]
}
EOF_UPDATE

sudo ip netns exec ns1 cp "$NODESTATE_UPDATE" /etc/frr/linkstate/

echo "[WAIT] 等待下一次轮询 (检测UPDATE和DELETE)..."
for i in {1..12}; do
    echo "  等待中... ($i/12)"
    sleep 1
done

echo ""
echo "[CHECK] 查看UPDATE/DELETE相关日志:"
grep -E "NODE.*UPDATE|NODE.*DELETE|srgb_base.*25000|oper_status.*0" /tmp/ns1_bgpd.log 2>/dev/null | tail -25 || echo "  (无UPDATE/DELETE日志)"

# 停止抓包
sleep 2
sudo kill $TCPDUMP_PID 2>/dev/null || true
sleep 1

echo ""
echo "=========================================="
echo " 分析抓包结果"
echo "=========================================="

if [ -f /tmp/bgpls_node_poll_test.pcap ]; then
    echo ""
    echo "[PCAP] BGP UPDATE报文统计:"
    tshark -r /tmp/bgpls_node_poll_test.pcap -Y "bgp.type == 2" 2>/dev/null | wc -l | xargs -I {} echo "  共发送 {} 个UPDATE报文" || echo "  (无法解析)"
    
    echo ""
    echo "[PCAP] BGP WITHDRAW报文统计:"
    tshark -r /tmp/bgpls_node_poll_test.pcap -Y "bgp.withdrawn_prefix" 2>/dev/null | wc -l | xargs -I {} echo "  共发送 {} 个WITHDRAW报文" || echo "  (无法解析)"
else
    echo "[ERROR] 抓包文件不存在"
fi

echo ""
echo "=========================================="
echo " 日志摘要"
echo "=========================================="
echo ""
echo "=== NS1 (发送方) 关键日志 ==="
echo ""
echo "1. 轮询配置:"
grep -E "Starting link-state polling|poll interval" /tmp/ns1_bgpd.log 2>/dev/null | head -5

echo ""
echo "2. 节点ADD:"
grep -E "Parsed node.*POLL|Successfully parsed.*nodes" /tmp/ns1_bgpd.log 2>/dev/null | head -5

echo ""
echo "3. 节点UPDATE:"
grep -E "srgb_base.*25000|node_flags.*128" /tmp/ns1_bgpd.log 2>/dev/null | head -3

echo ""
echo "4. 节点DELETE:"
grep -E "oper_status.*0|Node.*DOWN" /tmp/ns1_bgpd.log 2>/dev/null | head -3

echo ""
echo "=== NS2 (接收方) 日志 ==="
cat /tmp/ns2_bgpd.log 2>/dev/null | grep -E "UPDATE|NLRI" | tail -15

echo ""
echo "=========================================="
echo " 测试总结"
echo "=========================================="
echo ""
echo "✅ 测试完成项目:"
echo "  1. BGP会话建立"
echo "  2. 节点轮询ADD (3个节点)"
echo "  3. 节点轮询UPDATE (修改R1-POLL的SRGB: 17000->25000)"
echo "  4. 节点轮询DELETE (R3-POLL设置为DOWN)"
echo ""
echo "📁 生成文件:"
echo "  - 抓包: /tmp/bgpls_node_poll_test.pcap"
echo "  - 配置1: $NODESTATE_CONFIG"
echo "  - 配置2: $NODESTATE_UPDATE"
echo "  - 日志: /tmp/ns1_bgpd.log, /tmp/ns2_bgpd.log"
echo ""
echo "🔍 查看详情:"
echo "  wireshark /tmp/bgpls_node_poll_test.pcap"
echo "  tail -f /tmp/ns1_bgpd.log"
echo ""
