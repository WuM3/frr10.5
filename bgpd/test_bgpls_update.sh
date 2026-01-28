#!/bin/bash
# 测试BGP-LS UPDATE报文生成
# 使用两个不同的命名空间来建立真正的BGP邻居关系

set -e

cd /home/bgp/FRR-main

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
    # 保留抓包文件和日志供分析: /tmp/bgpls_test.pcap, /tmp/ns1_bgpd.log, /tmp/ns2_bgpd.log
}

trap cleanup EXIT
cleanup

echo "=========================================="
echo " BGP-LS UPDATE 报文测试"
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

# 创建配置文件 - ns1 (发送方)
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
 linkstate monitor
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

# 启动抓包 - 先创建文件并设置权限
echo "[START] 启动抓包..."
rm -f /tmp/bgpls_test.pcap 2>/dev/null
touch /tmp/bgpls_test.pcap
chmod 666 /tmp/bgpls_test.pcap
sudo ip netns exec ns1 tcpdump -i veth1 -nn port 179 -w /tmp/bgpls_test.pcap &
TCPDUMP_PID=$!
sleep 1

echo "[START] 启动ns2的bgpd..."
sudo ip netns exec ns2 ./bgpd/.libs/bgpd -f /tmp/ns2_bgpd.conf -i /tmp/ns2_bgpd.pid -z /tmp/ns2_zebra.api 2>&1 | tee /tmp/ns2_bgpd.log &
sleep 2

echo "[START] 启动ns1的bgpd..."
sudo ip netns exec ns1 ./bgpd/.libs/bgpd -f /tmp/ns1_bgpd.conf -i /tmp/ns1_bgpd.pid -z /tmp/ns1_zebra.api 2>&1 | tee /tmp/ns1_bgpd.log &
sleep 3

# 检查UDP端口是否监听
echo "[CHECK] 检查UDP端口9999..."
sudo ip netns exec ns1 ss -uln | grep 9999 || echo "  端口未监听"

echo "[WAIT] 等待BGP会话建立..."
for i in {1..20}; do
    if grep -q "Established" /tmp/ns1_bgpd.log 2>/dev/null; then
        echo "[SUCCESS] BGP会话已建立!"
        break
    fi
    echo "  等待中... ($i/20)"
    sleep 1
done

# 检查BGP状态
echo ""
echo "[STATUS] BGP邻居状态 (从ns1日志):"
grep -E "neighbor.*state|Established|NOTIFICATION" /tmp/ns1_bgpd.log 2>/dev/null | tail -5 || echo "  (无状态信息)"

echo ""
echo "[STATUS] 检查UDP服务器是否启动:"
grep -i "udp" /tmp/ns1_bgpd.log 2>/dev/null | head -5 || echo "  (无UDP信息)"

# 发送UDP链路状态数据
echo ""
echo "[TEST] 发送链路状态数据 (ADD)..."
UDP_DATA='{
  "version": "1.0",
  "timestamp": "2026-01-26T20:30:00Z",
  "links": [
    {
      "if_name": "r1-eth0",
      "if_index": 2,
      "nlri": {
        "protocol_id": 5,
        "identifier": 123456,
        "local_node": {"router_id": "192.168.1.1"},
        "remote_node": {"router_id": "192.168.1.2"},
        "link_descriptors": {"local_ipv4": "10.0.0.1", "remote_ipv4": "10.0.0.2"}
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
}'

echo "$UDP_DATA" | sudo ip netns exec ns1 nc -u -w1 127.0.0.1 9999
sleep 2

echo ""
echo "[CHECK] 查看ns1日志中的UDP处理:"
grep -E "UDP|linkstate_update|linkstate_add|BGP-LS" /tmp/ns1_bgpd.log 2>/dev/null | tail -20 || echo "  (无相关日志)"

echo ""
echo "[TEST] 发送链路状态数据 (UPDATE - 修改带宽和metric)..."
UPDATE_DATA='{
  "version": "1.0",
  "timestamp": "2026-01-26T20:30:05Z",
  "links": [
    {
      "if_name": "r1-eth0",
      "if_index": 2,
      "nlri": {
        "protocol_id": 5,
        "identifier": 123456,
        "local_node": {"router_id": "192.168.1.1"},
        "remote_node": {"router_id": "192.168.1.2"},
        "link_descriptors": {"local_ipv4": "10.0.0.1", "remote_ipv4": "10.0.0.2"}
      },
      "attributes": {
        "oper_status": 1,
        "max_bandwidth": 500000000,
        "te_metric": 20,
        "igp_metric": 20,
        "admin_group": 0,
        "unreserved_bw": [500000000, 500000000, 500000000, 500000000, 500000000, 500000000, 500000000, 500000000],
        "spf_sequence_number": 101,
        "spf_status": 0
      }
    }
  ]
}'

echo "$UPDATE_DATA" | sudo ip netns exec ns1 nc -u -w1 127.0.0.1 9999
sleep 2

echo ""
echo "[CHECK] 查看UPDATE相关日志:"
grep -E "UPDATE|linkstate_update|BGP-LS" /tmp/ns1_bgpd.log 2>/dev/null | tail -10 || echo "  (无UPDATE日志)"

echo ""
echo "[TEST] 发送链路状态数据 (DELETE)..."
DELETE_DATA='{
  "version": "1.0",
  "timestamp": "2026-01-26T20:30:10Z",
  "links": [
    {
      "if_name": "r1-eth0",
      "if_index": 2,
      "nlri": {
        "protocol_id": 5,
        "identifier": 123456,
        "local_node": {"router_id": "192.168.1.1"},
        "remote_node": {"router_id": "192.168.1.2"},
        "link_descriptors": {"local_ipv4": "10.0.0.1", "remote_ipv4": "10.0.0.2"}
      },
      "attributes": {
        "oper_status": 0,
        "max_bandwidth": 500000000,
        "te_metric": 20,
        "igp_metric": 20,
        "admin_group": 0,
        "unreserved_bw": [500000000, 500000000, 500000000, 500000000, 500000000, 500000000, 500000000, 500000000],
        "spf_sequence_number": 102,
        "spf_status": 0
      }
    }
  ]
}'

echo "$DELETE_DATA" | sudo ip netns exec ns1 nc -u -w1 127.0.0.1 9999
sleep 2

echo ""
echo "[CHECK] 查看DELETE相关日志:"
grep -E "DELETE|WITHDRAW|linkstate_delete" /tmp/ns1_bgpd.log 2>/dev/null | tail -10 || echo "  (无DELETE日志)"

echo ""
echo "=========================================="
echo " NODE NLRI 测试"
echo "=========================================="

echo ""
echo "[TEST] 发送节点状态数据 (NODE ADD)..."
NODE_ADD_DATA='{
  "version": "1.0",
  "timestamp": "2026-01-26T20:31:00Z",
  "nodes": [
    {
      "node_name": "router1",
      "nlri": {
        "protocol_id": 5,
        "identifier": 123456,
        "router_id": "192.168.1.1",
        "area_id": "0.0.0.0",
        "asn": 65001
      },
      "attributes": {
        "node_flags": 0,
        "node_name": "router1",
        "isis_area_id": "49.0001",
        "sr_capabilities": 1,
        "srgb_base": 16000,
        "srgb_range": 8000,
        "sr_algorithm": 0
      }
    }
  ]
}'

echo "$NODE_ADD_DATA" | sudo ip netns exec ns1 nc -u -w1 127.0.0.1 9999
sleep 2

echo ""
echo "[CHECK] 查看NODE ADD相关日志:"
grep -E "NODE|nodestate|BGP-LS.*[Nn]ode" /tmp/ns1_bgpd.log 2>/dev/null | tail -10 || echo "  (无NODE日志)"

echo ""
echo "[TEST] 发送节点状态数据 (NODE UPDATE)..."
NODE_UPDATE_DATA='{
  "version": "1.0",
  "timestamp": "2026-01-26T20:31:05Z",
  "nodes": [
    {
      "node_name": "router1",
      "nlri": {
        "protocol_id": 5,
        "identifier": 123456,
        "router_id": "192.168.1.1",
        "area_id": "0.0.0.0",
        "asn": 65001
      },
      "attributes": {
        "node_flags": 1,
        "node_name": "router1-updated",
        "isis_area_id": "49.0001",
        "sr_capabilities": 3,
        "srgb_base": 16000,
        "srgb_range": 8000,
        "sr_algorithm": 1
      }
    }
  ]
}'

echo "$NODE_UPDATE_DATA" | sudo ip netns exec ns1 nc -u -w1 127.0.0.1 9999
sleep 2

echo ""
echo "[CHECK] 查看NODE UPDATE相关日志:"
grep -E "NODE|nodestate|BGP-LS.*[Nn]ode" /tmp/ns1_bgpd.log 2>/dev/null | tail -10 || echo "  (无NODE UPDATE日志)"

echo ""
echo "[TEST] 发送节点状态数据 (NODE DELETE)..."
NODE_DELETE_DATA='{
  "version": "1.0",
  "timestamp": "2026-01-26T20:31:10Z",
  "nodes": [
    {
      "node_name": "router1",
      "nlri": {
        "protocol_id": 5,
        "identifier": 123456,
        "router_id": "192.168.1.1",
        "area_id": "0.0.0.0",
        "asn": 65001
      },
      "attributes": {
        "node_flags": 0,
        "node_name": "router1",
        "isis_area_id": "49.0001",
        "sr_capabilities": 0,
        "srgb_base": 0,
        "srgb_range": 0,
        "sr_algorithm": 0,
        "oper_status": 0
      }
    }
  ]
}'

echo "$NODE_DELETE_DATA" | sudo ip netns exec ns1 nc -u -w1 127.0.0.1 9999
sleep 2

echo ""
echo "[CHECK] 查看NODE DELETE相关日志:"
grep -E "NODE|nodestate_delete|WITHDRAW.*[Nn]ode" /tmp/ns1_bgpd.log 2>/dev/null | tail -10 || echo "  (无NODE DELETE日志)"

# 停止抓包
sleep 1
sudo kill $TCPDUMP_PID 2>/dev/null || true
sleep 1

echo ""
echo "=========================================="
echo " 分析抓包结果"
echo "=========================================="

if [ -f /tmp/bgpls_test.pcap ]; then
    echo ""
    echo "[PCAP] BGP报文列表:"
    tshark -r /tmp/bgpls_test.pcap -Y "bgp" 2>/dev/null || echo "  (无法解析)"
    
    echo ""
    echo "[PCAP] BGP UPDATE报文详情:"
    tshark -r /tmp/bgpls_test.pcap -Y "bgp.type == 2" -V 2>/dev/null | head -100 || echo "  (无UPDATE报文)"
    
    echo ""
    echo "[PCAP] 报文类型统计:"
    tshark -r /tmp/bgpls_test.pcap -Y "bgp" -T fields -e bgp.type 2>/dev/null | sort | uniq -c || true
else
    echo "[ERROR] 抓包文件不存在"
fi

echo ""
echo "=========================================="
echo " 完整日志"
echo "=========================================="
echo ""
echo "=== NS1 (发送方) 日志 ==="
cat /tmp/ns1_bgpd.log 2>/dev/null | tail -50

echo ""
echo "=== NS2 (接收方) 日志 ==="
cat /tmp/ns2_bgpd.log 2>/dev/null | tail -30

echo ""
echo "[DONE] 测试完成"
