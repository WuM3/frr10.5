#!/bin/bash
# UDP服务器测试脚本 - 验证完整流程并抓包
# 流程: UDP JSON → bgpd → BGP UPDATE报文

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BGPD="${SCRIPT_DIR}/.libs/bgpd"
PCAP_FILE="/tmp/udp_bgpls_test.pcap"
LOG_FILE="/tmp/udp_test.log"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $1"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] WARN:${NC} $1"; }
err() { echo -e "${RED}[$(date +%H:%M:%S)] ERROR:${NC} $1"; }

cleanup() {
    log "清理进程..."
    sudo pkill -9 -f "bgpd.*router[12]" 2>/dev/null || true
    sudo pkill tcpdump 2>/dev/null || true
    sudo rm -f /tmp/router*.pid 2>/dev/null || true
    sleep 1
}

trap cleanup EXIT

# 创建配置文件
create_configs() {
    log "创建BGP配置文件..."
    
    # Router1 - 带UDP服务器
    cat > /tmp/router1_udp.conf << 'EOF'
hostname router1
log stdout
router bgp 65001
  bgp router-id 1.1.1.1
  neighbor 127.0.0.1 remote-as 65002
  neighbor 127.0.0.1 port 1790
  address-family ipv4 linkstate
    neighbor 127.0.0.1 activate
  exit-address-family
  linkstate udp-server
EOF

    # Router2 - 监听1790端口
    cat > /tmp/router2_udp.conf << 'EOF'
hostname router2
log stdout
router bgp 65002
  bgp router-id 2.2.2.2
  bgp listen-port 1790
  neighbor 127.0.0.1 remote-as 65001
  address-family ipv4 linkstate
    neighbor 127.0.0.1 activate
  exit-address-family
EOF
}

# 启动BGP进程
start_bgpd() {
    log "启动Router2 (监听端口1790)..."
    sudo $BGPD -f /tmp/router2_udp.conf -i /tmp/router2.pid -Z router2 2>&1 | \
        sed 's/^/[R2] /' >> $LOG_FILE &
    sleep 2
    
    log "启动Router1 (带UDP服务器)..."
    sudo $BGPD -f /tmp/router1_udp.conf -i /tmp/router1.pid -Z router1 2>&1 | \
        sed 's/^/[R1] /' >> $LOG_FILE &
    sleep 3
    
    # 检查进程
    if pgrep -f "bgpd.*router1" > /dev/null && pgrep -f "bgpd.*router2" > /dev/null; then
        log "✓ 两个BGP进程都已启动"
    else
        err "BGP进程启动失败"
        return 1
    fi
    
    # 检查UDP端口
    if ss -ulnp 2>/dev/null | grep -q ":9999"; then
        log "✓ UDP服务器正在监听9999端口"
    else
        err "UDP服务器未启动"
        return 1
    fi
}

# 等待BGP会话建立
wait_for_session() {
    log "等待BGP会话建立..."
    for i in {1..30}; do
        if ss -tnp 2>/dev/null | grep -q ":1790.*ESTAB"; then
            log "✓ BGP会话已建立"
            return 0
        fi
        sleep 1
    done
    warn "BGP会话未建立，继续测试..."
    return 0
}

# 发送UDP测试数据
send_udp_data() {
    log "发送UDP链路状态数据..."
    
    # 创建测试JSON
    cat > /tmp/udp_test_add.json << 'EOF'
{
  "if_name": "eth0",
  "if_index": 2,
  "nlri": {
    "local_node": {"router_id": "1.1.1.1"},
    "remote_node": {"router_id": "2.2.2.2"},
    "link_descriptors": {
      "local_ipv4": "10.0.0.1",
      "remote_ipv4": "10.0.0.2"
    }
  },
  "attributes": {
    "oper_status": 1,
    "max_bandwidth": 1000000000,
    "igp_metric": 10
  }
}
EOF

    cat > /tmp/udp_test_delete.json << 'EOF'
{
  "if_name": "eth0",
  "nlri": {
    "local_node": {"router_id": "1.1.1.1"},
    "remote_node": {"router_id": "2.2.2.2"}
  },
  "attributes": {
    "oper_status": 0
  }
}
EOF

    log "发送ADD请求..."
    cat /tmp/udp_test_add.json | nc -u -w1 localhost 9999
    sleep 3
    
    log "发送DELETE请求..."
    cat /tmp/udp_test_delete.json | nc -u -w1 localhost 9999
    sleep 2
}

# 主函数
main() {
    log "=========================================="
    log "UDP服务器 → BGP UPDATE 完整测试"
    log "=========================================="
    
    cleanup
    > $LOG_FILE
    
    create_configs
    start_bgpd || exit 1
    wait_for_session
    
    # 启动抓包
    log "启动抓包 (BGP端口179/1790 + UDP端口9999)..."
    sudo tcpdump -i lo -nn -s0 'tcp port 179 or tcp port 1790 or udp port 9999' \
        -w $PCAP_FILE 2>/dev/null &
    TCPDUMP_PID=$!
    sleep 2
    
    send_udp_data
    
    # 停止抓包
    sleep 2
    sudo kill -2 $TCPDUMP_PID 2>/dev/null || true
    sleep 1
    
    log "=========================================="
    log "分析抓包结果"
    log "=========================================="
    
    if [ -f "$PCAP_FILE" ]; then
        log "UDP数据包:"
        sudo tshark -r $PCAP_FILE -Y "udp.port==9999" 2>/dev/null || \
            sudo tcpdump -r $PCAP_FILE -nn 'udp port 9999' 2>/dev/null | head -5
        
        echo ""
        log "BGP UPDATE报文:"
        sudo tshark -r $PCAP_FILE -Y "bgp.type==2" -V 2>/dev/null | head -100 || \
            sudo tcpdump -r $PCAP_FILE -nn -A 'tcp port 179 or tcp port 1790' 2>/dev/null | head -50
        
        echo ""
        log "抓包文件: $PCAP_FILE"
        log "使用 Wireshark 打开查看详情: wireshark $PCAP_FILE"
    fi
    
    log "=========================================="
    log "bgpd日志 (UDP相关):"
    grep -E "UDP|DEBUG|eth0|linkstate" $LOG_FILE 2>/dev/null | tail -20 || true
    
    log "测试完成!"
}

main "$@"
