## 1. 网络配置

```bash

sudo ip netns add test_spf
sudo ip netns add test_env

# 创建veth对连接两个namespace
sudo ip link add veth-spf type veth peer name veth-env
sudo ip link set veth-spf netns test_spf
sudo ip link set veth-env netns test_env

# 配置IP地址
sudo ip netns exec test_spf ip addr add 10.0.0.1/24 dev veth-spf
sudo ip netns exec test_env ip addr add 10.0.0.2/24 dev veth-env
sudo ip netns exec test_spf ip link set veth-spf up
sudo ip netns exec test_env ip link set veth-env up
sudo ip netns exec test_spf ip link set lo up
sudo ip netns exec test_env ip link set lo up
```

## 2. 创建BGP配置文件

**test_spf配置（发送方）：**

```bash
cat > /tmp/bgp_spf.conf << 'EOF'
hostname test-spf
log file /tmp/bgp_spf.log debugging
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
```

**test_env配置（接收方）：**

```bash
cat > /tmp/bgp_env.conf << 'EOF'
hostname test-env
log file /tmp/bgp_env.log debugging
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
```

## 3. 创建三个node文件，在`test_spf` 这个空间里，运行一个 UDP 客户端，把这三个文件的内容，发送到“该命名空间里本机的 127.0.0.1:9999”

**1：（ADD）**

```bash
cat > /tmp/node_add.json << 'EOF'
{
  "nodes": [
    {
      "node_name": "R1",
      "nlri": {
        "protocol_id": 5,
        "identifier": 1001,
        "local_node_descriptors": {
          "asn": 65001,
          "bgpls_id": 1,
          "ospf_area_id": 0,
          "router_id": "10.0.0.1"
        }
      },
      "attributes": {
        "node_flags": 192,
        "te_router_id": "10.0.0.1",
        "sr_capabilities": {
          "flags": 128,
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
```

**2：（UPDATE）**

```bash
cat > /tmp/node_update.json << 'EOF'
{
  "nodes": [
    {
      "node_name": "R1",
      "nlri": {
        "protocol_id": 5,
        "identifier": 1001,
        "local_node_descriptors": {
          "asn": 65001,
          "bgpls_id": 1,
          "ospf_area_id": 0,
          "router_id": "10.0.0.1"
        }
      },
      "attributes": {
        "node_flags": 192,
        "te_router_id": "10.0.0.1",
        "sr_capabilities": {
          "flags": 128,
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
    }
  ]
}
EOF

```

**3：（DELETE）**

```bash
cat > /tmp/node_delete.json << 'EOF'
{
  "nodes": [
    {
      "node_name": "R1",
      "nlri": {
        "protocol_id": 5,
        "identifier": 1001,
        "local_node_descriptors": {
          "asn": 65001,
          "bgpls_id": 1,
          "ospf_area_id": 0,
          "router_id": "10.0.0.1"
        }
      },
      "attributes": {
        "oper_status": 0
      }
    }
  ]
}
EOF
```

## 4.开三个终端

```bash
第一个：在 test_spf 这个网络命名空间里启动 FRR 的 BGP 守护进程 bgpd，并指定配置文件和 PID 文件。
sudo ip netns exec test_spf /home/bgp/FRR-main/bgpd/.libs/bgpd     -f /tmp/bgp_spf.conf     -i /tmp/bgp_spf.pid 

第二个：
sudo ip netns exec test_env /home/bgp/FRR-main/bgpd/.libs/bgpd     -f /tmp/bgp_env.conf     -i /tmp/bgp_env.pid

第三个：
sudo apt-get install -y netcat-openbsd
sudo ip netns exec test_spf nc -u -w1 127.0.0.1 9999 < /tmp/node_add.json
sudo ip netns exec test_spf nc -u -w1 127.0.0.1 9999 < /tmp/node_update.json
sudo ip netns exec test_spf nc -u -w1 127.0.0.1 9999 < /tmp/node_delete.json
```
