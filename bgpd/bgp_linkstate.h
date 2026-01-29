// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Link-State header
 * Copyright 2023 6WIND S.A.
 */

#ifndef _FRR_BGP_LINKSTATE_H
#define _FRR_BGP_LINKSTATE_H

/* ========================================================================
 * NLRI Type definitions (RFC 7752)
 * ======================================================================== */
#define BGPLS_NLRI_TYPE_NODE   1   /* Node NLRI */
#define BGPLS_NLRI_TYPE_LINK   2   /* Link NLRI */
#define BGPLS_NLRI_TYPE_PREFIX_V4  3   /* IPv4 Prefix NLRI */
#define BGPLS_NLRI_TYPE_PREFIX_V6  4   /* IPv6 Prefix NLRI */

/* Protocol ID definitions (RFC 7752 Table 2) */
#define BGPLS_PROTOCOL_ISIS_L1     1
#define BGPLS_PROTOCOL_ISIS_L2     2
#define BGPLS_PROTOCOL_OSPF_V2     3
#define BGPLS_PROTOCOL_DIRECT      4
#define BGPLS_PROTOCOL_STATIC      5
#define BGPLS_PROTOCOL_OSPF_V3     6

/* ========================================================================
 * Node State Information Structure (RFC 7752 Section 3.3.1 + RFC 9085)
 * ======================================================================== */

/**
 * 节点状态信息结构体
 * 
 * Node NLRI 格式 (RFC 7752 Figure 7):
 *   - Protocol-ID (1 byte)
 *   - Identifier (8 bytes)
 *   - Local Node Descriptors (variable)
 * 
 * Node Attributes (RFC 7752 Table 7 + RFC 9085 Section 2.1):
 *   - Node Flag Bits (TLV 1024)
 *   - Node Name (TLV 1026)
 *   - IS-IS Area Identifier (TLV 1027)
 *   - IPv4 Router-ID (TLV 1028)
 *   - IPv6 Router-ID (TLV 1029)
 *   - SR Capabilities (TLV 1034) - RFC 9085
 *   - SR Algorithm (TLV 1035) - RFC 9085
 *   - SR Local Block (TLV 1036) - RFC 9085
 *   - SRMS Preference (TLV 1037) - RFC 9085
 */
struct nodestate_info {
	char node_name[256];           /* 节点名称 (TLV 1026, max 255 bytes + null) */
	
	/* Node Descriptors (RFC 7752 Section 3.2.1.4) */
	uint32_t asn;                  /* Autonomous System Number (Sub-TLV 512) */
	uint32_t bgpls_id;             /* BGP-LS Identifier (Sub-TLV 513) */
	uint32_t ospf_area_id;         /* OSPF Area-ID (Sub-TLV 514) */
	struct in_addr router_id;      /* IGP Router-ID IPv4 (Sub-TLV 515) */
	struct in6_addr router_id_v6;  /* IGP Router-ID IPv6 (Sub-TLV 515 for IS-IS) */
	uint8_t iso_node_id[7];        /* IS-IS ISO System-ID (6 bytes) + PSN (1 byte) */
	uint8_t iso_node_id_len;       /* ISO Node-ID length (6 or 7) */
	
	/* Protocol and Instance */
	uint8_t protocol_id;           /* Protocol ID (1-6, see Table 2) */
	uint64_t identifier;           /* Instance Identifier (64-bit) */
	
	/* Node Flag Bits (TLV 1024, RFC 7752 Section 3.3.1.1) */
	uint8_t node_flags;
#define NODE_FLAG_OVERLOAD  0x80   /* O-bit: Overload */
#define NODE_FLAG_ATTACHED  0x40   /* T-bit: Attached */
#define NODE_FLAG_EXTERNAL  0x20   /* E-bit: External (OSPF AS-external) */
#define NODE_FLAG_ABR       0x10   /* B-bit: ABR */
#define NODE_FLAG_ROUTER    0x08   /* R-bit: Router (OSPFv3) */
#define NODE_FLAG_V6        0x04   /* V-bit: V6 capable (OSPFv3) */
	
	/* IS-IS Area Identifiers (TLV 1027) */
	uint8_t isis_area_id[13];      /* IS-IS Area Address (max 13 bytes) */
	uint8_t isis_area_id_len;      /* IS-IS Area Address length */
	
	/* IPv4/IPv6 Router-IDs for TE (TLV 1028, 1029) */
	struct in_addr te_router_id;   /* IPv4 Router-ID of Local Node (TLV 1028) */
	struct in6_addr te_router_id_v6; /* IPv6 Router-ID of Local Node (TLV 1029) */
	
	/* SR Capabilities (RFC 9085 TLV 1034) */
	uint8_t sr_capability_flags;   /* SR Capability Flags */
#define SR_CAP_FLAG_IPV4    0x80   /* I-flag: IPv4 MPLS forwarding */
#define SR_CAP_FLAG_IPV6    0x40   /* V-flag: IPv6 MPLS forwarding */
	uint32_t srgb_base;            /* SRGB Base Label */
	uint32_t srgb_range;           /* SRGB Range Size */
	
	/* SR Algorithm (RFC 9085 TLV 1035) */
	uint8_t sr_algorithms[8];      /* Supported SR Algorithms (max 8) */
	uint8_t sr_algorithm_count;    /* Number of algorithms */
#define SR_ALGO_SPF         0      /* Shortest Path First */
#define SR_ALGO_STRICT_SPF  1      /* Strict Shortest Path First */
	
	/* SR Local Block (RFC 9085 TLV 1036) */
	uint32_t srlb_base;            /* SRLB Base Label */
	uint32_t srlb_range;           /* SRLB Range Size */
	
	/* SRMS Preference (RFC 9085 TLV 1037) */
	uint8_t srms_preference;       /* SRMS Preference value */
	
	/* Node operational status (similar to link's oper_status) */
	uint8_t oper_status;           /* 操作状态: UP=1, DOWN=0 */
	
	/* 时间戳 */
	time_t last_update;            /* 最后更新时间 */
};

/* ========================================================================
 * Link State Information Structure (existing)
 * ======================================================================== */

/* 链路状态信息结构 */
struct linkstate_info {
	char if_name[32];              /* 接口名称 */
	uint32_t if_index;             /* 接口索引 */
	//safi_t safi;
	
	/* 状态信息 */
	uint8_t oper_status;           /* 操作状态: UP=1, DOWN=0 */
	uint8_t admin_status;          /* 管理状态 */
	
	/* 带宽信息 (单位: bps) */
	uint32_t max_bandwidth;        /* 最大带宽 */
	uint32_t max_reservable_bw;    /* 最大可预留带宽 */
	uint32_t unreserved_bw[8];     /* 未预留带宽(8个优先级) */
	
	/* 度量值 */
	uint32_t te_metric;            /* TE度量值 */
	uint32_t igp_metric;           /* IGP度量值 */
	
	/* 地址信息 */
	struct in_addr local_addr;     /* 本地IP地址 */
	struct in_addr remote_addr;    /* 对端IP地址 */
	
	/* 其他属性 */
	uint32_t admin_group;          /* 管理组 */
	struct in_addr router_id;      /* 本地路由器ID */
	struct in_addr remote_router_id; /* 对端路由器ID */
	
	/* RFC 9815 BGP-LS SPF扩展字段 */
	uint64_t spf_sequence_number;  /* SPF序列号 (TLV 1181) - 用于标识SPF计算版本 */
	uint8_t spf_status;            /* SPF状态标志 (TLV 1184) - Bit 0: S-bit (0=在SPF树中, 1=不在SPF树中) */
	
	time_t last_update;            /* 最后更新时间 */
};

void bgp_linkstate_init(void);

/* 定时器读取链路状态函数 */
extern void bgp_linkstate_poll_start(struct bgp *bgp);
extern void bgp_linkstate_poll_stop(struct bgp *bgp);
extern void bgp_linkstate_set_poll_interval(struct bgp *bgp, uint32_t interval);

/* UDP服务器函数 */
extern int bgp_linkstate_udp_server_start(struct bgp *bgp, uint16_t port);
extern void bgp_linkstate_udp_server_stop(void);

/* 哈希表管理函数 */
extern void bgp_linkstate_if_map_init(struct bgp *bgp);
extern void bgp_linkstate_if_map_finish(struct bgp *bgp);

#endif /* _FRR_BGP_LINKSTATE_H */

/**
 * 添加链路状态信息到BGP-LS RIB
 * 
 * @param bgp       - BGP实例
 * @param ls_info   - 链路状态信息
 * @param safi      - SAFI类型 (SAFI_LINKSTATE或SAFI_BGPLS_SPF)
 * @return 0 成功，-1 失败
 */
int linkstate_add(struct bgp *bgp, struct linkstate_info *ls_info, safi_t safi);

/**
 * 更新链路状态信息
 * 
 * @param bgp       - BGP实例
 * @param ls_info   - 新的链路状态信息
 * @param safi      - SAFI类型 (SAFI_LINKSTATE或SAFI_BGPLS_SPF)
 * @return 0 成功，-1 失败
 */
int linkstate_update(struct bgp *bgp, struct linkstate_info *ls_info, safi_t safi);

/**
 * 删除链路状态信息
 * 
 * @param bgp       - BGP实例
 * @param if_name   - 接口名
 * @param safi      - SAFI类型 (SAFI_LINKSTATE或SAFI_BGPLS_SPF)
 * @return 0 成功，-1 失败
 */
int linkstate_delete(struct bgp *bgp, const char *if_name, safi_t safi);

/* ========================================================================
 * Node State Functions
 * ======================================================================== */

/**
 * 添加节点状态信息到BGP-LS RIB
 * 
 * @param bgp       - BGP实例
 * @param ns_info   - 节点状态信息
 * @param safi      - SAFI类型 (SAFI_LINKSTATE或SAFI_BGPLS_SPF)
 * @return 0 成功，-1 失败
 */
int nodestate_add(struct bgp *bgp, struct nodestate_info *ns_info, safi_t safi);

/**
 * 更新节点状态信息
 * 
 * @param bgp       - BGP实例
 * @param ns_info   - 新的节点状态信息
 * @param safi      - SAFI类型 (SAFI_LINKSTATE或SAFI_BGPLS_SPF)
 * @return 0 成功，-1 失败
 */
int nodestate_update(struct bgp *bgp, struct nodestate_info *ns_info, safi_t safi);

/**
 * 删除节点状态信息
 * 
 * @param bgp       - BGP实例
 * @param node_name - 节点名称 (用作查找键)
 * @param safi      - SAFI类型 (SAFI_LINKSTATE或SAFI_BGPLS_SPF)
 * @return 0 成功，-1 失败
 */
int nodestate_delete(struct bgp *bgp, const char *node_name, safi_t safi);

/* 节点哈希表管理 */
extern void bgp_nodestate_map_init(struct bgp *bgp);
extern void bgp_nodestate_map_finish(struct bgp *bgp);