// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Link-State header
 * Copyright 2023 6WIND S.A.
 */

#ifndef _FRR_BGP_LINKSTATE_H
#define _FRR_BGP_LINKSTATE_H

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