// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Link-State
 * Copyright 2023 6WIND S.A.
 */

#include <zebra.h>

#include "prefix.h"
#include "lib_errors.h"
#include "frrevent.h"
#include "log.h"
#include "memory.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_linkstate.h"
#include "bgpd/bgp_linkstate_tlv.h"
#include "bgpd/bgp_attr.h"
#include "hash.h"

/* 内存类型：必须与 lib/prefix.c 中的定义完全一致
 * MTYPE 系统通过描述字符串匹配，确保分配和释放使用同一个类型
 */
DEFINE_MTYPE(LIB, PREFIX_LINKSTATE, "Prefix Link-State");

/* 临时禁用本文件的日志，避免 NSS 相关崩溃 */
#undef zlog_debug
#undef zlog_info
#undef zlog_warn
#undef zlog_err
#define zlog_debug(...) do { } while (0)
#define zlog_info(...) do { } while (0)
#define zlog_warn(...) do { } while (0)
#define zlog_err(...) do { } while (0)

/* 默认轮询间隔（秒） */
#define DEFAULT_LINKSTATE_POLL_INTERVAL 30

/* 链路状态信息包装器（用于哈希表存储 if_name → linkstate_info 映射）
 * 不能保存prefix，因为prefix中的ptr在dest释放后会失效
 * 正确的做法是保存linkstate_info，在DELETE时重新构建prefix */
struct linkstate_prefix_wrapper {
	char if_name[IFNAMSIZ];        /* 接口名（作为哈希键）*/
	struct linkstate_info ls_info; /* Link-State信息副本，用于DELETE时重建prefix */
	struct bgp_dest *dest;         /* RIB节点指针（用于快速update/delete查找）*/
};

/* 内存类型定义
 * 注意：BGP_ATTR_LS 和 BGP_ATTR_LS_DATA 已在 bgp_attr.c 中定义，
 * 这里使用 DECLARE_MTYPE 引用它们，避免重复定义导致的 UAF
 */
DEFINE_MTYPE_STATIC(BGPD, BGP_LINKSTATE_WRAPPER, "BGP LinkState Wrapper");
DECLARE_MTYPE(BGP_ATTR_LS);
DECLARE_MTYPE(BGP_ATTR_LS_DATA);
DEFINE_MTYPE_STATIC(BGPD, BGP_LINKSTATE_NLRI, "BGP LinkState NLRI");

/* 前向声明 */
static int build_bgpls_link_nlri(struct prefix *p, struct linkstate_info *ls_info);

/* ========================================================================
 * Link Attribute TLV编码辅助函数
 * ======================================================================== */

/**
 * IEEE 754浮点数转换：将uint32转换为float
 */
static inline float uint32_to_float(uint32_t u)
{
	union {
		float f;
		uint32_t u;
	} conv;
	conv.u = u;
	return conv.f;
}

/**
 * IEEE 754浮点数转换：将float转换为网络字节序uint32
 */
static inline uint32_t float_to_uint32_hton(float f)
{
	union {
		float f;
		uint32_t u;
	} conv;
	conv.f = f;
	return htonl(conv.u);
}

/**
 * 编码16位TLV头（Type + Length）
 */
static inline void put_tlv_header_u16(uint8_t *buf, uint16_t type, uint16_t length)
{
	*(uint16_t *)buf = htons(type);
	*(uint16_t *)(buf + 2) = htons(length);
}

/**
 * 编码32位整数TLV
 */
static size_t encode_tlv_uint32(uint8_t *buf, uint16_t type, uint32_t value)
{
	put_tlv_header_u16(buf, type, 4);
	*(uint32_t *)(buf + 4) = htonl(value);
	return 8;  // 4字节头 + 4字节值
}

/**
 * 编码带宽TLV (IEEE 754 float)
 * @param bw_bps 带宽，单位: bits per second
 */
static size_t encode_tlv_bandwidth(uint8_t *buf, uint16_t type, uint32_t bw_bps)
{
	put_tlv_header_u16(buf, type, 4);
	/* RFC 3630: 带宽单位是 bytes/sec (IEEE 754) */
	float bw_bytes_per_sec = (float)bw_bps / 8.0;
	*(uint32_t *)(buf + 4) = float_to_uint32_hton(bw_bytes_per_sec);
	return 8;
}

/**
 * 编码未预留带宽TLV (8个优先级，共32字节)
 * @param bw_array 8个优先级的带宽，单位: bits per second
 */
static size_t encode_tlv_unreserved_bw(uint8_t *buf, uint16_t type, uint32_t *bw_array)
{
	put_tlv_header_u16(buf, type, 32);
	for (int i = 0; i < 8; i++) {
		/* RFC 3630: 带宽单位是 bytes/sec (IEEE 754) */
		float bw_bytes_per_sec = (float)bw_array[i] / 8.0;
		*(uint32_t *)(buf + 4 + i * 4) = float_to_uint32_hton(bw_bytes_per_sec);
	}
	return 36;  // 4字节头 + 32字节值
}

/**
 * 编码IGP Metric TLV (variable length 1-3 bytes)
 */
static size_t encode_tlv_igp_metric(uint8_t *buf, uint16_t type, uint32_t metric)
{
	uint16_t len;
	if (metric <= 0xFF) {
		len = 1;
		put_tlv_header_u16(buf, type, len);
		buf[4] = (uint8_t)metric;
	} else if (metric <= 0xFFFF) {
		len = 2;
		put_tlv_header_u16(buf, type, len);
		*(uint16_t *)(buf + 4) = htons((uint16_t)metric);
	} else {
		len = 3;
		put_tlv_header_u16(buf, type, len);
		buf[4] = (metric >> 16) & 0xFF;
		*(uint16_t *)(buf + 5) = htons((uint16_t)(metric & 0xFFFF));
	}
	return 4 + len;
}

/**
 * 编码RFC 9815 SPF Sequence Number TLV (TLV 1181)
 */
static size_t encode_tlv_spf_sequence(uint8_t *buf, uint64_t sequence)
{
	put_tlv_header_u16(buf, BGP_LS_SPF_TLV_Sequence_Number, 8);
	*(uint32_t *)(buf + 4) = htonl((uint32_t)(sequence >> 32));
	*(uint32_t *)(buf + 8) = htonl((uint32_t)(sequence & 0xFFFFFFFF));
	return 12;  // 4字节头 + 8字节值
}

/**
 * 编码RFC 9815 SPF Status TLV (TLV 1184)
 */
static size_t encode_tlv_spf_status(uint8_t *buf, uint8_t status)
{
	put_tlv_header_u16(buf, BGP_LS_SPF_TLV_SPF_Status, 1);
	buf[4] = status;
	return 5;  // 4字节头 + 1字节值
}

/**
 * 构造Link Attribute TLVs并存入attr->link_state
 * 
 * @param attr        要填充的BGP属性
 * @param ls_info     链路状态信息源
 * @param safi        SAFI类型（SAFI_LINKSTATE或SAFI_BGPLS_SPF）
 * @return 0 成功, -1 失败
 */
static int encode_link_attributes(struct attr *attr, struct linkstate_info *ls_info, safi_t safi)
{
	uint8_t *tlv_buf;
	size_t offset = 0;
	size_t buf_size = 512;  // 预分配足够空间
	struct bgp_attr_ls *attr_ls;
	
	if (!attr || !ls_info) {
		return -1;
	}
	
	/* 分配TLV缓冲区 */
	tlv_buf = XCALLOC(MTYPE_BGP_ATTR_LS_DATA, buf_size);
	if (!tlv_buf) {
		zlog_err("%s: Failed to allocate TLV buffer", __func__);
		return -1;
	}
	
	/* ====================================================================
	 * RFC 7752 标准Link Attribute TLVs
	 * ==================================================================== */
	
	/* TLV 1088: Administrative Group (4 bytes) */
	if (ls_info->admin_group != 0) {
		offset += encode_tlv_uint32(tlv_buf + offset, 
		                            BGP_LS_TLV_ADMINISTRATIVE_GROUP,
		                            ls_info->admin_group);
	}
	
	/* TLV 1089: Maximum Link Bandwidth (IEEE 754, 4 bytes) */
	if (ls_info->max_bandwidth != 0) {
		offset += encode_tlv_bandwidth(tlv_buf + offset,
		                               BGP_LS_TLV_MAXIMUM_LINK_BANDWIDTH,
		                               ls_info->max_bandwidth);
	}
	
	/* TLV 1090: Maximum Reservable Bandwidth (IEEE 754, 4 bytes) */
	if (ls_info->max_reservable_bw != 0) {
		offset += encode_tlv_bandwidth(tlv_buf + offset,
		                               BGP_LS_TLV_MAX_RESERVABLE_LINK_BANDWIDTH,
		                               ls_info->max_reservable_bw);
	}
	
	/* TLV 1091: Unreserved Bandwidth (8×IEEE 754, 32 bytes) */
	bool has_unreserved = false;
	for (int i = 0; i < 8; i++) {
		if (ls_info->unreserved_bw[i] != 0) {
			has_unreserved = true;
			break;
		}
	}
	if (has_unreserved) {
		offset += encode_tlv_unreserved_bw(tlv_buf + offset,
		                                   BGP_LS_TLV_UNRESERVED_BANDWIDTH,
		                                   ls_info->unreserved_bw);
	}
	
	/* TLV 1092: TE Default Metric (4 bytes) */
	if (ls_info->te_metric != 0) {
		offset += encode_tlv_uint32(tlv_buf + offset,
		                            BGP_LS_TLV_TE_DEFAULT_METRIC,
		                            ls_info->te_metric);
	}
	
	/* TLV 1095: IGP Metric (variable, 1-3 bytes) */
	if (ls_info->igp_metric != 0) {
		offset += encode_tlv_igp_metric(tlv_buf + offset,
		                                BGP_LS_TLV_IGP_METRIC,
		                                ls_info->igp_metric);
	}
	
	/* ====================================================================
	 * RFC 9815 BGP-LS SPF扩展TLVs
	 * ==================================================================== */
	
	if (safi == SAFI_BGPLS_SPF) {
		/* TLV 1181: SPF Sequence Number (8 bytes) - 必须 */
		if (ls_info->spf_sequence_number != 0) {
			offset += encode_tlv_spf_sequence(tlv_buf + offset,
			                                  ls_info->spf_sequence_number);
		}
		
		/* TLV 1184: SPF Status (1 byte) - 必须 */
		/* Status bits:
		 * Bit 0: S-bit (SPF Status)
		 *   0 = Link is in SPF tree
		 *   1 = Link is NOT in SPF tree
		 */
		offset += encode_tlv_spf_status(tlv_buf + offset,
		                                ls_info->spf_status);
		
		zlog_debug("%s: Encoded SPF TLVs (seq=%lu, status=0x%02x)",
		          __func__, 
		          (unsigned long)ls_info->spf_sequence_number,
		          ls_info->spf_status);
	}
	
	/* 没有任何TLV时返回错误 */
	if (offset == 0) {
		XFREE(MTYPE_BGP_ATTR_LS_DATA, tlv_buf);
		zlog_warn("encode_link_attributes: No TLVs encoded for link");
		return -1;
	}
	
	/* 分配并填充bgp_attr_ls结构 */
	attr_ls = XCALLOC(MTYPE_BGP_ATTR_LS, sizeof(struct bgp_attr_ls));
	if (!attr_ls) {
		XFREE(MTYPE_BGP_ATTR_LS_DATA, tlv_buf);
		zlog_err("%s: Failed to allocate attr_ls", __func__);
		return -1;
	}
	
	attr_ls->length = offset;
	attr_ls->data = tlv_buf;
	attr_ls->refcnt = 0;  // 将由bgp_attr_intern设置
	
	/* 存入attr */
	attr->link_state = attr_ls;
	
	zlog_debug("encode_link_attributes: Encoded TLV data successfully");
	
	return 0;
}

/* 哈希表操作函数 */

/* 计算哈希值（基于接口名）*/
static unsigned int linkstate_if_map_hash_key(const void *data)
{
	const struct linkstate_prefix_wrapper *wrapper = data;
	return string_hash_make(wrapper->if_name);
}

/* 比较两个接口名是否相等 */
static bool linkstate_if_map_cmp(const void *d1, const void *d2)
{
	const struct linkstate_prefix_wrapper *w1 = d1;
	const struct linkstate_prefix_wrapper *w2 = d2;
	return (strcmp(w1->if_name, w2->if_name) == 0);
}

/* 哈希表分配函数 */
static void *linkstate_if_map_alloc(void *data)
{
	struct linkstate_prefix_wrapper *wrapper_in = data;
	struct linkstate_prefix_wrapper *wrapper_out;
	
	wrapper_out = XCALLOC(MTYPE_BGP_LINKSTATE_WRAPPER,
	                      sizeof(struct linkstate_prefix_wrapper));
	strncpy(wrapper_out->if_name, wrapper_in->if_name, sizeof(wrapper_out->if_name) - 1);
	memcpy(&wrapper_out->ls_info, &wrapper_in->ls_info, sizeof(wrapper_out->ls_info));
	
	return wrapper_out;
}

/* 初始化哈希表 */
void bgp_linkstate_if_map_init(struct bgp *bgp)
{
	if (!bgp->linkstate_if_map) {
		bgp->linkstate_if_map = hash_create(linkstate_if_map_hash_key,
		                                    linkstate_if_map_cmp,
		                                    "BGP LinkState IF Map");
		zlog_info("%s: Initialized linkstate interface map", __func__);
	}
}

/* 哈希清理回调函数 */
static void linkstate_prefix_free(void *data)
{
	if (data)
		XFREE(MTYPE_BGP_LINKSTATE_WRAPPER, data);
}

/* 清理哈希表 */
void bgp_linkstate_if_map_finish(struct bgp *bgp)
{
	if (bgp->linkstate_if_map) {
		hash_clean(bgp->linkstate_if_map, linkstate_prefix_free);
		hash_free(bgp->linkstate_if_map);
		bgp->linkstate_if_map = NULL;
		zlog_info("%s: Cleaned up linkstate interface map", __func__);
	}
}


/**
 * 构造BGP-LS Link NLRI
 * @param p        输出的prefix结构
 * @param ls_info  链路状态信息
 * @return 0 成功, -1 失败
 * 
 * 关键修复：现在在构造时预编码 NLRI 到缓冲区，这样 WITHDRAW 编码时
 * 不需要访问 ls_data（可能已被释放）。
 */
static int build_bgpls_link_nlri(struct prefix *p, struct linkstate_info *ls_info)
{
    uint8_t *buf;
    size_t offset = 0;
    
    if (!p || !ls_info) {
        return -1;
    }
    
    zlog_debug("BGPLS: build_bgpls_link_nlri for if_name=%s, if_index=%u",
               ls_info->if_name, ls_info->if_index);

    memset(p, 0, sizeof(*p));
    p->family = AF_LINKSTATE;
    p->u.prefix_linkstate.nlri_type = 0x0002;  // Link NLRI
    p->u.prefix_linkstate.ls_data = ls_info;   // Store pointer to semantic data
    p->prefixlen = 128;  // Nominal value for prefix comparison

    /* 关键修复：预编码 NLRI 到缓冲区，供 WITHDRAW 使用
     * 这解决了异步 bgp_process 时 ls_data 已被释放的问题
     */
    buf = p->u.prefix_linkstate.nlri_buf;
    
    /* 1. Protocol-ID (1 byte) - OSPF = 0x05 */
    buf[offset++] = 0x05;

    /* 2. Identifier (8 bytes) - use if_index */
    uint64_t identifier = (uint64_t)ls_info->if_index;
    buf[offset++] = (identifier >> 56) & 0xFF;
    buf[offset++] = (identifier >> 48) & 0xFF;
    buf[offset++] = (identifier >> 40) & 0xFF;
    buf[offset++] = (identifier >> 32) & 0xFF;
    buf[offset++] = (identifier >> 24) & 0xFF;
    buf[offset++] = (identifier >> 16) & 0xFF;
    buf[offset++] = (identifier >> 8) & 0xFF;
    buf[offset++] = identifier & 0xFF;

    /* 3. Local Node Descriptors (TLV 256 = 0x0100) */
    buf[offset++] = 0x01;
    buf[offset++] = 0x00;
    size_t local_node_len_offset = offset;
    offset += 2;  /* placeholder for length */

    /* Sub-TLV 515 (0x0203): IGP Router-ID */
    buf[offset++] = 0x02;
    buf[offset++] = 0x03;
    buf[offset++] = 0x00;
    buf[offset++] = 0x04;
    /* inet_pton 已存储网络字节序，直接拷贝，不需要 htonl */
    memcpy(&buf[offset], &ls_info->router_id.s_addr, 4);
    offset += 4;

    uint16_t local_node_len = offset - local_node_len_offset - 2;
    buf[local_node_len_offset] = (local_node_len >> 8) & 0xFF;
    buf[local_node_len_offset + 1] = local_node_len & 0xFF;

    /* 4. Remote Node Descriptors (TLV 257 = 0x0101) */
    buf[offset++] = 0x01;
    buf[offset++] = 0x01;
    size_t remote_node_len_offset = offset;
    offset += 2;

    /* Sub-TLV 515 (0x0203): IGP Router-ID */
    buf[offset++] = 0x02;
    buf[offset++] = 0x03;
    buf[offset++] = 0x00;
    buf[offset++] = 0x04;
    /* inet_pton 已存储网络字节序，直接拷贝，不需要 htonl */
    memcpy(&buf[offset], &ls_info->remote_router_id.s_addr, 4);
    offset += 4;

    uint16_t remote_node_len = offset - remote_node_len_offset - 2;
    buf[remote_node_len_offset] = (remote_node_len >> 8) & 0xFF;
    buf[remote_node_len_offset + 1] = remote_node_len & 0xFF;

    /* 5. Link Descriptors */
    /* TLV 259 (0x0103): IPv4 Interface Address */
    buf[offset++] = 0x01;
    buf[offset++] = 0x03;
    buf[offset++] = 0x00;
    buf[offset++] = 0x04;
    /* inet_pton 已存储网络字节序，直接拷贝，不需要 htonl */
    memcpy(&buf[offset], &ls_info->local_addr.s_addr, 4);
    offset += 4;

    /* TLV 260 (0x0104): IPv4 Neighbor Address */
    buf[offset++] = 0x01;
    buf[offset++] = 0x04;
    buf[offset++] = 0x00;
    buf[offset++] = 0x04;
    /* inet_pton 已存储网络字节序，直接拷贝，不需要 htonl */
    memcpy(&buf[offset], &ls_info->remote_addr.s_addr, 4);
    offset += 4;

    /* Save the pre-encoded NLRI length */
    p->u.prefix_linkstate.nlri_len = (uint16_t)offset;
    
    zlog_debug("BGPLS: prefix prepared with ls_data=%p, pre-encoded nlri_len=%zu",
               (void*)ls_info, offset);
    
    return 0;
}



























void bgp_linkstate_init(void)
{
	prefix_set_linkstate_display_hook(bgp_linkstate_nlri_prefix_display);
}
//读取配置文件 读取当前链路信息触发proces.
//接收delete add update


/* ========================================================================
 * 链路状态操作函数实现：linkstate_add / update / delete
 * ======================================================================== */

/**
 * 添加新的链路状态到 BGP-LS RIB
 * 
 * 调用场景：
 * 1. 首次发现新链路（接口up、建立邻接关系）
 * 2. 从配置文件初始化时加载链路
 * 3. 外部事件通知有新链路
 * 
 * @param bgp       BGP实例 - 提供RIB存储位置(bgp->rib[AFI][SAFI])和本地peer标识(bgp->peer_self)，是整个BGP进程的上下文
 * @param ls_info   链路状态信息 - 包含接口名、带宽、度量等32个字段，是要通告给对等体的原始数据源
 * @return 0 成功, -1 失败
 */
int linkstate_add(struct bgp *bgp, struct linkstate_info *ls_info, safi_t safi)
{
	struct prefix p;	//BGP-LS NLRI前缀，编码了链路的拓扑标识（router ID、接口地址等），作为RIB中的查找键
	struct attr attr;	//BGP属性结构，存储Link Attribute TLVs（带宽、度量等），在栈上临时构造后会被intern
	struct attr *attr_new;	//intern后的属性指针，指向全局共享属性池，用于节省内存（多条路由共享相同属性）
	struct bgp_dest *dest;	//RIB树中的目的节点，通过p查找或创建，一个dest对应一条链路的多条路径（多路径BGP）
	struct bgp_path_info *pi;	//路径信息结构，关联peer和attr，表示"从peer_self学到的到达dest的路径"，加入dest的链表
	
	if (!bgp || !ls_info) {
		return -1;
	}
	
	//1: 构造BGP-LS NLRI前缀
	/* FRR 10.x: prefix 必须完全初始化所有字段 */
	memset(&p, 0, sizeof(p));
	p.family = AF_LINKSTATE;   // AF_LINKSTATE (AF_MAX+3=48)
	p.prefixlen = 0;           // 初始值，build_bgpls_link_nlri 会更新
	
	/* 构造 NLRI 内容，会更新 p.prefixlen 和 p.u */
	if (build_bgpls_link_nlri(&p, ls_info) != 0) {
		return -1;
	}
	
	/* 验证 prefix 构造成功 */
	if (p.family != AF_LINKSTATE || p.prefixlen == 0) {
		return -1;
	}
		
	//2: 构造BGP属性（Link Attributes）
	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
	attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_LINK_STATE);  // 设置Link-State属性标志
	
	/* 编码Link Attribute TLVs到attr.link_state */
	int encode_ret = encode_link_attributes(&attr, ls_info, safi);
	if (encode_ret != 0) {
		return -1;
	}
	
	//3: Intern属性（引用计数管理）
	attr_new = bgp_attr_intern(&attr);  // 将attr加入全局属性池，返回共享指针
	
	//4: 获取或创建BGP RIB节点
	/* FRR 10.x: 使用标准的 bgp->rib[AFI][SAFI] 表 */
	struct bgp_table *table = bgp->rib[AFI_LINKSTATE][safi];
	if (!table) {
		/* 创建 BGP-LS 表 */
		table = bgp_table_init(bgp, AFI_LINKSTATE, safi);
		if (!table) {
			return -1;
		}
		bgp->rib[AFI_LINKSTATE][safi] = table;
	}
	
	/* 验证 table 和 prefix */
	assert(table != NULL);
	assert(table->route_table != NULL);
	assert(p.family == AF_LINKSTATE);
	assert(p.prefixlen > 0);
	
	/* 使用标准的 bgp_node_get() - FRR 期望的路径 */
	printf("[BGP-LS-ADD] Calling bgp_node_get with prefix: family=%d, prefixlen=%d, nlri_type=0x%04x, ptr=%p\n",
	       p.family, p.prefixlen, p.u.prefix_linkstate.nlri_type, (void*)p.u.prefix_linkstate.ls_data);
fflush(stdout);
	
	dest = bgp_node_get(table, &p);
	printf("[BGP-LS-ADD] bgp_node_get returned dest=%p, table=%p\n", (void*)dest, (void*)table);
	fflush(stdout);
	
	if (!dest) {
		printf("[BGP-LS-ADD-ERROR] bgp_node_get returned NULL!\n");
		fflush(stdout);
	return -1;
	}

//5: 创建BGP路径信息（使用peer_self作为本地路由源）
	/* 关键修复：必须使用 peer_self 而不是真实 peer！
	 * 
	 * 原因分析（对比 frr10.5-bgpls_v1.0 工作版本）：
	 * 1. BGP 的 anti-loop 机制会阻止将路由发回给学习它的 peer
	 * 2. 如果 pi->peer = real_peer，bgp_process 会检测到 pi->peer == target_peer 并跳过
	 * 3. 使用 peer_self 时，pi->peer != target_peer，所以会正常 announce
	 * 
	 * 这是 BGP-LS 本地路由注入的标准方法（参考旧版本第666行）
	 */
	attr_new = bgp_attr_intern(&attr);
	
	pi = info_make(ZEBRA_ROUTE_BGP,
	               BGP_ROUTE_STATIC,
	               0,
	               bgp->peer_self,  
	               attr_new,
	               dest);
	
	if (!pi) {
		zlog_warn("linkstate_add: Failed to create path_info");
		bgp_dest_unlock_node(dest);
		bgp_attr_unintern(&attr_new);
		return -1;
	}
	
	/* 设置路径标志 - 本地生成的路由 */
	SET_FLAG(pi->flags, BGP_PATH_VALID);
	
	/* 关键修复：强制触发通告（特别是 RE-ADD 场景）
	 * DELETE 后重新 ADD 时，FRR 没有 old_select 可对比
	 * 必须显式告诉它"这是需要重新通告的新路由"
	 */
	SET_FLAG(pi->flags, BGP_PATH_ATTR_CHANGED);
	
	printf("[BGP-LS-ADD] Created path_info with peer_self, flags=0x%x (with ATTR_CHANGED)\n", pi->flags);
	fflush(stdout);
	
	/* 添加到RIB */
	bgp_path_info_add(dest, pi);
	
	/* 检查可用的 peer */
	struct listnode *node;
	struct peer *peer;
	int peer_count = 0;
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		if (peer_established(peer->connection) && peer->afc_nego[AFI_LINKSTATE][safi]) {
			peer_count++;
			printf("[BGP-LS-ADD] Found established peer %s with BGP-LS capability\n",
			       peer->host);
		}
	}
	printf("[BGP-LS-ADD] Total available peers: %d\n", peer_count);
	fflush(stdout);
	
	if (peer_count == 0) {
		zlog_warn("linkstate_add: No peers available to announce BGP-LS route");
		printf("[BGP-LS-WARN] No established peers with BGP-LS capability\n");
		fflush(stdout);
		bgp_dest_unlock_node(dest);
		return 0;  /* 不是错误，只是没有peer */
	}
	
	/* 触发 BGP 处理（会向所有 peer 发送 UPDATE）*/
	printf("[BGP-LS-ADD] Calling bgp_process (will announce to all peers)\n");
	fflush(stdout);
	
	bgp_process(bgp, dest, pi, AFI_LINKSTATE, safi);
	
	printf("[BGP-LS-ADD] bgp_process completed, announced to %d peer(s)\n", peer_count);
	fflush(stdout);
	
	//6: 插入哈希表映射（if_name → dest + linkstate_info）
	if (!bgp->linkstate_if_map) {
		bgp_linkstate_if_map_init(bgp);
	}
	
	struct linkstate_prefix_wrapper wrapper_key;
	memset(&wrapper_key, 0, sizeof(wrapper_key));
	strncpy(wrapper_key.if_name, ls_info->if_name, sizeof(wrapper_key.if_name) - 1);
	memcpy(&wrapper_key.ls_info, ls_info, sizeof(wrapper_key.ls_info));
	wrapper_key.dest = dest;
	
	struct linkstate_prefix_wrapper *wrapper_result;
	wrapper_result = hash_get(bgp->linkstate_if_map, &wrapper_key,
	                          linkstate_if_map_alloc);
	
	if (wrapper_result) {
		wrapper_result->dest = dest;
		printf("[BGP-LS-INFO] Added %s to interface map (hash table)\n", ls_info->if_name);
		fflush(stdout);
	}
	
	printf("[BGP-LS-INFO] Successfully added link-state for %s\n", ls_info->if_name);
	fflush(stdout);
	return 0;
}

/**
 * 更新已存在的链路状态
 * 
 * 调用场景：
 * 1. 链路带宽变化
 * 2. 链路状态变化（UP/DOWN）
 * 3. 度量值更新
 * 4. TE参数变化
 * 5. 定时器轮询检测到变化
 * 
 * @param bgp       BGP实例 - 提供RIB查找位置，与add相同作用
 * @param ls_info   新的链路状态信息 - 包含更新后的带宽、度量等字段，用于重新编码TLV属性
 * @return 0 成功, -1 失败
 */
int linkstate_update(struct bgp *bgp, struct linkstate_info *ls_info, safi_t safi)
{
	/* 不再需要 struct prefix p，因为我们用interface name查找 */
	struct bgp_dest *dest;	//从hash table获取的已存在的RIB节点
	struct bgp_path_info *pi;	//dest中的现有路径信息，需要更新其attr指针指向新属性（先unintern旧的再intern新的）
	struct attr new_attr;	//基于旧属性复制并更新TLV字段的新属性，在栈上临时构造
	struct attr *attr_new;	//intern后的新属性指针，替换pi->attr实现属性更新，触发bgp_process发送UPDATE
	
	if (!bgp || !ls_info) {
		zlog_err("%s: Invalid parameters", __func__);
		printf("[BGP-LS-UPDATE-FATAL] Invalid parameters: bgp=%p, ls_info=%p\n", 
		       (void*)bgp, (void*)ls_info);
		fflush(stdout);
		return -1;
	}
	
	printf("[BGP-LS-UPDATE-ENTRY] linkstate_update() called for if_name='%s'\n", 
	       ls_info ? ls_info->if_name : "(null)");
	fflush(stdout);
	
	zlog_info("linkstate_update: Updating link-state (status=%d, bw=%u, metric=%u)",
		  ls_info->oper_status, ls_info->max_bandwidth, ls_info->igp_metric);
	
	//1: 确保hash table已初始化
	if (!bgp->linkstate_if_map) {
		printf("[BGP-LS-UPDATE] Hash table not initialized, calling init\n");
		fflush(stdout);
		bgp_linkstate_if_map_init(bgp);
	}
	
	//2: 不再构造NLRI，直接用interface name查找hash table
	/* 
	 * 修复后的正确做法：用interface name从hash table获取已存在的dest
	 */
	
	//2: 从interface hash table查找已有的dest（不重新build NLRI！）
	printf("[BGP-LS-UPDATE] Looking up dest by if_name='%s' in hash table\n", ls_info->if_name);
	fflush(stdout);
	
	/* 使用interface name从hash table查找已存在的dest
	 * 而不是重新build NLRI（每次build的ptr都不同，导致lookup失败）
	 */
	struct linkstate_prefix_wrapper lookup_key;
	memset(&lookup_key, 0, sizeof(lookup_key));
	strncpy(lookup_key.if_name, ls_info->if_name, sizeof(lookup_key.if_name) - 1);
	
	struct linkstate_prefix_wrapper *mapping = hash_lookup(bgp->linkstate_if_map, &lookup_key);
	
	printf("[BGP-LS-UPDATE-DEBUG] hash_lookup returned mapping=%p\n", (void*)mapping);
	if (mapping) {
		printf("[BGP-LS-UPDATE-DEBUG] mapping->dest=%p, mapping->if_name='%s'\n", 
		       (void*)mapping->dest, mapping->if_name);
	}
	fflush(stdout);
	
	if (!mapping || !mapping->dest) {
		/* Hash表中没有找到 → 这是第一次，需要add */
		printf("[BGP-LS-UPDATE] if_name='%s' not in hash table, calling linkstate_add\n", ls_info->if_name);
		fflush(stdout);
		/* 注意：不需要释放p，因为我们没有构建它 */
		return linkstate_add(bgp, ls_info, safi);
	}
	
	dest = mapping->dest;
	printf("[BGP-LS-UPDATE] Found dest=%p for if_name='%s'\n", (void*)dest, ls_info->if_name);
	fflush(stdout);
	
	//3: 检查该节点是否有路径信息（判断是add还是update）
	pi = bgp_dest_get_bgp_path_info(dest);
	if (!pi) {
		/* 节点存在但没有路径信息，需要调用add */
		printf("[BGP-LS-UPDATE] No path_info found, calling linkstate_add\n");
		fflush(stdout);
		bgp_dest_unlock_node(dest);  // 释放get的锁
		return linkstate_add(bgp, ls_info, safi);
	}
	// 数据来源：dest->info（路径信息链表头）
	
	//4: 构造新的Link Attribute TLVs（不复制旧属性，直接重新编码）
	memset(&new_attr, 0, sizeof(new_attr));
	bgp_attr_default_set(&new_attr, bgp, BGP_ORIGIN_IGP);
	new_attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_LINK_STATE);
	
	/* 重新编码Link Attribute TLVs（使用ls_info的新值）*/
	if (encode_link_attributes(&new_attr, ls_info, safi) != 0) {
		zlog_err("linkstate_update: Failed to encode updated link attributes");
		bgp_dest_unlock_node(dest);
		return -1;
	}
	
	//5: 先 intern 新属性（无论是否变化）
	/* 关键修复：必须先 intern 再比较，因为：
	 * 1. bgp_attr_intern 会规范化属性并返回共享副本
	 * 2. 如果提前返回，必须确保 new_attr 中的动态内存被正确处理
	 * 3. intern 后的属性由 FRR 的 attrhash 管理生命周期
	 */
	attr_new = bgp_attr_intern(&new_attr);
	
	//6: 检查属性是否真的发生变化
	if (attrhash_cmp(pi->attr, attr_new)) {
		/* 属性完全相同，无需更新 */
		zlog_debug("linkstate_update: Attributes unchanged, skipping update");
		printf("[BGP-LS-UPDATE] Attributes unchanged, no UPDATE needed\n");
		fflush(stdout);
		
		// 释放刚 intern 的属性（因为我们不使用它）
		bgp_attr_unintern(&attr_new);
		bgp_dest_unlock_node(dest);
		return 0;
	}
	
	printf("[BGP-LS-UPDATE] Attributes changed, updating path_info\n");
	fflush(stdout);
	
	//7: 更新路径信息的属性
	/* 关键：必须先保存旧 attr 指针，再赋值新 attr，最后 unintern 旧 attr
	 * 这样可以保持引用计数平衡：
	 * - 新 attr 的 refcnt = 1 (由 bgp_attr_intern 设置)
	 * - 旧 attr 通过 unintern 递减 refcnt，如果归零则释放
	 */
	struct attr *old_attr = pi->attr;   // 保存旧指针
	
	printf("[BGP-LS-UPDATE] old_attr=%p (refcnt=%u), new_attr=%p (refcnt=%u)\n", 
	       (void*)old_attr, old_attr->refcnt, (void*)attr_new, attr_new->refcnt);
	fflush(stdout);
	
	pi->attr = attr_new;                // 赋值新指针
	pi->uptime = monotime(NULL);        // 更新时间戳
	
	/* 设置属性变化标志，强制触发重新通告 */
	SET_FLAG(pi->flags, BGP_PATH_ATTR_CHANGED);
	
	/* 释放旧属性的引用（在赋值新指针之后）*/
	printf("[BGP-LS-UPDATE] Calling bgp_attr_unintern on old_attr...\n");
	fflush(stdout);
	bgp_attr_unintern(&old_attr);
	printf("[BGP-LS-UPDATE] bgp_attr_unintern completed\n");
	fflush(stdout);
	
	printf("[BGP-LS-UPDATE] Set BGP_PATH_ATTR_CHANGED flag, pi->flags=0x%x\n", pi->flags);
	fflush(stdout);

	//8: 触发BGP处理（自动发送UPDATE消息）
	printf("[BGP-LS-UPDATE] Calling bgp_process to trigger UPDATE\n");
	fflush(stdout);
	
	bgp_process(bgp, dest, pi, AFI_LINKSTATE, safi);
	/* bgp_process会：
	 * 1. 检测到BGP_PATH_ATTR_CHANGED标志
	 * 2. 调用 group_announce_route()
	 * 3. 生成UPDATE消息（包含新的Link Attribute TLVs）
	 * 4. 发送给所有BGP-LS对等体
	 */
	
	//9: 释放节点锁
	bgp_dest_unlock_node(dest);
	
	printf("[BGP-LS-UPDATE] Update completed successfully\n");
	fflush(stdout);
	
	zlog_info("linkstate_update: Successfully updated link-state");
	return 0;
}

/**
 * 删除链路状态（撤销通告）
 * 
 * 调用场景：
 * 1. 接口关闭（admin down）
 * 2. 链路故障持续一定时间
 * 3. 邻接关系断开
 * 4. 从配置中移除接口
 * 5. 路由器关闭前清理
 * 
 * @param bgp       BGP实例 - 提供RIB位置和哈希表(bgp->linkstate_if_map)用于查找和删除
 * @param if_name   接口名称 - 通过哈希表映射到prefix，因为delete时只知道接口名不知道完整NLRI
 * @return 0 成功, -1 失败
 */
int linkstate_delete(struct bgp *bgp, const char *if_name,safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	
	if (!bgp || !if_name) {
		zlog_err("%s: Invalid parameters", __func__);
		return -1;
	}
	
	printf("[BGP-LS-DELETE] Deleting link-state for %s\n", if_name);
	fflush(stdout);
	
	zlog_info("%s: Deleting link-state for %s", __func__, if_name);
	
	//1: 从哈希表查找 dest
	if (!bgp->linkstate_if_map) {
		printf("[BGP-LS-DELETE-ERROR] linkstate_if_map not initialized\n");
		fflush(stdout);
		zlog_err("%s: linkstate_if_map not initialized", __func__);
		return -1;
	}
	
	struct linkstate_prefix_wrapper lookup_key;
	memset(&lookup_key, 0, sizeof(lookup_key));
	strncpy(lookup_key.if_name, if_name, sizeof(lookup_key.if_name) - 1);
	
	printf("[BGP-LS-DELETE] Looking up interface '%s' in hash table\n", if_name);
	fflush(stdout);
	
	struct linkstate_prefix_wrapper *wrapper;
	wrapper = hash_lookup(bgp->linkstate_if_map, &lookup_key);
	
	printf("[BGP-LS-DELETE] hash_lookup returned: %p\n", (void*)wrapper);
	fflush(stdout);
	
	if (!wrapper || !wrapper->dest) {
		printf("[BGP-LS-DELETE-ERROR] Cannot find '%s' in hash table!\n", if_name);
		fflush(stdout);
		zlog_warn("%s: Cannot find link-state for interface %s in hash map",
		          __func__, if_name);
		return -1;
	}
	
	dest = wrapper->dest;
	printf("[BGP-LS-DELETE] Got dest=%p from hash, getting path_info...\n", (void*)dest);
	fflush(stdout);
	
	//2: 获取路径信息
	pi = bgp_dest_get_bgp_path_info(dest);
	if (!pi) {
		printf("[BGP-LS-DELETE-ERROR] No path_info found!\n");
		fflush(stdout);
		zlog_warn("%s: No path_info for %s", __func__, if_name);
		return -1;
	}
	
	printf("[BGP-LS-DELETE] Got path_info=%p, marking for delete...\n", (void*)pi);
	fflush(stdout);
	
	
	struct prefix *p = (struct prefix *)bgp_dest_get_prefix(dest);
	
	if (p && p->family == AF_LINKSTATE) {
		printf("[BGP-LS-DELETE] Using pre-encoded NLRI: nlri_len=%u, nlri_type=0x%04x\n", 
		       p->u.prefix_linkstate.nlri_len, p->u.prefix_linkstate.nlri_type);
		fflush(stdout);
		
		/* 关键修复：不再调用 prefix_linkstate_ptr_free()！
		 * nlri_buf 是内嵌在 prefix 中的，不需要释放。
		 * 只需清空 ls_data 指针（标记语义数据不再有效），
		 * 编码函数会使用 nlri_buf 中的预编码数据。
		 */
		p->u.prefix_linkstate.ls_data = NULL;
		
		printf("[BGP-LS-DELETE] Cleared ls_data pointer, nlri_buf still valid for encode\n");
		fflush(stdout);
	}
	
	bgp_path_info_mark_for_delete(dest, pi);
	
	printf("[BGP-LS-DELETE] Marked path for delete (flags=0x%x), calling bgp_process\n", pi->flags);
	fflush(stdout);
	
	bgp_process(bgp, dest, pi, AFI_LINKSTATE, safi);
	
	printf("[BGP-LS-DELETE] bgp_process queued, will send WITHDRAW\n");
	fflush(stdout);
	
	//4: 从哈希表删除映射（但不释放 dest，FRR 会处理）
	wrapper = hash_release(bgp->linkstate_if_map, &lookup_key);
	if (wrapper) {
		XFREE(MTYPE_BGP_LINKSTATE_WRAPPER, wrapper);
		printf("[BGP-LS-DELETE] Removed %s from hash table\n", if_name);
		fflush(stdout);
	} else {
		zlog_warn("%s: Failed to remove %s from interface map",
		         __func__, if_name);
	}
	
	printf("[BGP-LS-DELETE] Delete queued successfully for %s\n", if_name);
	fflush(stdout);
	
	zlog_info("%s: Delete queued successfully for %s", __func__, if_name);
	return 0;
}

/* ========================================================================
 * Node State (BGP-LS Node NLRI) 处理函数实现
 * 基于 RFC 7752 Node NLRI 和 RFC 9085 SR Node Attributes
 * ======================================================================== */

/* Node State 哈希表包装器 */
struct nodestate_prefix_wrapper {
	char node_name[256];            /* 节点名称（作为哈希键）*/
	struct nodestate_info ns_info;  /* Node State信息副本 */
	struct bgp_dest *dest;          /* RIB节点指针 */
};

/* 内存类型定义 */
DEFINE_MTYPE_STATIC(BGPD, BGP_NODESTATE_WRAPPER, "BGP NodeState Wrapper");

/* 哈希表操作函数 */

/* 计算哈希值（基于节点名）*/
static unsigned int nodestate_map_hash_key(const void *data)
{
	const struct nodestate_prefix_wrapper *wrapper = data;
	return string_hash_make(wrapper->node_name);
}

/* 比较两个节点名是否相等 */
static bool nodestate_map_cmp(const void *d1, const void *d2)
{
	const struct nodestate_prefix_wrapper *w1 = d1;
	const struct nodestate_prefix_wrapper *w2 = d2;
	return (strcmp(w1->node_name, w2->node_name) == 0);
}

/* 哈希表分配函数 */
static void *nodestate_map_alloc(void *data)
{
	struct nodestate_prefix_wrapper *wrapper_in = data;
	struct nodestate_prefix_wrapper *wrapper_out;
	
	wrapper_out = XCALLOC(MTYPE_BGP_NODESTATE_WRAPPER,
	                      sizeof(struct nodestate_prefix_wrapper));
	strncpy(wrapper_out->node_name, wrapper_in->node_name, sizeof(wrapper_out->node_name) - 1);
	memcpy(&wrapper_out->ns_info, &wrapper_in->ns_info, sizeof(wrapper_out->ns_info));
	
	return wrapper_out;
}

/* 哈希清理回调函数 */
static void nodestate_prefix_free(void *data)
{
	if (data)
		XFREE(MTYPE_BGP_NODESTATE_WRAPPER, data);
}

/* 初始化Node State哈希表 */
void bgp_nodestate_map_init(struct bgp *bgp)
{
	if (!bgp->nodestate_map) {
		bgp->nodestate_map = hash_create(nodestate_map_hash_key,
		                                  nodestate_map_cmp,
		                                  "BGP NodeState Map");
		zlog_info("%s: Initialized nodestate map", __func__);
	}
}

/* 清理Node State哈希表 */
void bgp_nodestate_map_finish(struct bgp *bgp)
{
	if (bgp->nodestate_map) {
		hash_clean(bgp->nodestate_map, nodestate_prefix_free);
		hash_free(bgp->nodestate_map);
		bgp->nodestate_map = NULL;
		zlog_info("%s: Cleaned up nodestate map", __func__);
	}
}

/**
 * 构造BGP-LS Node NLRI
 * 
 * RFC 7752 Figure 7 - Node NLRI Format:
 *   - Protocol-ID (1 byte)
 *   - Identifier (8 bytes)
 *   - Local Node Descriptors (variable)
 * 
 * @param p        输出的prefix结构
 * @param ns_info  节点状态信息
 * @return 0 成功, -1 失败
 */
static int build_bgpls_node_nlri(struct prefix *p, struct nodestate_info *ns_info)
{
	uint8_t *buf;
	size_t offset = 0;
	
	if (!p || !ns_info) {
		return -1;
	}
	
	zlog_debug("BGPLS: build_bgpls_node_nlri for node_name=%s", ns_info->node_name);

	memset(p, 0, sizeof(*p));
	p->family = AF_LINKSTATE;
	p->u.prefix_linkstate.nlri_type = BGPLS_NLRI_TYPE_NODE;  /* Node NLRI = 0x0001 */
	p->u.prefix_linkstate.ls_data = ns_info;
	p->prefixlen = 128;  /* Nominal value for prefix comparison */

	/* 预编码 NLRI 到缓冲区 */
	buf = p->u.prefix_linkstate.nlri_buf;
	
	/* 1. Protocol-ID (1 byte) - RFC 7752 Table 2 */
	buf[offset++] = ns_info->protocol_id ? ns_info->protocol_id : BGPLS_PROTOCOL_STATIC;

	/* 2. Identifier (8 bytes) */
	uint64_t identifier = ns_info->identifier;
	buf[offset++] = (identifier >> 56) & 0xFF;
	buf[offset++] = (identifier >> 48) & 0xFF;
	buf[offset++] = (identifier >> 40) & 0xFF;
	buf[offset++] = (identifier >> 32) & 0xFF;
	buf[offset++] = (identifier >> 24) & 0xFF;
	buf[offset++] = (identifier >> 16) & 0xFF;
	buf[offset++] = (identifier >> 8) & 0xFF;
	buf[offset++] = identifier & 0xFF;

	/* 3. Local Node Descriptors (TLV 256 = 0x0100) */
	buf[offset++] = 0x01;
	buf[offset++] = 0x00;
	size_t local_node_len_offset = offset;
	offset += 2;  /* placeholder for length */

	/* Sub-TLV 512 (0x0200): Autonomous System (4 bytes) */
	if (ns_info->asn != 0) {
		buf[offset++] = 0x02;
		buf[offset++] = 0x00;
		buf[offset++] = 0x00;
		buf[offset++] = 0x04;
		buf[offset++] = (ns_info->asn >> 24) & 0xFF;
		buf[offset++] = (ns_info->asn >> 16) & 0xFF;
		buf[offset++] = (ns_info->asn >> 8) & 0xFF;
		buf[offset++] = ns_info->asn & 0xFF;
	}

	/* Sub-TLV 513 (0x0201): BGP-LS Identifier (4 bytes) */
	if (ns_info->bgpls_id != 0) {
		buf[offset++] = 0x02;
		buf[offset++] = 0x01;
		buf[offset++] = 0x00;
		buf[offset++] = 0x04;
		buf[offset++] = (ns_info->bgpls_id >> 24) & 0xFF;
		buf[offset++] = (ns_info->bgpls_id >> 16) & 0xFF;
		buf[offset++] = (ns_info->bgpls_id >> 8) & 0xFF;
		buf[offset++] = ns_info->bgpls_id & 0xFF;
	}

	/* Sub-TLV 514 (0x0202): OSPF Area-ID (4 bytes) */
	if (ns_info->ospf_area_id != 0) {
		buf[offset++] = 0x02;
		buf[offset++] = 0x02;
		buf[offset++] = 0x00;
		buf[offset++] = 0x04;
		buf[offset++] = (ns_info->ospf_area_id >> 24) & 0xFF;
		buf[offset++] = (ns_info->ospf_area_id >> 16) & 0xFF;
		buf[offset++] = (ns_info->ospf_area_id >> 8) & 0xFF;
		buf[offset++] = ns_info->ospf_area_id & 0xFF;
	}

	/* Sub-TLV 515 (0x0203): IGP Router-ID */
	if (ns_info->router_id.s_addr != 0) {
		/* IPv4 Router-ID (4 bytes for OSPF) */
		buf[offset++] = 0x02;
		buf[offset++] = 0x03;
		buf[offset++] = 0x00;
		buf[offset++] = 0x04;
		memcpy(&buf[offset], &ns_info->router_id.s_addr, 4);
		offset += 4;
	} else if (ns_info->iso_node_id_len > 0) {
		/* IS-IS ISO System-ID (6 or 7 bytes) */
		buf[offset++] = 0x02;
		buf[offset++] = 0x03;
		buf[offset++] = 0x00;
		buf[offset++] = ns_info->iso_node_id_len;
		memcpy(&buf[offset], ns_info->iso_node_id, ns_info->iso_node_id_len);
		offset += ns_info->iso_node_id_len;
	}

	/* 更新Local Node Descriptors长度 */
	uint16_t local_node_len = offset - local_node_len_offset - 2;
	buf[local_node_len_offset] = (local_node_len >> 8) & 0xFF;
	buf[local_node_len_offset + 1] = local_node_len & 0xFF;

	/* Save the pre-encoded NLRI length */
	p->u.prefix_linkstate.nlri_len = (uint16_t)offset;
	
	zlog_debug("BGPLS: Node NLRI prepared with pre-encoded nlri_len=%zu", offset);
	
	printf("[BGP-LS-NODE] Built Node NLRI: nlri_len=%zu, router_id=%s\n",
	       offset, inet_ntoa(ns_info->router_id));
	fflush(stdout);
	
	return 0;
}

/**
 * 编码Node Attribute TLVs到attr->link_state
 * 
 * RFC 7752 Table 7 Node Attribute TLVs:
 *   - TLV 1024: Node Flag Bits
 *   - TLV 1026: Node Name
 *   - TLV 1027: IS-IS Area Identifier
 *   - TLV 1028: IPv4 Router-ID of Local Node
 *   - TLV 1029: IPv6 Router-ID of Local Node
 * 
 * RFC 9085 SR Node Attribute TLVs:
 *   - TLV 1034: SR Capabilities
 *   - TLV 1035: SR Algorithm
 *   - TLV 1036: SR Local Block
 *   - TLV 1037: SRMS Preference
 * 
 * @param attr      要填充的BGP属性
 * @param ns_info   节点状态信息源
 * @param safi      SAFI类型
 * @return 0 成功, -1 失败
 */
static int encode_node_attributes(struct attr *attr, struct nodestate_info *ns_info, safi_t safi)
{
	uint8_t *tlv_buf;
	size_t offset = 0;
	size_t buf_size = 512;
	struct bgp_attr_ls *attr_ls;
	
	if (!attr || !ns_info) {
		return -1;
	}
	
	/* 分配TLV缓冲区 */
	tlv_buf = XCALLOC(MTYPE_BGP_ATTR_LS_DATA, buf_size);
	if (!tlv_buf) {
		zlog_err("%s: Failed to allocate TLV buffer", __func__);
		return -1;
	}
	
	/* TLV 1024: Node Flag Bits (1 byte) */
	if (ns_info->node_flags != 0) {
		put_tlv_header_u16(tlv_buf + offset, 1024, 1);
		tlv_buf[offset + 4] = ns_info->node_flags;
		offset += 5;
	}
	
	/* TLV 1026: Node Name (variable, max 255 bytes) */
	if (ns_info->node_name[0] != '\0') {
		size_t name_len = strlen(ns_info->node_name);
		if (name_len > 255) name_len = 255;
		put_tlv_header_u16(tlv_buf + offset, 1026, name_len);
		memcpy(tlv_buf + offset + 4, ns_info->node_name, name_len);
		offset += 4 + name_len;
	}
	
	/* TLV 1027: IS-IS Area Identifier (variable) */
	if (ns_info->isis_area_id_len > 0) {
		put_tlv_header_u16(tlv_buf + offset, 1027, ns_info->isis_area_id_len);
		memcpy(tlv_buf + offset + 4, ns_info->isis_area_id, ns_info->isis_area_id_len);
		offset += 4 + ns_info->isis_area_id_len;
	}
	
	/* TLV 1028: IPv4 Router-ID of Local Node (4 bytes) */
	if (ns_info->te_router_id.s_addr != 0) {
		put_tlv_header_u16(tlv_buf + offset, 1028, 4);
		memcpy(tlv_buf + offset + 4, &ns_info->te_router_id.s_addr, 4);
		offset += 8;
	}
	
	/* TLV 1029: IPv6 Router-ID of Local Node (16 bytes) */
	/* 检查IPv6地址是否非零 */
	bool has_ipv6_router_id = false;
	for (int i = 0; i < 16; i++) {
		if (ns_info->te_router_id_v6.s6_addr[i] != 0) {
			has_ipv6_router_id = true;
			break;
		}
	}
	if (has_ipv6_router_id) {
		put_tlv_header_u16(tlv_buf + offset, 1029, 16);
		memcpy(tlv_buf + offset + 4, &ns_info->te_router_id_v6, 16);
		offset += 20;
	}
	
	/* RFC 9085 SR Node Attribute TLVs */
	
	/* TLV 1034: SR Capabilities */
	if (ns_info->srgb_range > 0) {
		/* SR Capabilities TLV format:
		 * - Flags (1 byte)
		 * - Reserved (1 byte)
		 * - Range Size (3 bytes)
		 * - SID/Label Sub-TLV (TLV 1161, 7 bytes for label)
		 */
		size_t sr_cap_len = 2 + 3 + 7;  /* flags+reserved + range + SID/Label sub-TLV */
		put_tlv_header_u16(tlv_buf + offset, 1034, sr_cap_len);
		offset += 4;
		
		tlv_buf[offset++] = ns_info->sr_capability_flags;  /* Flags */
		tlv_buf[offset++] = 0;  /* Reserved */
		
		/* Range Size (3 bytes) */
		tlv_buf[offset++] = (ns_info->srgb_range >> 16) & 0xFF;
		tlv_buf[offset++] = (ns_info->srgb_range >> 8) & 0xFF;
		tlv_buf[offset++] = ns_info->srgb_range & 0xFF;
		
		/* SID/Label Sub-TLV (Type 1161, Length 3 for label) */
		put_tlv_header_u16(tlv_buf + offset, 1161, 3);
		offset += 4;
		tlv_buf[offset++] = (ns_info->srgb_base >> 12) & 0xFF;
		tlv_buf[offset++] = (ns_info->srgb_base >> 4) & 0xFF;
		tlv_buf[offset++] = (ns_info->srgb_base << 4) & 0xF0;
	}
	
	/* TLV 1035: SR Algorithm */
	if (ns_info->sr_algorithm_count > 0) {
		put_tlv_header_u16(tlv_buf + offset, 1035, ns_info->sr_algorithm_count);
		memcpy(tlv_buf + offset + 4, ns_info->sr_algorithms, ns_info->sr_algorithm_count);
		offset += 4 + ns_info->sr_algorithm_count;
	}
	
	/* TLV 1036: SR Local Block */
	if (ns_info->srlb_range > 0) {
		size_t srlb_len = 2 + 3 + 7;
		put_tlv_header_u16(tlv_buf + offset, 1036, srlb_len);
		offset += 4;
		
		tlv_buf[offset++] = 0;  /* Flags */
		tlv_buf[offset++] = 0;  /* Reserved */
		
		/* Range Size (3 bytes) */
		tlv_buf[offset++] = (ns_info->srlb_range >> 16) & 0xFF;
		tlv_buf[offset++] = (ns_info->srlb_range >> 8) & 0xFF;
		tlv_buf[offset++] = ns_info->srlb_range & 0xFF;
		
		/* SID/Label Sub-TLV */
		put_tlv_header_u16(tlv_buf + offset, 1161, 3);
		offset += 4;
		tlv_buf[offset++] = (ns_info->srlb_base >> 12) & 0xFF;
		tlv_buf[offset++] = (ns_info->srlb_base >> 4) & 0xFF;
		tlv_buf[offset++] = (ns_info->srlb_base << 4) & 0xF0;
	}
	
	/* TLV 1037: SRMS Preference */
	if (ns_info->srms_preference != 0) {
		put_tlv_header_u16(tlv_buf + offset, 1037, 1);
		tlv_buf[offset + 4] = ns_info->srms_preference;
		offset += 5;
	}
	
	/* 如果没有任何TLV，至少编码Node Name */
	if (offset == 0 && ns_info->node_name[0] == '\0') {
		XFREE(MTYPE_BGP_ATTR_LS_DATA, tlv_buf);
		zlog_warn("encode_node_attributes: No attributes to encode");
		return -1;
	}
	
	/* 分配并填充bgp_attr_ls结构 */
	attr_ls = XCALLOC(MTYPE_BGP_ATTR_LS, sizeof(struct bgp_attr_ls));
	if (!attr_ls) {
		XFREE(MTYPE_BGP_ATTR_LS_DATA, tlv_buf);
		zlog_err("%s: Failed to allocate attr_ls", __func__);
		return -1;
	}
	
	attr_ls->length = offset;
	attr_ls->data = tlv_buf;
	attr_ls->refcnt = 0;
	
	attr->link_state = attr_ls;
	
	printf("[BGP-LS-NODE] Encoded %zu bytes of Node Attribute TLVs\n", offset);
	fflush(stdout);
	
	return 0;
}

/**
 * 添加新的节点状态到 BGP-LS RIB
 * 
 * @param bgp       BGP实例
 * @param ns_info   节点状态信息
 * @param safi      SAFI类型
 * @return 0 成功, -1 失败
 */
int nodestate_add(struct bgp *bgp, struct nodestate_info *ns_info, safi_t safi)
{
	struct prefix p;
	struct attr attr;
	struct attr *attr_new;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	
	if (!bgp || !ns_info) {
		return -1;
	}
	
	printf("[BGP-LS-NODE-ADD] Adding node: %s (router_id=%s)\n",
	       ns_info->node_name, inet_ntoa(ns_info->router_id));
	fflush(stdout);
	
	/* 1: 构造BGP-LS Node NLRI前缀 */
	memset(&p, 0, sizeof(p));
	if (build_bgpls_node_nlri(&p, ns_info) != 0) {
		return -1;
	}
	
	/* 2: 构造BGP属性（Node Attributes） */
	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
	attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_LINK_STATE);
	
	if (encode_node_attributes(&attr, ns_info, safi) != 0) {
		return -1;
	}
	
	/* 3: Intern属性 */
	attr_new = bgp_attr_intern(&attr);
	
	/* 4: 获取或创建BGP RIB节点 */
	struct bgp_table *table = bgp->rib[AFI_LINKSTATE][safi];
	if (!table) {
		table = bgp_table_init(bgp, AFI_LINKSTATE, safi);
		if (!table) {
			return -1;
		}
		bgp->rib[AFI_LINKSTATE][safi] = table;
	}
	
	dest = bgp_node_get(table, &p);
	if (!dest) {
		printf("[BGP-LS-NODE-ERROR] bgp_node_get returned NULL!\n");
		fflush(stdout);
		return -1;
	}

	/* 5: 创建BGP路径信息 */
	attr_new = bgp_attr_intern(&attr);
	
	pi = info_make(ZEBRA_ROUTE_BGP,
	               BGP_ROUTE_STATIC,
	               0,
	               bgp->peer_self,
	               attr_new,
	               dest);
	
	if (!pi) {
		zlog_warn("nodestate_add: Failed to create path_info");
		bgp_dest_unlock_node(dest);
		bgp_attr_unintern(&attr_new);
		return -1;
	}
	
	SET_FLAG(pi->flags, BGP_PATH_VALID);
	SET_FLAG(pi->flags, BGP_PATH_ATTR_CHANGED);
	
	bgp_path_info_add(dest, pi);
	bgp_process(bgp, dest, pi, AFI_LINKSTATE, safi);
	
	/* 6: 插入哈希表映射 */
	if (!bgp->nodestate_map) {
		bgp_nodestate_map_init(bgp);
	}
	
	struct nodestate_prefix_wrapper wrapper_key;
	memset(&wrapper_key, 0, sizeof(wrapper_key));
	strncpy(wrapper_key.node_name, ns_info->node_name, sizeof(wrapper_key.node_name) - 1);
	memcpy(&wrapper_key.ns_info, ns_info, sizeof(wrapper_key.ns_info));
	wrapper_key.dest = dest;
	
	struct nodestate_prefix_wrapper *wrapper_result;
	wrapper_result = hash_get(bgp->nodestate_map, &wrapper_key, nodestate_map_alloc);
	if (wrapper_result) {
		wrapper_result->dest = dest;
	}
	
	printf("[BGP-LS-NODE-ADD] Successfully added node: %s\n", ns_info->node_name);
	fflush(stdout);
	
	return 0;
}

/**
 * 更新已存在的节点状态
 * 
 * @param bgp       BGP实例
 * @param ns_info   新的节点状态信息
 * @param safi      SAFI类型
 * @return 0 成功, -1 失败
 */
int nodestate_update(struct bgp *bgp, struct nodestate_info *ns_info, safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct attr new_attr;
	struct attr *attr_new;
	
	if (!bgp || !ns_info) {
		return -1;
	}
	
	printf("[BGP-LS-NODE-UPDATE] Updating node: %s\n", ns_info->node_name);
	fflush(stdout);
	
	/* 1: 确保hash table已初始化 */
	if (!bgp->nodestate_map) {
		bgp_nodestate_map_init(bgp);
	}
	
	/* 2: 从hash table查找 */
	struct nodestate_prefix_wrapper lookup_key;
	memset(&lookup_key, 0, sizeof(lookup_key));
	strncpy(lookup_key.node_name, ns_info->node_name, sizeof(lookup_key.node_name) - 1);
	
	struct nodestate_prefix_wrapper *mapping = hash_lookup(bgp->nodestate_map, &lookup_key);
	
	if (!mapping || !mapping->dest) {
		/* 不存在，调用add */
		printf("[BGP-LS-NODE-UPDATE] Node not found, calling nodestate_add\n");
		fflush(stdout);
		return nodestate_add(bgp, ns_info, safi);
	}
	
	dest = mapping->dest;
	pi = bgp_dest_get_bgp_path_info(dest);
	if (!pi) {
		bgp_dest_unlock_node(dest);
		return nodestate_add(bgp, ns_info, safi);
	}
	
	/* 3: 构造新属性 */
	memset(&new_attr, 0, sizeof(new_attr));
	bgp_attr_default_set(&new_attr, bgp, BGP_ORIGIN_IGP);
	new_attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_LINK_STATE);
	
	if (encode_node_attributes(&new_attr, ns_info, safi) != 0) {
		bgp_dest_unlock_node(dest);
		return -1;
	}
	
	/* 4: Intern新属性 */
	attr_new = bgp_attr_intern(&new_attr);
	
	/* 5: 检查是否变化 */
	if (attrhash_cmp(pi->attr, attr_new)) {
		printf("[BGP-LS-NODE-UPDATE] Attributes unchanged\n");
		fflush(stdout);
		bgp_attr_unintern(&attr_new);
		bgp_dest_unlock_node(dest);
		return 0;
	}
	
	/* 6: 更新属性 */
	struct attr *old_attr = pi->attr;
	pi->attr = attr_new;
	pi->uptime = monotime(NULL);
	SET_FLAG(pi->flags, BGP_PATH_ATTR_CHANGED);
	bgp_attr_unintern(&old_attr);
	
	/* 7: 触发处理 */
	bgp_process(bgp, dest, pi, AFI_LINKSTATE, safi);
	bgp_dest_unlock_node(dest);
	
	printf("[BGP-LS-NODE-UPDATE] Update completed for node: %s\n", ns_info->node_name);
	fflush(stdout);
	
	return 0;
}

/**
 * 删除节点状态（撤销通告）
 * 
 * @param bgp       BGP实例
 * @param node_name 节点名称
 * @param safi      SAFI类型
 * @return 0 成功, -1 失败
 */
int nodestate_delete(struct bgp *bgp, const char *node_name, safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	
	if (!bgp || !node_name) {
		return -1;
	}
	
	printf("[BGP-LS-NODE-DELETE] Deleting node: %s\n", node_name);
	fflush(stdout);
	
	if (!bgp->nodestate_map) {
		zlog_err("%s: nodestate_map not initialized", __func__);
		return -1;
	}
	
	/* 1: 从哈希表查找 */
	struct nodestate_prefix_wrapper lookup_key;
	memset(&lookup_key, 0, sizeof(lookup_key));
	strncpy(lookup_key.node_name, node_name, sizeof(lookup_key.node_name) - 1);
	
	struct nodestate_prefix_wrapper *wrapper;
	wrapper = hash_lookup(bgp->nodestate_map, &lookup_key);
	
	if (!wrapper || !wrapper->dest) {
		zlog_warn("%s: Cannot find node %s in hash map", __func__, node_name);
		return -1;
	}
	
	dest = wrapper->dest;
	pi = bgp_dest_get_bgp_path_info(dest);
	if (!pi) {
		zlog_warn("%s: No path_info for %s", __func__, node_name);
		return -1;
	}
	
	/* 2: 标记删除 */
	struct prefix *p = (struct prefix *)bgp_dest_get_prefix(dest);
	if (p && p->family == AF_LINKSTATE) {
		p->u.prefix_linkstate.ls_data = NULL;
	}
	
	bgp_path_info_mark_for_delete(dest, pi);
	bgp_process(bgp, dest, pi, AFI_LINKSTATE, safi);
	
	/* 3: 从哈希表删除 */
	wrapper = hash_release(bgp->nodestate_map, &lookup_key);
	if (wrapper) {
		XFREE(MTYPE_BGP_NODESTATE_WRAPPER, wrapper);
	}
	
	printf("[BGP-LS-NODE-DELETE] Delete completed for node: %s\n", node_name);
	fflush(stdout);
	
	return 0;
}

