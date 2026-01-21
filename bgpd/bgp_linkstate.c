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

/* 链路状态前缀包装器（用于哈希表存储 if_name → prefix 映射）*/
struct linkstate_prefix_wrapper {
	char if_name[IFNAMSIZ];    /* 接口名（作为哈希键）*/
	struct prefix prefix;       /* 对应的BGP-LS NLRI前缀 */
};

/* 内存类型定义 */
DEFINE_MTYPE_STATIC(BGPD, BGP_LINKSTATE_WRAPPER, "BGP LinkState Wrapper");
DEFINE_MTYPE_STATIC(BGPD, BGP_ATTR_LS, "BGP Attribute Link-State");
DEFINE_MTYPE_STATIC(BGPD, BGP_ATTR_LS_DATA, "BGP Attribute Link-State Data");
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
 */
static size_t encode_tlv_bandwidth(uint8_t *buf, uint16_t type, uint32_t bw_mbps)
{
	put_tlv_header_u16(buf, type, 4);
	/* 将Mbps转换为bytes/sec，再转为IEEE 754 */
	float bw_bytes_per_sec = (float)bw_mbps * 1000000.0 / 8.0;
	*(uint32_t *)(buf + 4) = float_to_uint32_hton(bw_bytes_per_sec);
	return 8;
}

/**
 * 编码未预留带宽TLV (8个优先级，共32字节)
 */
static size_t encode_tlv_unreserved_bw(uint8_t *buf, uint16_t type, uint32_t *bw_array)
{
	put_tlv_header_u16(buf, type, 32);
	for (int i = 0; i < 8; i++) {
		float bw_bytes_per_sec = (float)bw_array[i] * 1000000.0 / 8.0;
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
	memcpy(&wrapper_out->prefix, &wrapper_in->prefix, sizeof(wrapper_out->prefix));
	
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
 */
static int build_bgpls_link_nlri(struct prefix *p, struct linkstate_info *ls_info)
{
	uint8_t *nlri_buf;
	uint8_t *alloc_buf = NULL;
	uint8_t tmp_buf[512];
	size_t offset = 0;

	if (!p || !ls_info) {
		return -1;
	}

	/* FRR 10.x: 不要清零整个 prefix，保留调用者设置的 family 和 prefixlen */
	// memset(p, 0, sizeof(*p));  // 不要这样做！会破坏 family 字段
	// p->family = AF_LINKSTATE;  // AF_LINKSTATE 未定义！
	// p->prefixlen = 0;
	
	/* 仅写入临时缓冲，避免破坏 prefix 结构 */
	memset(&p->u, 0, sizeof(p->u));
	memset(tmp_buf, 0, sizeof(tmp_buf));
	
	/* 使用临时缓冲区构造 NLRI */
	nlri_buf = tmp_buf;

	/* ------------------------------------------------------------------
	* 1.1 NLRI Type (2 bytes)
	* ------------------------------------------------------------------ */
	nlri_buf[offset++] = 0x00;  // Type高字节
	nlri_buf[offset++] = 0x02;  // Type低字节 = 0x0002 (Link NLRI)
	// 数据来源：固定值，表示这是Link类型的NLRI（RFC 7752定义）

	/* ------------------------------------------------------------------
	* 1.2 NLRI Length (2 bytes) - 先占位，后面回填
	* ------------------------------------------------------------------ */
	size_t length_offset = offset;  // 记录长度字段的位置
	nlri_buf[offset++] = 0x00;      // 长度高字节（占位）
	nlri_buf[offset++] = 0x00;      // 长度低字节（占位）
	// 数据来源：需要在所有数据编码完成后计算总长度并回填

	/* ------------------------------------------------------------------
	* 1.3 Protocol-ID (1 byte)
	* ------------------------------------------------------------------ */
	nlri_buf[offset++] = 0x05;  // Protocol-ID = 5 (Static)
	// 数据来源：固定值5，表示静态配置的链路状态信息

	/* ------------------------------------------------------------------
	* 1.4 Identifier (8 bytes) - 使用接口索引作为标识符
	* ------------------------------------------------------------------ */
	uint64_t identifier = (uint64_t)ls_info->if_index;
	memset(&nlri_buf[offset], 0, 8);  // 先清零
	nlri_buf[offset + 4] = (identifier >> 24) & 0xFF;
	nlri_buf[offset + 5] = (identifier >> 16) & 0xFF;
	nlri_buf[offset + 6] = (identifier >> 8) & 0xFF;
	nlri_buf[offset + 7] = identifier & 0xFF;
	offset += 8;
	// 数据来源：ls_info->if_index (接口索引，唯一标识这条链路)

	/* ------------------------------------------------------------------
	* 1.5 Local Node Descriptors (TLV 256)
	* ------------------------------------------------------------------ */
	// TLV 256: Local Node Descriptors
	nlri_buf[offset++] = 0x01;  // Type高字节 (256 = 0x0100)
	nlri_buf[offset++] = 0x00;  // Type低字节
	size_t local_node_len_offset = offset;  // 记录长度位置
	offset += 2;  // 跳过长度字段，稍后回填

	// Sub-TLV 515: IGP Router-ID (包含在Node Descriptor中)
	nlri_buf[offset++] = 0x02;  // Sub-TLV Type高字节 (515 = 0x0203)
	nlri_buf[offset++] = 0x03;  // Sub-TLV Type低字节
	nlri_buf[offset++] = 0x00;  // Sub-TLV Length高字节
	nlri_buf[offset++] = 0x04;  // Sub-TLV Length低字节 = 4 (IPv4地址长度)

	// 编码Router ID (4 bytes)
	nlri_buf[offset++] = (ls_info->router_id.s_addr >> 24) & 0xFF;
	nlri_buf[offset++] = (ls_info->router_id.s_addr >> 16) & 0xFF;
	nlri_buf[offset++] = (ls_info->router_id.s_addr >> 8) & 0xFF;
	nlri_buf[offset++] = ls_info->router_id.s_addr & 0xFF;
	// 数据来源：ls_info->router_id (本地路由器ID，来自linkstate_info结构体)

	// 回填Local Node Descriptors的长度
	uint16_t local_node_len = offset - local_node_len_offset - 2;
	nlri_buf[local_node_len_offset] = (local_node_len >> 8) & 0xFF;
	nlri_buf[local_node_len_offset + 1] = local_node_len & 0xFF;

	/* ------------------------------------------------------------------
	* 1.6 Remote Node Descriptors (TLV 257)
	* ------------------------------------------------------------------ */
	// TLV 257: Remote Node Descriptors
	nlri_buf[offset++] = 0x01;  // Type高字节 (257 = 0x0101)
	nlri_buf[offset++] = 0x01;  // Type低字节
	size_t remote_node_len_offset = offset;
	offset += 2;  // 跳过长度字段

	// Sub-TLV 515: IGP Router-ID
	nlri_buf[offset++] = 0x02;  // Sub-TLV Type高字节
	nlri_buf[offset++] = 0x03;  // Sub-TLV Type低字节
	nlri_buf[offset++] = 0x00;  // Sub-TLV Length高字节
	nlri_buf[offset++] = 0x04;  // Sub-TLV Length低字节

	// 编码Remote Router ID (4 bytes)
	nlri_buf[offset++] = (ls_info->remote_router_id.s_addr >> 24) & 0xFF;
	nlri_buf[offset++] = (ls_info->remote_router_id.s_addr >> 16) & 0xFF;
	nlri_buf[offset++] = (ls_info->remote_router_id.s_addr >> 8) & 0xFF;
	nlri_buf[offset++] = ls_info->remote_router_id.s_addr & 0xFF;
	// 数据来源：ls_info->remote_router_id (远端路由器ID，来自linkstate_info结构体)

	// 回填Remote Node Descriptors的长度
	uint16_t remote_node_len = offset - remote_node_len_offset - 2;
	nlri_buf[remote_node_len_offset] = (remote_node_len >> 8) & 0xFF;
	nlri_buf[remote_node_len_offset + 1] = remote_node_len & 0xFF;

	/* ------------------------------------------------------------------
	* 1.7 Link Descriptors
	* ------------------------------------------------------------------ */
	// TLV 259: IPv4 Interface Address
	nlri_buf[offset++] = 0x01;  // Type高字节 (259 = 0x0103)
	nlri_buf[offset++] = 0x03;  // Type低字节
	nlri_buf[offset++] = 0x00;  // Length高字节
	nlri_buf[offset++] = 0x04;  // Length低字节 = 4

	nlri_buf[offset++] = (ls_info->local_addr.s_addr >> 24) & 0xFF;
	nlri_buf[offset++] = (ls_info->local_addr.s_addr >> 16) & 0xFF;
	nlri_buf[offset++] = (ls_info->local_addr.s_addr >> 8) & 0xFF;
	nlri_buf[offset++] = ls_info->local_addr.s_addr & 0xFF;
	// 数据来源：ls_info->local_addr (本地接口IP地址，来自linkstate_info结构体)

	// TLV 260: IPv4 Neighbor Address
	nlri_buf[offset++] = 0x01;  // Type高字节 (260 = 0x0104)
	nlri_buf[offset++] = 0x04;  // Type低字节
	nlri_buf[offset++] = 0x00;  // Length高字节
	nlri_buf[offset++] = 0x04;  // Length低字节 = 4

	nlri_buf[offset++] = (ls_info->remote_addr.s_addr >> 24) & 0xFF;
	nlri_buf[offset++] = (ls_info->remote_addr.s_addr >> 16) & 0xFF;
	nlri_buf[offset++] = (ls_info->remote_addr.s_addr >> 8) & 0xFF;
	nlri_buf[offset++] = ls_info->remote_addr.s_addr & 0xFF;
	// 数据来源：ls_info->remote_addr (对端接口IP地址，来自linkstate_info结构体)

	/* ------------------------------------------------------------------
	* 1.8 回填NLRI总长度
	* ------------------------------------------------------------------ */
	uint16_t total_nlri_length = offset - 4;  // 不包括Type和Length字段本身
	nlri_buf[length_offset] = (total_nlri_length >> 8) & 0xFF;
	nlri_buf[length_offset + 1] = total_nlri_length & 0xFF;
	// 数据来源：计算得出（当前offset - 4）
	
	/* 检查长度并分配持久缓冲区 */
	if (offset == 0 || offset > sizeof(tmp_buf))
		return -1;

	alloc_buf = XCALLOC(MTYPE_BGP_LINKSTATE_NLRI, offset);
	if (!alloc_buf)
		return -1;

	memcpy(alloc_buf, tmp_buf, offset);

	/* 正确设置 AF_LINKSTATE 前缀指针与长度（字节数） */
	p->u.prefix_linkstate.nlri_type = 0x0002; /* Link NLRI */
	p->u.prefix_linkstate.ptr = (uintptr_t)alloc_buf;
	p->prefixlen = offset; /* length in bytes */
	
	/* 设置prefix长度（以bits为单位）
	 * BGP-LS NLRI的prefixlen应该是总字节数 * 8
	 * 这样BGP核心代码才能正确处理prefix
	 */
	p->prefixlen = offset * 8;
    
    return 0;  // 成功
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
	dest = bgp_node_get(table, &p);
	if (!dest) {
		if (p.u.prefix_linkstate.ptr) {
			void *nlri_ptr = (void *)p.u.prefix_linkstate.ptr;
			XFREE(MTYPE_BGP_LINKSTATE_NLRI, nlri_ptr);
		}
		return -1;
	}

	/* 释放临时 NLRI 缓冲区（已被 bgp_node_get 深拷贝） */
	if (p.u.prefix_linkstate.ptr) {
		void *nlri_ptr = (void *)p.u.prefix_linkstate.ptr;
		XFREE(MTYPE_BGP_LINKSTATE_NLRI, nlri_ptr);
	}
	
	//5: 创建BGP路径信息
	pi = info_make(ZEBRA_ROUTE_BGP,
		       BGP_ROUTE_STATIC,
		       0,
		       bgp->peer_self,
		       attr_new,
		       dest);
	
	if (!pi) {
		/* 注意：dest 由 bgp_node_get() 返回，属于 RIB 树管理，不应手动释放 */
		/* 需要 unlock dest 以释放我们的引用 */
		bgp_dest_unlock_node(dest);
		/* attr_new 也需要 unintern，因为没有 path_info 消费它 */
		bgp_attr_unintern(&attr_new);
		return -1;
	}
	
	//6: 添加到RIB
	bgp_path_info_add(dest, pi);  // 将pi添加到dest的路径链表中
	
	/* 手动设置路径为VALID，因为这是本地生成的路由 */
	SET_FLAG(pi->flags, BGP_PATH_VALID);
	
	/* 检查路径标志 */
	printf("[BGP-LS-INFO] pi->flags=0x%x, peer=%s, type=%d, sub_type=%d\n",
	       pi->flags, pi->peer->host, pi->type, pi->sub_type);
	printf("[BGP-LS-INFO] BGP_PATH_VALID=%d, BGP_PATH_SELECTED=%d, BGP_PATH_UNUSEABLE=%d\n",
	       CHECK_FLAG(pi->flags, BGP_PATH_VALID),
	       CHECK_FLAG(pi->flags, BGP_PATH_SELECTED),
	       CHECK_FLAG(pi->flags, BGP_PATH_UNUSEABLE));
	fflush(stdout);
	
	//插入哈希表映射（if_name → prefix）
	if (!bgp->linkstate_if_map) {
		bgp_linkstate_if_map_init(bgp);
	}
	
	struct linkstate_prefix_wrapper wrapper_key;
	memset(&wrapper_key, 0, sizeof(wrapper_key));
	strncpy(wrapper_key.if_name, ls_info->if_name, sizeof(wrapper_key.if_name) - 1);
	memcpy(&wrapper_key.prefix, &p, sizeof(p));
	
	/* 插入或更新哈希表（如果已存在会被替换）*/
	struct linkstate_prefix_wrapper *wrapper_result;
	wrapper_result = hash_get(bgp->linkstate_if_map, &wrapper_key,
	                          linkstate_if_map_alloc);
	
	if (wrapper_result) {
		printf("[BGP-LS-INFO] Added %s to interface map (hash table)\n", ls_info->if_name);
		fflush(stdout);
	} else {
		printf("[BGP-LS-WARN] Failed to add %s to interface map\n", ls_info->if_name);
		fflush(stdout);
	}
	
	//7: 触发BGP处理（自动生成UPDATE消息）
	printf("[BGP-LS-INFO] Calling bgp_process() for %s (AFI=%d, SAFI=%d)\n", 
	       ls_info->if_name, AFI_LINKSTATE, safi);
	
	/* 检查peer状态 */
	struct listnode *node;
	struct peer *peer_check;
	int peer_count = 0;
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer_check)) {
		peer_count++;
		printf("[BGP-LS-INFO] Peer %s: status=%d, afc[AFI_LINKSTATE][%d]=%d\n",
		       peer_check->host, peer_check->connection->status,
		       safi, peer_check->afc[AFI_LINKSTATE][safi]);
	}
	printf("[BGP-LS-INFO] Total peers: %d\n", peer_count);
	fflush(stdout);
	
	bgp_process(bgp, dest, pi, AFI_LINKSTATE, safi);
	/* bgp_process会：
	 * 1. 选择最优路径
	 * 2. 遍历所有BGP对等体
	 * 3. 调用group_announce_route()生成UPDATE消息
	 * 4. 将UPDATE发送给所有BGP-LS对等体
	 */
	
	printf("[BGP-LS-INFO] bgp_process() completed for %s\n", ls_info->if_name);
	fflush(stdout);
	
	//8: 释放节点锁
	bgp_dest_unlock_node(dest);
	
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

	struct prefix p;	//BGP-LS NLRI前缀，用于在RIB中查找已存在的dest节点
	struct bgp_dest *dest;	//查找到的RIB节点，如果为NULL说明链路不存在，会自动调用linkstate_add
	struct bgp_path_info *pi;	//dest中的现有路径信息，需要更新其attr指针指向新属性（先unintern旧的再intern新的）
	struct attr new_attr;	//基于旧属性复制并更新TLV字段的新属性，在栈上临时构造
	struct attr *attr_new;	//intern后的新属性指针，替换pi->attr实现属性更新，触发bgp_process发送UPDATE
	
	if (!bgp || !ls_info) {
		zlog_err("%s: Invalid parameters", __func__);
		return -1;
	}
	
	zlog_info("linkstate_update: Updating link-state (status=%d, bw=%u, metric=%u)",
		  ls_info->oper_status, ls_info->max_bandwidth, ls_info->igp_metric);
	
	//1: 构造BGP-LS NLRI前缀
	memset(&p, 0, sizeof(p));
	p.family = AF_LINKSTATE;   // AF_LINKSTATE (AF_MAX+3=48)
	p.prefixlen = 0;           // BGP-LS特殊规则：prefixlen设为0
	build_bgpls_link_nlri(&p, ls_info);		// 构造完整的NLRI内容
	
	//2: 查找RIB中的现有节点，找到返回 dest指针，找不到返回 NULL
	dest = bgp_node_lookup(bgp->rib[AFI_LINKSTATE][safi], &p);
	if (!dest) {
		/* 节点不存在，说明这是新链路，调用add函数 */
		zlog_info("%s: Link not found in RIB, calling linkstate_add", __func__);
		return linkstate_add(bgp, ls_info, safi);
	}
	
	//3: 查找该节点的路径信息
	pi = bgp_dest_get_bgp_path_info(dest);
	if (!pi) {
		/* 节点存在但没有路径信息（异常情况），调用add */
		zlog_warn("%s: Dest found but no path_info, calling linkstate_add", __func__);
		bgp_dest_unlock_node(dest);
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
	
	//5: 检查属性是否真的发生变化
	if (attrhash_cmp(pi->attr, &new_attr)) {
		/* 属性完全相同，无需更新 */
		zlog_debug("linkstate_update: Attributes unchanged, skipping update");
		// 释放临时属性（new_attr在栈上，link_state需要释放）
		if (new_attr.link_state) {
			XFREE(MTYPE_BGP_ATTR_LS_DATA, new_attr.link_state->data);
			XFREE(MTYPE_BGP_ATTR_LS, new_attr.link_state);
		}
		bgp_dest_unlock_node(dest);
		return 0;
	}
	// 数据来源：比较pi->attr和new_attr
	
	//6: 更新路径信息的属性
	bgp_attr_unintern(&pi->attr);       // 释放旧属性的引用
	attr_new = bgp_attr_intern(&new_attr);  // Intern新属性
	pi->attr = attr_new;                // 更新指针
	pi->uptime = monotime(NULL);        // 更新时间戳
	// 数据来源：new_attr → attr_new → pi->attr
	
	//7: 触发BGP处理（自动发送UPDATE消息）
	bgp_process(bgp, dest, pi, AFI_LINKSTATE, safi);
	/* bgp_process会：
	 * 1. 检测到属性变化
	 * 2. 生成UPDATE消息（包含新的Link Attribute TLVs）
	 * 3. 发送给所有BGP-LS对等体
	 */
	
	//8: 释放节点锁
	bgp_dest_unlock_node(dest);
	
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
	struct prefix p;	//从哈希表查找到的NLRI前缀，用于在RIB中定位要删除的dest节点
	struct bgp_dest *dest;	//要删除的RIB节点，通过p查找
	struct bgp_path_info *pi;	//dest中的路径信息，调用mark_for_delete标记删除
	
	if (!bgp || !if_name) {
		zlog_err("%s: Invalid parameters", __func__);
		return -1;
	}
	
	zlog_info("%s: Deleting link-state for %s", __func__, if_name);
	
	//1: 使用哈希表查找对应的BGP-LS前缀（O(1)查找）
	
	if (!bgp->linkstate_if_map) {
		zlog_err("%s: linkstate_if_map not initialized", __func__);
		return -1;
	}
	
	/* 准备查找键 */
	struct linkstate_prefix_wrapper lookup_key;
	memset(&lookup_key, 0, sizeof(lookup_key));
	strncpy(lookup_key.if_name, if_name, sizeof(lookup_key.if_name) - 1);
	
	/* 在哈希表中查找 */
	struct linkstate_prefix_wrapper *wrapper;
	wrapper = hash_lookup(bgp->linkstate_if_map, &lookup_key);
	if (!wrapper) {
		zlog_warn("%s: Cannot find link-state for interface %s in hash map",
		          __func__, if_name);
		return -1;
	}
	
	/* 复制找到的前缀 */
	memcpy(&p, &wrapper->prefix, sizeof(p));
	zlog_debug("%s: Found prefix for %s in hash map", __func__, if_name);
	
	//2: 查找RIB中的节点
	dest = bgp_node_lookup(bgp->rib[AFI_LINKSTATE][safi], &p);
	if (!dest) {
		zlog_warn("%s: Link-state dest not found for %s in RIB", __func__, if_name);
		/* 即使RIB中找不到，也要清理哈希表 */
		wrapper = hash_release(bgp->linkstate_if_map, &lookup_key);
		if (wrapper) {
			XFREE(MTYPE_BGP_LINKSTATE_WRAPPER, wrapper);
		}
		return -1;
	}
	
	//3: 获取路径信息
	pi = bgp_dest_get_bgp_path_info(dest);
	if (!pi) {
		/* 节点存在但无路径信息（异常情况）*/
		zlog_warn("%s: Dest found but no path_info for %s", __func__, if_name);
		bgp_dest_unlock_node(dest);
		/* 清理哈希表 */
		wrapper = hash_release(bgp->linkstate_if_map, &lookup_key);
		if (wrapper) {
			XFREE(MTYPE_BGP_LINKSTATE_WRAPPER, wrapper);
		}
		return -1;
	}
	
	//4: 标记路径为待删除
	bgp_path_info_mark_for_delete(dest, pi);
	/* 这会设置BGP_PATH_REMOVED标志，bgp_process会检测到这个标志 */
	
	//5: 触发BGP处理（自动发送WITHDRAW消息）
	bgp_process(bgp, dest, pi, AFI_LINKSTATE, safi);
	/* bgp_process会：
	 * 1. 检测到路径被标记为删除（BGP_PATH_REMOVED）
	 * 2. 调用bgp_path_info_reap()实际删除路径
	 * 3. 生成BGP UPDATE消息，WITHDRAWN_ROUTES包含该NLRI
	 * 4. 发送WITHDRAW给所有BGP-LS对等体
	 * 5. 对等体收到后会从其RIB中删除该链路状态
	 */
	
	//6: 释放节点锁
	bgp_dest_unlock_node(dest);
	
	//7: 从哈希表删除映射
	wrapper = hash_release(bgp->linkstate_if_map, &lookup_key);
	if (wrapper) {
		XFREE(MTYPE_BGP_LINKSTATE_WRAPPER, wrapper);
		zlog_debug("%s: Removed %s from interface map (hash table)",
		          __func__, if_name);
	} else {
		zlog_warn("%s: Failed to remove %s from interface map",
		         __func__, if_name);
	}
	
	zlog_info("%s: Successfully deleted link-state for %s", __func__,
		  if_name);
	return 0;
}

