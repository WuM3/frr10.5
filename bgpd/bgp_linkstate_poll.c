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
#include "linklist.h"
#include "command.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_linkstate.h"
#include "bgpd/bgp_linkstate_tlv.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_vty.h"
//#include "bgpd/bgp_ls_tvr.h"
#include "if.h"
#include "zclient.h"
#include <json-c/json.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* 临时禁用本文件的日志，避免 NSS 相关崩溃 */
/* 使用 printf 替代关键日志点，避免NSS调用 */
#undef zlog_debug
#undef zlog_info
#undef zlog_warn
#undef zlog_err
#define zlog_debug(...) do { } while (0)
#define zlog_info(...) printf("[BGP-LS-INFO] " __VA_ARGS__); printf("\n"); fflush(stdout)
#define zlog_warn(...) printf("[BGP-LS-WARN] " __VA_ARGS__); printf("\n"); fflush(stdout)
#define zlog_err(...) printf("[BGP-LS-ERROR] " __VA_ARGS__); printf("\n"); fflush(stdout)

/* 默认轮询间隔（秒） */
#define DEFAULT_LINKSTATE_POLL_INTERVAL 30

/* 链路状态配置文件目录和格式 */
#define LINKSTATE_CONFIG_DIR "/etc/frr/linkstate"
#define LINKSTATE_CONFIG_PATTERN "linkstate_"
#define LINKSTATE_CONFIG_EXT ".json"

/* 接口状态缓存结构（用于记录上次轮询的状态）*/
struct linkstate_cache_entry {
	char if_name[IFNAMSIZ];              /* 接口名（作为键）*/
	struct linkstate_info last_state;    /* 上次轮询的状态 */
	bool exists;                          /* 标记接口是否还存在 */
};

/* 内存类型 */
DEFINE_MTYPE_STATIC(BGPD, BGP_LINKSTATE_CACHE, "BGP LinkState Cache Entry");

/* 链路状态轮询定时器回调 */
static void bgp_linkstate_poll_timer(struct event *thread);

/* 哈希表操作函数 */
static unsigned int linkstate_cache_hash_key(const void *data)
{
	const struct linkstate_cache_entry *entry = data;
	return jhash(entry->if_name, strlen(entry->if_name), 0);
}

static bool linkstate_cache_hash_cmp(const void *d1, const void *d2)
{
	const struct linkstate_cache_entry *e1 = d1;
	const struct linkstate_cache_entry *e2 = d2;
	return (strcmp(e1->if_name, e2->if_name) == 0);
}

static void *linkstate_cache_hash_alloc(void *data)
{
	struct linkstate_cache_entry *entry = data;
	struct linkstate_cache_entry *new_entry;
	
	new_entry = XCALLOC(MTYPE_BGP_LINKSTATE_CACHE, sizeof(*new_entry));
	memcpy(new_entry, entry, sizeof(*new_entry));
	return new_entry;
}

/* 初始化状态缓存哈希表 */
static struct hash *linkstate_cache_init(void)
{
	return hash_create(linkstate_cache_hash_key,
	                   linkstate_cache_hash_cmp,
	                   "BGP LinkState Cache");
}

/* Free linkstate cache entry */
static void linkstate_cache_entry_free(void *data)
{
	XFREE(MTYPE_BGP_LINKSTATE_CACHE, data);
}

/* 清理缓存哈希表 */
static void linkstate_cache_finish(struct hash *cache)
{
	if (cache) {
		hash_clean(cache, linkstate_cache_entry_free);
		hash_free(cache);
	}
}

/**
 * 构造测试用的链路状态信息（当zebra不可用时）
 * 
 * @param if_name 接口名称
 * @param ls_info 输出的链路状态信息
 * @return 0 成功
 */
static int create_test_linkstate(const char *if_name, struct linkstate_info *ls_info)
{
	int i;
	
	if (!if_name ||!ls_info)
		return -1;
	
	memset(ls_info, 0, sizeof(*ls_info));
	
	/* 安全地复制接口名 */
	strncpy(ls_info->if_name, if_name, sizeof(ls_info->if_name) - 1);
	ls_info->if_name[sizeof(ls_info->if_name) - 1] = '\0';

	/* 硬编码测试数据 */
	ls_info->if_index = 999;
	ls_info->oper_status = 1;
	ls_info->admin_status = 1;
	ls_info->max_bandwidth = 1000000000;
	ls_info->max_reservable_bw = 1000000000;
	
	for (i = 0; i < 8; i++)
		ls_info->unreserved_bw[i] = 1000000000;

	ls_info->igp_metric = 10;
	ls_info->te_metric = 10;
	ls_info->admin_group = 0;
	ls_info->last_update = 0;

	return 0;
}

/**
 * 从系统读取单个接口的链路状态信息
 * 
 * @param if_name 接口名称
 * @param ls_info 输出的链路状态信息
 * @return 0 成功, -1 失败
 */
static int read_interface_linkstate(const char *if_name, struct linkstate_info *ls_info)
{
	struct interface *ifp;
	struct vrf *vrf;

	if (!if_name || !ls_info) {
		return -1;
	}

	memset(ls_info, 0, sizeof(*ls_info));
	snprintf(ls_info->if_name, sizeof(ls_info->if_name), "%s", if_name);

	/* 从 zebra 获取接口信息 */
	RB_FOREACH(vrf, vrf_name_head, &vrfs_by_name) {
		ifp = if_lookup_by_name(if_name, vrf->vrf_id);
		if (ifp)
			break;
	}

	if (!ifp) {
		/* 如果找不到接口，使用测试数据 */
		return create_test_linkstate(if_name, ls_info);
	}

	/* 填充基本接口信息 */
	ls_info->if_index = ifp->ifindex;
	ls_info->oper_status = if_is_up(ifp) ? 1 : 0;
	ls_info->admin_status = CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE) ? 1 : 0;

	/* 带宽信息 (转换为 bps) */
	if (ifp->bandwidth > 0) {
		ls_info->max_bandwidth = ifp->bandwidth * 1000; /* kbps -> bps */
		ls_info->max_reservable_bw = ls_info->max_bandwidth;
		/* 初始化未预留带宽（8个优先级全部可用）*/
		for (int i = 0; i < 8; i++)
			ls_info->unreserved_bw[i] = ls_info->max_bandwidth;
	}

	/* 度量值 (默认值，实际应从IGP获取) */
	ls_info->igp_metric = ifp->metric ? ifp->metric : 10;
	ls_info->te_metric = ls_info->igp_metric;

	/* 管理组 (默认为0) */
	ls_info->admin_group = 0;

	/* TODO: 从 IGP (OSPF/ISIS) 获取更详细的TE信息:
	 * - TE metric from OSPF/ISIS
	 * - SRLG information
	 * - Extended administrative groups
	 * - Local/Remote IP addresses from neighbor discovery
	 * - Router IDs from IGP
	 */

	ls_info->last_update = time(NULL);

	return 0;
}

/* ========================================================================
 * UDP Socket Server for Link-State Updates
 * ======================================================================== */

/* UDP服务器默认端口 */
#define LINKSTATE_UDP_PORT 9999
#define LINKSTATE_UDP_BUF_SIZE 65536

/* UDP服务器状态 */
static int udp_server_fd = -1;
static struct event *udp_server_event = NULL;

/**
 * 解析单个链路的JSON对象（复用read_linkstate_from_config的逻辑）
 * 
 * @param link_obj JSON链路对象
 * @param ls_info 输出的链路状态信息
 * @return 0 成功, -1 失败
 */
static int parse_link_json_object(struct json_object *link_obj,
                                   struct linkstate_info *ls_info)
{
	struct json_object *nlri_obj, *attr_obj;
	struct json_object *local_node, *remote_node, *link_desc, *unreserved_bw_array;
	
	if (!link_obj || !ls_info)
		return -1;
	
	memset(ls_info, 0, sizeof(*ls_info));
	
	/* 读取接口名 */
	struct json_object *if_name_obj;
	if (json_object_object_get_ex(link_obj, "if_name", &if_name_obj)) {
		snprintf(ls_info->if_name, sizeof(ls_info->if_name), "%s",
		         json_object_get_string(if_name_obj));
	} else {
		zlog_err("%s: Missing 'if_name' in link object", __func__);
		return -1;
	}
	
	/* 读取接口索引 */
	struct json_object *if_index_obj;
	if (json_object_object_get_ex(link_obj, "if_index", &if_index_obj)) {
		ls_info->if_index = json_object_get_int(if_index_obj);
	}
	
	/* 读取NLRI字段 */
	if (json_object_object_get_ex(link_obj, "nlri", &nlri_obj)) {
		/* Local Node */
		if (json_object_object_get_ex(nlri_obj, "local_node", &local_node)) {
			struct json_object *router_id_obj;
			if (json_object_object_get_ex(local_node, "router_id", &router_id_obj)) {
				inet_pton(AF_INET, json_object_get_string(router_id_obj),
				          &ls_info->router_id);
			}
		}
		
		/* Remote Node */
		if (json_object_object_get_ex(nlri_obj, "remote_node", &remote_node)) {
			struct json_object *router_id_obj;
			if (json_object_object_get_ex(remote_node, "router_id", &router_id_obj)) {
				inet_pton(AF_INET, json_object_get_string(router_id_obj),
				          &ls_info->remote_router_id);
			}
		}
		
		/* Link Descriptors */
		if (json_object_object_get_ex(nlri_obj, "link_descriptors", &link_desc)) {
			struct json_object *local_ipv4_obj, *remote_ipv4_obj;
			if (json_object_object_get_ex(link_desc, "local_ipv4", &local_ipv4_obj)) {
				inet_pton(AF_INET, json_object_get_string(local_ipv4_obj),
				          &ls_info->local_addr);
			}
			if (json_object_object_get_ex(link_desc, "remote_ipv4", &remote_ipv4_obj)) {
				inet_pton(AF_INET, json_object_get_string(remote_ipv4_obj),
				          &ls_info->remote_addr);
			}
		}
	}
	
	/* 读取Attributes字段 */
	if (json_object_object_get_ex(link_obj, "attributes", &attr_obj)) {
		struct json_object *val;
		
		if (json_object_object_get_ex(attr_obj, "oper_status", &val))
			ls_info->oper_status = json_object_get_int(val);
		
		if (json_object_object_get_ex(attr_obj, "max_bandwidth", &val))
			ls_info->max_bandwidth = json_object_get_int64(val);
		
		if (json_object_object_get_ex(attr_obj, "te_metric", &val))
			ls_info->te_metric = json_object_get_int(val);
		
		if (json_object_object_get_ex(attr_obj, "igp_metric", &val))
			ls_info->igp_metric = json_object_get_int(val);
		
		if (json_object_object_get_ex(attr_obj, "admin_group", &val))
			ls_info->admin_group = json_object_get_int(val);
		
		if (json_object_object_get_ex(attr_obj, "spf_sequence_number", &val))
			ls_info->spf_sequence_number = json_object_get_int64(val);
		
		if (json_object_object_get_ex(attr_obj, "spf_status", &val))
			ls_info->spf_status = json_object_get_int(val);
		
		/* Unreserved Bandwidth数组 */
		if (json_object_object_get_ex(attr_obj, "unreserved_bw", &unreserved_bw_array)) {
			int bw_len = json_object_array_length(unreserved_bw_array);
			for (int j = 0; j < bw_len && j < 8; j++) {
				struct json_object *bw_obj = json_object_array_get_idx(unreserved_bw_array, j);
				ls_info->unreserved_bw[j] = json_object_get_int64(bw_obj);
			}
		}
		
		ls_info->max_reservable_bw = ls_info->max_bandwidth;
	}
	
	ls_info->last_update = time(NULL);
	
	return 0;
}

/**
 * 解析单个节点的JSON对象
 * 
 * JSON格式示例:
 * {
 *   "node_name": "router1.example.com",
 *   "descriptors": {
 *     "asn": 65001,
 *     "bgpls_id": 0,
 *     "ospf_area_id": 0,
 *     "router_id": "192.168.1.1",
 *     "protocol_id": 5,
 *     "identifier": 0
 *   },
 *   "attributes": {
 *     "node_flags": 0,
 *     "te_router_id": "192.168.1.1",
 *     "sr_capabilities": {
 *       "flags": 192,
 *       "srgb_base": 16000,
 *       "srgb_range": 8000
 *     },
 *     "sr_algorithms": [0, 1],
 *     "srlb": {
 *       "base": 15000,
 *       "range": 1000
 *     },
 *     "oper_status": 1
 *   }
 * }
 * 
 * @param node_obj JSON节点对象
 * @param ns_info 输出的节点状态信息
 * @return 0 成功, -1 失败
 */
static int parse_node_json_object(struct json_object *node_obj,
                                   struct nodestate_info *ns_info)
{
	struct json_object *nlri_obj, *desc_obj, *attr_obj, *val;
	
	if (!node_obj || !ns_info)
		return -1;
	
	memset(ns_info, 0, sizeof(*ns_info));
	
	/* 默认oper_status为UP，除非显式设置为0 */
	ns_info->oper_status = 1;
	
	/* 读取节点名称（必需字段）*/
	struct json_object *node_name_obj;
	if (json_object_object_get_ex(node_obj, "node_name", &node_name_obj)) {
		snprintf(ns_info->node_name, sizeof(ns_info->node_name), "%s",
		         json_object_get_string(node_name_obj));
	} else {
		zlog_err("%s: Missing 'node_name' in node object", __func__);
		return -1;
	}
	
	/* 读取NLRI字段（支持新格式：nlri.local_node_descriptors）*/
	if (json_object_object_get_ex(node_obj, "nlri", &nlri_obj)) {
		/* Protocol ID (在nlri层级) */
		if (json_object_object_get_ex(nlri_obj, "protocol_id", &val))
			ns_info->protocol_id = json_object_get_int(val);
		
		/* Instance Identifier (在nlri层级) */
		if (json_object_object_get_ex(nlri_obj, "identifier", &val))
			ns_info->identifier = json_object_get_int64(val);
		
		/* Local Node Descriptors (新格式) */
		if (json_object_object_get_ex(nlri_obj, "local_node_descriptors", &desc_obj)) {
			/* Autonomous System Number (Sub-TLV 512) */
			if (json_object_object_get_ex(desc_obj, "asn", &val))
				ns_info->asn = json_object_get_int(val);
			
			/* BGP-LS Identifier (Sub-TLV 513) */
			if (json_object_object_get_ex(desc_obj, "bgpls_id", &val))
				ns_info->bgpls_id = json_object_get_int(val);
			
			/* OSPF Area-ID (Sub-TLV 514) */
			if (json_object_object_get_ex(desc_obj, "ospf_area_id", &val))
				ns_info->ospf_area_id = json_object_get_int(val);
			
			/* IGP Router-ID (Sub-TLV 515) */
			if (json_object_object_get_ex(desc_obj, "router_id", &val)) {
				inet_pton(AF_INET, json_object_get_string(val),
				          &ns_info->router_id);
			}
			
			/* IS-IS ISO System-ID (hex string, e.g., "0102.0304.0506") */
			if (json_object_object_get_ex(desc_obj, "iso_node_id", &val)) {
				const char *iso_str = json_object_get_string(val);
				/* 简化解析：假设格式为 "XXXX.XXXX.XXXX" */
				if (iso_str && strlen(iso_str) >= 14) {
					uint8_t *id = ns_info->iso_node_id;
					sscanf(iso_str, "%2hhx%2hhx.%2hhx%2hhx.%2hhx%2hhx",
					       &id[0], &id[1], &id[2], &id[3], &id[4], &id[5]);
					ns_info->iso_node_id_len = 6;
				}
			}
		}
	}
	/* 兼容旧格式：直接在node_obj下的descriptors字段 */
	else if (json_object_object_get_ex(node_obj, "descriptors", &desc_obj)) {
		/* Autonomous System Number (Sub-TLV 512) */
		if (json_object_object_get_ex(desc_obj, "asn", &val))
			ns_info->asn = json_object_get_int(val);
		
		/* BGP-LS Identifier (Sub-TLV 513) */
		if (json_object_object_get_ex(desc_obj, "bgpls_id", &val))
			ns_info->bgpls_id = json_object_get_int(val);
		
		/* OSPF Area-ID (Sub-TLV 514) */
		if (json_object_object_get_ex(desc_obj, "ospf_area_id", &val))
			ns_info->ospf_area_id = json_object_get_int(val);
		
		/* IGP Router-ID (Sub-TLV 515) */
		if (json_object_object_get_ex(desc_obj, "router_id", &val)) {
			inet_pton(AF_INET, json_object_get_string(val),
			          &ns_info->router_id);
		}
		
		/* Protocol ID */
		if (json_object_object_get_ex(desc_obj, "protocol_id", &val))
			ns_info->protocol_id = json_object_get_int(val);
		
		/* Instance Identifier */
		if (json_object_object_get_ex(desc_obj, "identifier", &val))
			ns_info->identifier = json_object_get_int64(val);
		
		/* IS-IS ISO System-ID (hex string, e.g., "0102.0304.0506") */
		if (json_object_object_get_ex(desc_obj, "iso_node_id", &val)) {
			const char *iso_str = json_object_get_string(val);
			/* 简化解析：假设格式为 "XXXX.XXXX.XXXX" */
			if (iso_str && strlen(iso_str) >= 14) {
				uint8_t *id = ns_info->iso_node_id;
				sscanf(iso_str, "%2hhx%2hhx.%2hhx%2hhx.%2hhx%2hhx",
				       &id[0], &id[1], &id[2], &id[3], &id[4], &id[5]);
				ns_info->iso_node_id_len = 6;
			}
		}
	}
	
	/* 读取Node Attributes字段 */
	if (json_object_object_get_ex(node_obj, "attributes", &attr_obj)) {
		/* Node Flag Bits (TLV 1024) */
		if (json_object_object_get_ex(attr_obj, "node_flags", &val))
			ns_info->node_flags = json_object_get_int(val);
		
		/* IPv4 TE Router-ID (TLV 1028) */
		if (json_object_object_get_ex(attr_obj, "te_router_id", &val)) {
			inet_pton(AF_INET, json_object_get_string(val),
			          &ns_info->te_router_id);
		}
		
		/* IPv6 TE Router-ID (TLV 1029) */
		if (json_object_object_get_ex(attr_obj, "te_router_id_v6", &val)) {
			inet_pton(AF_INET6, json_object_get_string(val),
			          &ns_info->te_router_id_v6);
		}
		
		/* IS-IS Area Identifier (TLV 1027) */
		if (json_object_object_get_ex(attr_obj, "isis_area_id", &val)) {
			const char *area_str = json_object_get_string(val);
			if (area_str) {
				/* 简化解析：假设格式为 "49.0001" 等 */
				size_t len = strlen(area_str);
				if (len > 0 && len <= 13) {
					/* 直接作为字符串存储（实际应解析为字节）*/
					memcpy(ns_info->isis_area_id, area_str, len);
					ns_info->isis_area_id_len = len;
				}
			}
		}
		
		/* SR Capabilities (RFC 9085 TLV 1034) */
		struct json_object *sr_cap_obj;
		if (json_object_object_get_ex(attr_obj, "sr_capabilities", &sr_cap_obj)) {
			if (json_object_object_get_ex(sr_cap_obj, "flags", &val))
				ns_info->sr_capability_flags = json_object_get_int(val);
			if (json_object_object_get_ex(sr_cap_obj, "srgb_base", &val))
				ns_info->srgb_base = json_object_get_int(val);
			if (json_object_object_get_ex(sr_cap_obj, "srgb_range", &val))
				ns_info->srgb_range = json_object_get_int(val);
		}
		
		/* SR Algorithms (RFC 9085 TLV 1035) */
		struct json_object *sr_algo_array;
		if (json_object_object_get_ex(attr_obj, "sr_algorithms", &sr_algo_array)) {
			int algo_len = json_object_array_length(sr_algo_array);
			if (algo_len > 8) algo_len = 8;
			for (int j = 0; j < algo_len; j++) {
				struct json_object *algo_obj = json_object_array_get_idx(sr_algo_array, j);
				ns_info->sr_algorithms[j] = json_object_get_int(algo_obj);
			}
			ns_info->sr_algorithm_count = algo_len;
		}
		
		/* SR Local Block (RFC 9085 TLV 1036) - 支持两种格式 */
		struct json_object *srlb_obj;
		/* 新格式: sr_local_block: {srlb_base, srlb_range} */
		if (json_object_object_get_ex(attr_obj, "sr_local_block", &srlb_obj)) {
			if (json_object_object_get_ex(srlb_obj, "srlb_base", &val))
				ns_info->srlb_base = json_object_get_int(val);
			if (json_object_object_get_ex(srlb_obj, "srlb_range", &val))
				ns_info->srlb_range = json_object_get_int(val);
		}
		/* 旧格式: srlb: {base, range} */
		else if (json_object_object_get_ex(attr_obj, "srlb", &srlb_obj)) {
			if (json_object_object_get_ex(srlb_obj, "base", &val))
				ns_info->srlb_base = json_object_get_int(val);
			if (json_object_object_get_ex(srlb_obj, "range", &val))
				ns_info->srlb_range = json_object_get_int(val);
		}
		
		/* SRMS Preference (RFC 9085 TLV 1037) */
		if (json_object_object_get_ex(attr_obj, "srms_preference", &val))
			ns_info->srms_preference = json_object_get_int(val);
		
		/* 操作状态 (类似link的oper_status) */
		if (json_object_object_get_ex(attr_obj, "oper_status", &val))
			ns_info->oper_status = json_object_get_int(val);
	}
	
	ns_info->last_update = time(NULL);
	
	printf("[BGP-LS-UDP] Parsed node: name=%s, router_id=%s, asn=%u\n",
	       ns_info->node_name, inet_ntoa(ns_info->router_id), ns_info->asn);
	fflush(stdout);
	
	return 0;
}

/**
 * 处理UDP接收到的JSON数据
 * 
 * 支持的格式:
 * 1. {"links": [...]} - 批量链路数组
 * 2. {"nodes": [...]} - 批量节点数组
 * 3. {"links": [...], "nodes": [...]} - 混合模式
 * 4. {"if_name": "...", ...} - 单个链路对象
 * 5. {"node_name": "...", ...} - 单个节点对象
 * 
 * @param bgp BGP实例
 * @param json_data JSON数据字符串
 * @param data_len 数据长度
 * @return 处理的对象数量，失败返回-1
 */
static int process_udp_linkstate_data(struct bgp *bgp, const char *json_data, size_t data_len)
{
	struct json_object *root, *links_array, *nodes_array, *link_obj, *node_obj;
	int link_count = 0, node_count = 0;
	int link_processed = 0, node_processed = 0;
	
	if (!bgp || !json_data || data_len == 0) {
		zlog_err("%s: Invalid parameters", __func__);
		return -1;
	}
	
	/* 解析JSON */
	root = json_tokener_parse(json_data);
	if (!root) {
		zlog_err("%s: Failed to parse JSON data", __func__);
		return -1;
	}
	
	/* ================================================================
	 * 处理Links数组
	 * ================================================================ */
	if (json_object_object_get_ex(root, "links", &links_array)) {
		int array_len = json_object_array_length(links_array);
		
		zlog_info("%s: Processing batch of %d links from UDP", __func__, array_len);
		printf("[BGP-LS-UDP] Processing %d links\n", array_len);
		fflush(stdout);
		
		for (int i = 0; i < array_len; i++) {
			link_obj = json_object_array_get_idx(links_array, i);
			if (!link_obj)
				continue;
			
			struct linkstate_info ls_info;
			if (parse_link_json_object(link_obj, &ls_info) != 0) {
				zlog_warn("%s: Failed to parse link object %d", __func__, i);
				continue;
			}
			
			link_count++;
			int ret = 0;
			
			if (ls_info.oper_status == 0) {
				printf("[BGP-LS-UDP] Link %s is DOWN, calling linkstate_delete\n",
				       ls_info.if_name);
				fflush(stdout);
				ret = linkstate_delete(bgp, ls_info.if_name, SAFI_LINKSTATE);
			} else {
				printf("[BGP-LS-UDP] Link %s is UP (oper_status=%d), calling linkstate_update\n",
				       ls_info.if_name, ls_info.oper_status);
				fflush(stdout);
				ret = linkstate_update(bgp, &ls_info, SAFI_LINKSTATE);
			}
			
			if (ret == 0)
				link_processed++;
		}
	}
	
	/* ================================================================
	 * 处理Nodes数组
	 * ================================================================ */
	if (json_object_object_get_ex(root, "nodes", &nodes_array)) {
		int array_len = json_object_array_length(nodes_array);
		
		zlog_info("%s: Processing batch of %d nodes from UDP", __func__, array_len);
		printf("[BGP-LS-UDP] Processing %d nodes\n", array_len);
		fflush(stdout);
		
		for (int i = 0; i < array_len; i++) {
			node_obj = json_object_array_get_idx(nodes_array, i);
			if (!node_obj)
				continue;
			
			struct nodestate_info ns_info;
			if (parse_node_json_object(node_obj, &ns_info) != 0) {
				zlog_warn("%s: Failed to parse node object %d", __func__, i);
				continue;
			}
			
			node_count++;
			int ret = 0;
			
			if (ns_info.oper_status == 0) {
				printf("[BGP-LS-UDP] Node %s is DOWN, calling nodestate_delete\n",
				       ns_info.node_name);
				fflush(stdout);
				ret = nodestate_delete(bgp, ns_info.node_name, SAFI_LINKSTATE);
			} else {
				printf("[BGP-LS-UDP] Node %s is UP (oper_status=%d), calling nodestate_update\n",
				       ns_info.node_name, ns_info.oper_status);
				fflush(stdout);
				ret = nodestate_update(bgp, &ns_info, SAFI_LINKSTATE);
			}
			
			if (ret == 0)
				node_processed++;
		}
	}
	
	/* ================================================================
	 * 处理单个对象（向后兼容）
	 * ================================================================ */
	if (link_count == 0 && node_count == 0) {
		/* 检查是否是单个link对象 */
		if (json_object_object_get_ex(root, "if_name", NULL)) {
			struct linkstate_info ls_info;
			
			if (parse_link_json_object(root, &ls_info) == 0) {
				link_count = 1;
				int ret = 0;
				
				if (ls_info.oper_status == 0) {
					printf("[BGP-LS-UDP] Link %s is DOWN, calling linkstate_delete\n",
					       ls_info.if_name);
					fflush(stdout);
					ret = linkstate_delete(bgp, ls_info.if_name, SAFI_LINKSTATE);
				} else {
					printf("[BGP-LS-UDP] Link %s is UP (oper_status=%d), calling linkstate_update\n",
					       ls_info.if_name, ls_info.oper_status);
					fflush(stdout);
					ret = linkstate_update(bgp, &ls_info, SAFI_LINKSTATE);
				}
				
				if (ret == 0)
					link_processed++;
			}
		}
		/* 检查是否是单个node对象 */
		else if (json_object_object_get_ex(root, "node_name", NULL)) {
			struct nodestate_info ns_info;
			
			if (parse_node_json_object(root, &ns_info) == 0) {
				node_count = 1;
				int ret = 0;
				
				if (ns_info.oper_status == 0) {
					printf("[BGP-LS-UDP] Node %s is DOWN, calling nodestate_delete\n",
					       ns_info.node_name);
					fflush(stdout);
					ret = nodestate_delete(bgp, ns_info.node_name, SAFI_LINKSTATE);
				} else {
					printf("[BGP-LS-UDP] Node %s is UP (oper_status=%d), calling nodestate_update\n",
					       ns_info.node_name, ns_info.oper_status);
					fflush(stdout);
					ret = nodestate_update(bgp, &ns_info, SAFI_LINKSTATE);
				}
				
				if (ret == 0)
					node_processed++;
			}
		}
		else {
			zlog_err("%s: Unknown JSON format - expected 'links', 'nodes', 'if_name', or 'node_name'",
			         __func__);
			json_object_put(root);
			return -1;
		}
	}
	
	json_object_put(root);
	
	int total_count = link_count + node_count;
	int total_processed = link_processed + node_processed;
	
	zlog_info("%s: Processed %d/%d objects (links: %d/%d, nodes: %d/%d)",
	          __func__, total_processed, total_count,
	          link_processed, link_count, node_processed, node_count);
	
	printf("[BGP-LS-UDP] Total processed: %d/%d (links: %d/%d, nodes: %d/%d)\n",
	       total_processed, total_count,
	       link_processed, link_count, node_processed, node_count);
	fflush(stdout);
	
	return total_processed;
}

/**
 * UDP服务器事件回调 - 接收并处理链路状态数据
 * 
 * @param thread 事件线程
 */
static void bgp_linkstate_udp_read(struct event *thread)
{
	struct bgp *bgp;
	char buf[LINKSTATE_UDP_BUF_SIZE];
	struct sockaddr_in client_addr;
	socklen_t addr_len = sizeof(client_addr);
	ssize_t recv_len;
	
	bgp = EVENT_ARG(thread);
	
	if (!bgp || udp_server_fd < 0) {
		zlog_err("%s: Invalid state", __func__);
		return;
	}
	
	/* 接收UDP数据 */
	recv_len = recvfrom(udp_server_fd, buf, sizeof(buf) - 1, 0,
	                    (struct sockaddr *)&client_addr, &addr_len);
	
	printf("[DEBUG-UDP] recvfrom returned: %zd\n", recv_len);
	fflush(stdout);
	
	if (recv_len < 0) {
		printf("[DEBUG-UDP] recvfrom error: %s\n", strerror(errno));
		fflush(stdout);
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			zlog_err("%s: recvfrom failed: %s", __func__, strerror(errno));
		}
		goto reschedule;
	}
	
	if (recv_len == 0) {
		printf("[DEBUG-UDP] recvfrom returned 0, goto reschedule\n");
		fflush(stdout);
		goto reschedule;
	}
	
	/* 确保字符串结尾 */
	buf[recv_len] = '\0';
	
	char client_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
	
	printf("[DEBUG-UDP] Received %zd bytes from %s:%d\n", recv_len, client_ip, ntohs(client_addr.sin_port));
	printf("[DEBUG-UDP] Data: %s\n", buf);
	fflush(stdout);
	
	zlog_info("%s: Received %zd bytes from %s:%d",
	          __func__, recv_len, client_ip, ntohs(client_addr.sin_port));
	
	/* 处理接收到的JSON数据 */
	int result = process_udp_linkstate_data(bgp, buf, recv_len);
	if (result < 0) {
		zlog_warn("%s: Failed to process UDP data from %s",
		          __func__, client_ip);
	}
	
reschedule:
	/* 重新注册读事件 */
	event_add_read(bm->master, bgp_linkstate_udp_read, bgp,
	               udp_server_fd, &udp_server_event);
}

/**
 * 启动UDP socket服务器接收链路状态信息
 * 
 * @param bgp BGP实例
 * @param port UDP端口号（0表示使用默认端口9999）
 * @return 0 成功, -1 失败
 */
int bgp_linkstate_udp_server_start(struct bgp *bgp, uint16_t port)
{
	struct sockaddr_in server_addr;
	int opt = 1;
	
	if (!bgp) {
		zlog_err("%s: BGP instance is NULL", __func__);
		return -1;
	}
	
	/* 如果已经在运行，先停止 */
	if (udp_server_fd >= 0) {
		zlog_warn("%s: UDP server already running, restarting...", __func__);
		bgp_linkstate_udp_server_stop();
	}
	
	/* 使用默认端口 */
	if (port == 0)
		port = LINKSTATE_UDP_PORT;
	
	/* 创建UDP socket */
	udp_server_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_server_fd < 0) {
		zlog_err("%s: Failed to create UDP socket: %s",
		         __func__, strerror(errno));
		return -1;
	}
	
	/* 设置socket选项 */
	if (setsockopt(udp_server_fd, SOL_SOCKET, SO_REUSEADDR,
	               &opt, sizeof(opt)) < 0) {
		zlog_warn("%s: setsockopt SO_REUSEADDR failed: %s",
		          __func__, strerror(errno));
	}
	
	/* 设置为非阻塞模式 */
	int flags = fcntl(udp_server_fd, F_GETFL, 0);
	if (flags >= 0) {
		fcntl(udp_server_fd, F_SETFL, flags | O_NONBLOCK);
	}
	
	/* 绑定地址 */
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(port);
	
	if (bind(udp_server_fd, (struct sockaddr *)&server_addr,
	         sizeof(server_addr)) < 0) {
		zlog_err("%s: Failed to bind UDP socket to port %d: %s",
		         __func__, port, strerror(errno));
		close(udp_server_fd);
		udp_server_fd = -1;
		return -1;
	}
	
	printf("[BGP-LS-INFO] UDP server started on port %d\n", port);
	fflush(stdout);
	
	zlog_info("%s: UDP server listening on port %d", __func__, port);
	
	/* 注册读事件 */
	event_add_read(bm->master, bgp_linkstate_udp_read, bgp,
	               udp_server_fd, &udp_server_event);
	
	return 0;
}

/**
 * 停止UDP socket服务器
 */
void bgp_linkstate_udp_server_stop(void)
{
	if (udp_server_event) {
		event_cancel(&udp_server_event);
		udp_server_event = NULL;
	}
	
	if (udp_server_fd >= 0) {
		close(udp_server_fd);
		udp_server_fd = -1;
		
		printf("[BGP-LS-INFO] UDP server stopped\n");
		fflush(stdout);
		
		zlog_info("%s: UDP server stopped", __func__);
	}
}

/**
 * 从配置文件读取监控的接口列表
 * 
 * @param bgp BGP实例
 * @param if_list 输出的接口名称列表
 * @param max_count 最大接口数量
 * @return 实际读取的接口数量
 */
static int read_monitored_interfaces(struct bgp *bgp, char if_list[][32], int max_count)
{
	struct listnode *node;
	char *if_name;
	int count = 0;

	if (!bgp) {
		zlog_err("%s: Invalid BGP instance", __func__);
		return 0;
	}

	/* 从 BGP 配置中读取监控接口列表 */
	if (bgp->linkstate_if_list) {
		for (ALL_LIST_ELEMENTS_RO(bgp->linkstate_if_list, node, if_name)) {
			if (count >= max_count) {
				zlog_warn("%s: Too many interfaces, max %d",
				          __func__, max_count);
				break;
			}
			snprintf(if_list[count++], 32, "%s", if_name);
		}
	}

	/* 如果配置为空，从所有可用接口中选择 */
	if (count == 0) {
		struct vrf *vrf;
		struct interface *ifp;

		zlog_info("%s: No configured interfaces, monitoring all available interfaces",
		          __func__);

		RB_FOREACH(vrf, vrf_name_head, &vrfs_by_name) {
			FOR_ALL_INTERFACES(vrf, ifp) {
				/* 跳过回环接口 */
				if (if_is_loopback(ifp))
					continue;

				/* 只监控UP的接口 */
				if (!if_is_up(ifp))
					continue;

				if (count >= max_count) {
					zlog_warn("%s: Reached max interface count %d",
					          __func__, max_count);
					if (count > 0) {
						zlog_info("%s: Monitoring %d interfaces", __func__, count);
						for (int i = 0; i < count; i++) {
							zlog_debug("%s:   [%d] %s", __func__, i+1, if_list[i]);
						}
					} else {
						zlog_warn("%s: No interfaces to monitor", __func__);
					}
					return count;
				}
				snprintf(if_list[count++], 32, "%s", ifp->name);
			}
		}
	}
	return count;
}

/**
 * 比较两个链路状态信息，判断是否有变化
 * 
 * @param old_info 旧的链路状态
 * @param new_info 新的链路状态
 * @return true 有变化, false 无变化
 */
static bool linkstate_info_changed(struct linkstate_info *old_info, 
                                   struct linkstate_info *new_info)
{
	if (!old_info || !new_info)
		return true;

	/* 检查关键字段是否变化 */
	if (old_info->oper_status != new_info->oper_status)
		return true;

	if (old_info->max_bandwidth != new_info->max_bandwidth)
		return true;

	if (old_info->te_metric != new_info->te_metric)
		return true;

	if (old_info->igp_metric != new_info->igp_metric)
		return true;

	/* 其他字段对比... */

	return false;
}


/**
 * 获取最新的链路状态配置文件路径
 * 
 * @param config_path 输出缓冲区（存储完整路径）
 * @param path_size 缓冲区大小
 * @return 0 成功, -1 失败
 */
static int get_latest_linkstate_config(char *config_path, size_t path_size)
{
	DIR *dir;
	struct dirent *entry;
	char latest_file[256] = {0};
	time_t latest_time = 0;
	
	if (!config_path || path_size == 0) {
		zlog_err("%s: Invalid parameters", __func__);
		return -1;
	}
	
	/* 打开配置文件目录 */
	dir = opendir(LINKSTATE_CONFIG_DIR);
	if (!dir) {
		zlog_err("%s: Cannot open directory %s: %s",
		          __func__, LINKSTATE_CONFIG_DIR, strerror(errno));
		return -1;
	}
	
	/* 遍历目录查找最新的配置文件 */
	while ((entry = readdir(dir)) != NULL) {
		char filepath[512];
		struct stat st;
		
		/* 检查文件名格式: linkstate_*.json */
		if (strncmp(entry->d_name, LINKSTATE_CONFIG_PATTERN,
		            strlen(LINKSTATE_CONFIG_PATTERN)) != 0)
			continue;
		
		if (strstr(entry->d_name, LINKSTATE_CONFIG_EXT) == NULL)
			continue;
		
		/* 获取文件的修改时间 */
		snprintf(filepath, sizeof(filepath), "%s/%s",
		         LINKSTATE_CONFIG_DIR, entry->d_name);
		
		if (stat(filepath, &st) != 0)
			continue;
		
		/* 记录最新的文件 */
		if (st.st_mtime > latest_time) {
			latest_time = st.st_mtime;
			snprintf(latest_file, sizeof(latest_file), "%s", entry->d_name);
		}
	}
	
	closedir(dir);
	
	if (latest_file[0] == '\0') {
		zlog_warn("%s: No linkstate config files found in %s",
		          __func__, LINKSTATE_CONFIG_DIR);
		return -1;
	}
	
	/* 构造完整路径 */
	snprintf(config_path, path_size, "%s/%s",
	         LINKSTATE_CONFIG_DIR, latest_file);
	
	zlog_info("%s: Found latest config file: %s (mtime=%ld)",
	          __func__, config_path, latest_time);
	return 0;
}

/**
 * 从JSON配置文件读取链路状态信息
 * 
 * @param config_file 配置文件路径
 * @param ls_info_array 输出的链路状态信息数组
 * @param max_count 最大链路数量
 * @return 实际读取的链路数量，失败返回-1
 */
static int read_linkstate_from_config(const char *config_file,
                                       struct linkstate_info *ls_info_array,
                                       int max_count)
{
	struct json_object *root, *links_array, *link_obj, *nlri_obj, *attr_obj;
	struct json_object *local_node, *remote_node, *link_desc, *unreserved_bw_array;
	int count = 0;
	FILE *fp;
	char *file_contents = NULL;
	long file_size;
	
	if (!config_file || !ls_info_array || max_count <= 0) {
		zlog_err("%s: Invalid parameters", __func__);
		return -1;
	}
	
	/* 读取JSON文件 */
	fp = fopen(config_file, "r");
	if (!fp) {
		zlog_err("%s: Cannot open config file %s: %s",
		          __func__, config_file, strerror(errno));
		return -1;
	}
	
	/* 获取文件大小 */
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	
	/* 读取文件内容 */
	file_contents = malloc(file_size + 1);
	if (!file_contents) {
		zlog_err("%s: Memory allocation failed", __func__);
		fclose(fp);
		return -1;
	}
	
	if (fread(file_contents, 1, file_size, fp) != (size_t)file_size) {
		zlog_err("%s: Failed to read config file", __func__);
		free(file_contents);
		fclose(fp);
		return -1;
	}
	file_contents[file_size] = '\0';
	fclose(fp);
	
	/* 解析JSON */
	root = json_tokener_parse(file_contents);
	free(file_contents);
	
	if (!root) {
		zlog_err("%s: Failed to parse JSON from %s", __func__, config_file);
		return -1;
	}
	
	/* 获取links数组 */
	if (!json_object_object_get_ex(root, "links", &links_array)) {
		zlog_err("%s: No 'links' array in config file", __func__);
		json_object_put(root);
		return -1;
	}
	
	/* 遍历每个链路 */
	int array_len = json_object_array_length(links_array);
	for (int i = 0; i < array_len && count < max_count; i++) {
		link_obj = json_object_array_get_idx(links_array, i);
		if (!link_obj)
			continue;
		
		struct linkstate_info *ls = &ls_info_array[count];
		memset(ls, 0, sizeof(*ls));
		
		/* 读取接口名 */
		struct json_object *if_name_obj;
		if (json_object_object_get_ex(link_obj, "if_name", &if_name_obj)) {
			snprintf(ls->if_name, sizeof(ls->if_name), "%s",
			         json_object_get_string(if_name_obj));
		}
		
		/* 读取接口索引 */
		struct json_object *if_index_obj;
		if (json_object_object_get_ex(link_obj, "if_index", &if_index_obj)) {
			ls->if_index = json_object_get_int(if_index_obj);
		}
		
		/* 读取NLRI字段 */
		if (json_object_object_get_ex(link_obj, "nlri", &nlri_obj)) {
			/* Local Node */
			if (json_object_object_get_ex(nlri_obj, "local_node", &local_node)) {
				struct json_object *router_id_obj;
				if (json_object_object_get_ex(local_node, "router_id", &router_id_obj)) {
					inet_pton(AF_INET, json_object_get_string(router_id_obj),
					          &ls->router_id);
				}
			}
			
			/* Remote Node */
			if (json_object_object_get_ex(nlri_obj, "remote_node", &remote_node)) {
				struct json_object *router_id_obj;
				if (json_object_object_get_ex(remote_node, "router_id", &router_id_obj)) {
					inet_pton(AF_INET, json_object_get_string(router_id_obj),
					          &ls->remote_router_id);
				}
			}
			
			/* Link Descriptors */
			if (json_object_object_get_ex(nlri_obj, "link_descriptors", &link_desc)) {
				struct json_object *local_ipv4_obj, *remote_ipv4_obj;
				if (json_object_object_get_ex(link_desc, "local_ipv4", &local_ipv4_obj)) {
					inet_pton(AF_INET, json_object_get_string(local_ipv4_obj),
					          &ls->local_addr);
				}
				if (json_object_object_get_ex(link_desc, "remote_ipv4", &remote_ipv4_obj)) {
					inet_pton(AF_INET, json_object_get_string(remote_ipv4_obj),
					          &ls->remote_addr);
				}
			}
		}
		
		/* 读取Attributes字段 */
		if (json_object_object_get_ex(link_obj, "attributes", &attr_obj)) {
			struct json_object *val;
			
			if (json_object_object_get_ex(attr_obj, "oper_status", &val))
				ls->oper_status = json_object_get_int(val);
			
			if (json_object_object_get_ex(attr_obj, "max_bandwidth", &val))
				ls->max_bandwidth = json_object_get_int64(val);
			
			if (json_object_object_get_ex(attr_obj, "te_metric", &val))
				ls->te_metric = json_object_get_int(val);
			
			if (json_object_object_get_ex(attr_obj, "igp_metric", &val))
				ls->igp_metric = json_object_get_int(val);
			
			if (json_object_object_get_ex(attr_obj, "admin_group", &val))
				ls->admin_group = json_object_get_int(val);
			
			if (json_object_object_get_ex(attr_obj, "spf_sequence_number", &val))
				ls->spf_sequence_number = json_object_get_int64(val);
			
			if (json_object_object_get_ex(attr_obj, "spf_status", &val))
				ls->spf_status = json_object_get_int(val);
			
			/* Unreserved Bandwidth数组 */
			if (json_object_object_get_ex(attr_obj, "unreserved_bw", &unreserved_bw_array)) {
				int bw_len = json_object_array_length(unreserved_bw_array);
				for (int j = 0; j < bw_len && j < 8; j++) {
					struct json_object *bw_obj = json_object_array_get_idx(unreserved_bw_array, j);
					ls->unreserved_bw[j] = json_object_get_int64(bw_obj);
				}
			}
			
			ls->max_reservable_bw = ls->max_bandwidth;
		}
		
		ls->last_update = time(NULL);
		
		zlog_debug("%s: Parsed link %s (status=%d, bw=%u, metric=%u)",
		           __func__, ls->if_name, ls->oper_status,
		           ls->max_bandwidth, ls->igp_metric);
		
		count++;
	}
	
	json_object_put(root);
	
	zlog_info("%s: Successfully parsed %d links from %s",
	          __func__, count, config_file);
	return count;
}

/**
 * 解析IS-IS Area ID字符串（格式: "49.0001"）
 * 
 * @param area_str Area ID字符串
 * @param isis_area_id 输出的Area ID字节数组
 * @param isis_area_id_len 输出的长度（最大13字节）
 * @return 0 成功, -1 失败
 */
static int parse_isis_area_id(const char *area_str, uint8_t *isis_area_id, uint8_t *isis_area_id_len)
{
    if (!area_str || !isis_area_id || !isis_area_id_len)
        return -1;
    
    /* 移除点号并解析十六进制字符串 */
    char hex_str[32];
    int hex_len = 0;
    
    for (int i = 0; area_str[i] && hex_len < sizeof(hex_str) - 1; i++) {
        if (area_str[i] != '.') {
            hex_str[hex_len++] = area_str[i];
        }
    }
    hex_str[hex_len] = '\0';
    
    /* 转换为字节数组 */
    int byte_count = 0;
    for (int i = 0; i < hex_len && byte_count < 13; i += 2) {
        unsigned int byte_val;
        if (sscanf(&hex_str[i], "%2x", &byte_val) == 1) {
            isis_area_id[byte_count++] = (uint8_t)byte_val;
        }
    }
    
    *isis_area_id_len = byte_count;
    
    return (byte_count > 0) ? 0 : -1;
}

/**
 * 解析IS-IS ISO System-ID字符串（格式: "1234.5678.9abc.00"）
 * 
 * @param iso_str ISO节点ID字符串
 * @param iso_node_id 输出的ISO节点ID字节数组
 * @param iso_node_id_len 输出的长度（6或7字节）
 * @return 0 成功, -1 失败
 */
static int parse_iso_node_id(const char *iso_str, uint8_t *iso_node_id, uint8_t *iso_node_id_len)
{
    if (!iso_str || !iso_node_id || !iso_node_id_len)
        return -1;
    
    /* 移除点号并解析十六进制字符串 */
    char hex_str[32];
    int hex_len = 0;
    
    for (int i = 0; iso_str[i] && hex_len < sizeof(hex_str) - 1; i++) {
        if (iso_str[i] != '.') {
            hex_str[hex_len++] = iso_str[i];
        }
    }
    hex_str[hex_len] = '\0';
    
    /* 转换为字节数组 */
    int byte_count = 0;
    for (int i = 0; i < hex_len && byte_count < 7; i += 2) {
        unsigned int byte_val;
        if (sscanf(&hex_str[i], "%2x", &byte_val) == 1) {
            iso_node_id[byte_count++] = (uint8_t)byte_val;
        }
    }
    
    *iso_node_id_len = byte_count;
    
    return (byte_count > 0) ? 0 : -1;
}

/**
 * 从JSON配置文件读取节点状态信息
 * 
 * @param config_file 配置文件路径
 * @param ns_info_array 输出的节点状态信息数组
 * @param max_count 最大节点数量
 * @return 实际读取的节点数量，失败返回-1
 */
static int read_nodestate_from_config(const char *config_file,
                                       struct nodestate_info *ns_info_array,
                                       int max_count)
{
    struct json_object *root, *nodes_array, *node_obj, *nlri_obj, *attr_obj;
    struct json_object *node_desc, *sr_cap_obj, *sr_algo_array, *sr_local_block;
    int count = 0;
    FILE *fp;
    char *file_contents = NULL;
    long file_size;
    
    if (!config_file || !ns_info_array || max_count <= 0) {
        zlog_err("%s: Invalid parameters", __func__);
        return -1;
    }
    
    /* 读取JSON文件 */
    fp = fopen(config_file, "r");
    if (!fp) {
        zlog_err("%s: Failed to open config file: %s", __func__, config_file);
        return -1;
    }
    
    /* 获取文件大小 */
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    /* 读取文件内容 */
    file_contents = malloc(file_size + 1);
    if (!file_contents) {
        fclose(fp);
        zlog_err("%s: Failed to allocate memory for file contents", __func__);
        return -1;
    }
    
    if (fread(file_contents, 1, file_size, fp) != (size_t)file_size) {
        free(file_contents);
        fclose(fp);
        zlog_err("%s: Failed to read file contents", __func__);
        return -1;
    }
    file_contents[file_size] = '\0';
    fclose(fp);
    
    /* 解析JSON */
    root = json_tokener_parse(file_contents);
    free(file_contents);
    
    if (!root) {
        zlog_err("%s: Failed to parse JSON", __func__);
        return -1;
    }
    
    /* 获取nodes数组 */
    if (!json_object_object_get_ex(root, "nodes", &nodes_array)) {
        json_object_put(root);
        zlog_err("%s: Missing 'nodes' array in JSON", __func__);
        return -1;
    }
    
    /* 遍历每个节点 */
    int array_len = json_object_array_length(nodes_array);
    for (int i = 0; i < array_len && count < max_count; i++) {
        node_obj = json_object_array_get_idx(nodes_array, i);
        if (!node_obj)
            continue;
        
        struct nodestate_info *ns_info = &ns_info_array[count];
        memset(ns_info, 0, sizeof(*ns_info));
        
        /* ================================================================
         * 读取节点名称
         * ================================================================ */
        struct json_object *node_name_obj;
        if (json_object_object_get_ex(node_obj, "node_name", &node_name_obj)) {
            const char *node_name = json_object_get_string(node_name_obj);
            strncpy(ns_info->node_name, node_name, sizeof(ns_info->node_name) - 1);
        }
        
        /* ================================================================
         * 读取NLRI字段 (Node Descriptors)
         * ================================================================ */
        if (json_object_object_get_ex(node_obj, "nlri", &nlri_obj)) {
            /* Protocol ID */
            struct json_object *protocol_id_obj;
            if (json_object_object_get_ex(nlri_obj, "protocol_id", &protocol_id_obj)) {
                ns_info->protocol_id = (uint8_t)json_object_get_int(protocol_id_obj);
            }
            
            /* Identifier */
            struct json_object *identifier_obj;
            if (json_object_object_get_ex(nlri_obj, "identifier", &identifier_obj)) {
                ns_info->identifier = (uint64_t)json_object_get_int64(identifier_obj);
            }
            
            /* Local Node Descriptors */
            if (json_object_object_get_ex(nlri_obj, "local_node_descriptors", &node_desc)) {
                /* ASN (Sub-TLV 512) */
                struct json_object *asn_obj;
                if (json_object_object_get_ex(node_desc, "asn", &asn_obj)) {
                    ns_info->asn = json_object_get_int(asn_obj);
                }
                
                /* BGP-LS Identifier (Sub-TLV 513) */
                struct json_object *bgpls_id_obj;
                if (json_object_object_get_ex(node_desc, "bgpls_id", &bgpls_id_obj)) {
                    ns_info->bgpls_id = json_object_get_int(bgpls_id_obj);
                }
                
                /* OSPF Area-ID (Sub-TLV 514) */
                struct json_object *ospf_area_obj;
                if (json_object_object_get_ex(node_desc, "ospf_area_id", &ospf_area_obj)) {
                    ns_info->ospf_area_id = json_object_get_int(ospf_area_obj);
                }
                
                /* IGP Router-ID IPv4 (Sub-TLV 515) */
                struct json_object *router_id_obj;
                if (json_object_object_get_ex(node_desc, "router_id", &router_id_obj)) {
                    const char *router_id_str = json_object_get_string(router_id_obj);
                    inet_pton(AF_INET, router_id_str, &ns_info->router_id);
                }
                
                /* IGP Router-ID IPv6 (Sub-TLV 515) */
                struct json_object *router_id_v6_obj;
                if (json_object_object_get_ex(node_desc, "router_id_v6", &router_id_v6_obj)) {
                    const char *router_id_v6_str = json_object_get_string(router_id_v6_obj);
                    inet_pton(AF_INET6, router_id_v6_str, &ns_info->router_id_v6);
                }
                
                /* IS-IS ISO System-ID */
                struct json_object *iso_node_id_obj;
                if (json_object_object_get_ex(node_desc, "iso_node_id", &iso_node_id_obj)) {
                    const char *iso_str = json_object_get_string(iso_node_id_obj);
                    parse_iso_node_id(iso_str, ns_info->iso_node_id, &ns_info->iso_node_id_len);
                }
            }
        }
        
        /* ================================================================
         * 读取Attributes字段 (Node Attributes)
         * ================================================================ */
        if (json_object_object_get_ex(node_obj, "attributes", &attr_obj)) {
            /* Node Flag Bits (TLV 1024) */
            struct json_object *node_flags_obj;
            if (json_object_object_get_ex(attr_obj, "node_flags", &node_flags_obj)) {
                ns_info->node_flags = (uint8_t)json_object_get_int(node_flags_obj);
            }
            
            /* IS-IS Area Identifier (TLV 1027) */
            struct json_object *isis_area_obj;
            if (json_object_object_get_ex(attr_obj, "isis_area_id", &isis_area_obj)) {
                const char *isis_area_str = json_object_get_string(isis_area_obj);
                parse_isis_area_id(isis_area_str, ns_info->isis_area_id, &ns_info->isis_area_id_len);
            }
            
            /* IPv4 TE Router-ID (TLV 1028) */
            struct json_object *te_router_id_obj;
            if (json_object_object_get_ex(attr_obj, "te_router_id", &te_router_id_obj)) {
                const char *te_router_id_str = json_object_get_string(te_router_id_obj);
                inet_pton(AF_INET, te_router_id_str, &ns_info->te_router_id);
            }
            
            /* IPv6 TE Router-ID (TLV 1029) */
            struct json_object *te_router_id_v6_obj;
            if (json_object_object_get_ex(attr_obj, "te_router_id_v6", &te_router_id_v6_obj)) {
                const char *te_router_id_v6_str = json_object_get_string(te_router_id_v6_obj);
                inet_pton(AF_INET6, te_router_id_v6_str, &ns_info->te_router_id_v6);
            }
            
            /* SR Capabilities (TLV 1034) */
            if (json_object_object_get_ex(attr_obj, "sr_capabilities", &sr_cap_obj)) {
                /* SR Capability Flags */
                struct json_object *sr_flags_obj;
                if (json_object_object_get_ex(sr_cap_obj, "flags", &sr_flags_obj)) {
                    ns_info->sr_capability_flags = (uint8_t)json_object_get_int(sr_flags_obj);
                }
                
                /* SRGB Base */
                struct json_object *srgb_base_obj;
                if (json_object_object_get_ex(sr_cap_obj, "srgb_base", &srgb_base_obj)) {
                    ns_info->srgb_base = json_object_get_int(srgb_base_obj);
                }
                
                /* SRGB Range */
                struct json_object *srgb_range_obj;
                if (json_object_object_get_ex(sr_cap_obj, "srgb_range", &srgb_range_obj)) {
                    ns_info->srgb_range = json_object_get_int(srgb_range_obj);
                }
            }
            
            /* SR Algorithms (TLV 1035) */
            if (json_object_object_get_ex(attr_obj, "sr_algorithms", &sr_algo_array)) {
                int algo_count = json_object_array_length(sr_algo_array);
                ns_info->sr_algorithm_count = (algo_count > 8) ? 8 : algo_count;
                for (int j = 0; j < ns_info->sr_algorithm_count; j++) {
                    struct json_object *algo_obj = json_object_array_get_idx(sr_algo_array, j);
                    ns_info->sr_algorithms[j] = (uint8_t)json_object_get_int(algo_obj);
                }
            }
            
            /* SR Local Block (TLV 1036) */
            if (json_object_object_get_ex(attr_obj, "sr_local_block", &sr_local_block)) {
                /* SRLB Base */
                struct json_object *srlb_base_obj;
                if (json_object_object_get_ex(sr_local_block, "srlb_base", &srlb_base_obj)) {
                    ns_info->srlb_base = json_object_get_int(srlb_base_obj);
                }
                
                /* SRLB Range */
                struct json_object *srlb_range_obj;
                if (json_object_object_get_ex(sr_local_block, "srlb_range", &srlb_range_obj)) {
                    ns_info->srlb_range = json_object_get_int(srlb_range_obj);
                }
            }
            
            /* SRMS Preference (TLV 1037) */
            struct json_object *srms_pref_obj;
            if (json_object_object_get_ex(attr_obj, "srms_preference", &srms_pref_obj)) {
                ns_info->srms_preference = (uint8_t)json_object_get_int(srms_pref_obj);
            }
            
            /* Node Operational Status */
            struct json_object *oper_status_obj;
            if (json_object_object_get_ex(attr_obj, "oper_status", &oper_status_obj)) {
                ns_info->oper_status = (uint8_t)json_object_get_int(oper_status_obj);
            }
        }
        
        /* 设置时间戳 */
        ns_info->last_update = time(NULL);
        
        count++;
        
        zlog_info("%s: Parsed node %d: name=%s, router_id=%s, asn=%u",
                  __func__, count, ns_info->node_name,
                  inet_ntoa(ns_info->router_id), ns_info->asn);
    }
    
    json_object_put(root);
    
    zlog_info("%s: Successfully parsed %d nodes from %s",
              __func__, count, config_file);
    return count;
}

/**
 * 获取最新的节点状态配置文件路径
 * 
 * @param config_path 输出缓冲区（存储完整路径）
 * @param path_size 缓冲区大小
 * @return 0 成功, -1 失败
 */
static int get_latest_nodestate_config(char *config_path, size_t path_size)
{
    DIR *dir;
    struct dirent *entry;
    char latest_file[256] = {0};
    time_t latest_time = 0;
    
    if (!config_path || path_size == 0) {
        zlog_err("%s: Invalid parameters", __func__);
        return -1;
    }
    
    /* 打开配置文件目录 */
    dir = opendir(LINKSTATE_CONFIG_DIR);
    if (!dir) {
        zlog_err("%s: Cannot open directory %s: %s",
                  __func__, LINKSTATE_CONFIG_DIR, strerror(errno));
        return -1;
    }
    
    /* 遍历目录查找最新的节点配置文件 */
    while ((entry = readdir(dir)) != NULL) {
        char filepath[512];
        struct stat st;
        
        /* 检查文件名格式: nodestate_*.json */
        if (strncmp(entry->d_name, "nodestate_", strlen("nodestate_")) != 0)
            continue;
        
        if (strstr(entry->d_name, ".json") == NULL)
            continue;
        
        /* 获取文件的修改时间 */
        snprintf(filepath, sizeof(filepath), "%s/%s",
                 LINKSTATE_CONFIG_DIR, entry->d_name);
        
        if (stat(filepath, &st) != 0)
            continue;
        
        /* 记录最新的文件 */
        if (st.st_mtime > latest_time) {
            latest_time = st.st_mtime;
            snprintf(latest_file, sizeof(latest_file), "%s", entry->d_name);
        }
    }
    
    closedir(dir);
    
    if (latest_file[0] == '\0') {
        zlog_debug("%s: No nodestate config files found in %s",
                   __func__, LINKSTATE_CONFIG_DIR);
        return -1;
    }
    
    /* 构造完整路径 */
    snprintf(config_path, path_size, "%s/%s",
             LINKSTATE_CONFIG_DIR, latest_file);
    
    zlog_info("%s: Found latest nodestate config file: %s (mtime=%ld)",
              __func__, config_path, latest_time);
    return 0;
}

static void bgp_linkstate_poll_timer(struct event *thread)
{
	struct bgp *bgp;
	int i;

	bgp = EVENT_ARG(thread);

	if (!bgp) {
		zlog_err("%s: BGP instance is NULL", __func__);
		return;
	}

	zlog_debug("%s: Polling link-state information from config file", __func__);

	/* =====================================================================
     * 第一部分：读取链路状态（已有代码）
     * ===================================================================== */
    
	/* 获取最新的配置文件路径 */
	char config_file[512];
	if (get_latest_linkstate_config(config_file, sizeof(config_file)) != 0) {
		zlog_warn("%s: No linkstate config file found, skipping this poll cycle",
		          __func__);
		/* 重新调度定时器 - 保持后台运行 */
		event_add_timer(bm->master, bgp_linkstate_poll_timer, bgp,
		        bgp->linkstate_poll_interval ?: DEFAULT_LINKSTATE_POLL_INTERVAL,
		        &bgp->t_linkstate_poll);
		return;
	}
	
	zlog_info("%s: Reading link states from config file: %s",
	          __func__, config_file);
	
	/* 从配置文件读取所有链路状态 */
	struct linkstate_info ls_info_array[64];  /* 最多支持64个链路 */
	int link_count = read_linkstate_from_config(config_file, ls_info_array, 64);
	
	if (link_count < 0) {
		zlog_err("%s: Failed to read config file %s", __func__, config_file);
		/* 重新调度定时器 */
		event_add_timer(bm->master, bgp_linkstate_poll_timer, bgp,
		        bgp->linkstate_poll_interval ?: DEFAULT_LINKSTATE_POLL_INTERVAL,
		        &bgp->t_linkstate_poll);
		return;
	}
	
	if (link_count == 0) {
		zlog_warn("%s: No links found in config file", __func__);
		/* 重新调度定时器 */
		event_add_timer(bm->master, bgp_linkstate_poll_timer, bgp,
		        bgp->linkstate_poll_interval ?: DEFAULT_LINKSTATE_POLL_INTERVAL,
		        &bgp->t_linkstate_poll);
		return;
	}
	
	/* 遍历每个链路，调用update函数处理（会自动判断是add还是update）*/
	for (i = 0; i < link_count; i++) {
		int ret = 0;
		  /* 根据 oper_status 判断操作类型:
         * oper_status = 1 (UP): 链路激活，调用 add 或 update
         * oper_status = 0 (DOWN): 链路失效，调用 delete
         */
        if (ls_info_array[i].oper_status == 0) {
            /* 链路 DOWN，删除该链路状态 */
            printf("[BGP-LS-POLL] Link %s is DOWN (oper_status=0), calling linkstate_delete\n",
                   ls_info_array[i].if_name);
            fflush(stdout);
            
            zlog_info("%s: Link %s is DOWN, calling delete",
                  __func__, ls_info_array[i].if_name);
            ret = linkstate_delete(bgp, ls_info_array[i].if_name, SAFI_LINKSTATE);
            if (ret != 0) {
                zlog_warn("%s: Failed to delete link-state for %s",
                      __func__, ls_info_array[i].if_name);
            }
        } else {
            /* 链路 UP，调用 update（会自动判断是 add 还是 update）*/
            printf("[BGP-LS-POLL] Link %s is UP (oper_status=%d), calling linkstate_update\n",
                   ls_info_array[i].if_name, ls_info_array[i].oper_status);
            fflush(stdout);
            
            ret = linkstate_update(bgp, &ls_info_array[i], SAFI_LINKSTATE);
            if (ret != 0) {
                zlog_warn("%s: Failed to update link-state for %s",
                      __func__, ls_info_array[i].if_name);
                continue;
            }
        }
		
		zlog_debug("%s: Processed link-state for %s (status=%d, bw=%u)",
		           __func__, ls_info_array[i].if_name,
		           ls_info_array[i].oper_status,
		           ls_info_array[i].max_bandwidth);
	}

	/* =====================================================================
     * 第二部分：读取节点状态（新增代码）
     * ===================================================================== */
    
    /* 获取节点配置文件路径（假设格式为 nodestate_*.json）*/
    char node_config_file[512];
    if (get_latest_nodestate_config(node_config_file, sizeof(node_config_file)) == 0) {
        zlog_info("%s: Reading node states from config file: %s",
                  __func__, node_config_file);
        
        /* 从配置文件读取所有节点状态 */
        struct nodestate_info ns_info_array[64];  /* 最多支持64个节点 */
        int node_count = read_nodestate_from_config(node_config_file, ns_info_array, 64);
        
        if (node_count < 0) {
            zlog_err("%s: Failed to read node config file %s", __func__, node_config_file);
        } else if (node_count == 0) {
            zlog_warn("%s: No nodes found in config file", __func__);
        } else {
            /* 遍历每个节点，调用相应的处理函数 */
            for (i = 0; i < node_count; i++) {
                int ret = 0;
                
                if (ns_info_array[i].oper_status == 0) {
                    /* 节点 DOWN，删除该节点状态 */
                    printf("[BGP-LS-POLL] Node %s is DOWN (oper_status=0), calling nodestate_delete\n",
                           ns_info_array[i].node_name);
                    fflush(stdout);
                    
                    zlog_info("%s: Node %s is DOWN, calling delete",
                              __func__, ns_info_array[i].node_name);
                    ret = nodestate_delete(bgp, ns_info_array[i].node_name, SAFI_LINKSTATE);
                    if (ret != 0) {
                        zlog_warn("%s: Failed to delete node-state for %s",
                                  __func__, ns_info_array[i].node_name);
                    }
                } else {
                    /* 节点 UP，调用 update（会自动判断是 add 还是 update）*/
                    printf("[BGP-LS-POLL] Node %s is UP (oper_status=%d), calling nodestate_update\n",
                           ns_info_array[i].node_name, ns_info_array[i].oper_status);
                    fflush(stdout);
                    
                    ret = nodestate_update(bgp, &ns_info_array[i], SAFI_LINKSTATE);
                    if (ret != 0) {
                        zlog_warn("%s: Failed to update node-state for %s",
                                  __func__, ns_info_array[i].node_name);
                        continue;
                    }
                }
                
                zlog_debug("%s: Processed node-state for %s (status=%d, asn=%u, srgb_base=%u)",
                           __func__, ns_info_array[i].node_name,
                           ns_info_array[i].oper_status,
                           ns_info_array[i].asn,
                           ns_info_array[i].srgb_base);
            }
            
            printf("[BGP-LS-POLL] Successfully processed %d nodes from config file\n", node_count);
            fflush(stdout);
        }
    } else {
        zlog_debug("%s: No nodestate config file found, skipping node processing",
                   __func__);
    }

	// /* 同时触发 TVR 路由读取（如果已启用）*/
	// if (bgp->tvr_state && bgp->tvr_enabled) {
	// 	zlog_debug("%s: Triggering TVR route reading", __func__);
	// 	tvr_read_current_routes(bgp->tvr_state);
	// }
	
	/* 重新调度定时器 - 保持后台持续运行 */
	event_add_timer(bm->master, bgp_linkstate_poll_timer, bgp,
	                bgp->linkstate_poll_interval ?: DEFAULT_LINKSTATE_POLL_INTERVAL,
	                &bgp->t_linkstate_poll);
}

/**
 * 启动链路状态定时轮询
 * 
 * @param bgp BGP实例
 */
void bgp_linkstate_poll_start(struct bgp *bgp)
{
	if (!bgp) {
		zlog_err("%s: BGP instance is NULL", __func__);
		return;
	}

	/* 如果已经在运行，先停止 */
	if (bgp->t_linkstate_poll) {
		event_cancel(&bgp->t_linkstate_poll);
	}

	/* 设置默认轮询间隔 */
	if (bgp->linkstate_poll_interval == 0) {
		bgp->linkstate_poll_interval = DEFAULT_LINKSTATE_POLL_INTERVAL;
	}

	printf("[BGP-LS-INFO] Starting link-state polling (interval=%u sec, first poll in %u sec)\n",
	       bgp->linkstate_poll_interval, bgp->linkstate_poll_interval);
	fflush(stdout);

	/* 自动启动UDP服务器（默认端口9999） */
	if (udp_server_fd < 0) {
		printf("[BGP-LS-INFO] Auto-starting UDP server on port %d\n", LINKSTATE_UDP_PORT);
		fflush(stdout);
		bgp_linkstate_udp_server_start(bgp, 0);
	}

	/* 延迟第一次轮询，等BGP会话建立 */
	event_add_timer(bm->master, bgp_linkstate_poll_timer, bgp,
			bgp->linkstate_poll_interval, &bgp->t_linkstate_poll);
}

/**
 * 停止链路状态定时轮询
 * 
 * @param bgp BGP实例
 */
void bgp_linkstate_poll_stop(struct bgp *bgp)
{
	if (!bgp)
		return;

	if (bgp->t_linkstate_poll) {
		event_cancel(&bgp->t_linkstate_poll);
		zlog_info("%s: Stopped link-state polling", __func__);
	}
}

/**
 * 设置轮询间隔
 * 
 * @param bgp BGP实例
 * @param interval 轮询间隔（秒）
 */
void bgp_linkstate_set_poll_interval(struct bgp *bgp, uint32_t interval)
{
	if (!bgp)
		return;

	if (interval < 5) {
		zlog_warn("%s: Interval %u too small, using minimum 5 sec",
		          __func__, interval);
		interval = 5;
	}

	if (interval > 3600) {
		zlog_warn("%s: Interval %u too large, using maximum 3600 sec",
		          __func__, interval);
		interval = 3600;
	}

	bgp->linkstate_poll_interval = interval;

	zlog_info("%s: Set link-state poll interval to %u sec",
	          __func__, interval);

	/* 如果定时器正在运行，重新调度 */
	if (bgp->t_linkstate_poll) {
		event_cancel(&bgp->t_linkstate_poll);
		event_add_timer(bm->master, bgp_linkstate_poll_timer, bgp,
		                interval, &bgp->t_linkstate_poll);
	}
}
/**
 * 清理BGP Link-State和TVR资源
 * 
 * @param bgp BGP实例
 */
void bgp_linkstate_cleanup(struct bgp *bgp)
{
	if (!bgp)
	return;

	/* 停止轮询 */
	bgp_linkstate_poll_stop(bgp);

	/* 停止UDP服务器 */
	bgp_linkstate_udp_server_stop();

	/* 清理状态缓存 */
	if (bgp->linkstate_cache) {
		linkstate_cache_finish(bgp->linkstate_cache);
		bgp->linkstate_cache = NULL;
		zlog_info("%s: Link-state cache cleaned up", __func__);
	}

	/* 清理TVR资源 */
	// TODO: Enable when TVR support is implemented
	//if (bgp->tvr_state) {
	//	tvr_cleanup(bgp->tvr_state);
	//	bgp->tvr_state = NULL;
	//	bgp->tvr_enabled = false;
	//	zlog_info("%s: TVR resources cleaned up", __func__);
	//}

	/* 清理接口列表 */
	if (bgp->linkstate_if_list) {
		/* 先释放列表中每个字符串 */
		struct listnode *node, *nnode;
		char *ifname;
		for (ALL_LIST_ELEMENTS(bgp->linkstate_if_list, node, nnode, ifname)) {
			XFREE(MTYPE_BGP_LINKSTATE_CACHE, ifname);
		}
		list_delete(&bgp->linkstate_if_list);
		zlog_info("%s: Link-state interface list cleaned up", __func__);
	}
}

/* ========================================================================
 * VTY Commands
 * ======================================================================== */

DEFUN(linkstate_monitor,
      linkstate_monitor_cmd,
      "linkstate monitor",
      "Link-state information\n"
      "Enable link-state monitoring\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	
	bgp_linkstate_poll_start(bgp);
	return CMD_SUCCESS;
}

DEFUN(no_linkstate_monitor,
      no_linkstate_monitor_cmd,
      "no linkstate monitor",
      NO_STR
      "Link-state information\n"
      "Disable link-state monitoring\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	
	bgp_linkstate_poll_stop(bgp);
	return CMD_SUCCESS;
}

DEFUN(linkstate_poll_interval,
      linkstate_poll_interval_cmd,
      "linkstate poll-interval (10-3600)",
      "Link-state information\n"
      "Set polling interval\n"
      "Interval in seconds\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx = 0;
	uint32_t interval;

	argv_find(argv, argc, "(10-3600)", &idx);
	interval = strtoul(argv[idx]->arg, NULL, 10);

	bgp_linkstate_set_poll_interval(bgp, interval);
	return CMD_SUCCESS;
}

DEFUN(linkstate_monitor_interface,
      linkstate_monitor_interface_cmd,
      "linkstate monitor interface IFNAME",
      "Link-state information\n"
      "Enable link-state monitoring\n"
      "Monitor specific interface\n"
      "Interface name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx = 0;
	char *ifname;

	argv_find(argv, argc, "IFNAME", &idx);
	ifname = argv[idx]->arg;

	/* Initialize monitoring if not already started */
	if (!bgp->linkstate_cache) {
		bgp_linkstate_poll_start(bgp);
	}

	/* Add interface to monitoring list */
	if (!bgp->linkstate_if_list) {
		bgp->linkstate_if_list = list_new();
	}
	
	/* Check if interface already in list */
	struct listnode *node;
	char *existing_if;
	for (ALL_LIST_ELEMENTS_RO(bgp->linkstate_if_list, node, existing_if)) {
		if (strcmp(existing_if, ifname) == 0) {
			vty_out(vty, "%% Interface %s already monitored\n", ifname);
			return CMD_WARNING;
		}
	}
	
	listnode_add(bgp->linkstate_if_list, XSTRDUP(MTYPE_BGP_LINKSTATE_CACHE, ifname));
	vty_out(vty, "%% Monitoring interface %s\n", ifname);
	
	return CMD_SUCCESS;
}

DEFUN(linkstate_udp_server,
      linkstate_udp_server_cmd,
      "linkstate udp-server [port (1024-65535)]",
      "Link-state information\n"
      "Start UDP server for link-state updates\n"
      "UDP port number\n"
      "Port number (default: 9999)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	uint16_t port = 0;
	int idx = 0;

	if (argv_find(argv, argc, "(1024-65535)", &idx)) {
		port = strtoul(argv[idx]->arg, NULL, 10);
	}

	if (bgp_linkstate_udp_server_start(bgp, port) == 0) {
		vty_out(vty, "%% UDP server started on port %d\n",
		        port ? port : LINKSTATE_UDP_PORT);
	} else {
		vty_out(vty, "%% Failed to start UDP server\n");
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(no_linkstate_udp_server,
      no_linkstate_udp_server_cmd,
      "no linkstate udp-server",
      NO_STR
      "Link-state information\n"
      "Stop UDP server for link-state updates\n")
{
	bgp_linkstate_udp_server_stop();
	vty_out(vty, "%% UDP server stopped\n");
	return CMD_SUCCESS;
}

void bgp_linkstate_poll_init(void)
{
	zlog_info("BGP Linkstate Poll: Initializing VTY commands");
	
	/* Install VTY commands */
	install_element(BGP_NODE, &linkstate_monitor_cmd);
	install_element(BGP_NODE, &no_linkstate_monitor_cmd);
	install_element(BGP_NODE, &linkstate_poll_interval_cmd);
	install_element(BGP_NODE, &linkstate_monitor_interface_cmd);
	install_element(BGP_NODE, &linkstate_udp_server_cmd);
	install_element(BGP_NODE, &no_linkstate_udp_server_cmd);
	
	zlog_info("BGP Linkstate Poll: VTY commands installed successfully");
}
