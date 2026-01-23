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

void bgp_linkstate_poll_init(void)
{
	zlog_info("BGP Linkstate Poll: Initializing VTY commands");
	
	/* Install VTY commands */
	install_element(BGP_NODE, &linkstate_monitor_cmd);
	install_element(BGP_NODE, &no_linkstate_monitor_cmd);
	install_element(BGP_NODE, &linkstate_poll_interval_cmd);
	install_element(BGP_NODE, &linkstate_monitor_interface_cmd);
	
	zlog_info("BGP Linkstate Poll: VTY commands installed successfully");
}
