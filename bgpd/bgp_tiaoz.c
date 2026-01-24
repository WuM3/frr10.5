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
		/* 调用 update 函数处理链路状态（会自动判断是add还是update）*/
		if (linkstate_update(bgp, &ls_info_array[i], SAFI_LINKSTATE) != 0) {
			zlog_warn("%s: Failed to update link-state for %s",
			          __func__, ls_info_array[i].if_name);
			continue;
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