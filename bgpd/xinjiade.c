
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