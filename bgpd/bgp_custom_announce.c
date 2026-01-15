// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Custom Route Announcement Functions
 * Copyright (C) 2026 Custom Implementation
 */

#include <zebra.h>

#include "prefix.h"
#include "log.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_custom_announce.h"

/**
 * 触发BGP UPDATE发送给邻居
 */
int my_bgp_announce_route(struct bgp *bgp, 
			  struct prefix *prefix,
			  afi_t afi, 
			  safi_t safi,
			  struct bgp_path_info *pi)
{
	struct bgp_dest *dest;
	struct bgp_table *table;
	
	/* 添加调试日志 */
	if (bgp_debug_update(NULL, prefix, NULL, 1))
		zlog_debug("%s: Entering for prefix %pFX, afi=%d, safi=%d, pi=%p",
			   __func__, prefix, afi, safi, pi);
	
	/* 参数检查 */
	if (!bgp) {
		zlog_err("%s: BGP instance is NULL", __func__);
		return -1;
	}
	
	if (!prefix) {
		zlog_err("%s: Prefix is NULL", __func__);
		return -1;
	}
	
	/* 获取对应的BGP路由表 */
	table = bgp->rib[afi][safi];
	if (!table) {
		zlog_err("%s: No BGP table for afi=%d safi=%d", 
			 __func__, afi, safi);
		return -1;
	}
	
	/* 在路由表中查找前缀节点 */
	dest = bgp_node_lookup(table, prefix);
	if (!dest) {
		zlog_warn("%s: Prefix %pFX not found in BGP table", 
			  __func__, prefix);
		return -1;
	}
	
	/* 调用核心函数触发UPDATE */
	if (bgp_debug_update(NULL, prefix, NULL, 1))
		zlog_debug("%s: Calling group_announce_route for %pFX",
			   __func__, prefix);
	
	group_announce_route(bgp, afi, safi, dest, pi);
	
	/* 解锁节点 */
	bgp_dest_unlock_node(dest);
	
	zlog_info("%s: Successfully triggered UPDATE for prefix %pFX",
		  __func__, prefix);
	
	return 0;
}

/**
 * 自动查找最佳路径并通告
 */
int my_bgp_announce_route_simple(struct bgp *bgp,
				 struct prefix *prefix,
				 afi_t afi,
				 safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct bgp_table *table;
	
	if (!bgp || !prefix) {
		zlog_err("%s: Invalid parameters", __func__);
		return -1;
	}
	
	table = bgp->rib[afi][safi];
	if (!table) {
		zlog_err("%s: No BGP table", __func__);
		return -1;
	}
	
	/* 查找前缀节点 */
	dest = bgp_node_lookup(table, prefix);
	if (!dest) {
		zlog_warn("%s: Prefix %pFX not found", __func__, prefix);
		return -1;
	}
	
	/* 查找最佳路径（SELECTED标记） */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
			break;
	}
	
	if (!pi) {
		zlog_warn("%s: No selected path for prefix %pFX", 
			  __func__, prefix);
		bgp_dest_unlock_node(dest);
		return -1;
	}
	
	/* 触发UPDATE */
	group_announce_route(bgp, afi, safi, dest, pi);
	
	bgp_dest_unlock_node(dest);
	
	zlog_info("%s: Announced prefix %pFX with selected path",
		  __func__, prefix);
	
	return 0;
}

/**
 * 通告给特定邻居
 */
int my_bgp_announce_to_peer(struct peer *peer,
			    struct prefix *prefix,
			    afi_t afi,
			    safi_t safi,
			    struct bgp_path_info *pi)
{
	struct bgp_dest *dest;
	struct bgp_table *table;
	struct peer_af *paf;
	struct update_subgroup *subgrp;
	
	if (!peer || !prefix) {
		zlog_err("%s: Invalid parameters", __func__);
		return -1;
	}
	
	table = peer->bgp->rib[afi][safi];
	if (!table) {
		zlog_err("%s: No BGP table", __func__);
		return -1;
	}
	
	dest = bgp_node_lookup(table, prefix);
	if (!dest) {
		zlog_warn("%s: Prefix %pFX not found", __func__, prefix);
		return -1;
	}
	
	/* 获取该peer的peer_af */
	paf = peer_af_find(peer, afi, safi);
	if (!paf || !paf->subgroup) {
		zlog_warn("%s: No peer_af or subgroup for peer %s",
			  __func__, peer->host);
		bgp_dest_unlock_node(dest);
		return -1;
	}
	
	subgrp = paf->subgroup;
	
	/* 处理该路由的通告 */
	if (pi) {
		/* 通告路由 */
		subgroup_process_announce_selected(subgrp, pi, dest, afi, safi,
			bgp_addpath_id_for_peer(peer, afi, safi, &pi->tx_addpath));
		
		zlog_info("%s: Announced prefix %pFX to peer %s",
			  __func__, prefix, peer->host);
	} else {
		/* 撤销路由 */
		bgp_adj_out_unset_subgroup(dest, subgrp, 1, 0);
		
		zlog_info("%s: Withdrew prefix %pFX from peer %s",
			  __func__, prefix, peer->host);
	}
	
	bgp_dest_unlock_node(dest);
	return 0;
}
