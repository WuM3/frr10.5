// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Custom Route Announcement Functions
 * Copyright (C) 2026 Custom Implementation
 */

#ifndef _FRR_BGP_CUSTOM_ANNOUNCE_H
#define _FRR_BGP_CUSTOM_ANNOUNCE_H

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"

/**
 * 触发BGP UPDATE发送给邻居
 * 
 * @param bgp       - BGP实例指针
 * @param prefix    - 要通告的前缀
 * @param afi       - 地址族（AFI_IP 或 AFI_IP6）
 * @param safi      - 子地址族（SAFI_UNICAST等）
 * @param pi        - 路径信息（NULL表示撤销）
 * 
 * @return 0 成功，-1 失败
 */
extern int my_bgp_announce_route(struct bgp *bgp, 
				 struct prefix *prefix,
				 afi_t afi, 
				 safi_t safi,
				 struct bgp_path_info *pi);

/**
 * 简化版本：自动查找最佳路径并通告
 * 
 * @param bgp    - BGP实例
 * @param prefix - 前缀
 * @param afi    - 地址族
 * @param safi   - 子地址族
 * 
 * @return 0 成功，-1 失败
 */
extern int my_bgp_announce_route_simple(struct bgp *bgp,
					struct prefix *prefix,
					afi_t afi,
					safi_t safi);

/**
 * 通告给特定邻居
 * 
 * @param peer   - 指定的peer
 * @param prefix - 前缀
 * @param afi    - 地址族
 * @param safi   - 子地址族
 * @param pi     - 路径信息
 * 
 * @return 0 成功，-1 失败
 */
extern int my_bgp_announce_to_peer(struct peer *peer,
				   struct prefix *prefix,
				   afi_t afi,
				   safi_t safi,
				   struct bgp_path_info *pi);

#endif /* _FRR_BGP_CUSTOM_ANNOUNCE_H */
