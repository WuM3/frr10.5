// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Link-State VTY header
 * Copyright 2023 6WIND S.A.
 */

#ifndef _FRR_BGP_LINKSTATE_VTY_H
#define _FRR_BGP_LINKSTATE_VTY_H

struct vty;
struct bgp;

void bgp_linkstate_vty_init(void);
void bgp_config_write_linkstate(struct vty *vty, struct bgp *bgp);

#endif /* _FRR_BGP_LINKSTATE_VTY_H */
