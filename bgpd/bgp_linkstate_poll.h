/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * BGP Link-State Polling Header
 * Copyright (C) 2024 FRRouting
 */

#ifndef _FRR_BGP_LINKSTATE_POLL_H
#define _FRR_BGP_LINKSTATE_POLL_H

/**
 * Initialize BGP linkstate polling module
 * Registers VTY commands for linkstate polling configuration
 */
extern void bgp_linkstate_poll_init(void);

/**
 * Trigger immediate link-state polling (exported for FSM use)
 */
extern void bgp_linkstate_poll_timer(struct event *t);

/**
 * Cleanup BGP linkstate resources
 * Should be called during BGP instance cleanup
 */
extern void bgp_linkstate_cleanup(struct bgp *bgp);

#endif /* _FRR_BGP_LINKSTATE_POLL_H */
