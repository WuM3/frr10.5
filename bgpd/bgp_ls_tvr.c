/*
 * BGP Link-State Time-Variant Routing Implementation
 * Copyright (C) 2026
 *
 * This file is part of FRRouting.
 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "frrevent.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "linklist.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_ls_tvr.h"
#include "bgpd/bgp_packet.h"

DEFINE_MTYPE_STATIC(BGPD, TVR_STATE, "TVR Routing State");

#define TVR_MIN_UPDATE_INTERVAL_S 1

/**
 * Convert time value to milliseconds
 */
uint64_t tvr_time_to_ms(uint32_t value, enum tvr_time_unit unit)
{
    switch (unit) {
    case TVR_TIME_UNIT_NS:
        return value / 1000000;
    case TVR_TIME_UNIT_US:
        return value / 1000;
    case TVR_TIME_UNIT_MS:
        return value;
    case TVR_TIME_UNIT_S:
        return value * 1000;
    default:
        return value;
    }
}

/**
 * Set update interval (seconds) and reschedule timer if running
 */
int tvr_set_update_interval(struct tvr_routing_state *state, uint32_t seconds)
{
    uint64_t interval_ms;

    if (!state || !state->bgp) {
        zlog_err("TVR: Invalid state for update interval");
        return -1;
    }

    if (seconds < TVR_MIN_UPDATE_INTERVAL_S) {
        zlog_err("TVR: update interval must be >= %u seconds",
                 TVR_MIN_UPDATE_INTERVAL_S);
        return -1;
    }

    state->config.time_slice_value = seconds;
    state->config.time_slice_unit = TVR_TIME_UNIT_S;

    if (state->bgp)
        // Update interval is stored in scheduler_config.time_slice_ms

    if (state->active) {
        if (state->timer)
            event_cancel(&state->timer);

        interval_ms = tvr_time_to_ms(state->config.time_slice_value,
                                     state->config.time_slice_unit);

        event_add_timer_msec(bm->master, tvr_timer_callback, state,
                             interval_ms, &state->timer);
    }

    zlog_info("TVR: update interval set to %u seconds", seconds);
    return 0;
}

/**
 * Read current routing state
 */
int tvr_read_current_routes(struct tvr_routing_state *state)
{
    struct bgp_dest *dest;
    struct bgp_path_info *pi;
    uint32_t route_count = 0;
    struct bgp_table *table;

    if (!state || !state->bgp) {
        zlog_err("TVR: Invalid state for reading routes");
        return -1;
    }

    state->last_read_time = time(NULL);
    state->read_count++;

    zlog_info("TVR: Reading routes (iteration #%lu)", 
              (unsigned long)state->read_count);

    /* Only process AFI_LINKSTATE + SAFI_BGPLS_TVR routes */
    table = state->bgp->rib[AFI_LINKSTATE][SAFI_BGPLS_TVR];
    if (!table) {
        zlog_debug("TVR: No route table for AFI_LINKSTATE/SAFI_BGPLS_TVR");
        return 0;
    }

    /* Iterate through all TVR routes in the table */
    for (dest = bgp_table_top(table); dest; 
         dest = bgp_route_next(dest)) {
        const struct prefix *p = bgp_dest_get_prefix(dest);

        for (pi = bgp_dest_get_bgp_path_info(dest); pi;
             pi = pi->next) {
            char prefix_str[PREFIX_STRLEN];
            
            prefix2str(p, prefix_str, sizeof(prefix_str));
            route_count++;

            if (bgp_debug_update(NULL, NULL, NULL, 0)) {
                zlog_debug("TVR: Route %s, type %d, sub_type %d",
                          prefix_str, pi->type, pi->sub_type);
            }

            /* Process the route through BGP route processing */
            bgp_process(state->bgp, dest, pi, AFI_LINKSTATE, SAFI_BGPLS_TVR);
        }
    }

    zlog_info("TVR: Read %u BGP-LS TVR routes at time_slice interval", route_count);
    return 0;
}

/**
 * Timer callback function
 */
void tvr_timer_callback(struct event *thread)
{
	struct tvr_routing_state *state;
	uint64_t interval_ms;

	state = EVENT_ARG(thread);
	if (!state) {
		zlog_err("TVR: Invalid state in timer callback");
		return;
	}

	state->timer = NULL;

	/* Read current routes */
	tvr_read_current_routes(state);

	/* Reschedule timer if still active */
	if (state->active) {
		interval_ms = tvr_time_to_ms(state->config.time_slice_value,
		                             state->config.time_slice_unit);
		
		event_add_timer_msec(bm->master, tvr_timer_callback, state,
		                     interval_ms, &state->timer);
	}
}

/**
 * Initialize TVR routing state
 */
struct tvr_routing_state *tvr_init(struct bgp *bgp)
{
    struct tvr_routing_state *state;

    if (!bgp) {
            zlog_err("TVR: Invalid BGP instance");
            return NULL;
    }

    state = XCALLOC(MTYPE_TVR_STATE, sizeof(struct tvr_routing_state));
    state->bgp = bgp;
    state->active = false;
    state->read_count = 0;
    state->last_read_time = 0;
    state->timer = NULL;

    state->config.time_slice_value = TVR_DEFAULT_UPDATE_INTERVAL_S;
    state->config.time_slice_unit = TVR_TIME_UNIT_S;
    state->config.timeout_value = 5;
    state->config.timeout_unit = TVR_TIME_UNIT_S;

    zlog_info("TVR: Initialized for BGP instance %s", 
                bgp->name_pretty ? bgp->name_pretty : "default");

    return state;
}


/**
 * Start TVR periodic routing reads
 */
int tvr_start(struct tvr_routing_state *state)
{
	uint64_t interval_ms;

	if (!state) {
		zlog_err("TVR: Invalid state for start");
		return -1;
	}

	if (state->active) {
		zlog_warn("TVR: Already active");
		return 0;
	}

	state->active = true;
	interval_ms = tvr_time_to_ms(state->config.time_slice_value,
	                             state->config.time_slice_unit);

	zlog_info("TVR: Starting periodic route reads every %lu ms",
	          (unsigned long)interval_ms);

	/* Schedule first timer */
	event_add_timer_msec(bm->master, tvr_timer_callback, state,
	                     interval_ms, &state->timer);

	return 0;
}

/**
 * Stop TVR periodic routing reads
 */
void tvr_stop(struct tvr_routing_state *state)
{
	if (!state)
		return;

	state->active = false;

	if (state->timer) {
		event_cancel(&state->timer);
		state->timer = NULL;
	}

	zlog_info("TVR: Stopped periodic route reads");
}

/**
 * Cleanup TVR routing state
 */
void tvr_cleanup(struct tvr_routing_state *state)
{
	if (!state)
		return;

	tvr_stop(state);
	
	zlog_info("TVR: Cleanup complete, total reads: %lu",
	          (unsigned long)state->read_count);

	XFREE(MTYPE_TVR_STATE, state);
}

/**
 * Get statistics
 */
void tvr_get_stats(struct tvr_routing_state *state, uint64_t *read_count,
                   time_t *last_read)
{
	if (!state)
		return;

	if (read_count)
		*read_count = state->read_count;
	
	if (last_read)
		*last_read = state->last_read_time;
}
