/*
 * BGP Link-State Time-Variant Routing Header
 * Copyright (C) 2026
 *
 * This file is part of FRRouting.
 */

#ifndef _BGP_LS_TVR_H
#define _BGP_LS_TVR_H

#include "frrevent.h"
#include "bgpd/bgpd.h"

#define TVR_DEFAULT_UPDATE_INTERVAL_S 10

/* Time unit enumeration */
enum tvr_time_unit {
	TVR_TIME_UNIT_MS = 0,  /* milliseconds */
	TVR_TIME_UNIT_S,       /* seconds */
	TVR_TIME_UNIT_US,      /* microseconds */
	TVR_TIME_UNIT_NS       /* nanoseconds */
};

/* TVR scheduler configuration */
struct tvr_scheduler_config {
	uint32_t time_slice_value;       /* Time slice value */
	enum tvr_time_unit time_slice_unit;  /* Time slice unit */
	uint32_t timeout_value;          /* Timeout value */
	enum tvr_time_unit timeout_unit;     /* Timeout unit */
};

/* TVR routing state */
struct tvr_routing_state {
	struct event *timer;            /* Timer thread */
	struct tvr_scheduler_config config;  /* Scheduler configuration */
	struct bgp *bgp;                 /* BGP instance */
	bool active;                     /* Active flag */
	uint64_t read_count;             /* Number of route reads */
	time_t last_read_time;           /* Last read timestamp */
};

/* Function prototypes */

/**
 * Set update interval (seconds) from FRR config
 * @param state TVR routing state
 * @param seconds Interval in seconds (must be > 0)
 * @return 0 on success, -1 on error
 */
extern int tvr_set_update_interval(struct tvr_routing_state *state,
                                   uint32_t seconds);

/**
 * Convert time value to milliseconds
 * @param value Time value
 * @param unit Time unit
 * @return Time in milliseconds
 */
extern uint64_t tvr_time_to_ms(uint32_t value, enum tvr_time_unit unit);

/**
 * Read current routing state
 * @param state TVR routing state
 * @return 0 on success, -1 on error
 */
extern int tvr_read_current_routes(struct tvr_routing_state *state);

/**
 * Timer callback function
 * @param thread Thread structure
 * @return 0
 */
extern void tvr_timer_callback(struct event *thread);

/**
 * Initialize TVR routing state
 * @param bgp BGP instance
 * @return Initialized TVR state or NULL on error
 */
extern struct tvr_routing_state *tvr_init(struct bgp *bgp);

/**
 * Start TVR periodic routing reads
 * @param state TVR routing state
 * @return 0 on success, -1 on error
 */
extern int tvr_start(struct tvr_routing_state *state);

/**
 * Stop TVR periodic routing reads
 * @param state TVR routing state
 */
extern void tvr_stop(struct tvr_routing_state *state);

/**
 * Cleanup TVR routing state
 * @param state TVR routing state
 */
extern void tvr_cleanup(struct tvr_routing_state *state);

/**
 * Get statistics
 * @param state TVR routing state
 * @param read_count Output: number of reads
 * @param last_read Output: last read time
 */
extern void tvr_get_stats(struct tvr_routing_state *state,
                          uint64_t *read_count,
                          time_t *last_read);

#endif /* _BGP_LS_TVR_H */
