/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2016 George Washington University
 *            2015-2016 University of California Riverside
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * onvm_pkt_helper.c - packet helper routines
 ********************************************************************/

#include "onvm_comm_utils.h"

#include <rte_branch_prediction.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#ifdef HAS_CLOCK_GETTIME_MONOTONIC
  struct timespec start, stop;
  struct timespec gstart, gstop;
#else
  struct timeval start, stop;
  struct timeval gstart, gstop;
#endif


inline int onvm_util_get_cur_time(onvm_time_t* ct) {
#ifdef HAS_CLOCK_GETTIME_MONOTONIC
        if (clock_gettime(USE_THIS_CLOCK, (struct timespec *) &ct->t) == -1) {
                perror("clock_gettime");
                return 1;
        }
#else
        if (gettimeofday(&ct->t, NULL) == -1) {
                perror("gettimeofday");
                return 1;
        }
#endif
        return 0;
}


inline int onvm_util_get_start_time(onvm_interval_timer_t* ct) {
#ifdef HAS_CLOCK_GETTIME_MONOTONIC
        if (clock_gettime(USE_THIS_CLOCK, &ct->ts.t) == -1) {
                perror("clock_gettime");
                return 1;
        }
#else
        if (gettimeofday(&ct->ts.t, NULL) == -1) {
                perror("gettimeofday");
                return 1;
        }
#endif
        return 0;
}

inline int onvm_util_get_stop_time(onvm_interval_timer_t* ct) {
#ifdef HAS_CLOCK_GETTIME_MONOTONIC
        if (clock_gettime(USE_THIS_CLOCK, &ct->tp.t) == -1) {
                perror("clock_gettime");
                return 1;
        }
#else
        if (gettimeofday(&ct->tp.t, NULL) == -1) {
                perror("gettimeofday");
                return 1;
        }
#endif
        return 0;
}

inline int64_t onvm_util_get_elapsed_time(onvm_interval_timer_t* ct) {
#ifdef HAS_CLOCK_GETTIME_MONOTONIC
        int64_t delta = ((ct->tp.t.tv_sec - ct->ts.t.tv_sec) * 1000000000
                        + (ct->tp.t.tv_nsec - ct->ts.t.tv_nsec));
#else
        int64_t delta = (ct->tp.t.tv_sec - ct->ts.t.tv_sec) * 1000000000 +
        (ct->tp.t.tv_usec - ct->ts.t.tv_usec) * 1000;
#endif
        return delta;
}

inline int64_t onvm_util_get_diff_time_now(onvm_time_t* cs) {
        onvm_time_t cp;
        onvm_util_get_cur_time(&cp);
#ifdef HAS_CLOCK_GETTIME_MONOTONIC
        int64_t delta = ((cp.t.tv_sec - cs->t.tv_sec) * 1000000000
                        + (cp.t.tv_nsec - cs->t.tv_nsec));
#else
        int64_t delta = (cp.t.tv_sec - cs->t.tv_sec) * 1000000000 +
        (cp.t.tv_usec - cs->t.tv_usec) * 1000;
#endif
        return delta;
}

inline unsigned long onvm_util_get_difftime_us(onvm_time_t *cs, onvm_time_t *cp) {
#ifdef HAS_CLOCK_GETTIME_MONOTONIC
        unsigned long delta = ((cp->t.tv_sec - cs->t.tv_sec) * SECOND_TO_MICRO_SECOND
                        + ((cp->t.tv_nsec - cs->t.tv_nsec)/1000));
#else
        int64_t delta = (cp->t.tv_sec - cs->t.tv_sec) * SECOND_TO_MICRO_SECOND +
        (cp->t.tv_usec - cs->t.tv_usec);
#endif
        return delta;
}

inline uint64_t onvm_util_get_current_cpu_cycles(void) {
        return rte_rdtsc_precise();
}

inline uint64_t onvm_util_get_diff_cpu_cycles(uint64_t start, uint64_t end) {
        if(end > start) {
                return (uint64_t) (end -start);
        }
        return 0;
}

inline uint64_t onvm_util_get_diff_cpu_cycles_in_us(uint64_t start, uint64_t end) {
        if(end > start) {
                return (uint64_t) (((end -start)*SECOND_TO_MICRO_SECOND)/rte_get_tsc_hz());
        }
        return 0;
}

inline uint64_t onvm_util_get_elapsed_cpu_cycles(uint64_t start) {
        return onvm_util_get_diff_cpu_cycles(start, onvm_util_get_current_cpu_cycles());
}

inline uint64_t onvm_util_get_elapsed_cpu_cycles_in_us(uint64_t start) {
        return onvm_util_get_diff_cpu_cycles_in_us(start, onvm_util_get_current_cpu_cycles());
}

