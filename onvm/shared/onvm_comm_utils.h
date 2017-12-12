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
 * onvm_pkt_helper.h - packet helper routines
 ********************************************************************/

#ifndef _ONVM_COMM_UTILS_H_
#define _ONVM_COMM_UTILS_H_

/***************************Standard C library********************************/
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <semaphore.h>
#include <fcntl.h>
#include <mqueue.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <time.h>
/*****************************Internal headers********************************/
#if defined(_POSIX_TIMERS) && (_POSIX_TIMERS > 0) &&                           \
    defined(_POSIX_MONOTONIC_CLOCK)
#define HAS_CLOCK_GETTIME_MONOTONIC
#endif
#define USE_THIS_CLOCK  CLOCK_MONOTONIC //CLOCK_THREAD_CPUTIME_ID //CLOCK_PROCESS_CPUTIME_ID //CLOCK_MONOTONIC

typedef struct onvm_time_s {
#ifdef HAS_CLOCK_GETTIME_MONOTONIC
  struct timespec t;
#else
  struct timeval t;
#endif
}onvm_time_t;
typedef struct onvm_interval_timer_s {
        onvm_time_t ts;
        onvm_time_t tp;
}onvm_interval_timer_t;

inline int onvm_util_get_cur_time(onvm_time_t* ct);
inline int onvm_util_get_start_time(onvm_interval_timer_t* ct);
inline int onvm_util_get_stop_time(onvm_interval_timer_t* ct);
inline int64_t onvm_util_get_elapsed_time(onvm_interval_timer_t *ct);
inline int64_t onvm_util_get_diff_time_now(onvm_time_t* ct);
inline unsigned long onvm_util_get_difftime_us(onvm_time_t *cs, onvm_time_t *cp);

#define SECOND_TO_MICRO_SECOND          (1000*1000)
#define NANO_SECOND_TO_MICRO_SECOND(x)  (double)((x)/(1000))
#define MICRO_SECOND_TO_SECOND(x)       (double)((x)/(SECOND_TO_MICRO_SECOND))
//#define USE_THIS_CLOCK  CLOCK_MONOTONIC //CLOCK_THREAD_CPUTIME_ID //CLOCK_PROCESS_CPUTIME_ID //CLOCK_MONOTONIC
typedef struct stats_time_info {
        uint8_t in_read;
        onvm_time_t prev_time;
        onvm_time_t cur_time;
}nf_stats_time_info_t;

#include <rte_cycles.h>
typedef struct stats_cycle_info {
        uint8_t in_read;
        uint64_t prev_cycles;
        uint64_t cur_cycles;
}stats_cycle_info_t;
inline uint64_t onvm_util_get_current_cpu_cycles(void);
inline uint64_t onvm_util_get_diff_cpu_cycles(uint64_t start, uint64_t end);
inline uint64_t onvm_util_get_diff_cpu_cycles_in_us(uint64_t start, uint64_t end);
inline uint64_t onvm_util_get_elapsed_cpu_cycles(uint64_t start);
inline uint64_t onvm_util_get_elapsed_cpu_cycles_in_us(uint64_t start);

#endif  // _ONVM_COMM_UTILS_H_"
