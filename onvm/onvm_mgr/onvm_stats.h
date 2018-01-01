/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2017 George Washington University
 *            2015-2017 University of California Riverside
 *            2010-2014 Intel Corporation. All rights reserved.
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
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
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
 ********************************************************************/


/******************************************************************************
                                 onvm_stats.h

            This file contains all function prototypes related to
            statistics display.

******************************************************************************/


#ifndef _ONVM_STATS_H_
#define _ONVM_STATS_H_
#include <rte_ether.h>


#include "cJSON.h"

#define ONVM_STR_STATS_STDOUT "stdout"
#define ONVM_STR_STATS_STDERR "stderr"
#define ONVM_STR_STATS_WEB "web"

#define ONVM_STATS_FOPEN_ARGS "w+"
#define ONVM_STATS_PATH_BASE "../onvm_web/"
#define ONVM_JSON_STATS_FILE ONVM_STATS_PATH_BASE "onvm_json_stats.json"
#define ONVM_STATS_FILE ONVM_STATS_PATH_BASE "onvm_stats.txt"

#define ONVM_JSON_PORT_STATS_KEY "onvm_port_stats"
#define ONVM_JSON_NF_STATS_KEY "onvm_nf_stats"
#define ONVM_JSON_TIMESTAMP_KEY "last_updated"

#define ONVM_SNPRINTF(str_, sz_, fmt_, ...)                                     \
        do {                                                                    \
                (str_) = (char *)malloc(sizeof(char) * (sz_));                  \
                if (!(str_))                                                    \
                        rte_exit(-1, "ERROR! [%s,%d]: unable to malloc str.\n", \
                                 __FUNCTION__, __LINE__);                       \
                snprintf((str_), (sz_), (fmt_), __VA_ARGS__);                   \
        } while (0)

typedef enum {
        ONVM_STATS_NONE = 0,
        ONVM_STATS_STDOUT,
        ONVM_STATS_STDERR,
        ONVM_STATS_WEB
} ONVM_STATS_OUTPUT;

cJSON* onvm_json_root;
cJSON* onvm_json_port_stats_arr;
cJSON* onvm_json_nf_stats_arr;
cJSON* onvm_json_port_stats[RTE_MAX_ETHPORTS];
cJSON* onvm_json_nf_stats[MAX_NFS];

/*********************************Interfaces**********************************/
typedef struct onvm_stats_snapshot {
        uint64_t rx_delta;          // rx packets in sampled interval
        uint64_t tx_delta;          // tx packets in sampled interval
        uint64_t rx_drop_delta;     // rx drops in sampled interval
        uint64_t tx_drop_delta;     // tx drops in sampled interval
        uint32_t arrival_rate;      // (rx_delta+rx_drops_delta)/interval
        uint32_t rx_rate;           // (rx_delta)/interval
        uint32_t serv_rate;         // (tx_rate)/interval)
        uint32_t tx_rate;           // (tx_rate+tx_drops_delta)/interval)
        uint32_t rx_drop_rate;      // (rx_drops_delta)/interval)
        uint32_t tx_drop_rate;      // (tx_drops_delta)/interval)
}onvm_stats_snapshot_t;

/*********************************Interfaces**********************************/


/*
 * Interface called by the manager to tell the stats module where to print
 * You should only call this once
 *
 * Input: a STATS_OUTPUT enum value representing output destination.  If
 * STATS_NONE is specified, then stats will not be printed to the console or web
 * browser.  If STATS_STDOUT or STATS_STDOUT is specified, then stats will be
 * output the respective stream.
 */
void onvm_stats_set_output(ONVM_STATS_OUTPUT output);

/*
 * Interface to close out file descriptions and clean up memory
 * To be called when the stats loop is done
 */
void onvm_stats_cleanup(void);

/* Interace to retieve nf stats
 * difftime: if 0 : only read but do not update params and rate else update
 */
int get_onvm_nf_stats_snapshot(unsigned nf_index, onvm_stats_snapshot_t *snapshot, unsigned difftime);

/* Interace to retieve nf stats
 * difftime: if 0 : read and update params and cache params locally; else return cached params.
 */
int get_onvm_nf_stats_snapshot_v2(unsigned nf_index, onvm_stats_snapshot_t *snapshot, unsigned difftime);

/*
 * Interface called by the ONVM Manager to display all statistics
 * available.
 *
 * Input : time passed since last display (to compute packet rate)
 *
 */
void onvm_stats_display_all(unsigned difftime);


/*
 * Interface called by the ONVM Manager to clear all clients statistics
 * available.
 *
 * Note : this function doesn't use onvm_stats_clear_client for each client,
 * since with a huge number of clients, the additional functions calls would
 * incur a visible slowdown.
 *
 */
void onvm_stats_clear_all_clients(void);
#define onvm_stats_clear_all_nfs onvm_stats_clear_all_clients


/*
 * Interface called by the ONVM Manager to clear one client's statistics.
 *
 * Input : the client id
 *
 */
void onvm_stats_clear_client(uint16_t id);
#define onvm_stats_clear_nf(x) onvm_stats_clear_client(x)


/******************************Main functions*********************************/


/*
 * Function displaying statistics for all ports
 *
 * Input : time passed since last display (to compute packet rate)
 *
 */
void onvm_stats_display_ports(unsigned difftime);


/*
 * Function displaying statistics for all clients
 *
 * Input : time passed since last display (to compute packet rate)
 */
void onvm_stats_display_clients(__attribute__((unused)) unsigned difftime);

/*
 * Function displaying statistics for all active service chains (flow_entry*)
 *
 * Input : time passed since last display (to compute packet rate)
 */
void onvm_stats_display_chains(unsigned difftime);
/******************************Helper functions*******************************/


/*
 * Function clearing the terminal and moving back the cursor to the top left.
 * 
 */
void onvm_stats_clear_terminal(void);


/*
 * Function giving the MAC address of a port in string format.
 *
 * Input  : port
 * Output : its MAC address
 * 
 */
const char * onvm_stats_print_MAC(uint8_t port);

/*
 * Function printing MAC address 
 * 
 */

void onvm_print_ethaddr(const char *name, struct ether_addr *eth_addr);

extern ONVM_STATS_OUTPUT stats_destination;

#endif  // _ONVM_STATS_H_
