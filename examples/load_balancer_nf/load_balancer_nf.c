/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2017 George Washington University
 *            2015-2017 University of California Riverside
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
 *  load_balancer.c - an example Layer 3 round-robin load balancer.
 ********************************************************************/

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <assert.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_memory.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "onvm_flow_table.h"
#include "onvm_flow_dir.h"
#include "onvm_sc_common.h"

#define NF_TAG "load_balancer_nf"
#define TABLE_SIZE  SDN_FT_ENTRIES  //65536


/* Struct for flow info */
typedef struct flow_info {
        uint16_t svc_id;
        uint16_t inst_id;
        uint16_t flow_index;
        uint16_t is_active;
        uint64_t last_pkt_cycles;
}flow_info_t;

#ifdef ENABLE_NFV_RESL
#else
#endif

#define MAX_BACKEND_SERVERS (10)
#define MAX_FILE_NAME_LEN (256)
#define MAX_IFACE_NAME_LEN  (256)
flow_info_t ft[TABLE_SIZE];

/* Struct for load balancer information */
typedef struct nf_loadbalance {

#ifndef ENABLE_NFV_RESL
        struct onvm_ft *ft;
#else
        //flow_info_t ft[TABLE_SIZE];
        flow_info_t *ft;
#endif

        /* for cleaning up connections */
        uint16_t num_stored;
        uint64_t elapsed_cycles;
        uint64_t last_cycles;
        uint32_t expire_time;

        /* Per Service Selection logic */
        uint8_t last_sel_inst_id[MAX_SERVICES];

        /* Exclude or Include service list */
        uint16_t exclude_svc_list[MAX_SERVICES];

}nf_loadbalance_t;



/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

nf_loadbalance_t *lb;
/* number of package between each print */
static uint32_t print_delay = 1;

/* Service and nf_per service lookups */
extern uint16_t **services;
extern uint16_t *nf_per_service_count;
extern struct port_info *ports;

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage: %s [EAL args] -- [NF_LIB args] -- nf_svc_id_list -p <print_delay>\n\n", progname);
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c;

        while ((c = getopt(argc, argv, "p:")) != -1) {
                switch (c) {
                case 'p':
                        print_delay = strtoul(optarg, NULL, 10);
                        break;
                case '?':
                        usage(progname);
                        if (optopt == 'd')
                                RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                        else if (optopt == 'p')
                                RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                        else if (isprint(optopt))
                                RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
                        else
                                RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
                        return -1;
                default:
                        usage(progname);
                        return -1;
                }
        }
        return optind;
}


/*
 * This function displays stats. It uses ANSI terminal codes to clear
 * screen when called. It is called from a single non-master
 * thread in the server process, when the process is run with more
 * than one lcore enabled.
 */
static void
do_stats_display(struct rte_mbuf* pkt) {
        const char clr[] = { 27, '[', '2', 'J', '\0' };
        const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
        static uint64_t pkt_process = 0;
        struct ipv4_hdr* ip;

        pkt_process += print_delay;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);
        return;

        printf("PACKETS\n");
        printf("-----\n");
        printf("Port : %d\n", pkt->port);
        printf("Size : %d\n", pkt->pkt_len);
        printf("N°   : %"PRIu64"\n", pkt_process);
        printf("\n\n");

        ip = onvm_pkt_ipv4_hdr(pkt);
        if (ip != NULL) {
                onvm_pkt_print(pkt);
        } else {
                printf("No IP4 header found\n");
        }
}


#ifndef ENABLE_NFV_RESL
#define DIRTY_MAP_PER_CHUNK_SIZE ((sizeof(dirty_mon_state_map_tbl_t) + sizeof(nf_loadbalance_t) + TABLE_SIZE*(sizeof(flow_info_t)))/(sizeof(uint64_t)*CHAR_BIT))
#endif
static inline uint64_t map_tag_index_to_dirty_chunk_bit_index(uint16_t ft_index) {
        uint32_t start_offset = sizeof(dirty_mon_state_map_tbl_t) + sizeof(nf_loadbalance_t) + ft_index*sizeof(flow_info_t);
        uint32_t end_offset = start_offset + sizeof(flow_info_t);
        uint64_t dirty_map_bitmask = 0;
        dirty_map_bitmask |= (1<< (start_offset/DIRTY_MAP_PER_CHUNK_SIZE));
        dirty_map_bitmask |= (1<< (end_offset/DIRTY_MAP_PER_CHUNK_SIZE));
        //printf("\n For %d, 0x%lx\n",(int)vlan_tbl_index, dirty_map_bitmask);
        return dirty_map_bitmask;
}
static inline int update_dirty_state_index(uint16_t ft_index) {
        if(dirty_state_map) {
                dirty_state_map->dirty_index |= map_tag_index_to_dirty_chunk_bit_index(ft_index);
        }
        return ft_index;
}
/*
 * Updates flow info to be "active" or "expired"
 */
static int
update_status(uint64_t elapsed_cycles, struct flow_info *data) {
        if (unlikely(data == NULL)) {
                return -1;
        }
        if ((elapsed_cycles - data->last_pkt_cycles) / rte_get_timer_hz() >= lb->expire_time) {
                //data->is_active = 0;
        } else {
                //data->is_active = 1;
        }

        return 0;
}

/*
 * Clears expired entries from the flow table
 */
static int
clear_entries(void) {
        if (unlikely(lb == NULL)) {
                return -1;
        }

        printf("Clearing expired entries\n");

        struct flow_info *data = NULL;
        uint32_t next = 0;
        for(next=0; next < TABLE_SIZE; next++) {
                if (update_status(lb->elapsed_cycles, data) < 0) {
                        return -1;
                }
                if (!data->is_active) { // if (!data->flow_index)
                        lb->num_stored--;
                        data->is_active = 0;
                }
        }
        return 0;
}

static inline int
setup_nf_instances_for_chain( __attribute__((unused)) struct rte_mbuf* pkt,  __attribute__((unused)) struct onvm_pkt_meta* meta,  __attribute__((unused)) struct flow_info *data, struct onvm_flow_entry *flow_entry) {

        if(ONVM_NF_ACTION_TO_NF_INSTANCE == flow_entry->sc->sc[0].action)
                return 0;

        uint16_t dst_instance_id, service_id, active_nf_count;
        int i = 1;
        for(;i<=flow_entry->sc->chain_length;i++) {
                service_id = flow_entry->sc->sc[i].service;
                active_nf_count = nf_per_service_count[service_id];
                if(0 == active_nf_count) return -1;
                dst_instance_id = services[service_id][lb->last_sel_inst_id[service_id]%active_nf_count];
#ifdef ENABLE_NFV_RESL
                /* If we pick the standby NF then reset from beginning:: This will esnure that we never pick the stanbdy NF for load balancing :: Assuming secondary NFs are always at the bottom of the list  */
                if(is_secondary_active_nf_id(dst_instance_id)) {
                        lb->last_sel_inst_id[service_id] = 0;
                        dst_instance_id = services[service_id][lb->last_sel_inst_id[service_id]%active_nf_count];
                } else {
                        lb->last_sel_inst_id[service_id]++;
                }
#else
                lb->last_sel_inst_id[service_id]++;
#endif
                if(dst_instance_id) {
                        printf("\n Resolved packet: dst_instance_id=[%d] for service_id[%d], active_nf_count[%d]", dst_instance_id,service_id, active_nf_count);
                        //update the action for this flow entry to use the instance mapping directly
                        onvm_sc_set_entry(flow_entry->sc, i, ONVM_NF_ACTION_TO_NF_INSTANCE, dst_instance_id, 0);
                }
        }
        return 0;
}
/*
 * Adds an entry to the flow table. It first checks if the table is full, and
 * if so, it calls clear_entries() to free up space.
 */
static inline int
table_add_entry(struct rte_mbuf* pkt,  __attribute__((unused)) struct onvm_pkt_meta* meta, struct flow_info *data, struct onvm_flow_entry *flow_entry) {

        lb->num_stored++;
        //data->dest = lb->num_stored % lb->server_count;
        setup_nf_instances_for_chain(pkt, meta,data, flow_entry);
        data->last_pkt_cycles = lb->elapsed_cycles;
        data->is_active = 1;
        
        if (TABLE_SIZE - 1 - lb->num_stored == 0) {
                clear_entries();
        }

        return 0;
}

/*
 * Looks up a packet hash to see if there is a matching key in the table.
 * If it finds one, it updates the metadata associated with the key entry,
 * and if it doesn't, it calls table_add_entry() to add it to the table.
 * Duplicate Packets will not add any table entry but get forwarded to the next
 * instance in the chain.
 */
static int
table_lookup_and_set_entry(struct rte_mbuf* pkt,  __attribute__((unused)) struct onvm_pkt_meta* meta) {
        int tbl_index = -ENOENT;
        struct flow_info *data = NULL;
        struct onvm_flow_entry *flow_entry = NULL;

        onvm_flow_dir_get_pkt(pkt, &flow_entry);
        if(flow_entry) {
                tbl_index = flow_entry->entry_index;
        }
        if (tbl_index < 0) {
                printf("Some other error occurred with the packet hashing\n");
                return -1;
        }
#ifdef ENABLE_NFV_RESL
        data = &lb->ft[tbl_index];
#else
        struct onvm_ft_ipv4_5tuple key;
        onvm_ft_fill_key_symmetric(&key, pkt);
        tbl_index = onvm_ft_lookup_key(lb->ft, &key, (char **)&data); //Note: TODO: Currently incomplete
#endif
        if(data->is_active == 0) {
                table_add_entry(pkt,meta,data,flow_entry);
                update_dirty_state_index(tbl_index);
        } else {
                //must map this packet to previously marked instances; just skip and continue
        }
        data->last_pkt_cycles = lb->elapsed_cycles;
        return 0;
}

static
int lb_callback_handler(void);
static
int lb_callback_handler(void) {
        lb->elapsed_cycles = rte_get_tsc_cycles();

        if ((lb->elapsed_cycles - lb->last_cycles) / rte_get_timer_hz() > lb->expire_time) {
                lb->last_cycles = lb->elapsed_cycles;
        }

        return 0;
}
static inline int forward_pkt_to_alt_port(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
        printf("Setting to redirect on alternate port\n ");
        //meta->destination = (pkt->port == 0)? (1):(0);
        if(ports->num_ports > 1) {
                meta->destination = (pkt->port == 0)? (1):(0);
        }
        else {
                meta->destination = pkt->port;
        }
        meta->action = ONVM_NF_ACTION_OUT; //ONVM_NF_ACTION_DROP;
        return 0;
}
/* Note:
 * for this NF to process a packet; the Packet should already be classified and
 * corresponding flow Rule must be set! Based on this Flow Rule and logical SC
 * this NF can select/load balance the traffic across the active NF Instances of
 * each service type in the chain.
 * Otherwise the packets will be dropped!
 *
 */
static int
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
        static uint32_t counter = 0;
        int ret =0;

        /* Unknown packet type */
        if (pkt->hash.rss == 0) {
                return forward_pkt_to_alt_port(pkt,meta);
        }

        /* Get the packet flow entry */
        ret = table_lookup_and_set_entry(pkt, meta);
        if (ret == -1) {
                //meta->action = ONVM_NF_ACTION_DROP;
                //meta->destination = 0;
                //return 0;
                return forward_pkt_to_alt_port(pkt,meta);
        } else {
                meta->src = 0;
                meta->chain_index = 0;
                meta->action = ONVM_NF_ACTION_NEXT;
        }

        if (++counter == print_delay) {
                do_stats_display(pkt);
                //print_flow_info(flow_info);
                counter = 0;
        }
        return 0;
}

int main(int argc, char *argv[]) {
        int arg_offset;
        const char *progname = argv[0];
        
        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG)) < 0)
                return -1;
        argc -= arg_offset;
        argv += arg_offset;

        if(services == NULL || nf_per_service_count == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Missing Dependencies <services> or <nf_per_service_count> information!");
        }

#ifdef ENABLE_NFV_RESL
        if(nf_info->nf_state_mempool) {
                dirty_state_map = (dirty_mon_state_map_tbl_t*)nf_info->nf_state_mempool;
                lb = (nf_loadbalance_t*)(dirty_state_map+1);  //lb = (nf_loadbalance_t*)nf_info->nf_state_mempool;
                lb->ft = (flow_info_t*)(lb +1);
        }
#else
        lb = rte_calloc("state", 1, sizeof(nf_loadbalance_t), 0);
#endif
        if (lb == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Unable to initialize NF lb struct");
        }
        if (parse_app_args(argc, argv, progname) < 0)
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");

#ifndef ENABLE_NFV_RESL
        lb->ft = onvm_ft_create(TABLE_SIZE, sizeof(struct flow_info));
#endif
        if (lb->ft == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Unable to create flow table");
        }

        lb->expire_time = 32;
        lb->elapsed_cycles = rte_get_tsc_cycles();

        //onvm_nflib_run(nf_info, &packet_handler);
        onvm_nflib_run_callback(nf_info, &packet_handler, &lb_callback_handler);
        printf("If we reach here, program is ending\n");

        return 0;
}
