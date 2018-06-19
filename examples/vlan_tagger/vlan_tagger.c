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
 * monitor.c - an example using onvm. Print a message each p package received
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

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_malloc.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "onvm_flow_dir.h"

#define NF_TAG "vlan_tagger"

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

/* number of package between each print */
static uint32_t print_delay = 25000000;

/* destination port, NF serviceID or NF Instance ID*/
static uint32_t destination = 0;

#define BASE_VLAN_TAG   (0x0001)    //Note: 0x000 is reserved
#define MAX_VLAN_TAG    (0x0FFF)    //Note: 0xFFF is reserved, valid till 0xFFE
static uint16_t vlan_tag_value = (BASE_VLAN_TAG);
static int get_new_vlan_tag_value(void) {
        //return ( ((vlan_tag_value==MAX_VLAN_TAG)?(vlan_tag_value=BASE_VLAN_TAG):(vlan_tag_value)) | ((vlan_tag_value++)%MAX_VLAN_TAG) );
        ((vlan_tag_value==MAX_VLAN_TAG)?(vlan_tag_value=BASE_VLAN_TAG):(vlan_tag_value));
        return ( ((vlan_tag_value++)%MAX_VLAN_TAG) );
}
typedef struct vlan_tag_info_table {
        uint16_t ft_index;
        uint16_t vlan_tag;
        uint32_t tag_counter;
        uint64_t pkt_counter;
}vlan_tag_info_table_t;
vlan_tag_info_table_t *vtag_tbl = NULL;


#ifdef ENABLE_NFV_RESL
//#define DIRTY_MAP_PER_CHUNK_SIZE (_NF_STATE_SIZE/(sizeof(uint64_t)*CHAR_BIT))
#define MAX_STATE_ELEMENTS  ((_NF_STATE_SIZE-sizeof(dirty_mon_state_map_tbl_t))/sizeof(vlan_tag_info_table_t))
#else
#define VLAN_NF_STATE_SIZE (64*1024)
#define DIRTY_MAP_PER_CHUNK_SIZE (VLAN_NF_STATE_SIZE/(sizeof(uint64_t)*CHAR_BIT))
#define MAX_STATE_ELEMENTS  ((VLAN_NF_STATE_SIZE-sizeof(dirty_mon_state_map_tbl_t))/sizeof(vlan_tag_info_table_t))
void *vlan_state_mp = NULL;
#endif

/* We can have more entries supported in SDN_FT than this state table or vice versa: hence hash entries to available MAX_STATE_ELEMENTS */
#define MAP_SDN_FT_INDEX_TO_VLAN_STATE_TBL_INDEX(sdn_ft_index) ((sdn_ft_index)%(MAX_STATE_ELEMENTS))

#ifdef MIMIC_FTMB
extern uint8_t SV_ACCES_PER_PACKET;
#endif
/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage: %s [EAL args] -- [NF_LIB args] -- -d <destination> -p <print_delay>\n\n", progname);
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c, dst_flag = 0;

        while ((c = getopt(argc, argv, "d:p:")) != -1) {
                switch (c) {
                case 'd':
                        destination = strtoul(optarg, NULL, 10);
                        dst_flag = 1;
                        break;
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

        if (!dst_flag) {
                RTE_LOG(INFO, APP, "Simple Forward NF requires destination flag -d.\n");
                return -1;
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
        static int pkt_process = 0;

        pkt_process += print_delay;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("PACKETS\n");
        printf("-----\n");
        printf("Port : %d\n", pkt->port);
        printf("Size : %d\n", pkt->pkt_len);
        printf("N°   : %d\n", pkt_process);
        if(vtag_tbl) {
                printf("Share Counter: %d\n", vtag_tbl[0].tag_counter);
                printf("Pkt Counter: %li\n", vtag_tbl[0].pkt_counter);
                printf("Dirty Bits: 0x%lx\n", dirty_state_map->dirty_index);
        }
        printf("\n\n");
#if 0
        struct ipv4_hdr* ip;
        ip = onvm_pkt_ipv4_hdr(pkt);
        if (ip != NULL) {
                onvm_pkt_print(pkt);
        } else {
                printf("No IP4 header found\n");
        }
#endif
}

#if 0
int get_vtag_tbl_index(__attribute__((unused)) struct rte_mbuf* pkt, __attribute__((unused)) struct onvm_pkt_meta* meta);
int get_vtag_tbl_index(__attribute__((unused)) struct rte_mbuf* pkt, __attribute__((unused)) struct onvm_pkt_meta* meta) {
        int tbl_index = -1;
        if(vtag_tbl  == NULL) {
                if(nf_info->nf_state_mempool) {
                        dirty_state_map = (dirty_mon_state_map_tbl_t*)nf_info->nf_state_mempool;
                        vtag_tbl = (vlan_tag_info_table_t*)(dirty_state_map+1);
                        vtag_tbl[0].tag_counter+=1;
                } else {
                        return -1;
                }
                if(meta->ft_index) {
                        ;
                }
        }
        return tbl_index;
}
#endif
static inline uint64_t map_tag_index_to_dirty_chunk_bit_index(uint16_t vlan_tbl_index) {
        uint32_t start_offset = sizeof(dirty_mon_state_map_tbl_t) + vlan_tbl_index*sizeof(vlan_tag_info_table_t);
        uint32_t end_offset = start_offset + sizeof(vlan_tag_info_table_t);
        uint64_t dirty_map_bitmask = 0;
        dirty_map_bitmask |= (1<< (start_offset/DIRTY_MAP_PER_CHUNK_SIZE));
        dirty_map_bitmask |= (1<< (end_offset/DIRTY_MAP_PER_CHUNK_SIZE));
        //printf("\n For %d, 0x%lx\n",(int)vlan_tbl_index, dirty_map_bitmask);
        return dirty_map_bitmask;
}
static inline int update_dirty_state_index(uint16_t vtag_index) {
        if(dirty_state_map) {
                dirty_state_map->dirty_index |= map_tag_index_to_dirty_chunk_bit_index(vtag_index);
                //if(dirty_state_map->dirty_index == 0)
                        //dirty_state_map->dirty_index |= (1L<<(rand() % 60));
        }
        return vtag_index;
}
static inline int save_packet_state(uint16_t vtag_index, int vlan_tag) {
        if(vtag_tbl) {
//#define ENABLE_LOCAL_LATENCY_PROFILER
#ifdef ENABLE_LOCAL_LATENCY_PROFILER
                static int countm = 0;uint64_t start_cycle=0;onvm_interval_timer_t ts_p;
                countm++;
                if(countm == 1000*1000*20) {
                        onvm_util_get_start_time(&ts_p);
                        start_cycle = onvm_util_get_current_cpu_cycles();
                }
#endif
                if(unlikely(vtag_tbl[vtag_index].vlan_tag != vlan_tag)) {
                        vtag_tbl[vtag_index].vlan_tag = vlan_tag;
                        vtag_tbl[vtag_index].pkt_counter =1;
                } else {
                        vtag_tbl[vtag_index].pkt_counter+=1;
                }
                update_dirty_state_index(vtag_index);
#ifdef ENABLE_LOCAL_LATENCY_PROFILER
                if(countm == 1000*1000*20) {
                        fprintf(stdout, "STATE REPLICATION TIME (Marking): %li(ns) and %li (cycles) \n", onvm_util_get_elapsed_time(&ts_p), onvm_util_get_elapsed_cpu_cycles(start_cycle));
                        countm=0;
                }
#endif
        }
        return 0;
}

static void
do_check_and_insert_vlan_tag(struct rte_mbuf* pkt, __attribute__((unused)) struct onvm_pkt_meta* meta) {

        /* This function will check if it is a valid ETH Packet and if it is not a vlan_tagged, inserts a vlan tag */
        struct ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
        if (!eth) {
                exit(0);
                return ;
        }
        /* check packet type and process to insert vlan */
        if (ETHER_TYPE_IPv4 == rte_be_to_cpu_16(eth->ether_type)) {
                //printf("\n BEFORE: PKT_SIZE:0x%x, Before NH [0x%x]!", pkt->pkt_len, rte_be_to_cpu_16(eth->ether_type));
                /* Make space to Append VLAN tag to the Packet */
                if (rte_vlan_insert(&pkt)) {
                        printf("\nFailed to Insert Vlan Header to the Packet!!!!\n");
                        return;
                }
                /* Get the FT Index and Index in VLAN STATE TABLE  */
                uint16_t vlan_ft_index = 0;
#ifdef ENABLE_FT_INDEX_IN_META
                vlan_ft_index = (uint16_t) MAP_SDN_FT_INDEX_TO_VLAN_STATE_TBL_INDEX(meta->ft_index);
#else

                {
                        //printf("\n\n Inserting Vlan Tag\n");
                        struct onvm_flow_entry *flow_entry = NULL;
                        onvm_flow_dir_get_pkt(pkt, &flow_entry);
                        if(flow_entry) {
                                vlan_ft_index = (uint16_t) MAP_SDN_FT_INDEX_TO_VLAN_STATE_TBL_INDEX(flow_entry->entry_index);
                        }
                }
#endif
                /* Extract the vlan tag: Reuse if entry is set; or get new one */
                uint16_t vlan_tag = ((vtag_tbl[vlan_ft_index].vlan_tag)?(vtag_tbl[vlan_ft_index].vlan_tag):get_new_vlan_tag_value());
                //printf("\n\n Inserting Vlan Tag=%d for vlan_ft_index=%d\n",vlan_tag, vlan_ft_index);


                struct vlan_hdr *vlan = (struct vlan_hdr*)(rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr));
                vlan->vlan_tci = rte_cpu_to_be_16((uint16_t)vlan_tag);
                vlan->eth_proto = eth->ether_type;
                eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_VLAN);
                //printf("\n PKT_SIZE:0x%x, VLAN [0x%x, 0x%x:: 0x%x] and NH [0x%x], is already inserted!", pkt->pkt_len, rte_be_to_cpu_16(vlan->vlan_tci), rte_be_to_cpu_16(vlan->eth_proto), ETHER_TYPE_IPv4, rte_be_to_cpu_16(eth->ether_type));

                save_packet_state(vlan_ft_index, vlan_tag);

                rte_vlan_strip(pkt);
                eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);  //strip function doesnt restore; hence must restore eth type explicitly,
                //printf("\n After PKT_SIZE:0x%x, After NH [0x%x] !\n", pkt->pkt_len, rte_be_to_cpu_16(eth->ether_type));
        }
        else if (ETHER_TYPE_VLAN == rte_be_to_cpu_16(eth->ether_type)) {
                /*
                 struct vlan_hdr *vlan = (struct vlan_hdr*)(rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr));
                 if (vlan) {
                         printf("\nVLAN [0x%x, 0x%x] is already inserted!\n", rte_be_to_cpu_16(vlan->vlan_tci), rte_be_to_cpu_16(vlan->eth_proto));
                }
                */
        }
        else {
                printf("\nUnknown Ethernet Type [0x%x]!\n ", rte_be_to_cpu_16(eth->ether_type));
        }
        return;
}
#ifdef ENABLE_ND_MARKING_IN_NFS
/* Frequency of Non-determinism events : after every nondet_freq micro seconds */
//static uint32_t nondet_freq = (1000);
static uint64_t cycles_per_nd_mark = (3*1000*1000*1);
//static uint64_t cycles_per_nd_mark =(nondet_freq*rte_get_timer_hz())/(1000*1000);
static volatile uint32_t nd_counter = 1;
static uint64_t last_cycle;
static uint64_t cur_cycle;
#endif

static int
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
        static uint32_t counter = 0;
        if (++counter == print_delay) {
                do_stats_display(pkt);
                counter = 0;
        }
        //printf("\n Inside Packet Handler\n");
#ifdef ENABLE_ND_MARKING_IN_NFS
        if(nd_counter == 0) {
                //meta->reserved_word |= NF_NEED_ND_SYNC;
                //printf("\n NF is raising ND Event!\n\n");
        } nd_counter++;
        if(0 == last_cycle) last_cycle = rte_get_tsc_cycles();
#endif
        do_check_and_insert_vlan_tag(pkt,meta);
        //if(0 == counter) do_stats_display(pkt);

        //meta->action = ONVM_NF_ACTION_TONF;
        //meta->destination = destination;

        meta->action = ONVM_NF_ACTION_OUT;
        meta->destination = pkt->port;

        //printf("\n Leaving Packet Handler\n");
        return 0;
}

#ifdef ENABLE_ND_MARKING_IN_NFS
static int
callback_handler(void) {
        //return 0;
        cur_cycle = rte_get_tsc_cycles();
        uint64_t delta_cycles = cur_cycle - last_cycle;
        if (last_cycle && (((delta_cycles)) >=  cycles_per_nd_mark)) {
#ifdef ENABLE_LOCAL_LATENCY_PROFILER
                printf("Total elapsed cycles  %"PRIu64" (%"PRIu64" us) and packets before nd_sync: %" PRIu32 "\n", (delta_cycles),(((delta_cycles)*SECOND_TO_MICRO_SECOND)/rte_get_tsc_hz()), nd_counter);
#endif
                last_cycle = cur_cycle;
                nd_counter=0;
        }

        return 0;
}
#endif

int main(int argc, char *argv[]) {
        int arg_offset;

        const char *progname = argv[0];

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG)) < 0)
                return -1;
        argc -= arg_offset;
        argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0)
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");

#ifdef ENABLE_NFV_RESL
        if(nf_info->nf_state_mempool) {
                dirty_state_map = (dirty_mon_state_map_tbl_t*)nf_info->nf_state_mempool;
                vtag_tbl = (vlan_tag_info_table_t*)(dirty_state_map+1);
                vtag_tbl[0].tag_counter+=1;
        }
#else
        //Allocate for state table memory
        vlan_state_mp = rte_calloc("vlan_state_table",1, VLAN_NF_STATE_SIZE, 0);
        if (vlan_state_mp == NULL) {
                rte_exit(EXIT_FAILURE, "Cannot allocate memory for vlan_state_mp program details\n");
        } else {
                dirty_state_map = (dirty_mon_state_map_tbl_t*)vlan_state_mp;
                vtag_tbl = (vlan_tag_info_table_t*)(dirty_state_map+1);
                vtag_tbl[0].tag_counter+=1;
        }
#endif
#ifdef MIMIC_FTMB
SV_ACCES_PER_PACKET = 3;
#endif

#ifndef ENABLE_ND_MARKING_IN_NFS
        onvm_nflib_run(nf_info, &packet_handler);
#else
        onvm_nflib_run_callback(nf_info, &packet_handler, &callback_handler);
#endif

#ifndef ENABLE_NFV_RESL
        rte_free(vlan_state_mp);
#endif
        printf("If we reach here, program is ending");
        return 0;
}
