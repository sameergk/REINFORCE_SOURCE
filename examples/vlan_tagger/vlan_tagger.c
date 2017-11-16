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

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "onvm_flow_dir.h"

#define NF_TAG "vlan_tagger"

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

/* number of package between each print */
static uint32_t print_delay = 5000000;


static uint32_t destination;

typedef struct vlan_tag_info_table {
        uint16_t ft_index;
        uint16_t vlan_tag;
        uint32_t tag_counter;
        uint64_t pkt_counter;
}vlan_tag_info_table_t;
vlan_tag_info_table_t *vtag_tbl = NULL;

typedef struct dirty_mon_state_map_tbl {
        uint64_t dirty_index;   //Bit index to every 1K LSB=0-1K, MSB=63-64K
}dirty_mon_state_map_tbl_t;
dirty_mon_state_map_tbl_t *dirty_state_map = NULL;
#ifdef ENABLE_NFV_RESL
#define MAX_STATE_ELEMENTS  ((_NF_STATE_SIZE-sizeof(dirty_mon_state_map_tbl_t))/sizeof(vlan_tag_info_table_t))
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
#ifdef ENABLE_NFV_RESL
static int save_packet_state(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
        if(nf_info->state_mempool) {
                if(vtag_tbl  == NULL) {
                        dirty_state_map = (dirty_mon_state_map_tbl_t*)nf_info->state_mempool;
                        vtag_tbl = (vlan_tag_info_table_t*)(dirty_state_map+1);
                        vtag_tbl[0].tag_counter+=1;
                }
                if(vtag_tbl && meta && pkt) {
                        struct onvm_flow_entry *flow_entry = NULL;
                        onvm_flow_dir_get_pkt(pkt, &flow_entry);
                        if(flow_entry) {
                                vtag_tbl[flow_entry->entry_index].ft_index = meta->src;
                                vtag_tbl[flow_entry->entry_index].pkt_counter +=1;
                                //vtag_tbl[flow_entry->entry_index].ft_index = 0;
                                //vtag_tbl[flow_entry->entry_index].vlan_tag = vlan_tag;
                        } else {
                                vtag_tbl[0].pkt_counter+=1;
                                //vtag_tbl[0].ft_index = 0;
                                //vtag_tbl[0].vlan_tag = vlan_tag;
                        }
                }
        }
        return 0;
}
#endif //#ifdef ENABLE_NFV_RESL
static void
do_check_and_insert_vlan_tag(struct rte_mbuf* pkt, __attribute__((unused)) struct onvm_pkt_meta* meta) {
        /* This function will check if it is a valid ETH Packet
         * and if it is not a vlan_tagged, inserts a vlan tag
         */
        struct ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
        if (!eth) {
                exit(0);
                return ;
        }
        uint16_t vlan_tag = 0x10;
        if (ETHER_TYPE_IPv4 == rte_be_to_cpu_16(eth->ether_type)) {
                if (rte_vlan_insert(&pkt)) {
                        printf("\nFailed to Insert Vlan Header to the Packet!!!!\n");
                        return;
                }
                struct vlan_hdr *vlan = (struct vlan_hdr*)(rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr));
                vlan->vlan_tci = rte_cpu_to_be_16((uint16_t)vlan_tag);
                //vlan->eth_proto = rte_cpu_to_be_16(ETHER_TYPE_ARP);
                //printf("\nVLAN [0x%x, 0x%x] is already inserted!\n", rte_be_to_cpu_16(vlan->vlan_tci), rte_be_to_cpu_16(vlan->eth_proto));
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

        //rte_vlan_strip(pkt);
#ifdef ENABLE_NFV_RESL
        save_packet_state(pkt,meta);
#endif //#ifdef ENABLE_NFV_RESL

        return;
}
static int
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
        static uint32_t counter = 0;
        if (++counter == print_delay) {
                do_stats_display(pkt);
                counter = 0;
        }

        do_check_and_insert_vlan_tag(pkt,meta);
        //if(0 == counter) do_stats_display(pkt);

        meta->action = ONVM_NF_ACTION_TONF;
        meta->destination = destination;

        meta->action = ONVM_NF_ACTION_OUT;
        meta->destination = pkt->port;
        return 0;
}


int main(int argc, char *argv[]) {
        int arg_offset;

        const char *progname = argv[0];

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG)) < 0)
                return -1;
        argc -= arg_offset;
        argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0)
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");

        onvm_nflib_run(nf_info, &packet_handler);
        printf("If we reach here, program is ending");
        return 0;
}
