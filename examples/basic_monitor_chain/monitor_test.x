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

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "onvm_flow_dir.h"



#define NF_TAG "basic_monitor"

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

/* number of package between each print */
static uint32_t print_delay = 1000000;

typedef struct monitor_state_info_table {
        uint16_t ft_index;
        uint16_t tag_counter;
        uint32_t pkt_counter;
}monitor_state_info_table_t;
monitor_state_info_table_t *mon_state_tbl = NULL;

#if 0
typedef struct dirty_mon_state_map_tbl {
        uint64_t dirty_index;   //Bit index to every 1K LSB=0-1K, MSB=63-64K
}dirty_mon_state_map_tbl_t;
dirty_mon_state_map_tbl_t *dirty_state_map = NULL;
#endif

#ifdef ENABLE_NFV_RESL
#define MAX_STATE_ELEMENTS  ((_NF_STATE_SIZE-sizeof(dirty_mon_state_map_tbl_t))/sizeof(monitor_state_info_table_t))
#endif

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage: %s [EAL args] -- [NF_LIB args] -- -p <print_delay>\n\n", progname);
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c;

        while ((c = getopt (argc, argv, "p:")) != -1) {
                switch (c) {
                case 'p':
                        print_delay = strtoul(optarg, NULL, 10);
                        RTE_LOG(INFO, APP, "print_delay = %d\n", print_delay);
                        break;
                case '?':
                        usage(progname);
                        if (optopt == 'p')
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
//	return ;
        const char clr[] = { 27, '[', '2', 'J', '\0' };
        const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
        static int pkt_process = 0;
        struct ipv4_hdr* ip;

        pkt_process += print_delay;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("PACKETS\n");
        printf("-----\n");
        printf("Port : %d\n", pkt->port);
        printf("Size : %d\n", pkt->pkt_len);
        printf("Hash : %u\n", pkt->hash.rss);
        printf("N°   : %d\n", pkt_process);
#ifdef ENABLE_NFV_RESL
        printf("MAX State: %lu\n", MAX_STATE_ELEMENTS);
#endif
        printf("\n\n");

        ip = onvm_pkt_ipv4_hdr(pkt);
        if (ip != NULL) {
                onvm_pkt_print(pkt);
        } else {
                printf("No IP4 header found [%d]\n", pkt_process);
        }
}
#ifdef ENABLE_NFV_RESL
static int save_packet_state(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
//return 0;
        if(nf_info->nf_state_mempool) {
                if(mon_state_tbl  == NULL) {
                        dirty_state_map = (dirty_mon_state_map_tbl_t*)nf_info->nf_state_mempool;
                        mon_state_tbl = (monitor_state_info_table_t*)(dirty_state_map+1);
                        //mon_state_tbl[0].ft_index = 0;
                        mon_state_tbl[0].tag_counter+=1;
                }
                if(mon_state_tbl) {
                        if(meta && pkt) {
                                struct onvm_flow_entry *flow_entry = NULL;
                                onvm_flow_dir_get_pkt(pkt, &flow_entry);
                                if(flow_entry) {
                                        mon_state_tbl[flow_entry->entry_index].ft_index = meta->src;
                                        mon_state_tbl[flow_entry->entry_index].pkt_counter +=1;
                                }
                        }
                        mon_state_tbl[0].pkt_counter+=1;
                }
        }
        return 0;
}
#endif //#ifdef ENABLE_NFV_RESL
static int
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
        static uint32_t counter = 0;
        if (++counter == print_delay) {
                do_stats_display(pkt);
                counter = 0;
        }

        meta->action = ONVM_NF_ACTION_OUT;
        meta->destination = pkt->port;


        if (onvm_pkt_mac_addr_swap(pkt, 0) != 0) {
                printf("ERROR: MAC failed to swap!\n");
        }

#ifdef ENABLE_NFV_RESL
        save_packet_state(pkt,meta);
#endif //#ifdef ENABLE_NFV_RESL
        return 0;
}
#define NUM_PKTS 128
struct rte_mempool *pktmbuf_pool_g;
static struct rte_mbuf* create_ipv4_udp_packet(void) {
        //printf("\n Crafting BFD packet for buffer [%p]\n", pkt);

        uint8_t c_addr[ETHER_ADDR_LEN] = {0x8C, 0xDC, 0xD4, 0xAC, 0x6C, 0x7D};
        uint8_t s_addr[ETHER_ADDR_LEN] = {0x8C, 0xDC, 0xD4, 0xAC, 0x6B, 0x21};
        struct rte_mbuf* pkt = rte_pktmbuf_alloc(pktmbuf_pool_g);
        if(NULL == pktmbuf_pool_g) {
                return NULL;
        }

        /* craft eth header */
        struct ether_hdr *ehdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
        /* set ether_hdr fields here e.g. */
        memset(ehdr,0, sizeof(struct ether_hdr));
        memcpy(&ehdr->s_addr, c_addr, sizeof(c_addr));
        memcpy(&ehdr->d_addr, s_addr, sizeof(s_addr));
        ehdr->ether_type = rte_bswap16(ETHER_TYPE_IPv4);

        /* craft ipv4 header */
        struct ipv4_hdr *iphdr = (struct ipv4_hdr *)(&ehdr[1]);
        memset(iphdr,0, sizeof(struct ipv4_hdr));
        iphdr->src_addr = IPv4(10,0,0,3);
        iphdr->dst_addr = IPv4(10,10,1,4);

        /* set ipv4 header fields here */
        struct udp_hdr *uhdr = (struct udp_hdr *)(&iphdr[1]);
        /* set udp header fields here, e.g. */
        uhdr->src_port = rte_bswap16(3333);
        uhdr->dst_port = rte_bswap16(2222);
        uhdr->dgram_len = 10;

        //set packet properties
        size_t pkt_size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +sizeof(struct udp_hdr);
        pkt->data_len = pkt_size+10;
        pkt->pkt_len = pkt_size+10;

        return pkt;
}
static void send_initial_pkts(void) {
        struct rte_mbuf* pkts[NUM_PKTS];
        int i;
        pktmbuf_pool_g = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(pktmbuf_pool_g == NULL) {
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }
        printf("Creating %d packets to send to %d\n", NUM_PKTS, 0);
        for (i=0; i < NUM_PKTS; i++) {
                struct onvm_pkt_meta* pmeta;
                //pkts[i] = rte_pktmbuf_alloc(pktmbuf_pool_g);
                pkts[i] = create_ipv4_udp_packet();
                pmeta = onvm_get_pkt_meta(pkts[i]);
                pmeta->destination = 1;
                pmeta->action = ONVM_NF_ACTION_TONF;
                pkts[i]->port = 3;
                pkts[i]->hash.rss = i+1;

                pmeta->destination = 0;
                pmeta->action = ONVM_NF_ACTION_OUT;

                onvm_nflib_return_pkt(pkts[i]);
        }
        return;
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

        send_initial_pkts();

        onvm_nflib_run(nf_info, &packet_handler);
        printf("If we reach here, program is ending");
        return 0;
}
