/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2016 George Washington University
 *            2015-2016 University of California Riverside
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
 ********************************************************************/


/******************************************************************************

                              onvm_bfd.c

       This file contains all functions related to BFD management.

******************************************************************************/
#include "onvm_bfd.h"
#include "onvm_mgr.h"
//#include <rte_mbuf.h>
/********************* BFD Specific Defines and Structs ***********************/
#define BFD_PKT_OFFSET (sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr))
#define BFD_CHECKPOINT_PERIOD_IN_US  (100)  // use high precision 100us; ensure that it is at least 1RTT

typedef struct bfd_session_status {
        BFD_StateValue local_state;
        BFD_StateValue remote_state;
        BFD_DiagStateValue local_diags;
        BFD_DiagStateValue remote_diags;

        uint64_t local_descr;
        uint64_t remote_descr;

        uint64_t tx_rx_interval;
        uint64_t last_sent_pkt_ts;
        uint64_t last_rcvd_pkt_ts;
        uint64_t pkt_missed_counter;

}bfd_session_status_t;


struct rte_timer bfd_status_checkpoint_timer;
bfd_session_status_t bfd_sess_info[RTE_MAX_ETHPORTS];
/********************* BFD Specific Defines and Structs ***********************/

/********************* Local Functions Declaration ****************************/
int create_bfd_packet(struct rte_mbuf* pkt);
int parse_bfd_packet(struct rte_mbuf* pkt);
/********************** Local Functions Definition ****************************/
int
onvm_bfd_start(void) {
        return 0;
}

int
onvm_bfd_stop(void) {
        return 0;
}
static void
bfd_status_checkpoint_timer_cb(__attribute__((unused)) struct rte_timer *ptr_timer,
        __attribute__((unused)) void *ptr_data) {
        //printf("In nf_status_checkpoint_timer_cb@: %"PRIu64"\n", onvm_util_get_current_cpu_cycles() );
        return;
}
static inline int initialize_bfd_timers(void) {
        uint64_t ticks = ((uint64_t)BFD_CHECKPOINT_PERIOD_IN_US *(rte_get_timer_hz()/1000000));
        rte_timer_reset_sync(&bfd_status_checkpoint_timer,ticks,PERIODICAL,
                        rte_lcore_id(), &bfd_status_checkpoint_timer_cb, NULL);
        return 0;
}

/******************** BFD Packet Processing Functions *************************/
int create_bfd_packet(struct rte_mbuf* pkt) {
        printf("\n Crafting BFD packet for buffer [%p]\n", pkt);

        /* craft eth header */
        struct ether_hdr *ehdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
        /* set ether_hdr fields here e.g. */
        memset(ehdr,0, sizeof(struct ether_hdr));
        //memset(&ehdr->s_addr,0, sizeof(ehdr->s_addr));
        //memset(&ehdr->d_addr,0, sizeof(ehdr->d_addr));
        ehdr->ether_type = rte_bswap16(ETHER_TYPE_IPv4);
        ehdr->ether_type = rte_bswap16(ETHER_TYPE_BFD);     //change to specific type for ease of packet handling.

        /* craft ipv4 header */
        struct ipv4_hdr *iphdr = (struct ipv4_hdr *)(&ehdr[1]);
        memset(iphdr,0, sizeof(struct ipv4_hdr));

        /* set ipv4 header fields here */
        struct udp_hdr *uhdr = (struct udp_hdr *)(&iphdr[1]);
        /* set udp header fields here, e.g. */
        uhdr->src_port = rte_bswap16(3784);
        uhdr->dst_port = rte_bswap16(3784);

        BfdPacket *bfdp = (BfdPacket *)(&uhdr[1]);
        bfdp->header.flags = 0;
        return 0;
}
int parse_bfd_packet(struct rte_mbuf* pkt) {
        struct udp_hdr *uhdr;
        BfdPacket *bfdp = NULL;

        uhdr = (struct udp_hdr*)(rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
        bfdp = (BfdPacket *)(&uhdr[1]);
        //bfdp = (BfdPacket*)(rte_pktmbuf_mtod(pkt, uint8_t*) + BFD_PKT_OFFSET);

        if(unlikely((sizeof(BfdPacket) > rte_be_to_cpu_16(uhdr->dgram_len)))) return -1;

        if(bfdp->header.flags == 0) return 0;
        return 0;
}

/********************************Interfaces***********************************/
int
onvm_bfd_process_incoming_packets(__attribute__((unused)) struct thread_info *rx, struct rte_mbuf *pkts[], uint16_t rx_count) {
        uint16_t i=0;
        for(;i<rx_count;i++) {
                parse_bfd_packet(pkts[i]);
        }
        return 0;
}
int
onvm_bfd_init(onvm_bfd_init_config_t *bfd_config) {
        if(unlikely(NULL == bfd_config)) return 0;
        printf("ONVM_BFD: INIT with identifier=%d(%x)", bfd_config->bfd_identifier, bfd_config->bfd_identifier);

        struct rte_mempool *pktmbuf_pool = NULL;
        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(NULL == pktmbuf_pool) {
                return -1;
        }

        struct rte_mbuf *buf = rte_pktmbuf_alloc(pktmbuf_pool);
        if(NULL == pktmbuf_pool) {
                return -1;
        }

        create_bfd_packet(buf);

        //@Note: The Timer runs in the caller thread context (Main or Wakethread): Must ensure the freq is > 1/bfd interval
        initialize_bfd_timers();

        return 0;
}

int
onvm_bfd_deinit(void) {
        return 0;
}


