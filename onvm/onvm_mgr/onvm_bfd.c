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
#include "onvm_pkt.h"

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


extern struct rte_mempool *pktmbuf_pool;
struct rte_timer bfd_status_checkpoint_timer;
bfd_session_status_t bfd_sess_info[RTE_MAX_ETHPORTS];
bfd_status_notifier_cb notifier_cb;
BfdPacket bfd_template;
/********************* BFD Specific Defines and Structs ***********************/

/********************* Local Functions Declaration ****************************/
struct rte_mbuf* create_bfd_packet(void);
int parse_bfd_packet(struct rte_mbuf* pkt);
static void send_bfd_echo_packets(void);
static void check_bdf_remote_status(void);
/********************** Local Functions Definition ****************************/
static void init_bfd_session_status(uint64_t local_desc) {
        uint8_t i = 0;
        for(i=0;i< ports->num_ports;i++) {
                bfd_sess_info[i].local_state    = Init;
                bfd_sess_info[i].remote_state   = Init;

                bfd_sess_info[i].local_diags    = None;
                bfd_sess_info[i].remote_diags   = None;

                bfd_sess_info[i].local_descr    = local_desc;
                bfd_sess_info[i].remote_descr   = local_desc;

                bfd_sess_info[i].tx_rx_interval = 0;
                bfd_sess_info[i].last_sent_pkt_ts = 0;
                bfd_sess_info[i].last_rcvd_pkt_ts = 0;
                bfd_sess_info[i].pkt_missed_counter = 0;
        }
}
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
        send_bfd_echo_packets();
        check_bdf_remote_status();
        return;
}
static inline int initialize_bfd_timers(void) {
        uint64_t ticks = ((uint64_t)BFD_CHECKPOINT_PERIOD_IN_US *(rte_get_timer_hz()/1000000));
        rte_timer_reset_sync(&bfd_status_checkpoint_timer,ticks,PERIODICAL,
                        rte_lcore_id(), &bfd_status_checkpoint_timer_cb, NULL);
        return 0;
}

/******************** BFD Packet Processing Functions *************************/
static inline int bfd_send_packet_out(uint8_t port_id, uint16_t queue_id, struct rte_mbuf *tx_pkt) {
        uint16_t sent_packets = rte_eth_tx_burst(port_id,queue_id, &tx_pkt, 1);
        if(unlikely(sent_packets  == 0)) {
                onvm_pkt_drop(tx_pkt);
        }
        //printf("\n %d BFD Packets were sent!", sent_packets);
        return sent_packets;
}
static void set_bfd_packet_template(uint32_t my_desc) {
        bfd_template.header.versAndDiag = 0x00;
        bfd_template.header.flags= 0x00;
        bfd_template.header.length=sizeof(BfdPacket);
        bfd_template.header.myDisc=rte_cpu_to_be_32(my_desc);
        bfd_template.header.yourDisc=0;
        bfd_template.header.txDesiredMinInt=rte_cpu_to_be_32(BFDMinTxInterval_us);
        bfd_template.header.rxRequiredMinInt=rte_cpu_to_be_32(BFDMinRxInterval_us);
        bfd_template.header.rxRequiredMinEchoInt=rte_cpu_to_be_32(BFDEchoInterval_us);
}

static void parse_and_set_bfd_session_info(struct rte_mbuf* pkt,BfdPacket *bfdp) {
        uint8_t port_id = pkt->port; //rem_desc & 0xFF;
        if(port_id < ports->num_ports) {
                if(Init == bfd_sess_info[port_id].remote_state) {
                        bfd_sess_info[port_id].remote_state = Up;
                        bfd_sess_info[port_id].remote_descr = rte_be_to_cpu_32(bfdp->header.myDisc);
                } else if (Down == bfd_sess_info[port_id].remote_state || AdminDown == bfd_sess_info[port_id].remote_state) {
                        bfd_sess_info[port_id].remote_state = Up;
                        bfd_sess_info[port_id].remote_descr = rte_be_to_cpu_32(bfdp->header.myDisc);
                }
                //bfd_sess_info[port_id].remote_state = (BFD_StateValue)bfdp->header.flags;   //todo: parse flag to status
                bfd_sess_info[port_id].remote_diags = (BFD_DiagStateValue)bfdp->header.versAndDiag; //todo: parse verse_and_diag to diag_status
                bfd_sess_info[port_id].last_rcvd_pkt_ts = onvm_util_get_current_cpu_cycles();
        }
}

struct rte_mbuf* create_bfd_packet(void) {
        //printf("\n Crafting BFD packet for buffer [%p]\n", pkt);

        struct rte_mbuf* pkt = rte_pktmbuf_alloc(pktmbuf_pool);
        if(NULL == pktmbuf_pool) {
                return NULL;
        }

        /* craft eth header */
        struct ether_hdr *ehdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
        /* set ether_hdr fields here e.g. */
        memset(ehdr,0, sizeof(struct ether_hdr));
        //memset(&ehdr->s_addr,0, sizeof(ehdr->s_addr));
        //memset(&ehdr->d_addr,0, sizeof(ehdr->d_addr));
        //ehdr->ether_type = rte_bswap16(ETHER_TYPE_IPv4);
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

        rte_memcpy(bfdp, &bfd_template, sizeof(BfdPacketHeader));

        //set packet properties
        size_t pkt_size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +sizeof(BfdPacket);
        pkt->data_len = pkt_size;
        pkt->pkt_len = pkt_size;

        return pkt;
}
int parse_bfd_packet(struct rte_mbuf* pkt) {
        struct udp_hdr *uhdr;
        BfdPacket *bfdp = NULL;

        uhdr = (struct udp_hdr*)(rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
        bfdp = (BfdPacket *)(&uhdr[1]);
        //bfdp = (BfdPacket*)(rte_pktmbuf_mtod(pkt, uint8_t*) + BFD_PKT_OFFSET);

        if(unlikely((sizeof(BfdPacket) > rte_be_to_cpu_16(uhdr->dgram_len)))) return -1;

        parse_and_set_bfd_session_info(pkt, bfdp);
        //if(bfdp->header.flags == 0) return 0;
        return 0;
}
static void send_bfd_echo_packets(void) {
        uint16_t i=0;
        struct rte_mbuf *pkt = NULL;
        for(i=0; i< ports->num_ports; i++) {
                if(Init == bfd_sess_info[i].local_state) {
                        bfd_sess_info[i].local_state = Up;
                } else if (Down == bfd_sess_info[i].local_state || AdminDown == bfd_sess_info[i].local_state) continue;

                pkt = create_bfd_packet();
                if(pkt) {
                        bfd_sess_info[i].last_sent_pkt_ts = onvm_util_get_current_cpu_cycles();
                        bfd_send_packet_out(i, 0, pkt);
                }
        }
        return ;
}
static void check_bdf_remote_status(void) {
        uint16_t i=0;
        uint64_t elapsed_time = 0;
        for(i=0; i< ports->num_ports; i++) {
                if(bfd_sess_info[i].remote_state !=Up) continue;
                elapsed_time = onvm_util_get_elapsed_cpu_cycles_in_us(bfd_sess_info[i].last_rcvd_pkt_ts);
                if(elapsed_time > BFD_TIMEOUT_INTERVAL) {
                        //Shift from Up to Down and notify Link Down Status
                        bfd_sess_info[i].remote_state = Down;
                        if(notifier_cb) {
                                notifier_cb(i,BFD_STATUS_REMOTE_DOWN);
                        }
                }
        }
        return ;
}
/********************************Interfaces***********************************/
int
onvm_bfd_process_incoming_packets(__attribute__((unused)) struct thread_info *rx, struct rte_mbuf *pkts[], uint16_t rx_count) {
        uint16_t i=0;
        printf("\n parsing Incoming BFD packets[%d]!!!\n", rx_count);
        for(;i<rx_count;i++) {
                parse_bfd_packet(pkts[i]);
        }
        return 0;
}
int
onvm_bfd_init(onvm_bfd_init_config_t *bfd_config) {
        if(unlikely(NULL == bfd_config)) return 0;
        printf("ONVM_BFD: INIT with identifier=%d(%x)", bfd_config->bfd_identifier, bfd_config->bfd_identifier);

        if(NULL == pktmbuf_pool) {
                pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
                if(NULL == pktmbuf_pool) {
                        return -1;
                }
        }

        notifier_cb = bfd_config->cb_func;
        set_bfd_packet_template(bfd_config->bfd_identifier);
        init_bfd_session_status(bfd_config->bfd_identifier);

        //@Note: The Timer runs in the caller thread context (Main or Wakethread): Must ensure the freq is > 1/bfd interval
        initialize_bfd_timers();

        return 0;
}

int
onvm_bfd_deinit(void) {
        return 0;
}


int onvm_print_bfd_status(__attribute__((unused)) FILE *fp) {
        fprintf(fp, "BFD\n");
        fprintf(fp,"-----\n");
        uint8_t i = 0;
        for(i=0; i< ports->num_ports; i++) {
                fprintf(fp, "Port:%d Local status:%d, Remote Status:%d rx_us:%"PRIu64" tx_us:%"PRIu64"\n",
                                i, bfd_sess_info[i].local_state,  bfd_sess_info[i].remote_state,
                                onvm_util_get_elapsed_cpu_cycles_in_us(bfd_sess_info[i].last_sent_pkt_ts),
                                onvm_util_get_elapsed_cpu_cycles_in_us(bfd_sess_info[i].last_rcvd_pkt_ts));
        }
        return 0;
}
