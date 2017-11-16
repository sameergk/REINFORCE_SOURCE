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

                              onvm_special_nf0.c

       This file contains all functions related to NF management.

******************************************************************************/

#include "onvm_mgr.h"
#include "onvm_pkt.h"
#include "onvm_nf.h"
#include "onvm_special_nf0.h"
#include "onvm_stats.h"

/**************************Macros and Feature Definitions**********************/
/* Enable the ONVM_MGR to act as a 2-port bridge without any NFs */
#define ONVM_MGR_ACT_AS_2PORT_FWD_BRIDGE    // Work as bridge < without any NFs :: only testing purpose.. >
//#define SEND_DIRECT_ON_ALT_PORT
//#define DELAY_BEFORE_SEND
//#define DELAY_PER_PKT (5) //20micro seconds

/*************************Local functions Declaration**************************/

/*******************************Helper functions********************************/


#ifdef ONVM_MGR_ACT_AS_2PORT_FWD_BRIDGE
static int onv_pkt_send_on_alt_port(struct thread_info *rx, struct rte_mbuf *pkts[], uint16_t rx_count);
int send_direct_on_alt_port(struct rte_mbuf *pkts[], uint16_t rx_count);

int send_direct_on_alt_port(struct rte_mbuf *pkts[], uint16_t rx_count) {
        uint16_t i, sent_0,sent_1;
        volatile struct tx_stats *tx_stats;
        tx_stats = &(ports->tx_stats);

        struct rte_mbuf *pkts_0[PACKET_READ_SIZE];
        struct rte_mbuf *pkts_1[PACKET_READ_SIZE];
        uint16_t count_0=0, count_1=0;

        for (i = 0; i < rx_count; i++) {
                if (pkts[i]->port == 0) {
                        pkts_1[count_1++] = pkts[i];
                } else {
                        pkts_0[count_0++] = pkts[i];
                }
        }
#ifdef DELAY_BEFORE_SEND
        usleep(DELAY_PER_PKT*count_0);
#endif
        if(count_0) {
                uint8_t port_id = 0;
                sent_0 = rte_eth_tx_burst(port_id,
                                        0,//tx->queue_id,
                                        pkts_0,
                                        count_0);
                if (unlikely(sent_0 < count_0)) {
                        for (i = sent_0; i < count_0; i++) {
                                onvm_pkt_drop(pkts_0[i]);
                        }
                        tx_stats->tx_drop[0] += (count_0 - sent_0);
                }
                tx_stats->tx[0] += sent_0;
        }
#ifdef DELAY_BEFORE_SEND
        usleep(DELAY_PER_PKT*count_1);
#endif
        if(count_1) {
                uint8_t port_id = 0;
                if(ports->num_ports > 1 ) port_id=1;
                sent_1 = rte_eth_tx_burst(port_id,
                                        0,//tx->queue_id,
                                        pkts_1,
                                        count_1);
                if (unlikely(sent_1 < count_1)) {
                        for (i = sent_1; i < count_1; i++) {
                                onvm_pkt_drop(pkts_1[i]);
                        }
                        tx_stats->tx_drop[1] += (count_1 - sent_1);
                }
                tx_stats->tx[1] += sent_1;
        }
        return 0;
}
static int onv_pkt_send_on_alt_port(struct thread_info *rx, struct rte_mbuf *pkts[], uint16_t rx_count) {

        int ret = 0;
        int i = 0;
        struct onvm_pkt_meta *meta = NULL;
        struct rte_mbuf *pkt = NULL;
        static struct client *cl = NULL; //&clients[0];

        if (rx == NULL || pkts == NULL || rx_count== 0)
                return ret;

#ifdef SEND_DIRECT_ON_ALT_PORT
        return send_direct_on_alt_port(pkts, rx_count);
#endif //SEND_DIRECT_ON_ALT_PORT

        for (i = 0; i < rx_count; i++) {
               meta = (struct onvm_pkt_meta*) &(((struct rte_mbuf*)pkts[i])->udata64);
               meta->src = 0;
               meta->chain_index = 0;
               pkt = (struct rte_mbuf*)pkts[i];
                if (pkt->port == 0) {
                        meta->destination = 0;
                        if(ports->num_ports > 1 ) {
                                meta->destination = 1;
                        }
                }
                else {
                        meta->destination = 0;
                }
                meta->action = ONVM_NF_ACTION_OUT;
        }

        //Make use of the internal NF[0]
        cl = &clients[0];
        // DO ONCE: Ensure destination NF is running and ready to receive packets
        if (!onvm_nf_is_valid(cl)) {
                start_special_nf0();
        }

        //Push all packets directly to the NF[0]->tx_ring
        int enq_status = rte_ring_enqueue_bulk(cl->tx_q, (void **)pkts, rx_count);
        if (enq_status) {
                //printf("Enqueue to NF[0] Tx Buffer failed!!");
                onvm_pkt_drop_batch(pkts,rx_count);
                cl->stats.rx_drop += rx_count;
        }
        return ret;
}
#endif //ONVM_MGR_ACT_AS_2PORT_FWD_BRIDGE
/*******************************File Interface functions********************************/
int onv_pkt_send_to_special_nf0(struct thread_info *rx, struct rte_mbuf *pkts[], uint16_t rx_count) {
#ifdef ONVM_MGR_ACT_AS_2PORT_FWD_BRIDGE
        return onv_pkt_send_on_alt_port(rx,pkts,rx_count);
#else
        onvm_pkt_drop_batch(pkts, rx_count);
        return 0;
#endif //ONVM_MGR_ACT_AS_2PORT_FWD_BRIDGE
}
int start_special_nf0(void) {
        //Make use of the internal NF[0]
        static struct client *cl = NULL;
        cl = &clients[0];
        // DO ONCE: Ensure destination NF is running and ready to receive packets
        if (!onvm_nf_is_valid(cl)) {
                void *mempool_data = NULL;
                struct onvm_nf_info *info = NULL;
                struct rte_mempool *nf_info_mp = NULL;
                nf_info_mp = rte_mempool_lookup(_NF_MEMPOOL_NAME);
                if (nf_info_mp == NULL) {
                        printf("Failed to get NF_MEMPOOL");
                        return 0;
                }
                if (rte_mempool_get(nf_info_mp, &mempool_data) < 0) {
                        printf("Failed to get client info memory");
                        return 0;
                }
                if (mempool_data == NULL) {
                        printf("Client Info struct not allocated");
                        return 0;
                }

                info = (struct onvm_nf_info*) mempool_data;
                info->instance_id = 0;
                info->service_id = 0;
                info->status = NF_RUNNING;
                info->tag = "INTERNAL_BRIDGE";

                cl->info=info;
        }
        return onvm_nf_is_valid(cl);
}
int stop_special_nf0(void) {
        return 0;
}

