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
#include "onvm_rsync.h"
//#include "onvm_stats.h"
#include "onvm_ft_install.h"
//#include "shared/onvm_pkt_helper.h"
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_arp.h>
#ifdef ENABLE_VXLAN
#include "onvm_vxlan.h"
#ifdef ENABLE_ZOOKEEPER
#include "onvm_zookeeper.h"
#endif
#endif

#ifdef ENABLE_REMOTE_SYNC_WITH_TX_LATCH

struct rte_timer nf_status_checkpoint_timer;
#define RSYNC_CHECK_INTERVAL_NS     (100*1000)
#define NF_CHECKPOINT_PERIOD_IN_US  (100)       // use high precision 100us; ensure that it is at least 1RTT

#define NEED_REMOTE_TS_TABLE_SYNC   (0x01)
#define NEED_REMOTE_NF_STATE_SYNC   (0x10)

#ifdef ENABLE_PER_FLOW_TS_STORE
dirty_mon_state_map_tbl_t *dirty_state_map = NULL;
onvm_per_flow_ts_info_t   *tx_ts_table = NULL;
//size of mempool = _PER_FLOW_TS_SIZE;
#define DIRTY_MAP_PER_CHUNK_SIZE (_NF_STATE_SIZE/(sizeof(uint64_t)*CHAR_BIT))
#define MAX_TX_TS_ENTRIES        ((_NF_STATE_SIZE -sizeof(dirty_mon_state_map_tbl_t))/(sizeof(uint64_t)*CHAR_BIT))
#endif

typedef struct remote_node_config {
        uint8_t mac_addr_bytes[ETHER_ADDR_LEN];
        uint32_t ip_addr;
}remote_node_config_t;
static remote_node_config_t rsync_node_info = {
                .mac_addr_bytes={0x8C, 0xDC, 0xD4, 0xAC, 0x6B, 0x21},
                .ip_addr=IPv4(10,10,1,4)
};

#define STATE_TYPE_TX_TS_TABLE  (0)
#define STATE_TYPE_NF_MEMPOOL   (1)
#define STATE_TYPE_SVC_MEMPOOL  (2)

#define MAX_STATE_SIZE_PER_PACKET   (1024)
typedef struct state_tx_meta {
        uint8_t state_type;     //TX_TS_TYPE; NF_STATE; SERV_STATE;
        uint8_t nf_or_svc_id;   //Id of the NF(NF_STATE) or SVC (SERVICE_STATE)
        uint16_t start_offset;  //Offset in the global mempool
        uint8_t trans_id;       //Id of the atomic transaction
        uint8_t last_packet;    //Indicate whether it is last packet or still more to follow.
        uint32_t reserved;      //Note Size per packet is Fixed to 1024 Bytes.
}state_tx_meta_t;

typedef struct state_transfer_packet_hdr {
        state_tx_meta_t meta;
        uint8_t data[MAX_STATE_SIZE_PER_PACKET];
}state_transfer_packet_hdr_t;

struct rte_mempool *pktmbuf_pool = NULL;


extern uint32_t nf_mgr_id;
/***********************Internal Functions************************************/
static inline int send_packets_out(uint8_t port_id, uint16_t queue_id, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
static struct rte_mbuf* craft_state_update_packet(uint8_t port, state_tx_meta_t meta, uint8_t *pData, uint32_t data_len);

int transmit_tx_port_packets(void);
static int transmit_tx_tx_state_latch_rings(void);
static int transmit_tx_nf_state_latch_rings(void);
static int extract_and_parse_tx_port_packets(void);

static int rsync_tx_ts_state(void);
static int rsync_nf_state(void);
static int rsync_wait_for_commit_ack(void);

static inline int initialize_rsync_timers(void);
/***********************Internal Functions************************************/
static uint8_t get_transaction_id(void) {
        static uint8_t trans_id = 0;
        return trans_id++;
}
/***********************DPDK TIMER FUNCTIONS**********************************/
static void
nf_status_checkpoint_timer_cb(__attribute__((unused)) struct rte_timer *ptr_timer,
        __attribute__((unused)) void *ptr_data) {

        rsync_nf_state();
        rsync_wait_for_commit_ack();
        transmit_tx_nf_state_latch_rings();
        //printf("In nf_status_checkpoint_timer_cb@: %"PRIu64"\n", onvm_util_get_current_cpu_cycles() );
        return;
}
static inline int initialize_rsync_timers(void) {
        uint64_t ticks = ((uint64_t)NF_CHECKPOINT_PERIOD_IN_US *(rte_get_timer_hz()/1000000));
        rte_timer_reset_sync(&nf_status_checkpoint_timer,ticks,PERIODICAL,
                        rte_lcore_id(), &nf_status_checkpoint_timer_cb, NULL);
        return 0;
}
/***********************DPDK TIMER FUNCTIONS**********************************/

/***********************Internal Functions************************************/
/***********************DPDK TIMER FUNCTIONS**********************************/
static struct rte_mbuf* craft_state_update_packet(uint8_t port, state_tx_meta_t meta, uint8_t *pData, uint32_t data_len) {
        struct rte_mbuf *out_pkt = NULL;
        //struct onvm_pkt_meta *pmeta = NULL;
        struct ether_hdr *eth_hdr = NULL;
        state_transfer_packet_hdr_t *s_hdr = NULL;
        size_t pkt_size = 0;

        //Allocate New Packet
        out_pkt = rte_pktmbuf_alloc(pktmbuf_pool);
        if (out_pkt == NULL) {
                rte_free(out_pkt);
                return NULL;
        }

        //set packet properties
        pkt_size = sizeof(struct ether_hdr) + sizeof(struct state_transfer_packet_hdr);
        out_pkt->data_len = pkt_size;
        out_pkt->pkt_len = pkt_size;

        //Set Ethernet Header info
        eth_hdr = onvm_pkt_ether_hdr(out_pkt);
        ether_addr_copy(&ports->mac[port], &eth_hdr->s_addr);
        eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_RSYNC_DATA);
        ether_addr_copy((const struct ether_addr *)&rsync_node_info.mac_addr_bytes, &eth_hdr->d_addr);

        //SET RSYNC DATA
        s_hdr = rte_pktmbuf_mtod_offset(out_pkt, state_transfer_packet_hdr_t*, sizeof(struct ether_hdr));
        s_hdr->meta = meta;
        rte_memcpy(s_hdr->data, pData, data_len);

        //SEND PACKET OUT/SET METAINFO
        //pmeta = onvm_get_pkt_meta(out_pkt);
        //pmeta->destination = port;
        //pmeta->action = ONVM_NF_ACTION_OUT;

        return out_pkt;
        //return send_packets_out(port, 0, &out_pkt, 1);
}

/***********************TX STATE TABLE UPDATE**********************************/
static int rsync_tx_ts_state(void) {

        uint16_t i=0;
        struct rte_mbuf *pkts[PACKET_READ_SIZE*2];
        state_tx_meta_t meta = {.state_type= STATE_TYPE_TX_TS_TABLE, .nf_or_svc_id=0, .start_offset=0, .reserved=nf_mgr_id, .trans_id=get_transaction_id()};

        if(likely(dirty_state_map && dirty_state_map->dirty_index)) {

#ifdef ENABLE_LOCAL_LATENCY_PROFILER
                onvm_util_get_start_time(&ts);
#endif
                //Note: Must always ensure that dirty_map is carried over first; so that the remote replica can use this value to update only the changed states
                uint64_t dirty_index = dirty_state_map->dirty_index;
                uint64_t copy_index = 0;
                uint64_t copy_setbit = 0;
                //uint16_t copy_offset = 0;
                for(;dirty_index;copy_index++) {
                        copy_setbit = (1L<<(copy_index));
                        if(dirty_index&copy_setbit) {
                                meta.start_offset = copy_index*DIRTY_MAP_PER_CHUNK_SIZE;
                                pkts[i++] = craft_state_update_packet(0,meta, (((uint8_t*)onvm_mgr_tx_per_flow_ts_info)+meta.start_offset),DIRTY_MAP_PER_CHUNK_SIZE);
                                dirty_index^=copy_setbit;
                        }
                }
                dirty_state_map->dirty_index =0;
#ifdef ENABLE_LOCAL_LATENCY_PROFILER
                //fprintf(stdout, "STATE REPLICATION TIME: %li ns\n", onvm_util_get_elapsed_time(&ts));
#endif
        }
        //check if packets are created and need to be transmitted out;
        if(i) {
                uint8_t out_port = 0;
                //printf("\n $$$$ Sending [%d] packets for Tx_TimeStamp Sync $$$$\n", i);
                send_packets_out(out_port, 0, pkts, i);
        }
        return 0;
}
static int rsync_nf_state(void) {
        //Note: Size of NF_STATE_SIZE=64K and total_chunks=64 => size_per_chunk=1K -- can fit in 1 packet But
        //      size of SVC_STATE_SIZE=4MB and total_chunks=64 => size_per_chunk=64K -- so, each service each chunk requires 64 sends. -- must optimize -- DPI is an exception..

        uint8_t out_port = 0;
        uint16_t i=0;
        uint8_t active_services[MAX_SERVICES] = {0};
        struct rte_mbuf *pkts[PACKET_READ_SIZE*2];
        state_tx_meta_t meta = {.state_type= STATE_TYPE_NF_MEMPOOL, .nf_or_svc_id=0, .start_offset=0, .reserved=nf_mgr_id,.trans_id=get_transaction_id()};
        void *pReplicaStateMempool = NULL;
        dirty_mon_state_map_tbl_t *dirty_state_map = NULL;
        uint16_t nf_id = 0; //uint16_t alt_nf_id;
        for(;nf_id < MAX_SERVICES; nf_id++) active_services[nf_id]=0;

        //Start with Each NF Instance ID which is active and valid and start gathering all changed NF state;
        for (nf_id = 0; nf_id < MAX_CLIENTS; nf_id++) {
                //Get the Processing (Actively Running and Processing packets) NF Instance ID */
                if (likely(onvm_nf_is_processing(&clients[nf_id]))){
                        //store the corresponding service id for Global state transfer :: What if there are multiple active NFs for same service; we should still ensure that svc is used only once.
                        active_services[clients[nf_id].info->service_id] = 1;//active_services[j++] = clients[nf_id].info->service_id;

                        //retrieve the associated standby nf_id;
                        //alt_nf_id = get_associated_active_or_standby_nf_id(nf_id);

                        //sync state from the standby NFs memory: To avoid sync issues-- still possible; TODO: must ensure that update (write in NFLIB must not happen while we read here). How?
                        pReplicaStateMempool = clients[get_associated_active_or_standby_nf_id(nf_id)].nf_state_mempool;
                        if(likely(NULL != pReplicaStateMempool)) {
                                dirty_state_map = (dirty_mon_state_map_tbl_t*)pReplicaStateMempool;

                        } else continue;

                        if(likely(dirty_state_map && dirty_state_map->dirty_index)) {
                                meta.nf_or_svc_id = nf_id;

#ifdef ENABLE_LOCAL_LATENCY_PROFILER
                                onvm_util_get_start_time(&ts);
#endif
                                //Note: Must always ensure that dirty_map is carried over first; so that the remote replica can use this value to update only the changed states
                                uint64_t dirty_index = dirty_state_map->dirty_index;
                                uint64_t copy_index = 0;
                                uint64_t copy_setbit = 0;
                                //uint16_t copy_offset = 0;
                                for(;dirty_index;copy_index++) {
                                        copy_setbit = (1L<<(copy_index));
                                        if(dirty_index&copy_setbit) {
                                                meta.start_offset = copy_index*DIRTY_MAP_PER_CHUNK_SIZE;
                                                pkts[i++] = craft_state_update_packet(0,meta, (((uint8_t*)pReplicaStateMempool)+meta.start_offset),DIRTY_MAP_PER_CHUNK_SIZE);
                                                dirty_index^=copy_setbit;
                                                //If we exhaust all the packets, then we must send out packets before processing further state
                                                if( (i+1) == PACKET_READ_SIZE*2) {
                                                        send_packets_out(out_port, 0, pkts, i);
                                                        i=0;
                                                }
                                        }
                                }
                                dirty_state_map->dirty_index =0;
#ifdef ENABLE_LOCAL_LATENCY_PROFILER
                                        //fprintf(stdout, "STATE REPLICATION TIME: %li ns\n", onvm_util_get_elapsed_time(&ts));
#endif
                        }
                        //Either Send State update for each NF or batch with other NF State? ( IF batch multiple NFs, then move it out of for_loop )
                        //check if packets are created and need to be transmitted out;
                        if(i) {
                                //printf("\n $$$$ Sending [%d] packets for NF Instance [%d] State Sync $$$$\n", i, nf_id);
                                send_packets_out(out_port, 0, pkts, i);
                                i=0;
                        }
                }
        }

        //Start now for NF Service ID that are marked as active and valid while gathering all changed NF state; TODO: Chunk size correction 1K to 64K
        for (nf_id = 0; nf_id < MAX_SERVICES; nf_id++) {
                meta.state_type = STATE_TYPE_SVC_MEMPOOL;
                //Get the Processing (Actively Running and Processing packets) NF Instance ID */
                if (likely(active_services[nf_id])){
                        //sync state from the standby NFs memory: To avoid sync issues-- still possible; TODO: must ensure that update (write in NFLIB must not happen while we read here). How?
                        pReplicaStateMempool = services_state_pool[nf_id];
                        if(likely(NULL != pReplicaStateMempool)) {
                                dirty_state_map = (dirty_mon_state_map_tbl_t*)pReplicaStateMempool;

                        } else continue;

                        if(likely(dirty_state_map && dirty_state_map->dirty_index)) {
                                meta.nf_or_svc_id = nf_id;

#ifdef ENABLE_LOCAL_LATENCY_PROFILER
                                onvm_util_get_start_time(&ts);
#endif
                                //Note: Must always ensure that dirty_map is carried over first; so that the remote replica can use this value to update only the changed states
                                uint64_t dirty_index = dirty_state_map->dirty_index;
                                uint64_t copy_index = 0;
                                uint64_t copy_setbit = 0;
                                //uint16_t copy_offset = 0;
                                for(;dirty_index;copy_index++) {
                                        copy_setbit = (1L<<(copy_index));
                                        if(dirty_index&copy_setbit) {
                                                meta.start_offset = copy_index*DIRTY_MAP_PER_CHUNK_SIZE;
                                                pkts[i++] = craft_state_update_packet(0,meta, (((uint8_t*)pReplicaStateMempool)+meta.start_offset),DIRTY_MAP_PER_CHUNK_SIZE);
                                                dirty_index^=copy_setbit;
                                                //If we exhaust all the packets, then we must send out packets before processing further state
                                                if( (i+1) == PACKET_READ_SIZE*2) {
                                                        send_packets_out(out_port, 0, pkts, i);
                                                        i=0;
                                                }
                                        }
                                }
                                dirty_state_map->dirty_index =0;
#ifdef ENABLE_LOCAL_LATENCY_PROFILER
                                        //fprintf(stdout, "STATE REPLICATION TIME: %li ns\n", onvm_util_get_elapsed_time(&ts));
#endif
                        }
                        //Either Send State update for each NF or batch with other NF State? ( IF batch multiple NFs, then move it out of for_loop )
                        //check if packets are created and need to be transmitted out;
                        if(i) {
                                //printf("\n $$$$ Sending [%d] packets for NF Instdance [%d] State Sync $$$$\n", i, nf_id);
                                send_packets_out(out_port, 0, pkts, i);
                                i=0;
                        }
                }
        }

        return 0;
}
static int rsync_wait_for_commit_ack(void) {
        return 0;
}

/***********************Internal Functions************************************/
/***********************TX STATE TABLE UPDATE**********************************/
#ifdef ENABLE_PER_FLOW_TS_STORE
static inline uint64_t tx_ts_map_tag_index_to_dirty_chunk_bit_index(uint16_t tx_tbl_index) {
        uint32_t start_offset = sizeof(dirty_mon_state_map_tbl_t) + tx_tbl_index*sizeof(onvm_per_flow_ts_info_t);
        uint32_t end_offset = start_offset + sizeof(onvm_per_flow_ts_info_t);
        uint64_t dirty_map_bitmask = 0;
        dirty_map_bitmask |= (1<< (start_offset/DIRTY_MAP_PER_CHUNK_SIZE));
        dirty_map_bitmask |= (1<< (end_offset/DIRTY_MAP_PER_CHUNK_SIZE));
        //printf("\n For %d, 0x%lx\n",(int)tx_tbl_index, dirty_map_bitmask);
        return dirty_map_bitmask;
}
static inline void tx_ts_update_dirty_state_index(uint16_t tx_tbl_index) {
        if(dirty_state_map) {
                dirty_state_map->dirty_index |= tx_ts_map_tag_index_to_dirty_chunk_bit_index(tx_tbl_index);
        }
        return;
}
#endif
static inline void update_flow_tx_ts_table(uint64_t flow_index,  __attribute__((unused)) uint64_t ts){ // __attribute__((unused)) struct onvm_pkt_meta* meta,  __attribute__((unused)) struct onvm_flow_entry *flow_entry) {
#ifdef ENABLE_PER_FLOW_TS_STORE
        if(unlikely(flow_index >=MAX_TX_TS_ENTRIES)){
                printf("\n Incorrect Index:%lld\n", (long long)flow_index);
                return;
        }
        if(tx_ts_table) {
                tx_ts_table[flow_index].ts = ts;
                tx_ts_update_dirty_state_index(flow_index);
        }
#endif
        return;
}

static inline int initialize_tx_ts_table(void) {
#ifdef ENABLE_PER_FLOW_TS_STORE
        if(onvm_mgr_tx_per_flow_ts_info) {
                dirty_state_map = (dirty_mon_state_map_tbl_t*)onvm_mgr_tx_per_flow_ts_info;
                tx_ts_table = (onvm_per_flow_ts_info_t*)(dirty_state_map+1);
        }
#endif
        return 0;
}
/***********************TX STATE TABLE UPDATE**********************************/

/***********************Internal Functions************************************/
/***********************PACKET TRANSMIT FUNCTIONS******************************/
static inline int send_packets_out(uint8_t port_id, uint16_t queue_id, struct rte_mbuf **tx_pkts, uint16_t nb_pkts) {
        uint16_t sent_packets = rte_eth_tx_burst(port_id,queue_id, tx_pkts, nb_pkts);
        if(unlikely(sent_packets < nb_pkts)) {
                uint16_t i = sent_packets;
                for(; i< nb_pkts;i++)
                        onvm_pkt_drop(tx_pkts[i]);
        }
        return sent_packets;
}
//Bypass Function to directly enqueue to Tx Port Ring and Flush to ETH Ports
int transmit_tx_port_packets(void) {
        uint16_t i, j, count= PACKET_READ_SIZE*2, sent=0;
        struct rte_mbuf *pkts[PACKET_READ_SIZE*2];

        for(j=0; j < MIN(ports->num_ports, ONVM_NUM_RSYNC_PORTS); j++) {
                unsigned tx_count = rte_ring_count(tx_port_ring[j]);
                //printf("\n %d Pkts in %d port\n", tx_count, j);
                while(tx_count) {
                        count = rte_ring_dequeue_burst(tx_port_ring[j], (void**)pkts, PACKET_READ_SIZE*2);
                        if(unlikely(j == (ONVM_NUM_RSYNC_PORTS-1))) {
                                for(i=0; i < count;i++) {
                                        uint8_t port = (onvm_get_pkt_meta((struct rte_mbuf*) pkts[i]))->destination;
                                        sent = send_packets_out(port,0, &pkts[i],1);
                                }
                        } else {
                                sent = send_packets_out(j,0, pkts,count);
                        }
                        //tx_count-=count;
                        if(tx_count > count) tx_count-=count;
                        else break;
                }
        }
#if 0
        unsigned tx_count = rte_ring_count(tx_port_ring);
        while(tx_count) {
                count = rte_ring_dequeue_burst(tx_port_ring, (void**)pkts, PACKET_READ_SIZE*2);
                for(i=0; i < count;i++) {
                        uint8_t port = (onvm_get_pkt_meta((struct rte_mbuf*) pkts[i]))->destination;
                        if(likely(rte_eth_tx_burst(port,0, &pkts[i],1))) {
                                ;
                        } else {
                                onvm_pkt_drop(pkts[i]);
                        }
                }
        }
#endif
        //unsigned sent_count = rte_eth_tx_burst(port,0,tx->port_tx_buf[port].buffer, tx->port_tx_buf[port].count);
        return sent;
}

static int transmit_tx_tx_state_latch_rings(void) {
        uint16_t i, j, count= PACKET_READ_SIZE*2, sent=0;
        struct rte_mbuf *pkts[PACKET_READ_SIZE*2];

        for(j=0; j < MIN(ports->num_ports, ONVM_NUM_RSYNC_PORTS); j++) {
                unsigned tx_count = rte_ring_count(tx_tx_state_latch_ring[j]);
                //printf("\n %d Pkts in tx_tx_state_latch_ring[%d] port\n", tx_count, j);
                while(tx_count) {
                        count = rte_ring_dequeue_burst(tx_tx_state_latch_ring[j], (void**)pkts, PACKET_READ_SIZE*2);
                        if(unlikely(j == (ONVM_NUM_RSYNC_PORTS-1))) {
                                for(i=0; i < count;i++) {
                                        uint8_t port = (onvm_get_pkt_meta((struct rte_mbuf*) pkts[i]))->destination;
                                        sent = send_packets_out(port,0, &pkts[i],1);
                                }
                        } else {
                                sent = send_packets_out(j,0, pkts,count);
                        }
                        //tx_count-=count;
                        if(tx_count > count) tx_count-=count;
                        else break;
                }
        }
        return sent;
}
static int transmit_tx_nf_state_latch_rings(void) {
        uint16_t i, j, count= PACKET_READ_SIZE*2, sent=0;
        struct rte_mbuf *pkts[PACKET_READ_SIZE*2];

        for(j=0; j < MIN(ports->num_ports, ONVM_NUM_RSYNC_PORTS); j++) {
                unsigned tx_count = rte_ring_count(tx_nf_state_latch_ring[j]);
                //printf("\n %d Pkts in tx_nf_state_latch[%d] port\n", tx_count, j);
                while(tx_count) {
                        count = rte_ring_dequeue_burst(tx_nf_state_latch_ring[j], (void**)pkts, PACKET_READ_SIZE*2);
                        if(unlikely(j == (ONVM_NUM_RSYNC_PORTS-1))) {
                                for(i=0; i < count;i++) {
                                        uint8_t port = (onvm_get_pkt_meta((struct rte_mbuf*) pkts[i]))->destination;
                                        sent = send_packets_out(port,0, &pkts[i],1);
                                }
                        } else {
                                sent = send_packets_out(j,0, pkts,count);
                        }
                        //tx_count-=count;
                        if(tx_count > count) tx_count-=count;
                        else break;
                }
        }
        return sent;
}
static inline int get_flow_entry_index(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta) {
#ifdef ENABLE_FT_INDEX_IN_META
        if(meta->ft_index) return meta->ft_index;
        else
#endif
        {
                struct onvm_flow_entry *flow_entry = NULL;
                onvm_flow_dir_get_pkt(pkt, &flow_entry);
                if(flow_entry) return flow_entry->entry_index;
        }
        return -1;
}
/* This Function extracts the packets from the Tx_Port_RingBuffers and
 * 1. For Each packet:
 *  a) Extract the Time Stamp Information and Update to TX TS Table
 *  b) Determine where to Destination Ring buffer: where to Enqueue the packet
 *      i) if Marked Critical in Meta; then  Enqueue to NF_STATE_LATCH ring
 *      ii)if Not Marked Critical in Meta; then  Enqueue to TX_STATE_LATCH ring
 * Note: The NF STATE LATCH for subsequent packets need to persist. therefore
 * When NF marks in meta; either NF or NFLIB must mark the info in FT
 * This rsync module can clear this FT information only when the NF State
 * is synchronized to remote node.
 */
static int extract_and_parse_tx_port_packets(void) {
        int ret = 0;
        uint16_t i, j, count= PACKET_READ_SIZE*2, sent=0;
        uint64_t ts[PACKET_READ_SIZE*2];
        uint16_t out_pkts_nf_count, out_pkts_tx_count;
        struct rte_mbuf *in_pkts[PACKET_READ_SIZE*2];
        struct rte_mbuf *out_pkts_tx[PACKET_READ_SIZE*2];
        struct rte_mbuf *out_pkts_nf[PACKET_READ_SIZE*2];
        struct onvm_pkt_meta* meta;
        //struct onvm_flow_entry *flow_entry;

        for(j=0; j < MIN(ports->num_ports, ONVM_NUM_RSYNC_PORTS); j++) {
                unsigned tx_count = rte_ring_count(tx_port_ring[j]);
                //printf("\n %d packets in tx_port_ring[%d]\n", tx_count, j);
                while(tx_count) {
                        //retrieve batch of packets
                        count = rte_ring_dequeue_burst(tx_port_ring[j], (void**)in_pkts, PACKET_READ_SIZE*2);
                        //extract timestamp for these batch of packets
                        onvm_util_get_marked_packet_timestamp((struct rte_mbuf**)in_pkts, ts, count);
                        out_pkts_tx_count = 0; out_pkts_nf_count = 0;
                        for(i=0; i < count;i++) {
                                meta = onvm_get_pkt_meta((struct rte_mbuf*) in_pkts[i]);
                                //uint8_t port = meta->destination;
                                uint8_t dest = meta->reserved_word&0x01;
                                int flow_index = get_flow_entry_index(in_pkts[i], meta);
                                if(flow_index >= 0) {
#ifdef ENABLE_PER_FLOW_TS_STORE
                                update_flow_tx_ts_table(flow_index, ts[i]);
                                ret |=NEED_REMOTE_TS_TABLE_SYNC;
#endif
                                }
                                //If Flow/Packet needs NF state to be synchronized
                                if(unlikely(dest)) {
                                        out_pkts_nf[out_pkts_nf_count++] = in_pkts[i];
                                        ret |=NEED_REMOTE_NF_STATE_SYNC;
                                } else {
                                        out_pkts_tx[out_pkts_tx_count++] = in_pkts[i];
                                }
                        }
                        if(likely(out_pkts_tx_count)){
                                sent = rte_ring_enqueue_burst(tx_tx_state_latch_ring[j], (void**)out_pkts_tx,  out_pkts_tx_count);
                                if (unlikely(sent < out_pkts_tx_count)) {
                                        uint8_t k = sent;
                                        for(;k<out_pkts_tx_count;k++) {
                                                onvm_pkt_drop(out_pkts_tx[k]);
                                        }
                                }
                        }
                        if(unlikely(out_pkts_nf_count)){
                                sent = rte_ring_enqueue_burst(tx_nf_state_latch_ring[j], (void**)out_pkts_nf,  out_pkts_nf_count);
                                if (unlikely(sent < out_pkts_nf_count)) {
                                        uint8_t k = sent;
                                        for(;k<out_pkts_nf_count;k++) {
                                                onvm_pkt_drop(out_pkts_nf[k]);
                                        }
                                }
                        }
                        if(tx_count > count) tx_count-=count;
                        else break;
                }
        }
        return ret;
}
/***********************PACKET TRANSMIT FUNCTIONS******************************/

/******************************APIs********************************************/
int rsync_process_rsync_in_pkts(__attribute__((unused)) struct thread_info *rx, struct rte_mbuf *pkts[], uint16_t rx_count) {
        onvm_pkt_drop_batch(pkts,rx_count);
        if(pkts) return rx_count;
        return 0;
}
int rsync_start(__attribute__((unused)) void *arg) {

        //return transmit_tx_port_packets();

        //First Extract and Parse Tx Port Packets and update TS info in Tx Table
        int ret = extract_and_parse_tx_port_packets();
        //printf("\n extract_and_parse_tx_port_packets() returned %d\n",ret);

        //Check and Initiate Remote Sync of Tx State
        if(ret & NEED_REMOTE_TS_TABLE_SYNC) {
                rsync_tx_ts_state();
        }
        //Now release the packets from Tx State Latch Ring
        transmit_tx_tx_state_latch_rings();

        //check and Initiate remote NF Sync
        if(ret & NEED_REMOTE_NF_STATE_SYNC) {

        }
        //Now release the packets from NF
        transmit_tx_nf_state_latch_rings();
        //Note: There is an issue without lock: while updating any new flow comes with new non-determinism then it might be released much earlier.

        return 0;
}

int
rsync_main(__attribute__((unused)) void *arg) {


        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(NULL == pktmbuf_pool) {
                return -1;
        }

        //Initalize the Timer for performing periodic NF State Snapshotting
        initialize_rsync_timers();

        //Initalize the Tx Timestamp Table for all flow entries
        initialize_tx_ts_table();

        //struct timespec req = {0,RSYNC_CHECK_INTERVAL_NS}, res = {0,0};
        while (true) {
                //start Tx port Packet Processing
                rsync_start(arg);

                //check for timer Expiry
                rte_timer_manage();

                //nanosleep(&req, &res); //usleep(100);
        }
        return 0;
}
#endif //ENABLE_REMOTE_SYNC_WITH_TX_LATCH
