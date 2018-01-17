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
#include "onvm_init.h"
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

#define STATE_TYPE_TX_TS_TABLE  (0x01)
#define STATE_TYPE_NF_MEMPOOL   (0x02)
#define STATE_TYPE_SVC_MEMPOOL  (0x04)
#define STATE_REQ_TO_RSP_LSH    (4)
#define STATE_TYPE_TX_TS_ACK    (STATE_TYPE_TX_TS_TABLE << STATE_REQ_TO_RSP_LSH)    //(0x10)
#define STATE_TYPE_NF_MEM_ACK   STATE_TYPE_NF_MEMPOOL << STATE_REQ_TO_RSP_LSH)      //(0x20)
#define STATE_TYPE_SVC_MEM_ACK  STATE_TYPE_SVC_MEMPOOL << STATE_REQ_TO_RSP_LSH)     // (0x40)
#define STATE_TYPE_REQ_MASK     (0x0F)
#define STATE_TYPE_RSP_MASK     (0xF0)


#define MAX_STATE_SIZE_PER_PACKET   (1024)
typedef struct state_tx_meta {
        uint8_t state_type;     //TX_TS_TYPE; NF_STATE; SERV_STATE;
        uint8_t trans_id;       //Id of the atomic transaction
        uint8_t flags;          //Additional Flags: TBD; ex. last packet or still more to follow.
        uint8_t nf_or_svc_id;   //Id of the NF(NF_STATE) or SVC (SERVICE_STATE)
        uint16_t start_offset;  //Offset in the global mempool
        uint32_t reserved;      //Note Size per packet is Fixed to 1024 Bytes.
}state_tx_meta_t;

typedef struct state_transfer_packet_hdr {
        state_tx_meta_t meta;
        uint8_t data[MAX_STATE_SIZE_PER_PACKET];
}state_transfer_packet_hdr_t;

typedef struct transfer_ack_packet_hdr {
        state_tx_meta_t meta;
}transfer_ack_packet_hdr_t;
extern struct rte_mempool *pktmbuf_pool;


extern uint32_t nf_mgr_id;
/***********************Internal Functions************************************/
static inline int send_packets_out(uint8_t port_id, uint16_t queue_id, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
static inline int log_transaction_and_send_packets_out(uint8_t trans_id, uint8_t port_id, uint16_t queue_id, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
static struct rte_mbuf* craft_state_update_packet(uint8_t port, state_tx_meta_t meta, uint8_t *pData, uint32_t data_len);

int transmit_tx_port_packets(void);
static int transmit_tx_tx_state_latch_rings(void);
static int transmit_tx_nf_state_latch_rings(void);
static int extract_and_parse_tx_port_packets(void);

//Functions to transmit local state to remote node
static int rsync_tx_ts_state_to_remote(void);
static int rsync_nf_state_to_remote(void);
static int rsync_wait_for_commit_ack(uint8_t trans_id);

//Functions to send response for remote node updates
//static int rsync_tx_ts_state_ack_resp_to_remote();
//static int rsync_nf_state_ack_resp_to_remote();

//Functions to sync local state from remote node packets
//static int rsync_tx_ts_state_from_remote(void);
//static int rsync_nf_state_from_remote(void);

static inline int initialize_rsync_timers(void);
/***********************Internal Functions************************************/
static uint8_t get_transaction_id(void) {
        static uint8_t trans_id = 0;
        return trans_id++;
}
#define MAX_RSYNC_TRANSACTIONS (256)    //(sizeof(uint8_t)*CHAR_BIT)
static volatile uint8_t trans_queue[MAX_RSYNC_TRANSACTIONS];
static uint8_t log_transaction_id(uint8_t tid) {
        return (trans_queue[tid] = tid);
}
static uint8_t clear_transaction_id (uint8_t tid) {
        return (trans_queue[tid]^= tid);
}
/***********************DPDK TIMER FUNCTIONS**********************************/
static void
nf_status_checkpoint_timer_cb(__attribute__((unused)) struct rte_timer *ptr_timer,
        __attribute__((unused)) void *ptr_data) {

        uint8_t trans_id = rsync_nf_state_to_remote();
        if(trans_id) {
                rsync_wait_for_commit_ack(trans_id);
        }
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
static void bswap_rsync_hdr_data(state_tx_meta_t *meta, int to_be) {
        if(to_be) {
                meta->start_offset = rte_cpu_to_be_16(meta->start_offset);
                meta->reserved = rte_cpu_to_be_32(meta->reserved);

        } else {
                meta->start_offset = rte_be_to_cpu_16(meta->start_offset);
                meta->reserved =  rte_be_to_cpu_32(meta->reserved);
                //uint8_t *pdata = rsync_req->data;
        }
}
//static
inline int rsync_print_rsp_packet(transfer_ack_packet_hdr_t *rsync_pkt);
//static
inline int rsync_print_rsp_packet(transfer_ack_packet_hdr_t *rsync_pkt) {
        printf("TYPE: %" PRIu8 "\n", rsync_pkt->meta.state_type & 0b11111111);
        printf("NF_ID: %" PRIu8 "\n", rsync_pkt->meta.nf_or_svc_id & 0b11111111);
        printf("TRAN_ID: %" PRIu8 "\n", rsync_pkt->meta.trans_id & 0b11111111);
        printf("FLAGS: %" PRIu8 "\n", rsync_pkt->meta.flags & 0b11111111);
        printf("start Offset: %" PRIu16 "\n", rte_be_to_cpu_16(rsync_pkt->meta.start_offset));
        printf("Reserved: %" PRIu32 "\n", rte_be_to_cpu_32(rsync_pkt->meta.reserved));
        return rsync_pkt->meta.state_type;
}
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
        bswap_rsync_hdr_data(&s_hdr->meta, 1);
        if(data_len) {
                rte_memcpy(s_hdr->data, pData, data_len);
        }

        //SEND PACKET OUT/SET METAINFO
        //pmeta = onvm_get_pkt_meta(out_pkt);
        //pmeta->destination = port;
        //pmeta->action = ONVM_NF_ACTION_OUT;

        return out_pkt;
        //return send_packets_out(port, 0, &out_pkt, 1);
}

/***********************TX STATE TABLE UPDATE**********************************/
static int rsync_tx_ts_state_to_remote(void) {

        uint16_t i=0;
        struct rte_mbuf *pkts[PACKET_READ_SIZE*2];
        state_tx_meta_t meta = {.state_type= STATE_TYPE_TX_TS_TABLE, .nf_or_svc_id=0, .start_offset=0, .reserved=nf_mgr_id, .trans_id=0};

        if(likely(dirty_state_map && dirty_state_map->dirty_index)) {

#ifdef ENABLE_LOCAL_LATENCY_PROFILER
                onvm_util_get_start_time(&ts);
#endif
                meta.trans_id = get_transaction_id();
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
                //check if packets are created and need to be transmitted out;
                if(i) {
                        uint8_t out_port = 0;
                        //printf("\n $$$$ Sending [%d] packets for Tx_TimeStamp Sync $$$$\n", i);
                        log_transaction_and_send_packets_out(meta.trans_id, out_port, 0, pkts, i); //send_packets_out(out_port, 0, pkts, i);
                }
#ifdef ENABLE_LOCAL_LATENCY_PROFILER
                //fprintf(stdout, "STATE REPLICATION TIME: %li ns\n", onvm_util_get_elapsed_time(&ts));
#endif
                return meta.trans_id;
        }
        return 0;
}
static int rsync_nf_state_to_remote(void) {
        //Note: Size of NF_STATE_SIZE=64K and total_chunks=64 => size_per_chunk=1K -- can fit in 1 packet But
        //      size of SVC_STATE_SIZE=4MB and total_chunks=64 => size_per_chunk=64K -- so, each service each chunk requires 64 sends. -- must optimize -- DPI is an exception..

        uint8_t out_port = 0;
        uint16_t i=0;
        uint8_t active_services[MAX_SERVICES] = {0};
        struct rte_mbuf *pkts[PACKET_READ_SIZE*2];
        state_tx_meta_t meta = {.state_type= STATE_TYPE_NF_MEMPOOL, .nf_or_svc_id=0, .start_offset=0, .reserved=nf_mgr_id,.trans_id=0};
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
                                if(unlikely(0 == meta.trans_id)) meta.trans_id=get_transaction_id();

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
                                                        log_transaction_and_send_packets_out(meta.trans_id, out_port, 0, pkts, i); //send_packets_out(out_port, 0, pkts, i);
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
                                send_packets_out(out_port, 0, pkts, i); //log_transaction_and_send_packets_out(meta.trans_id, out_port, 0, pkts, i);
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
                                if(unlikely(0 == meta.trans_id)) meta.trans_id=get_transaction_id();

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
                                                        log_transaction_and_send_packets_out(meta.trans_id, out_port, 0, pkts, i); //send_packets_out(out_port, 0, pkts, i);
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
                                send_packets_out(out_port, 0, pkts, i); //log_transaction_and_send_packets_out(meta.trans_id, out_port, 0, pkts, i);
                                i=0;
                        }
                }
        }

        return meta.trans_id;
        return 0;
}
#define MAX_TRANS_COMMIT_WAIT_COUNTER   (0)
static int rsync_wait_for_commit_ack(uint8_t trans_id) {
        struct timespec req = {0,100}, res = {0,0};
        int wait_counter = 0; //hack till remote_node also sends
        do {
                nanosleep(&req, &res);
                if((++wait_counter) > MAX_TRANS_COMMIT_WAIT_COUNTER) break;
        }while(trans_queue[trans_id]);
        clear_transaction_id(trans_id);
        return 0;
}
static int rsync_wait_for_commit_acks(uint8_t *trans_id_list, uint8_t count) {
        uint8_t i; uint8_t wait_needed=0;
        //push the trans_ids to trans_queue
        for(i=0; i< count; i++) {
                trans_queue[trans_id_list[i]] = trans_id_list[i];
        }
        //TEST_HACK to bypass wait_on_acks //return wait_needed;

        //poll/wait till trans_queue[ids[]] is cleared.
        struct timespec req = {0,100}, res = {0,0};
        int wait_counter = 0; //hack till remote_node also sends
        do {
                wait_needed= 0;
                for(i=0; i< count; i++) {
                        if(trans_queue[trans_id_list[i]]) wait_needed = 1;
                }
                nanosleep(&req, &res);
                if((++wait_counter) > MAX_TRANS_COMMIT_WAIT_COUNTER) break;
        }while(wait_needed);
        //need notifier to clear the transactions
        //clear the transactions.
        for(i=0; i< count; i++) {
                clear_transaction_id(trans_id_list[i]);
        }
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

#ifdef PROFILE_PACKET_PROCESSING_LATENCY
        onvm_util_calc_chain_processing_latency(tx_pkts, nb_pkts);
#endif
        uint16_t sent_packets = rte_eth_tx_burst(port_id,queue_id, tx_pkts, nb_pkts);
        if(unlikely(sent_packets < nb_pkts)) {
                uint16_t i = sent_packets;
                for(; i< nb_pkts;i++)
                        onvm_pkt_drop(tx_pkts[i]);
        }
        {
                volatile struct tx_stats *tx_stats = &(ports->tx_stats);
                tx_stats->tx_drop[port_id] = sent_packets;
                tx_stats->tx_drop[port_id] += (nb_pkts - sent_packets);
        }
        return sent_packets;
}
static inline int log_transaction_and_send_packets_out(uint8_t trans_id, uint8_t port_id, uint16_t queue_id, struct rte_mbuf **tx_pkts, uint16_t nb_pkts) {
        log_transaction_id(trans_id);
#ifdef PROFILE_PACKET_PROCESSING_LATENCY
        onvm_util_calc_chain_processing_latency(tx_pkts, nb_pkts);
#endif
        uint16_t sent_packets = rte_eth_tx_burst(port_id,queue_id, tx_pkts, nb_pkts);
        if(unlikely(sent_packets < nb_pkts)) {
                uint16_t i = sent_packets;
                for(; i< nb_pkts;i++)
                        onvm_pkt_drop(tx_pkts[i]);
        }
        {
                volatile struct tx_stats *tx_stats = &(ports->tx_stats);
                tx_stats->tx_drop[port_id] = sent_packets;
                tx_stats->tx_drop[port_id] += (nb_pkts - sent_packets);
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
#if 0
                                for(i=0; i < count;i++) {
                                        uint8_t port = (onvm_get_pkt_meta((struct rte_mbuf*) pkts[i]))->destination;
                                        sent = send_packets_out(port,0, &pkts[i],1);
                                }
#endif
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

//Function to transmit/release the Tx packets (that were waiting for Tx state update completion)
static int transmit_tx_tx_state_latch_rings(void) {
        uint16_t i, j, count= PACKET_READ_SIZE*10, sent=0;
        struct rte_mbuf *pkts[PACKET_READ_SIZE*10];

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
//Function to transmit/release the Tx packets (that were waiting for NF state update completion)
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
static inline int get_flow_entry_index(__attribute__((unused)) struct rte_mbuf *pkt, struct onvm_pkt_meta *meta) {
#ifdef ENABLE_FT_INDEX_IN_META
        return meta->ft_index;
#else
        {
                //printf("\n Extracting from Flow DIR Entry: \n");
                struct onvm_flow_entry *flow_entry = NULL;
                onvm_flow_dir_get_pkt(pkt, &flow_entry);
                if(flow_entry) return flow_entry->entry_index;
        }
#endif
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
/* PACKET RECEIVE FUNCTIONS */
static inline int rsync_process_req_packet(__attribute__((unused)) state_transfer_packet_hdr_t *rsync_req, uint8_t in_port) {

        state_tx_meta_t meta_out = rsync_req->meta;
        struct rte_mbuf *pkt;
#if 0
        uint16_t i=0;
        struct rte_mbuf *pkts[PACKET_READ_SIZE*2];
        uint8_t type   = rsync_req->meta.state_type & 0b11111111;
        uint8_t nf_id  = rsync_req->meta.nf_or_svc_id & 0b11111111;
        uint8_t tnx_id = rsync_req->meta.trans_id & 0b11111111;
        uint8_t flags  = rsync_req->meta.flags & 0b11111111;
        uint16_t s_offt= rte_be_to_cpu_16(rsync_req->meta.start_offset);
        uint32_t resv =  rte_be_to_cpu_32(rsync_req->meta.reserved);
        uint8_t *pdata = rsync_req->data;
        //bswap_rsync_hdr_data(&rsync_req->meta, 0);
#endif
        bswap_rsync_hdr_data(&meta_out, 0);
        printf("\n Received RSYNC Request Packet with Transaction:[%d] for [Type:%d, SVC/NFID:%d, offset:[%d]] !\n", meta_out.trans_id, meta_out.state_type, meta_out.nf_or_svc_id, meta_out.start_offset);

        //For Tx_TS State:  copy sent data from the start_offset to the mempool.
        //For NF_STATE_MEMORY: <Communicate to Standby NF, if none; then it must be instantiated first; then send message to NFLIB so that it can copy the state
        //FOR_SVC_STATE_MEMORY:

        switch(meta_out.state_type) {
        case STATE_TYPE_TX_TS_TABLE:
                //update TX_TS_TABLE and send Response to TID
                break;
        case STATE_TYPE_NF_MEMPOOL:
                //update NF_MEMPOOL_TABLE and send Response to TID
                break;
        case STATE_TYPE_SVC_MEMPOOL:
                //update SVC_MEMPOOL_TABLE and send Response to TID
                break;
        default:
                break;
        }

        //send response packet
        meta_out.state_type = (meta_out.state_type<<STATE_REQ_TO_RSP_LSH);
        pkt = craft_state_update_packet(in_port,meta_out,NULL,0);
        if(pkt) {
                send_packets_out(in_port, 0, &pkt, 1);
        }

        return 0;
}
static inline int rsync_process_rsp_packet(__attribute__((unused)) transfer_ack_packet_hdr_t *rsync_rsp) {
#if 0
        //Parse the transaction id and notify/unblock processing thread to release the packets out.
#endif
        uint8_t trans_id = rsync_rsp->meta.trans_id;
        if(trans_queue[trans_id]) {
                trans_queue[trans_id] = 0;
                //printf("\n Received RSYNC Response Packet with Transaction:[%d] for [Type:%d, SVC/NFID:%d, offset:[%d]] !\n", rsync_rsp->meta.trans_id, rsync_rsp->meta.state_type, rsync_rsp->meta.nf_or_svc_id, rsync_rsp->meta.start_offset);
                printf("\n Received RSYNC Response:: Transaction:[%d] for [Type:%d, SVC/NFID:%d] got committed!\n", trans_id, rsync_rsp->meta.state_type, rsync_rsp->meta.nf_or_svc_id);
        }
        //will it be better to copy to temp and byte swap then byteswap packet memory?
        //bswap_rsync_hdr_data(&rsync_rsp->meta, 0);

        return 0;
}
/******************************APIs********************************************/
int rsync_process_rsync_in_pkts(__attribute__((unused)) struct thread_info *rx, struct rte_mbuf *pkts[], uint16_t rx_count) {
        uint16_t i=0;
        //struct ether_hdr *eth = NULL;
        transfer_ack_packet_hdr_t *rsycn_pkt = NULL;
        state_transfer_packet_hdr_t *rsync_req = NULL;

        //Validate packet properties
        //if(pkts[i]->pkt_len < (sizeof(struct ether_hdr) + sizeof(struct transfer_ack_packet_hdr_t));
        //if(pkts[i]->data_len < (sizeof(struct ether_hdr) + sizeof(struct state_transfer_packet_hdr_t));

        //process each packet
        for(i=0; i < rx_count; i++) {
                //eth = rte_pktmbuf_mtod(pkts[i], struct ether_hdr *);
                rsycn_pkt = (transfer_ack_packet_hdr_t*)(rte_pktmbuf_mtod(pkts[i], uint8_t*) + sizeof(struct ether_hdr));
                //printf("Received RSYNC Message Type [%d]:\n",rsync_print_rsp_packet(rsycn_pkt));
                if(rsycn_pkt) {
                        if( STATE_TYPE_RSP_MASK & rsycn_pkt->meta.state_type) {
                                //process the response packet: check for Tran ID and unblock 2 phase commit..
                                rsync_process_rsp_packet(rsycn_pkt);
                        }
                        else {
                                rsync_req = (state_transfer_packet_hdr_t*)(rte_pktmbuf_mtod(pkts[i], uint8_t*) + sizeof(struct ether_hdr));
                                rsync_process_req_packet(rsync_req, pkts[i]->port);
                                //process rsync_req packet: check the nf_svd_id; extract data and update mempool memory of respective NFs
                                //Once you receive last flag or flag with different Transaction ID then, Generate response packet for the (current) marked transaction.
                        }
                }
        }
        //release all the packets and return
        onvm_pkt_drop_batch(pkts,rx_count);
        if(pkts) return rx_count;
        return 0;
}
int rsync_start(__attribute__((unused)) void *arg) {

        uint8_t trans_ids[2] = {0,0},tid=0;
        //return transmit_tx_port_packets();    //TEST_HACK to directly transfer out the packets

        //First Extract and Parse Tx Port Packets and update TS info in Tx Table
        int ret = extract_and_parse_tx_port_packets();
        //ret = 0;    //TEST_HACK to bypass TS Table and NF Shared Memory packet transfer
        //printf("\n extract_and_parse_tx_port_packets() returned %d\n",ret);

        //Check and Initiate Remote Sync of Tx State
        if(ret & NEED_REMOTE_TS_TABLE_SYNC) {
                uint8_t trans_id = rsync_tx_ts_state_to_remote();
                if(trans_id) {
#ifdef USE_BATCHED_RSYNC_TRANSACTIONS
                        trans_ids[tid++] = trans_id;
#else
                        rsync_wait_for_commit_ack(trans_id);
#endif


                }
#ifndef USE_BATCHED_RSYNC_TRANSACTIONS
                //Now release the packets from Tx State Latch Ring
                transmit_tx_tx_state_latch_rings();
#endif
        }

        //TODO:communicate to Peer Node (Predecessor/Remote Node) to release the logged packets till TS.
        //How? -- there can be packets in fastchain and some in slow chain. How will you notify? -- rely on best effort (every 1ms) it will refresh.
        //14.88Mpps => 14.88K (~15K, 1.25MB) for 1ms,  and 100ms => (~1500K packets, 125MB) data.

        //check and Initiate remote NF Sync
        if(ret & NEED_REMOTE_NF_STATE_SYNC) {
                uint8_t trans_id = rsync_nf_state_to_remote();
                if(trans_id) {
#ifdef USE_BATCHED_RSYNC_TRANSACTIONS
                        trans_ids[tid++] = trans_id;
#else
                        rsync_wait_for_commit_ack(trans_id);
#endif
                }
#ifndef USE_BATCHED_RSYNC_TRANSACTIONS
                //Now release the packets from NF
                transmit_tx_nf_state_latch_rings();
#endif
        }
#ifdef USE_BATCHED_RSYNC_TRANSACTIONS
        //optimize by batching transactions.. transfer all transactions and wait or acks
        {
                rsync_wait_for_commit_acks(trans_ids,tid);
                //Now release the packets from Tx State Latch Ring
                transmit_tx_tx_state_latch_rings();
                //Now release the packets from NF
                transmit_tx_nf_state_latch_rings();
        }
#endif
        //Note: There is an issue without lock: while updating any new flow comes with new non-determinism then it might be released much earlier.
        return 0;
}

int
rsync_main(__attribute__((unused)) void *arg) {

        if(NULL == pktmbuf_pool) {
                pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
                if(NULL == pktmbuf_pool) {
                        return -1;
                }
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

                //nanosleep(&req, &res);
        }
        return 0;
}
#endif //ENABLE_REMOTE_SYNC_WITH_TX_LATCH
