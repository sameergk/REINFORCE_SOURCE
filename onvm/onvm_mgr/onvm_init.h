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

                                 onvm_init.h

       Header for the initialisation function and global variables and
       data structures.


******************************************************************************/


#ifndef _ONVM_INIT_H_
#define _ONVM_INIT_H_

/***************************Standard C library********************************/

//#ifdef INTERRUPT_SEM  //move maro to makefile, otherwise uncomemnt or need to include these after including common.h
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <semaphore.h>
#include <fcntl.h>
#include <mqueue.h>
//#endif //INTERRUPT_SEM

/********************************DPDK library*********************************/

#include <rte_byteorder.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_fbk_hash.h>
#include <rte_cycles.h>
#include <rte_errno.h>


/*****************************Internal library********************************/


#include "onvm_mgr/onvm_args.h"
#include "shared/onvm_includes.h"
#include "shared/common.h"
#include "shared/onvm_sc_mgr.h"
#include "shared/onvm_sc_common.h"
#include "shared/onvm_flow_table.h"
#include "shared/onvm_flow_dir.h"


/***********************************Macros************************************/


#define MBUFS_PER_CLIENT 1536 //65536 //10240 //1536                            (use U: 1536, T:1536)
#define MBUFS_PER_PORT 10240 //(10240) //2048 //10240 //65536 //10240 //1536    (use U: 10240, T:10240)
#define MBUF_CACHE_SIZE 512
#define MBUF_OVERHEAD (sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define RX_MBUF_DATA_SIZE 2048
#define MBUF_SIZE (RX_MBUF_DATA_SIZE + MBUF_OVERHEAD)

#define NF_INFO_SIZE sizeof(struct onvm_nf_info)
#define NF_INFO_CACHE 8

#define RTE_MP_RX_DESC_DEFAULT 1024 //(1024) //512 //512 //1536 //2048 //1024 //512 (use U:1024, T:512)
#define RTE_MP_TX_DESC_DEFAULT 1024 //(1024) //512 //512 //1536 //2048 //1024 //512 (use U:1024, T:512)
//#define CLIENT_QUEUE_RINGSIZE  (512) //4096 //(4096) //(512)  //128 //4096  //4096 //128   (use U:4096, T:512) //256
#define CLIENT_QUEUE_RINGSIZE  (4096) //4096 //(4096) //(512)  //128 //4096  //4096 //128   (use U:4096, T:512) //256
//For TCP UDP use 70,40
//For TCP TCP, IO use 80 20

// Note: Based on the approach the tuned values change. For NF Throttling (80/75,20/25) works better, for Packet Throttling (70,50 or 70,40 or 80,40) seems better -- must be tuned and set accordingly.
#ifdef NF_BACKPRESSURE_APPROACH_1
#define CLIENT_QUEUE_RING_THRESHOLD (80)
#define CLIENT_QUEUE_RING_THRESHOLD_GAP (20) //(25)
#else  // defined NF_BACKPRESSURE_APPROACH_2 or other
#define CLIENT_QUEUE_RING_THRESHOLD (80)
#define CLIENT_QUEUE_RING_THRESHOLD_GAP (20)
#endif //NF_BACKPRESSURE_APPROACH_1

#define CLIENT_QUEUE_RING_WATER_MARK_SIZE ((uint32_t)((CLIENT_QUEUE_RINGSIZE*CLIENT_QUEUE_RING_THRESHOLD)/100))
#define CLIENT_QUEUE_RING_LOW_THRESHOLD ((CLIENT_QUEUE_RING_THRESHOLD > CLIENT_QUEUE_RING_THRESHOLD_GAP) ? (CLIENT_QUEUE_RING_THRESHOLD-CLIENT_QUEUE_RING_THRESHOLD_GAP):(CLIENT_QUEUE_RING_THRESHOLD))
#define CLIENT_QUEUE_RING_LOW_WATER_MARK_SIZE ((uint32_t)((CLIENT_QUEUE_RINGSIZE*CLIENT_QUEUE_RING_LOW_THRESHOLD)/100))
#define ECN_EWMA_ALPHA  (0.25)
#define CLIENT_QUEUE_RING_ECN_MARK_SIZE ((uint32_t)(((1-ECN_EWMA_ALPHA)*CLIENT_QUEUE_RING_WATER_MARK_SIZE) + ((ECN_EWMA_ALPHA)*CLIENT_QUEUE_RING_LOW_WATER_MARK_SIZE)))///2)
#define NO_FLAGS 0

#define ONVM_NUM_RX_THREADS 1

#define DYNAMIC_CLIENTS 1
#define STATIC_CLIENTS 0


/******************************Data structures********************************/
#ifdef ENABLE_NF_BACKPRESSURE //NF_BACKPRESSURE_APPROACH_1
//#if defined (ENABLE_NF_BACKPRESSURE) && defined (NF_BACKPRESSURE_APPROACH_1)
typedef struct bottleneck_ft_data {
        uint16_t chain_index;           //index of NF (bottleneck) in the chain
         struct onvm_flow_entry* bft;   //flow_entry field
}bottleneck_ft_data_t;
typedef struct bottleneck_ft_info {
        uint16_t bft_count;         // num of entries in the bft[]
        uint16_t r_h;               // read_head in the bft[]
        uint16_t w_h;               // write head in the bft[]
        uint16_t max_len;           // Max size/count of bft[]
        //struct onvm_flow_entry* bft[CLIENT_QUEUE_RINGSIZE];
        bottleneck_ft_data_t bft[CLIENT_QUEUE_RINGSIZE*2+1];
}bottlenect_ft_info_t;

#endif //ENABLE_NF_BACKPRESSURE

/*
 * Define a client structure with all needed info, including
 * stats from the clients.
 */
struct client {
        struct rte_ring *rx_q;
        struct rte_ring *tx_q;
        struct onvm_nf_info *info;
        uint16_t instance_id;
        /* these stats hold how many packets the client will actually receive,
         * and how many packets were dropped because the client's queue was full.
         * The port-info stats, in contrast, record how many packets were received
         * or transmitted on an actual NIC port.
         */
        struct {
                volatile uint64_t rx;
                volatile uint64_t rx_drop;
                volatile uint64_t act_out;
                volatile uint64_t act_tonf;
                volatile uint64_t act_drop;
                volatile uint64_t act_next;
                volatile uint64_t act_buffer;
                #ifdef INTERRUPT_SEM
                volatile uint64_t wakeup_count;
                volatile uint64_t prev_rx;
                volatile uint64_t prev_rx_drop;
                volatile uint64_t prev_wakeup_count;
                #endif

//#ifdef ENABLE_NF_BACKPRESSURE
#if defined (ENABLE_NF_BACKPRESSURE) && defined (NF_BACKPRESSURE_APPROACH_1)
                volatile uint64_t bkpr_drop;
                volatile uint64_t prev_bkpr_drop;
#endif //#if defined (ENABLE_NF_BACKPRESSURE) && defined (NF_BACKPRESSURE_APPROACH_1)


//#ifdef ENABLE_NF_BACKPRESSURE
#if defined (ENABLE_NF_BACKPRESSURE) && defined (NF_BACKPRESSURE_APPROACH_1) && defined (BACKPRESSURE_EXTRA_DEBUG_LOGS)
                uint16_t max_rx_q_len;
                uint16_t max_tx_q_len;
                uint16_t bkpr_count;
#endif //defined (ENABLE_NF_BACKPRESSURE) && defined (NF_BACKPRESSURE_APPROACH_1) && defined (BACKPRESSURE_EXTRA_DEBUG_LOGS)
        } stats;
        
#ifdef ENABLE_NF_BACKPRESSURE
//#if defined (ENABLE_NF_BACKPRESSURE) && defined (NF_BACKPRESSURE_APPROACH_1)
        uint16_t is_bottleneck;         //status: not marked=0/marked for enqueue=1/enqueued as bottleneck=2
        bottlenect_ft_info_t bft_list;
#endif //defined (ENABLE_NF_BACKPRESSURE) && defined (NF_BACKPRESSURE_APPROACH_1)

        /* mutex and semaphore name for NFs to wait on */ 
        #ifdef INTERRUPT_SEM        
        const char *sem_name;
        key_t shm_key;
        rte_atomic16_t *shm_server;     //0=running; 1=blocked_on_rx (no pkts to process); 2=blocked_on_tx (cannot push packets)

        #ifdef USE_SEMAPHORE        
        sem_t *mutex;
        #endif

        #ifdef ENABLE_NF_BACKPRESSURE
        //uint8_t highest_downstream_nf_index_id;   // can get rid of this field
        //uint8_t rx_buffer_overflow;     // can get_rid of this field
        #ifdef NF_BACKPRESSURE_APPROACH_2
        uint8_t throttle_this_upstream_nf; // rename downstream_nf_overflow to throttle_this_upstream_nf;
        uint64_t throttle_count;
        #endif // NF_BACKPRESSURE_APPROACH_2
        #endif //ENABLE_NF_BACKPRESSURE

        #endif //INTERRUPT_SEM
};

#if defined (INTERRUPT_SEM) && defined (USE_SOCKET)
extern int onvm_socket_id;
#endif

#if defined (INTERRUPT_SEM) && defined (USE_ZMQ)
extern void *zmq_ctx;
extern void *onvm_socket_id;
extern void *onvm_socket_ctx;
#endif

/*
 * Shared port info, including statistics information for display by server.
 * Structure will be put in a memzone.
 * - All port id values share one cache line as this data will be read-only
 * during operation.
 * - All rx statistic values share cache lines, as this data is written only
 * by the server process. (rare reads by stats display)
 * - The tx statistics have values for all ports per cache line, but the stats
 * themselves are written by the clients, so we have a distinct set, on different
 * cache lines for each client to use.
 */
struct rx_stats{
        uint64_t rx[RTE_MAX_ETHPORTS];
};


struct tx_stats{
        uint64_t tx[RTE_MAX_ETHPORTS];
        uint64_t tx_drop[RTE_MAX_ETHPORTS];
};


struct port_info {
        uint8_t num_ports;
        uint8_t id[RTE_MAX_ETHPORTS];
        volatile struct rx_stats rx_stats;
        volatile struct tx_stats tx_stats;
};



/*************************External global variables***************************/


extern struct client *clients;

extern struct rte_ring *nf_info_queue;
extern struct rte_mempool *nf_info_pool;

/* the shared port information: port numbers, rx and tx stats etc. */
extern struct port_info *ports;

extern struct rte_mempool *pktmbuf_pool;
extern volatile uint16_t num_clients;
extern uint16_t num_services;
extern uint16_t default_service;
extern uint16_t **services;
extern uint16_t *nf_per_service_count;
extern unsigned num_sockets;
extern struct onvm_service_chain *default_chain;
extern struct onvm_ft *sdn_ft;

#ifdef ENABLE_NFV_RESL
#ifdef ENABLE_NF_MGR_IDENTIFIER
extern uint32_t nf_mgr_id;
#endif // ENABLE_NF_MGR_IDENTIFIER
#endif // ENABLE_NFV_RESL

/**********************************Functions**********************************/

/*
 * Function that initialize all data structures, memory mapping and global
 * variables.
 *
 * Input  : the number of arguments (following C conventions)
 *          an array of the arguments as strings
 * Output : an error code
 *
 */
int init(int argc, char *argv[]);

#endif  // _ONVM_INIT_H_
