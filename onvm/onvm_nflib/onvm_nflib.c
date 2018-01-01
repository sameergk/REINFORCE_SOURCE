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
 ********************************************************************/

/******************************************************************************

                                  onvm_nflib.c


                  File containing all functions of the NF API


******************************************************************************/

#include "onvm_nflib_internal.h"
#include "onvm_nflib.h"

/*********************************************************************/
/*            NF LIB Feature flags specific functions                */
/*********************************************************************/

#ifdef TEST_MEMCPY_OVERHEAD
static inline void allocate_base_memory(void) {
        base_memory = calloc(1,2*MEMCPY_SIZE);
}
static inline void do_memcopy(void *from_pointer) {
        if(likely(base_memory && from_pointer)) {
                memcpy(base_memory,from_pointer,MEMCPY_SIZE);
        }
}
#endif //TEST_MEMCPY_OVERHEAD

/*********************************************************************/
nf_explicit_callback_function nf_ecb = NULL;
static uint8_t need_ecb = 0;
void register_explicit_callback_function(nf_explicit_callback_function ecb) {
        if(ecb) {
                nf_ecb = ecb;
        }
        return;
}
/******************************************************************************/
/*                        HISTOGRAM DETAILS                                   */
/******************************************************************************/


/************************************API**************************************/

#ifdef USE_CGROUPS_PER_NF_INSTANCE
#include <stdlib.h>
uint32_t get_nf_core_id(void);
void init_cgroup_info(struct onvm_nf_info *nf_info);
int set_cgroup_cpu_share(struct onvm_nf_info *nf_info, unsigned int share_val);

uint32_t get_nf_core_id(void) {
        return rte_lcore_id();
}

int set_cgroup_cpu_share(struct onvm_nf_info *nf_info, unsigned int share_val) {
        /*
        unsigned long shared_bw_val = (share_val== 0) ?(1024):(1024*share_val/100); //when share_val is relative(%)
        if (share_val >=100) {
                shared_bw_val = shared_bw_val/100;
        }*/

        unsigned long shared_bw_val = (share_val== 0) ?(1024):(share_val);  //when share_val is absolute bandwidth
        const char* cg_set_cmd = get_cgroup_set_cpu_share_cmd(nf_info->instance_id, shared_bw_val);
        printf("\n CMD_TO_SET_CPU_SHARE: %s", cg_set_cmd);
        int ret = system(cg_set_cmd);
        if  (0 == ret) {
                nf_info->cpu_share = shared_bw_val;
        }
        return ret;
}
void init_cgroup_info(struct onvm_nf_info *nf_info) {
        int ret = 0;
        const char* cg_name = get_cgroup_name(nf_info->instance_id);
        const char* cg_path = get_cgroup_path(nf_info->instance_id);
        printf("\n NF cgroup name and path: %s, %s", cg_name,cg_path);

        /* Check and create the CGROUP if necessary */
        const char* cg_crt_cmd = get_cgroup_create_cgroup_cmd(nf_info->instance_id);
        printf("\n CMD_TO_CREATE_CGROUP_for_NF: %d, %s", nf_info->instance_id, cg_crt_cmd);
        ret = system(cg_crt_cmd);

        /* Add the pid to the CGROUP */
        const char* cg_add_cmd = get_cgroup_add_task_cmd(nf_info->instance_id, nf_info->pid);
        printf("\n CMD_TO_ADD_NF_TO_CGROUP: %s", cg_add_cmd);
        ret = system(cg_add_cmd);

        /* Retrieve the mapped core-id */
        nf_info->core_id = get_nf_core_id();

        /* Initialize the cpu.shares to default value (100%) */
        ret = set_cgroup_cpu_share(nf_info, 0);

        printf("NF on core=%u added to cgroup: %s, ret=%d", nf_info->core_id, cg_name,ret);
        return;
}
#endif //USE_CGROUPS_PER_NF_INSTANCE


/******************************Timer Helper functions*******************************/
#ifdef ENABLE_TIMER_BASED_NF_CYCLE_COMPUTATION
static void
stats_timer_cb(__attribute__((unused)) struct rte_timer *ptr_timer,
        __attribute__((unused)) void *ptr_data) {

#ifdef INTERRUPT_SEM
        counter = SAMPLING_RATE;
#endif //INTERRUPT_SEM

        //printf("\n On core [%d] Inside Timer Callback function: %"PRIu64" !!\n", rte_lcore_id(), rte_rdtsc_precise());
        //printf("Echo %d", system("echo > hello_timer.txt"));
        //printf("\n Inside Timer Callback function: %"PRIu64" !!\n", rte_rdtsc_precise());
}

static inline void
init_nflib_timers(void) {
        //unsigned cur_lcore = rte_lcore_id();
        //unsigned timer_core = rte_get_next_lcore(cur_lcore, 1, 1);
        //printf("cur_core [%u], timer_core [%u]", cur_lcore,timer_core);
        rte_timer_subsystem_init();
        rte_timer_init(&stats_timer);
        rte_timer_reset_sync(&stats_timer,
                                (NF_STATS_PERIOD_IN_MS * rte_get_timer_hz()) / 1000,
                                PERIODICAL,
                                rte_lcore_id(), //timer_core
                                &stats_timer_cb, NULL
                                );
}
#endif

int
onvm_nflib_init(int argc, char *argv[], const char *nf_tag) {
        const struct rte_memzone *mz_nf;
        const struct rte_memzone *mz_port;
        const struct rte_memzone *mz_scp;
        const struct rte_memzone *mz_services;
        const struct rte_memzone *mz_nf_per_service;
        struct rte_mempool *mp;
        struct onvm_service_chain **scp;
        int retval_eal, retval_parse, retval_final;

#ifdef ENABLE_LOCAL_LATENCY_PROFILER
        onvm_util_get_start_time(&g_ts);
#endif
        if ((retval_eal = rte_eal_init(argc, argv)) < 0)
                return -1;

        /* Modify argc and argv to conform to getopt rules for parse_nflib_args */
        argc -= retval_eal; argv += retval_eal;

        /* Reset getopt global variables opterr and optind to their default values */
        opterr = 0; optind = 1;

        if ((retval_parse = onvm_nflib_parse_args(argc, argv)) < 0)
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");

        /*
         * Calculate the offset that the nf will use to modify argc and argv for its
         * getopt call. This is the sum of the number of arguments parsed by
         * rte_eal_init and parse_nflib_args. This will be decremented by 1 to assure
         * getopt is looking at the correct index since optind is incremented by 1 each
         * time "--" is parsed.
         * This is the value that will be returned if initialization succeeds.
         */
        retval_final = (retval_eal + retval_parse) - 1;

        /* Reset getopt global variables opterr and optind to their default values */
        opterr = 0; optind = 1;

        /* Lookup mempool for nf_info struct */
        nf_info_mp = rte_mempool_lookup(_NF_MEMPOOL_NAME);
        if (nf_info_mp == NULL)
                rte_exit(EXIT_FAILURE, "No Client Info mempool - bye\n");

        /* Lookup mempool for NF messages */
        nf_msg_pool = rte_mempool_lookup(_NF_MSG_POOL_NAME);
        if (nf_msg_pool == NULL)
                rte_exit(EXIT_FAILURE, "No NF Message mempool - bye\n");

        /* Initialize the info struct */
        nf_info = onvm_nflib_info_init(nf_tag);

        mp = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if (mp == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get mempool for mbufs\n");

        /* Lookup mempool for NF structs */
        mz_nf = rte_memzone_lookup(MZ_CLIENT_INFO);
        if (mz_nf == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get NF structure mempool\n");
        nfs = mz_nf->addr;

        mz_services = rte_memzone_lookup(MZ_SERVICES_INFO);
        if (mz_services == NULL) {
                rte_exit(EXIT_FAILURE, "Cannot get service information\n");
        }
        services = mz_services->addr;

        mz_nf_per_service = rte_memzone_lookup(MZ_NF_PER_SERVICE_INFO);
        if (mz_nf_per_service == NULL) {
                rte_exit(EXIT_FAILURE, "Cannot get NF per service information\n");
        }
        nf_per_service_count = mz_nf_per_service->addr;

        mz_port = rte_memzone_lookup(MZ_PORT_INFO);
        if (mz_port == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get port info structure\n");
        ports = mz_port->addr;

        mz_scp = rte_memzone_lookup(MZ_SCP_INFO);
        if (mz_scp == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get service chain info structre\n");
        scp = mz_scp->addr;
        default_chain = *scp;

        onvm_sc_print(default_chain);

        mgr_msg_ring = rte_ring_lookup(_MGR_MSG_QUEUE_NAME);
        if (mgr_msg_ring == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get MGR Message ring");
#ifdef ENABLE_SYNC_MGR_TO_NF_MSG
        mgr_rsp_ring = rte_ring_lookup(_MGR_RSP_QUEUE_NAME);
        if (mgr_rsp_ring == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get MGR response (SYNC) ring");
#endif
        onvm_nflib_startup();

#ifdef INTERRUPT_SEM
        init_shared_cpu_info(nf_info->instance_id);
#endif

#ifdef USE_CGROUPS_PER_NF_INSTANCE
        init_cgroup_info(nf_info);
#endif

#ifdef ENABLE_TIMER_BASED_NF_CYCLE_COMPUTATION
        init_nflib_timers();
#endif  //ENABLE_TIMER_BASED_NF_CYCLE_COMPUTATION

#ifdef STORE_HISTOGRAM_OF_NF_COMPUTATION_COST
        hist_init_v2(&nf_info->ht2);    //hist_init( &ht, MAX_NF_COMP_COST_CYCLES);
#endif

#ifdef ENABLE_ECN_CE
        hist_init_v2(&nf_info->ht2_q);    //hist_init( &ht, MAX_NF_COMP_COST_CYCLES);
#endif

#ifdef TEST_MEMCPY_OVERHEAD
        allocate_base_memory();
#endif

#ifdef ENABLE_LOCAL_LATENCY_PROFILER
        int64_t ttl_elapsed = onvm_util_get_elapsed_time(&g_ts);
        printf("WAIT_TIME(INIT-->START-->Init_end): %li ns\n", ttl_elapsed);
#endif
        RTE_LOG(INFO, APP, "Finished Process Init.\n");
        return retval_final;
}

#ifdef INTERRUPT_SEM
void onvm_nf_yeild(__attribute__((unused))struct onvm_nf_info* info, __attribute__((unused)) uint8_t reason_rxtx) {
        
        /* For now discard the special NF instance and put all NFs to wait */
       // if ((!ONVM_SPECIAL_NF) || (info->instance_id != 1)) { }

#ifdef ENABLE_NF_YIELD_NOTIFICATION_COUNTER
        if(reason_rxtx) {
                this_nf->stats.tx_drop+=1;
        }else {
                this_nf->stats.yield_count +=1;
        }
#endif

#ifdef USE_POLL_MODE
        return;
#endif

        //do not block if running status is off.
        if(unlikely(!keep_running)) return;

        rte_atomic16_set(flag_p, 1);  //rte_atomic16_cmpset(flag_p, 0, 1);
#ifdef USE_SEMAPHORE
        sem_wait(mutex);
#endif
        
        //check and trigger explicit callabck before returning.
        if(need_ecb && nf_ecb) {
                need_ecb = 0;
                nf_ecb();
        }
}
#ifdef INTERRUPT_SEM
static inline void  onvm_nf_wake_notify(__attribute__((unused))struct onvm_nf_info* info);
static inline void  onvm_nf_wake_notify(__attribute__((unused))struct onvm_nf_info* info)
{
#ifdef USE_SEMAPHORE
        sem_post(mutex);
        //printf("Triggered to wakeup the NF thread internally");
#endif
        return;
}
static inline void onvm_nflib_implicit_wakeup(void);
static inline void onvm_nflib_implicit_wakeup(void) {
        if ((rte_atomic16_read(flag_p) ==1)) {
                rte_atomic16_set(flag_p, 0);
                onvm_nf_wake_notify(nf_info);
        }
}
#endif //#ifdef INTERRUPT_SEM

static inline void start_ppkt_processing_cost(uint64_t *start_tsc) {
        if (counter % SAMPLING_RATE == 0) {
                *start_tsc = onvm_util_get_current_cpu_cycles();//compute_start_cycles(); //rte_rdtsc();
        }
}
static inline void end_ppkt_processing_cost(uint64_t start_tsc) {
        if (counter % SAMPLING_RATE == 0) {
                this_nf->stats.comp_cost = onvm_util_get_elapsed_cpu_cycles(start_tsc);
                if (this_nf->stats.comp_cost > RTDSC_CYCLE_COST) {
                        this_nf->stats.comp_cost -= RTDSC_CYCLE_COST;
                }
#ifdef STORE_HISTOGRAM_OF_NF_COMPUTATION_COST
                hist_store_v2(&nf_info->ht2, this_nf->stats.comp_cost);
                //avoid updating 'nf_info->comp_cost' as it will be calculated in the weight assignment function
                //nf_info->comp_cost  = hist_extract_v2(&nf_info->ht2,VAL_TYPE_RUNNING_AVG);
#else   //just save the running average
                nf_info->comp_cost  = (nf_info->comp_cost == 0)? (this_nf->stats.comp_cost): ((nf_info->comp_cost+this_nf->stats.comp_cost)/2);

#endif //STORE_HISTOGRAM_OF_NF_COMPUTATION_COST

#ifdef ENABLE_TIMER_BASED_NF_CYCLE_COMPUTATION
                counter = 1;
#endif  //ENABLE_TIMER_BASED_NF_CYCLE_COMPUTATION

#ifdef ENABLE_ECN_CE
                hist_store_v2(&nf_info->ht2_q, rte_ring_count(rx_ring));
#endif
        }

        #ifndef ENABLE_TIMER_BASED_NF_CYCLE_COMPUTATION
        counter++;  //computing for first packet makes also account reasonable cycles for cache-warming.
        #endif //ENABLE_TIMER_BASED_NF_CYCLE_COMPUTATION
}
#endif  //INTERRUPT_SEM
#ifdef ENABLE_NFV_RESL
static inline void
onvm_nflib_wait_till_notification(void) {
        printf("\n Client [%d] is paused and waiting for SYNC Signal\n", nf_info->instance_id);
#ifdef ENABLE_LOCAL_LATENCY_PROFILER
        onvm_util_get_start_time(&ts);
#endif
        do {
                onvm_nf_yeild(nf_info,YEILD_DUE_TO_EXPLICIT_REQ);
                /* Next Check for any Messages/Notifications */
                onvm_nflib_dequeue_messages();
        }while(nf_info->status == NF_PAUSED);

#ifdef ENABLE_LOCAL_LATENCY_PROFILER
        printf("SIGNAL_TIME(PAUSE-->RESUME): %li ns\n", onvm_util_get_elapsed_time(&ts));
#endif
        printf("\n Client [%d] completed wait on SYNC Signal \n", nf_info->instance_id);
}
#endif //ENABLE_NFV_RESL


static inline void onvm_nflib_check_and_wait_if_interrupted(void);
static inline void onvm_nflib_check_and_wait_if_interrupted(void) {
#if defined (INTERRUPT_SEM) && ((defined(NF_BACKPRESSURE_APPROACH_2) || defined(USE_ARBITER_NF_EXEC_PERIOD)) || defined(ENABLE_NFV_RESL))
        if(unlikely(NF_PAUSED == nf_info->status)) {
                printf("\n Explicit Pause request from ONVM_MGR\n ");
                onvm_nflib_wait_till_notification();
                printf("\n Explicit Pause Completed by NF\n");
        }
        else if (unlikely(rte_atomic16_read(flag_p) ==1)) {
                printf("\n Explicit Yield request from ONVM_MGR\n ");
                onvm_nf_yeild(nf_info,YEILD_DUE_TO_EXPLICIT_REQ);
                printf("\n Explicit Yield Completed by NF\n");
        }
#endif
}

#if defined(ENABLE_SHADOW_RINGS)
static inline void onvm_nflib_handle_tx_shadow_ring(void);
static inline void onvm_nflib_handle_tx_shadow_ring(void) {

        /* Foremost Move left over processed packets from Tx shadow ring to the Tx Ring if any */
        if(unlikely( (rte_ring_count(tx_sring)))) {
                uint16_t nb_pkts = CLIENT_SHADOW_RING_SIZE;
                uint16_t tx_spkts;
                void *pkts[CLIENT_SHADOW_RING_SIZE];
                do
                {
                        // Extract packets from Tx shadow ring
                        tx_spkts = rte_ring_dequeue_burst(tx_sring, pkts, nb_pkts);

                        //fprintf(stderr, "\n Move processed packets from Shadow Tx Ring to Tx Ring [%d] packets from shadow ring( Re-queue)!\n", tx_spkts);
                        //Push the packets to the Tx ring
                        if(unlikely(rte_ring_enqueue_bulk(tx_ring, pkts, tx_spkts) == -ENOBUFS)) {
#ifdef INTERRUPT_SEM
                                //To preserve the packets, re-enqueue packets back to the the shadow ring
                                rte_ring_enqueue_bulk(tx_sring, pkts, tx_spkts);

                                //printf("\n Yielding till Tx Ring has space for tx_shadow buffer Packets \n");
                                onvm_nf_yeild(nf_info,YIELD_DUE_TO_FULL_TX_RING);
                                //printf("\n Resuming till Tx Ring has space for tx_shadow buffer Packets \n");
#endif
                        }
                }while(rte_ring_count(tx_sring) && keep_running);
                this_nf->stats.tx += tx_spkts;
        }
}
#endif // defined(ENABLE_SHADOW_RINGS)

static inline int onvm_nflib_fetch_packets( void **pkts, unsigned max_packets);
static inline int onvm_nflib_fetch_packets( void **pkts, unsigned max_packets) {
#if defined(ENABLE_SHADOW_RINGS)

        /* Address the buffers in the Tx Shadow Ring before starting to process the new packets */
        onvm_nflib_handle_tx_shadow_ring();

        /* First Dequeue the packets pulled from Rx Shadow Ring if not empty*/
        if (unlikely( (rte_ring_count(rx_sring)))) {
                max_packets = rte_ring_dequeue_burst(rx_sring, pkts, max_packets);
                fprintf(stderr, "Dequeued [%d] packets from shadow ring( Re-Run)!\n", max_packets);
        }
        /* ELSE: Get Packets from Main Rx Ring */
        else
#endif
        max_packets = (uint16_t)rte_ring_dequeue_burst(rx_ring, pkts, max_packets);

        if(likely(max_packets)) {
#if defined(ENABLE_SHADOW_RINGS)
                /* Also enqueue the packets pulled from Rx ring or Rx Shadow into Rx Shadow Ring */
                if (unlikely(rte_ring_enqueue_bulk(rx_sring, pkts, max_packets) == -ENOBUFS)) {
                        fprintf(stderr, "Enqueue: %d packets to shadow ring Failed!\n", max_packets);
                }
#endif
        } else { //if(0 == max_packets){
#ifdef INTERRUPT_SEM
                //printf("\n Yielding till Rx Ring has Packets to process \n");
                onvm_nf_yeild(nf_info,YIELD_DUE_TO_EMPTY_RX_RING);
                //printf("\n Resuming from Rx Ring has Packets to process \n");
#endif
        }
        return max_packets;
}
static inline void onvm_nflib_process_packets_batch(void **pkts, unsigned nb_pkts, pkt_handler handler);
static inline void onvm_nflib_process_packets_batch(void **pkts, unsigned nb_pkts, pkt_handler handler) {
        int ret_act;
        uint16_t i=0;
        uint32_t tx_batch_size = 0;
        void *pktsTX[NF_PKT_BATCH_SIZE];

#ifdef INTERRUPT_SEM
        // To account NFs computation cost (sampled over SAMPLING_RATE packets)
        uint64_t start_tsc = 0;
#endif
        for (i = 0; i < nb_pkts; i++) {

#ifdef INTERRUPT_SEM
                start_ppkt_processing_cost(&start_tsc);
#endif
                ret_act = (*handler)((struct rte_mbuf*) pkts[i], onvm_get_pkt_meta((struct rte_mbuf*) pkts[i]));

#if defined(TEST_MEMCPY_MODE_PER_PACKET)
                do_memcopy(nf_info->nf_state_mempool);
#endif

#ifdef INTERRUPT_SEM
                end_ppkt_processing_cost(start_tsc);
#endif  //INTERRUPT_SEM

                /* NF returns 0 to return packets or 1 to buffer */
                if (likely(ret_act == 0)) {
                        pktsTX[tx_batch_size++] = pkts[i];
#if defined(ENABLE_SHADOW_RINGS)
                        /* Move this processed packet (Head of Rx shadow Ring) to Tx Shadow Ring */
                        void *pkt_rx;
                        rte_ring_sc_dequeue(rx_sring, &pkt_rx);
                        rte_ring_sp_enqueue(tx_sring, pkts[i]);
#endif
                }
                else {
#ifdef ENABLE_NF_TX_STAT_LOGS
                        this_nf->stats.tx_buffer++;
#endif
#if defined(ENABLE_SHADOW_RINGS)
                        /* Remove this buffered packet from Rx shadow Ring, Should we buffer it separately, or assume NF has held on to it and NF state update reflects it. */
                        void *pkt_rx;
                        rte_ring_sc_dequeue(rx_sring, &pkt_rx);
                        //rte_ring_sp_enqueue(rx_sring, pkts[i]); //TODO: Need separate buffer packets holder; cannot use the rx_sring
#endif
                }
        } //End Batch Process;

        /* Perform Post batch processing actions */
#if defined(TEST_MEMCPY_MODE_PER_BATCH)
        do_memcopy(nf_info->nf_state_mempool);
#endif //TEST_MEMCPY_OVERHEAD

        if(likely(tx_batch_size)) {
                if(likely(0 == rte_ring_enqueue_bulk(tx_ring, pktsTX, tx_batch_size))) {
                        this_nf->stats.tx += tx_batch_size;
                } else {
#if defined(NF_LOCAL_BACKPRESSURE)
                        do {
#ifdef INTERRUPT_SEM
                                //printf("\n Yielding till Tx Ring has place to store Packets\n");
                                onvm_nf_yeild(nf_info, YIELD_DUE_TO_FULL_TX_RING);
                                //printf("\n Resuming from Tx Ring wait to store Packets\n");
#endif
                                if (tx_batch_size > rte_ring_free_count(tx_ring)) {
                                        continue;
                                }
                        } while (rte_ring_enqueue_bulk(tx_ring,pktsTX, tx_batch_size) && keep_running);
                        this_nf->stats.tx += tx_batch_size;
#endif  //NF_LOCAL_BACKPRESSURE
                }
        }

#if defined(ENABLE_SHADOW_RINGS)
        /* Finally clear all packets from the Tx Shadow Ring and also Rx shadow Ring */
        rte_ring_sc_dequeue_burst(tx_sring,pkts,rte_ring_count(tx_sring));
        if(unlikely(rte_ring_count(rx_sring))) {
                //These are the held packets in the NF in this round:
                rte_ring_sc_dequeue_burst(rx_sring,pkts,rte_ring_count(rx_sring));
                //fprintf(stderr, "BATCH END: %d packets still in Rx shadow ring!\n", rte_ring_sc_dequeue_burst(rx_sring,pkts,rte_ring_count(rx_sring)));
        }
#endif
}

int
onvm_nflib_run(
        struct onvm_nf_info* info,
        int(*handler)(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta)
        ) {
        void *pkts[NF_PKT_BATCH_SIZE]; //better to use (NF_PKT_BATCH_SIZE*2)
        uint16_t nb_pkts;
        
        printf("\nClient process %d handling packets\n", info->instance_id);
        printf("[Press Ctrl-C to quit ...]\n");

        /* Listen for ^C so we can exit gracefully */
        signal(SIGINT, onvm_nflib_handle_signal);
        
        onvm_nflib_notify_ready();

        /* First Check for any Messages/Notifications */
        onvm_nflib_dequeue_messages();

#ifdef ENABLE_LOCAL_LATENCY_PROFILER
        printf("WAIT_TIME(INIT-->START-->RUN-->RUNNING): %li ns\n", onvm_util_get_elapsed_time(&g_ts));
#endif

        for (;keep_running;) {
                /* check if signaled to block, then block:: TODO: Merge this to the Message above */
                onvm_nflib_check_and_wait_if_interrupted();

                nb_pkts = onvm_nflib_fetch_packets(pkts, NF_PKT_BATCH_SIZE);
                if(likely(nb_pkts)) {
                        /* Give each packet to the user processing function */
                        onvm_nflib_process_packets_batch(pkts, nb_pkts, handler);
                }

#ifdef ENABLE_TIMER_BASED_NF_CYCLE_COMPUTATION
                rte_timer_manage();
#endif  //ENABLE_TIMER_BASED_NF_CYCLE_COMPUTATION

                /* Finally Check for any Messages/Notifications */
                onvm_nflib_dequeue_messages();
        }

        printf("\n NF is Exiting...!\n");
        onvm_nflib_cleanup();
        return 0;
}


int
onvm_nflib_return_pkt(struct rte_mbuf* pkt) {
        /* FIXME: should we get a batch of buffered packets and then enqueue? Can we keep stats? */
        if(unlikely(rte_ring_enqueue(tx_ring, pkt) == -ENOBUFS)) {
                rte_pktmbuf_free(pkt);
                this_nf->stats.tx_drop++;
                return -ENOBUFS;
        }
        else {
#ifdef ENABLE_NF_TX_STAT_LOGS
                this_nf->stats.tx_returned++;
#endif
        }
        return 0;
}


void
onvm_nflib_stop(void) {
        rte_exit(EXIT_SUCCESS, "Done.");
}

int
onvm_nflib_drop_pkt(struct rte_mbuf* pkt) {
        rte_pktmbuf_free(pkt);
        this_nf->stats.tx_drop++;
        return 0;
}

void notify_for_ecb(void) {
        need_ecb = 1;
#ifdef INTERRUPT_SEM
        if ((rte_atomic16_read(flag_p) ==1)) {
            onvm_nf_wake_notify(nf_info);
        }
#endif
        return;
}

int
onvm_nflib_handle_msg(struct onvm_nf_msg *msg) {
        switch(msg->msg_type) {
        case MSG_STOP:
                keep_running = 0;
                if(NF_PAUSED == nf_info->status) {
                        nf_info->status = NF_RUNNING;
#ifdef INTERRUPT_SEM
                        onvm_nflib_implicit_wakeup(); //TODO: change this ecb call; split ecb call to two funcs. sounds stupid but necessary as cache update of flag_p takes time; otherwise results in sleep-wkup cycles
#endif
                }
                RTE_LOG(INFO, APP, "Shutting down...\n");
                break;
        case MSG_NF_TRIGGER_ECB:
                notify_for_ecb();
                break;
        case MSG_PAUSE:
                if(NF_PAUSED != nf_info->status) {
                        RTE_LOG(INFO, APP, "NF Status changed to Pause!...\n");
                        nf_info->status = NF_PAUSED;
                }
                RTE_LOG(INFO, APP, "NF Pausing!...\n");
                break;
        case MSG_RESUME: //MSG_RUN
                nf_info->status = NF_RUNNING;
#ifdef INTERRUPT_SEM
                        onvm_nflib_implicit_wakeup(); //TODO: change this ecb call; split ecb call to two funcs. sounds stupid but necessary as cache update of flag_p takes time; otherwise results in sleep-wkup cycles
#endif
                RTE_LOG(INFO, APP, "Resuming NF...\n");
                break;
        case MSG_NOOP:
        default:
                break;
        }
        return 0;
}

static inline void
onvm_nflib_dequeue_messages(void) {
        // Check and see if this NF has any messages from the manager
        if (likely(rte_ring_count(nf_msg_ring) == 0)) {
                return;
        }
        struct onvm_nf_msg *msg = NULL;
        rte_ring_dequeue(nf_msg_ring, (void**)(&msg));
        onvm_nflib_handle_msg(msg);
        rte_mempool_put(nf_msg_pool, (void*)msg);
}
/******************************Helper functions*******************************/
static struct onvm_nf_info *
onvm_nflib_info_init(const char *tag)
{
        void *mempool_data;
        struct onvm_nf_info *info;

        if (rte_mempool_get(nf_info_mp, &mempool_data) < 0) {
                rte_exit(EXIT_FAILURE, "Failed to get client info memory");
        }

        if (mempool_data == NULL) {
                rte_exit(EXIT_FAILURE, "Client Info struct not allocated");
        }

        info = (struct onvm_nf_info*) mempool_data;
        info->instance_id = initial_instance_id;
        info->service_id = service_id;
        info->status = NF_WAITING_FOR_ID;
        info->tag = tag;

        info->pid = getpid();

        return info;
}


static void
onvm_nflib_usage(const char *progname) {
        printf("Usage: %s [EAL args] -- "
#ifdef ENABLE_STATIC_ID
               "[-n <instance_id>]"
#endif
               "[-r <service_id>]\n\n", progname);
}


static int
onvm_nflib_parse_args(int argc, char *argv[]) {
        const char *progname = argv[0];
        int c;

        opterr = 0;
#ifdef ENABLE_STATIC_ID
        while ((c = getopt (argc, argv, "n:r:")) != -1)
#else
        while ((c = getopt (argc, argv, "r:")) != -1)
#endif
                switch (c) {
#ifdef ENABLE_STATIC_ID
                case 'n':
                        initial_instance_id = (uint16_t) strtoul(optarg, NULL, 10);
                        break;
#endif
                case 'r':
                        service_id = (uint16_t) strtoul(optarg, NULL, 10);
                        // Service id 0 is reserved
                        if (service_id == 0) service_id = -1;
                        break;
                case '?':
                        onvm_nflib_usage(progname);
                        if (optopt == 'n')
                                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                        else if (isprint(optopt))
                                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                        else
                                fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
                        return -1;
                default:
                        return -1;
                }

        if (service_id == (uint16_t)-1) {
                /* Service ID is required */
                fprintf(stderr, "You must provide a nonzero service ID with -r\n");
                return -1;
        }
        return optind;
}


static void
onvm_nflib_handle_signal(int sig)
{
        if (sig == SIGINT) {
                keep_running = 0;
#ifdef INTERRUPT_SEM
                onvm_nflib_implicit_wakeup();
#endif
        }
        /* TODO: Main thread for INTERRUPT_SEM case: Must additionally relinquish SEM, SHM */
}

static inline void
onvm_nflib_cleanup(void)
{
        struct onvm_nf_msg *shutdown_msg;
        nf_info->status = NF_STOPPED;

#ifndef ENABLE_MSG_CONSTRUCT_NF_INFO_NOTIFICATION
        /* Put this NF's info struct back into queue for manager to ack shutdown */
        if (mgr_msg_ring == NULL) {
                rte_mempool_put(nf_info_mp, nf_info); // give back memory
                rte_exit(EXIT_FAILURE, "Cannot get nf_info ring for shutdown");
        }

        if (rte_ring_enqueue(mgr_msg_ring, nf_info) < 0) {
                rte_mempool_put(nf_info_mp, nf_info); // give back mermory
                rte_exit(EXIT_FAILURE, "Cannot send nf_info to manager for shutdown");
        }
        return ;
#else
        /* Put this NF's info struct back into queue for manager to ack shutdown */
        if (mgr_msg_ring == NULL) {
                rte_mempool_put(nf_info_mp, nf_info); // give back mermory
                rte_exit(EXIT_FAILURE, "Cannot get nf_info ring for shutdown");
        }
        if (rte_mempool_get(nf_msg_pool, (void**)(&shutdown_msg)) != 0) {
                rte_mempool_put(nf_info_mp, nf_info); // give back mermory
                rte_exit(EXIT_FAILURE, "Cannot create shutdown msg");
        }

        shutdown_msg->msg_type = MSG_NF_STOPPING;
        shutdown_msg->msg_data = nf_info;

        if (rte_ring_enqueue(mgr_msg_ring, shutdown_msg) < 0) {
                rte_mempool_put(nf_info_mp, nf_info); // give back mermory
                rte_mempool_put(nf_msg_pool, shutdown_msg);
                rte_exit(EXIT_FAILURE, "Cannot send nf_info to manager for shutdown");
        }
        return;
#endif
}

static inline int
onvm_nflib_notify_ready(void) {
        int ret = 0;

#ifdef ENABLE_LOCAL_LATENCY_PROFILER
        onvm_util_get_start_time(&ts);
#endif
        nf_info->status = NF_WAITING_FOR_RUN;

#ifdef ENABLE_MSG_CONSTRUCT_NF_INFO_NOTIFICATION
        struct onvm_nf_msg *startup_msg;
        /* Put this NF's info struct onto queue for manager to process startup */
        ret = rte_mempool_get(nf_msg_pool, (void**)(&startup_msg));
        if (ret != 0) return ret;

        startup_msg->msg_type = MSG_NF_READY;
        startup_msg->msg_data = nf_info;
        ret = rte_ring_enqueue(mgr_msg_ring, startup_msg);
        if (ret < 0) {
                rte_mempool_put(nf_msg_pool, startup_msg);
                return ret;
        }
#else
        /* Put this NF's info struct onto queue for manager to process startup */
        ret = rte_ring_enqueue(mgr_msg_ring, nf_info);
        if (ret < 0) {
                rte_mempool_put(nf_info_mp, nf_info); // give back memory
                rte_exit(EXIT_FAILURE, "Cannot send nf_info to manager");
        }
#endif
        /* Wait for a client id to be assigned by the manager */
        RTE_LOG(INFO, APP, "Waiting for manager to put to RUN state...\n");
        struct timespec req = {0,1000}, res = {0,0};
        for (; nf_info->status == (uint16_t)NF_WAITING_FOR_RUN ;) {
                nanosleep(&req, &res); //sleep(1); //better poll for some time and exit if failed within that time.?
        }
#ifdef ENABLE_LOCAL_LATENCY_PROFILER
        int64_t ttl_elapsed = onvm_util_get_elapsed_time(&ts);
        printf("WAIT_TIME(START-->RUN): %li ns\n", ttl_elapsed);
#endif

#if 0
        if(NF_PAUSED == nf_info->status) {
                onvm_nflib_wait_till_notification();
        }
        if(NF_RUNNING != nf_info->status) {
                switch(nf_info->status) {
                case NF_PAUSED:
                        onvm_nflib_wait_till_notification();
                        break;
                case NF_STOPPED:
                        onvm_nflib_cleanup();
                        rte_exit(EXIT_FAILURE, "NF RUNfailed! moving to shutdown!");
                        break;
                default:
                        break;
                }
        }
#endif
        return 0;
}

static inline void
onvm_nflib_startup(void) {

#ifdef ENABLE_LOCAL_LATENCY_PROFILER
        onvm_util_get_start_time(&ts);
#endif
#ifdef ENABLE_MSG_CONSTRUCT_NF_INFO_NOTIFICATION
        struct onvm_nf_msg *startup_msg;
        /* Put this NF's info struct into queue for manager to process startup shutdown */
        if (rte_mempool_get(nf_msg_pool, (void**)(&startup_msg)) != 0) {
                rte_mempool_put(nf_info_mp, nf_info); // give back mermory
                rte_exit(EXIT_FAILURE, "Cannot create shutdown msg");
        }
        startup_msg->msg_type = MSG_NF_STARTING;
        startup_msg->msg_data = nf_info;
        if (rte_ring_enqueue(mgr_msg_ring, startup_msg) < 0) {
                rte_mempool_put(nf_info_mp, nf_info); // give back mermory
                rte_mempool_put(nf_msg_pool, startup_msg);
                rte_exit(EXIT_FAILURE, "Cannot send nf_info to manager for startup");
        }
#else
        /* Put this NF's info struct onto queue for manager to process startup */
        if (rte_ring_enqueue(mgr_msg_ring, nf_info) < 0) {
                rte_mempool_put(nf_info_mp, nf_info); // give back mermory
                rte_exit(EXIT_FAILURE, "Cannot send nf_info to manager");
        }
#endif

        /* Wait for a client id to be assigned by the manager */
        RTE_LOG(INFO, APP, "Waiting for manager to assign an ID...\n");
        struct timespec req = {0,1000}, res = {0,0};
        for (; nf_info->status == (uint16_t)NF_WAITING_FOR_ID ;) {
                nanosleep(&req,&res);//sleep(1);
        }
#ifdef ENABLE_LOCAL_LATENCY_PROFILER
        int64_t ttl_elapsed = onvm_util_get_elapsed_time(&ts);
        printf("WAIT_TIME(INIT-->START): %li ns\n", ttl_elapsed);
#endif

        /* This NF is trying to declare an ID already in use. */
        if (nf_info->status == NF_ID_CONFLICT) {
                rte_mempool_put(nf_info_mp, nf_info);
                rte_exit(NF_ID_CONFLICT, "Selected ID already in use. Exiting...\n");
        } else if(nf_info->status == NF_NO_IDS) {
                rte_mempool_put(nf_info_mp, nf_info);
                rte_exit(NF_NO_IDS, "There are no ids available for this NF\n");
        } else if(nf_info->status != NF_STARTING) {
                rte_mempool_put(nf_info_mp, nf_info);
                rte_exit(EXIT_FAILURE, "Error occurred during manager initialization\n");
        }
        RTE_LOG(INFO, APP, "Using Instance ID %d\n", nf_info->instance_id);
        RTE_LOG(INFO, APP, "Using Service ID %d\n", nf_info->service_id);

        /* Firt update this client structure pointer */
        this_nf = &nfs[nf_info->instance_id];

        /* Now, map rx and tx rings into client space */
        rx_ring = rte_ring_lookup(get_rx_queue_name(nf_info->instance_id));
        if (rx_ring == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get RX ring - is server process running?\n");

        tx_ring = rte_ring_lookup(get_tx_queue_name(nf_info->instance_id));
        if (tx_ring == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get TX ring - is server process running?\n");

        #if defined(ENABLE_SHADOW_RINGS)
        rx_sring = rte_ring_lookup(get_rx_squeue_name(nf_info->instance_id));
        if (rx_sring == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get RX Shadow ring - is server process running?\n");

        tx_sring = rte_ring_lookup(get_tx_squeue_name(nf_info->instance_id));
        if (tx_sring == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get TX Shadow ring - is server process running?\n");
        #endif

        nf_msg_ring = rte_ring_lookup(get_msg_queue_name(nf_info->instance_id));
        if (nf_msg_ring == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get nf msg ring");
}

#ifdef INTERRUPT_SEM
static void set_cpu_sched_policy_and_mode(void) {
        return;

        struct sched_param param;
        pid_t my_pid = getpid();
        sched_getparam(my_pid, &param);
        param.__sched_priority = 20;
        sched_setscheduler(my_pid, SCHED_RR, &param);
}

static void 
init_shared_cpu_info(uint16_t instance_id) {
        const char *sem_name;
        int shmid;
        key_t key;
        char *shm;

        sem_name = get_sem_name(instance_id);
        fprintf(stderr, "sem_name=%s for client %d\n", sem_name, instance_id);

        #ifdef USE_SEMAPHORE
        mutex = sem_open(sem_name, 0, 0666, 0);
        if (mutex == SEM_FAILED) {
                perror("Unable to execute semaphore");
                fprintf(stderr, "unable to execute semphore for client %d\n", instance_id);
                sem_close(mutex);
                exit(1);
        }
        #endif

        /* get flag which is shared by server */
        key = get_rx_shmkey(instance_id);
        if ((shmid = shmget(key, SHMSZ, 0666)) < 0) {
                perror("shmget");
                fprintf(stderr, "unable to Locate the segment for client %d\n", instance_id);
                exit(1);
        }

        if ((shm = shmat(shmid, NULL, 0)) == (char *) -1) {
                fprintf(stderr, "can not attach the shared segment to the client space for client %d\n", instance_id);
                exit(1);
        }

        flag_p = (rte_atomic16_t *)shm;

        set_cpu_sched_policy_and_mode();

        // Get the FlowTable Entries Exported to the NF.
        #if defined(ENABLE_NFV_RESL)
        onvm_flow_dir_nf_init();
        #endif //#if defined(ENABLE_NFV_RESL)
}
#endif //INTERRUPT_SEM

