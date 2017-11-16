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
#if defined(_POSIX_TIMERS) && (_POSIX_TIMERS > 0) &&                           \
    defined(_POSIX_MONOTONIC_CLOCK)
#define HAS_CLOCK_GETTIME_MONOTONIC
#endif

#define ENABLE_LOCAL_LATENCY_PROFILER
#ifdef ENABLE_LOCAL_LATENCY_PROFILER
#ifdef HAS_CLOCK_GETTIME_MONOTONIC
  struct timespec start, stop;
#else
  struct timeval start, stop;
#endif
int64_t delta = 0;
int get_cur_time(void* ct);
int get_start_time(void);
int get_stop_time(void);
int64_t get_elapsed_time(void);
int get_cur_time(void* ct)
{
#ifdef HAS_CLOCK_GETTIME_MONOTONIC
    if (clock_gettime(USE_THIS_CLOCK,(struct timespec *)ct) == -1) {
      perror("clock_gettime");
      return 1;
    }
#else
    if (gettimeofday(&ct, NULL) == -1) {
      perror("gettimeofday");
      return 1;
    }
#endif
    return 0;
}

int get_start_time(void)
{
#ifdef HAS_CLOCK_GETTIME_MONOTONIC
    if (clock_gettime(USE_THIS_CLOCK, &start) == -1) {
      perror("clock_gettime");
      return 1;
    }
#else
    if (gettimeofday(&start, NULL) == -1) {
      perror("gettimeofday");
      return 1;
    }
#endif
    return 0;
}

int get_stop_time(void)
{
#ifdef HAS_CLOCK_GETTIME_MONOTONIC
    if (clock_gettime(USE_THIS_CLOCK, &stop) == -1) {
      perror("clock_gettime");
      return 1;
    }
#else
    if (gettimeofday(&stop, NULL) == -1) {
      perror("gettimeofday");
      return 1;
    }
#endif
    return 0;
}
#ifdef HAS_CLOCK_GETTIME_MONOTONIC
int64_t get_ttl_time(struct timespec start, struct timespec stop);
int64_t get_ttl_time(struct timespec start, struct timespec stop)
{
#else
int64_t get_ttl_time(struct timeval start, struct timeval stop)
#endif
#ifdef HAS_CLOCK_GETTIME_MONOTONIC
        delta = ((stop.tv_sec - start.tv_sec) * 1000000000 +
             (stop.tv_nsec - start.tv_nsec));
#else
        delta = (stop.tv_sec - start.tv_sec) * 1000000000 +
             (stop.tv_usec - start.tv_usec) * 1000;
#endif
        return delta;
}

int64_t get_elapsed_time(void)
{
#ifdef HAS_CLOCK_GETTIME_MONOTONIC
        delta = ((stop.tv_sec - start.tv_sec) * 1000000000 +
             (stop.tv_nsec - start.tv_nsec));
#else
        delta = (stop.tv_sec - start.tv_sec) * 1000000000 +
             (stop.tv_usec - start.tv_usec) * 1000;
#endif
        return delta;
}
#endif //ENABLE_LOCAL_LATENCY_PROFILER
/*********************************************************************/

nf_explicit_callback_function nf_ecb = NULL;
static uint8_t need_ecb = 0;
void register_explicit_callback_function(nf_explicit_callback_function ecb) {
        if(ecb) {
                nf_ecb = ecb;
        }
        return;
}

/*****************************************************************************
                        HISTOGRAM DETAILS
*/

/******************************************************************************/

/************************************API**************************************/
#define USE_STATIC_IDS
#define RTDSC_CYCLE_COST    (20*2) // profiled  approx. 18~27cycles per call

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
#endif


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
#endif

int
onvm_nflib_init(int argc, char *argv[], const char *nf_tag) {
        const struct rte_memzone *mz;
        const struct rte_memzone *mz_scp;
        struct rte_mempool *mp;
        struct onvm_service_chain **scp;
        int retval_eal, retval_parse, retval_final;

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

        /* Initialize the info struct */
        nf_info = onvm_nflib_info_init(nf_tag);

        mp = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if (mp == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get mempool for mbufs\n");

        mz = rte_memzone_lookup(MZ_CLIENT_INFO);
        if (mz == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get tx info structure\n");
        tx_stats = mz->addr;

        mz_scp = rte_memzone_lookup(MZ_SCP_INFO);
        if (mz_scp == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get service chain info structre\n");
        scp = mz_scp->addr;
        default_chain = *scp;

        onvm_sc_print(default_chain);

        nf_info_ring = rte_ring_lookup(_NF_QUEUE_NAME);
        if (nf_info_ring == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get nf_info ring");

        /* Put this NF's info struct onto queue for manager to process startup */
        if (rte_ring_enqueue(nf_info_ring, nf_info) < 0) {
                rte_mempool_put(nf_info_mp, nf_info); // give back mermory
                rte_exit(EXIT_FAILURE, "Cannot send nf_info to manager");
        }

        /* Wait for a client id to be assigned by the manager */
        RTE_LOG(INFO, APP, "Waiting for manager to assign an ID...\n");
        for (; nf_info->status == (uint16_t)NF_WAITING_FOR_ID ;) {
                sleep(1);
        }

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
        //sleep(2);

        /* Now, map rx and tx rings into client space */
        rx_ring = rte_ring_lookup(get_rx_queue_name(nf_info->instance_id));
        if (rx_ring == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get RX ring - is server process running?\n");

        tx_ring = rte_ring_lookup(get_tx_queue_name(nf_info->instance_id));
        if (tx_ring == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get TX ring - is server process running?\n");

        /* Tell the manager we're ready to recieve packets */
        //nf_info->status = NF_RUNNING;

        nf_info->pid = getpid();

        #ifdef INTERRUPT_SEM
        init_shared_cpu_info(nf_info->instance_id);

        #ifdef USE_SIGNAL
        //nf_info->pid = getpid();
        #endif //USE_SIGNAL

        #endif

#ifdef USE_CGROUPS_PER_NF_INSTANCE
        init_cgroup_info(nf_info);
#endif

#ifdef ENABLE_TIMER_BASED_NF_CYCLE_COMPUTATION
        //unsigned cur_lcore = rte_lcore_id();
        //unsigned timer_core = rte_get_next_lcore(cur_lcore, 1, 1);
        //printf("cur_core [%u], timer_core [%u]", cur_lcore,timer_core);
        rte_timer_subsystem_init();
        rte_timer_init(&nf_info->stats_timer);
        rte_timer_reset_sync(&nf_info->stats_timer,
                                (STATS_PERIOD_IN_MS * rte_get_timer_hz()) / 1000,
                                PERIODICAL,
                                rte_lcore_id(), //timer_core
                                &stats_timer_cb, NULL
                                );
#endif  //ENABLE_TIMER_BASED_NF_CYCLE_COMPUTATION

#ifdef STORE_HISTOGRAM_OF_NF_COMPUTATION_COST
        hist_init_v2(&nf_info->ht2);    //hist_init( &ht, MAX_NF_COMP_COST_CYCLES);
#endif

#ifdef ENABLE_ECN_CE
        hist_init_v2(&nf_info->ht2_q);    //hist_init( &ht, MAX_NF_COMP_COST_CYCLES);
#endif
        RTE_LOG(INFO, APP, "Finished Process Init.\n");
        return retval_final;
}

#ifdef INTERRUPT_SEM
void onvm_nf_yeild(struct onvm_nf_info* info);
void onvm_nf_yeild(struct onvm_nf_info* info) {
        
        /* For now discard the special NF instance and put all NFs to wait */
        if ((!ONVM_SPECIAL_NF) || (info->instance_id != 1)) { }
        
        tx_stats->wkup_count[info->instance_id] += 1;
        rte_atomic16_set(flag_p, 1);  //rte_atomic16_cmpset(flag_p, 0, 1);
        

        #ifdef USE_SEMAPHORE
        sem_wait(mutex);
        #endif

        #ifdef USE_POLL_MODE
        // no operation; continue;
        #endif
        
        //check and trigger explicit callabck before returning.
        if(need_ecb && nf_ecb) {
                need_ecb = 0;
                nf_ecb();
        }
}
void onvm_nf_wake_notify(__attribute__((unused))struct onvm_nf_info* info);
void onvm_nf_wake_notify(__attribute__((unused))struct onvm_nf_info* info)
{
        #ifdef USE_SEMAPHORE
        sem_post(mutex);
        //printf("Triggered to wakeup the NF thread internally");
        #endif

        #ifdef USE_POLL_MODE
        rte_atomic16_read(clients[instance_id].shm_server);
        #endif
        
        return;
}

uint64_t compute_start_cycles(void);// __attribute__((always_inline));
uint64_t compute_total_cycles(uint64_t start_t); //__attribute__((always_inline));

uint64_t compute_start_cycles(void)
{
        return rte_rdtsc_precise();
        //return rte_rdtsc();
        //return (uint64_t) 100;
}
uint64_t compute_total_cycles(uint64_t start_t)
{
       uint64_t end_t = compute_start_cycles();
       return (end_t - start_t);
}

#endif  //INTERRUPT_SEM

int
onvm_nflib_run(
        struct onvm_nf_info* info,
        int(*handler)(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta)
        ) {
        void *pkts[PKT_READ_SIZE];
        struct onvm_pkt_meta* meta;
        
        #ifdef INTERRUPT_SEM
        // To account NFs computation cost (sampled over SAMPLING_RATE packets)
        uint64_t start_tsc = 0; // end_tsc = 0;
        #endif
        
        printf("\nClient process %d handling packets\n", info->instance_id);
        printf("[Press Ctrl-C to quit ...]\n");

        /* Listen for ^C so we can exit gracefully */
        signal(SIGINT, onvm_nflib_handle_signal);
        
#ifdef ENABLE_LOCAL_LATENCY_PROFILER
        get_start_time();
#endif

        nf_info->status = NF_WAITING_FOR_RUN;
        /* Put this NF's info struct onto queue for manager to process startup */
        if (rte_ring_enqueue(nf_info_ring, nf_info) < 0) {
                rte_mempool_put(nf_info_mp, nf_info); // give back mermory
                rte_exit(EXIT_FAILURE, "Cannot send nf_info to manager");
        }
        /* Wait for a client id to be assigned by the manager */
        RTE_LOG(INFO, APP, "Waiting for manager to put to RUN state...\n");
        struct timespec req = {0,1000}, res = {0,0};
        for (; nf_info->status == (uint16_t)NF_WAITING_FOR_RUN ;) {
                nanosleep(&req, &res); //sleep(1); //better poll for some time and exit if failed within that time.?
        }
#ifdef ENABLE_LOCAL_LATENCY_PROFILER
        get_stop_time();
        int64_t ttl_elapsed = get_elapsed_time();
        printf("WAIT_TIME: %li ns\n", ttl_elapsed);
#endif
        /* Note: There is no need for synchronization here; as NF Manager will update the status to Running and only then it will be registered to deliver the packets.
        Also the NF MANGER will put the NF to the RUNNING STATE */
        //nf_info->status = NF_RUNNING;

#ifdef ENABLE_NFV_RESL
        //By default: let the process start in waiting state and let NF Manage wake up the thread when necessary.
        //if(!is_primary_active_nf_id(nf_info->instance_id)) {
                printf("\n Client [%d] is Waiting for SYNC Signal\n", nf_info->instance_id);
                onvm_nf_yeild(info);
                printf("\n Client [%d] is starting to process packets \n", nf_info->instance_id);
        /* }
        else {
                //primary must begin to process packet only after standby NF stops processing packets
                onvm_nf_yeild(info);
        }*/
#endif

        for (; keep_running;) {
                uint16_t i, j, nb_pkts = PKT_READ_SIZE;
                void *pktsTX[PKT_READ_SIZE];
                uint32_t tx_batch_size = 0;
                int ret_act;

                /* check if signalled to block, then block */
                #if defined(ENABLE_NF_BACKPRESSURE) && (defined(NF_BACKPRESSURE_APPROACH_2) || defined(USE_ARBITER_NF_EXEC_PERIOD)) || defined(ENABLE_NFV_RESL)
                #ifdef INTERRUPT_SEM
                if (rte_atomic16_read(flag_p) ==1) {
                        printf("\n Explicit Yield request from ONVM_MGR\n ");
                        onvm_nf_yeild(info);
                        printf("\n Explicit Yield Completed by NF\n");
                }
                #endif  // INTERRUPT_SEM
                #endif  // defined(ENABLE_NF_BACKPRESSURE) && defined(NF_BACKPRESSURE_APPROACH_2)

                nb_pkts = (uint16_t)rte_ring_dequeue_burst(rx_ring, pkts, nb_pkts);

                if(nb_pkts == 0) {
                        #ifdef INTERRUPT_SEM
                        onvm_nf_yeild(info);                     
                        #endif
                        continue;
                }

                /* Give each packet to the user proccessing function */
                for (i = 0; i < nb_pkts; i++) {
                        meta = onvm_get_pkt_meta((struct rte_mbuf*)pkts[i]);


                        #ifdef INTERRUPT_SEM
                        //meta = onvm_get_pkt_meta((struct rte_mbuf*)pkts[i]);
                        if (counter % SAMPLING_RATE == 0) {
                                start_tsc = compute_start_cycles(); //rte_rdtsc();
                        }
                        #endif

                        ret_act = (*handler)((struct rte_mbuf*)pkts[i], meta);
                        
                        #ifdef INTERRUPT_SEM
                        if (counter % SAMPLING_RATE == 0) {
                                tx_stats->comp_cost[info->instance_id] = compute_total_cycles(start_tsc);
                                if (tx_stats->comp_cost[info->instance_id] > RTDSC_CYCLE_COST) {
                                        tx_stats->comp_cost[info->instance_id] -= RTDSC_CYCLE_COST;
                                }

                                #ifdef USE_CGROUPS_PER_NF_INSTANCE

                                #ifdef STORE_HISTOGRAM_OF_NF_COMPUTATION_COST
                                hist_store_v2(&info->ht2, tx_stats->comp_cost[info->instance_id]);  //hist_store(&ht,tx_stats->comp_cost[info->instance_id]); //tx_stats->comp_cost[info->instance_id] = max_nf_computation_cost;
                                //avoid updating 'nf_info->comp_cost' as it will be calculated in the weight assignment function
                                //nf_info->comp_cost  = hist_extract_v2(&nf_info->ht2,VAL_TYPE_RUNNING_AVG);
                                #endif //STORE_HISTOGRAM_OF_NF_COMPUTATION_COST
                                #else   //just use the running average
                                nf_info->comp_cost  = (nf_info->comp_cost == 0)? (tx_stats->comp_cost[info->instance_id]): ((nf_info->comp_cost+tx_stats->comp_cost[info->instance_id])/2);
                                #endif //USE_CGROUPS_PER_NF_INSTANCE

                                #ifdef ENABLE_TIMER_BASED_NF_CYCLE_COMPUTATION
                                counter = 1;
                                #endif  //ENABLE_TIMER_BASED_NF_CYCLE_COMPUTATION

                                #ifdef ENABLE_ECN_CE
                                hist_store_v2(&info->ht2_q, rte_ring_count(rx_ring));
                                #endif
                        }

                        #ifndef ENABLE_TIMER_BASED_NF_CYCLE_COMPUTATION
                        counter++;  //computing for first packet makes also account reasonable cycles for cache-warming.
                        #endif //ENABLE_TIMER_BASED_NF_CYCLE_COMPUTATION

                        #endif  //INTERRUPT_SEM

                        /* NF returns 0 to return packets or 1 to buffer */
                        if(likely(ret_act == 0)) {
                                pktsTX[tx_batch_size++] = pkts[i];
                        }
                        else {
                                tx_stats->tx_buffer[info->instance_id]++;
                        }
                }

                #ifdef ENABLE_TIMER_BASED_NF_CYCLE_COMPUTATION
                rte_timer_manage();
                #endif  //ENABLE_TIMER_BASED_NF_CYCLE_COMPUTATION

                if (unlikely(tx_batch_size > 0 && rte_ring_enqueue_bulk(tx_ring, pktsTX, tx_batch_size) == -ENOBUFS)) {

                        #ifdef PRE_PROCESS_DROP_ON_RX

                        #ifdef DROP_APPROACH_3
                        int ret_status = -ENOBUFS;
                        do
                        {
                                #ifdef DROP_APPROACH_3_WITH_SYNC
                                #ifdef INTERRUPT_SEM
                                onvm_nf_yeild(info);
                                #endif
                                #endif

                                if (tx_batch_size <= rte_ring_free_count(tx_ring)) {
                                        ret_status = rte_ring_enqueue_bulk(tx_ring, pktsTX, tx_batch_size);
                                        if ( 0 ==  ret_status){
                                                tx_stats->tx[info->instance_id] += tx_batch_size;
                                                tx_batch_size=0;
                                                //break;
                                        }
                                }
                        }while(ret_status);
                        //printf("Total Retry attempts [%d]:", j);
                        #endif  //DROP_APPROACH_3

                        #endif  //PRE_PROCESS_DROP_ON_RX

                        tx_stats->tx_drop[info->instance_id] += tx_batch_size;
                        for (j = 0; j < tx_batch_size; j++) {
                                rte_pktmbuf_free(pktsTX[j]);
                        }
                } else {
                        tx_stats->tx[info->instance_id] += tx_batch_size;
                }
        }

        nf_info->status = NF_STOPPED;

        /* Put this NF's info struct back into queue for manager to ack shutdown */
        nf_info_ring = rte_ring_lookup(_NF_QUEUE_NAME);
        if (nf_info_ring == NULL) {
                rte_mempool_put(nf_info_mp, nf_info); // give back mermory
                rte_exit(EXIT_FAILURE, "Cannot get nf_info ring for shutdown");
        }

        if (rte_ring_enqueue(nf_info_ring, nf_info) < 0) {
                rte_mempool_put(nf_info_mp, nf_info); // give back mermory
                rte_exit(EXIT_FAILURE, "Cannot send nf_info to manager for shutdown");
        }
        return 0;
}


int
onvm_nflib_return_pkt(struct rte_mbuf* pkt) {
        /* FIXME: should we get a batch of buffered packets and then enqueue? Can we keep stats? */
        if(unlikely(rte_ring_enqueue(tx_ring, pkt) == -ENOBUFS)) {
                rte_pktmbuf_free(pkt);
                tx_stats->tx_drop[nf_info->instance_id]++;
                return -ENOBUFS;
        }
        else tx_stats->tx_returned[nf_info->instance_id]++;
        return 0;
}


void
onvm_nflib_stop(void) {
        rte_exit(EXIT_SUCCESS, "Done.");
}

int
onvm_nflib_drop_pkt(struct rte_mbuf* pkt) {
        rte_pktmbuf_free(pkt);
        tx_stats->tx_drop[nf_info->instance_id]++;
        return 0;
}


void notify_for_ecb(void) {
        need_ecb = 1;
        if ((rte_atomic16_read(flag_p) ==1)) {
            onvm_nf_wake_notify(nf_info);
        }
        return;
}

int
onvm_nflib_handle_msg(struct onvm_nf_msg *msg) {
        switch(msg->msg_type) {
        case MSG_STOP:
                RTE_LOG(INFO, APP, "Shutting down...\n");
                keep_running = 0;
                break;
        case MSG_NF_TRIGGER_ECB:
            notify_for_ecb();
            break;
        case MSG_NOOP:
        default:
                break;
        }

        return 0;
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

        return info;
}


static void
onvm_nflib_usage(const char *progname) {
        printf("Usage: %s [EAL args] -- "
#ifdef USE_STATIC_IDS
               "[-n <instance_id>]"
#endif
               "[-r <service_id>]\n\n", progname);
}


static int
onvm_nflib_parse_args(int argc, char *argv[]) {
        const char *progname = argv[0];
        int c;

        opterr = 0;
#ifdef USE_STATIC_IDS
        while ((c = getopt (argc, argv, "n:r:")) != -1)
#else
        while ((c = getopt (argc, argv, "r:")) != -1)
#endif
                switch (c) {
#ifdef USE_STATIC_IDS
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
                if (/*(mutex) && */(rte_atomic16_read(flag_p) ==1)) {
                        rte_atomic16_set(flag_p, 0);
                        
                        #ifdef USE_SEMAPHORE
                        sem_post(mutex);
                        #endif
                }
                #endif
        }
        /* TODO: Main thread for INTERRUPT_SEM case: Must additionally relinquish SEM, SHM */
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
        #if (defined(ENABLE_NF_BACKPRESSURE) && defined(NF_BACKPRESSURE_APPROACH_3)) || defined(DUMMY_FT_LOAD_ONLY)
        onvm_flow_dir_nf_init();
        #endif //# defined(ENABLE_NF_BACKPRESSURE) && defined(NF_BACKPRESSURE_APPROACH_3)
}
#endif

