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
                                   main.c

     File containing the main function of the manager and all its worker
     threads.

******************************************************************************/


#include "onvm_mgr.h"
#include "onvm_stats.h"
#include "onvm_pkt.h"
#include "onvm_nf.h"
#include "onvm_wakemgr.h"
#include "onvm_special_nf0.h"


#ifdef ENABLE_BFD
#include "onvm_bfd.h"
#endif

#ifdef TEST_INLINE_FUNCTION_CALL
int process_nf_function_inline(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta);
int process_nf_function_inline(__attribute__((unused)) struct rte_mbuf* pkt, __attribute__((unused)) struct onvm_pkt_meta* meta) {
        return 0;
}
nf_pkt_handler nf_process_packet = process_nf_function_inline;
#endif

#ifdef ENABLE_ZOOKEEPER
#include "onvm_zookeeper.h"
#include "onvm_zk_common.h"
#else
uint8_t remote_eth_addr[6];
struct ether_addr remote_eth_addr_struct;
#endif

typedef struct thread_core_map_t {
        unsigned rx_th_core[ONVM_NUM_RX_THREADS];
        unsigned tx_t_core[8];
#ifdef INTERRUPT_SEM
        unsigned wk_th_core[ONVM_NUM_WAKEUP_THREADS];
#endif
        unsigned mn_th_core;
}thread_core_map_t;
static thread_core_map_t thread_core_map;

#ifdef ENABLE_USE_RTE_TIMER_MODE_FOR_MAIN_THREAD

#define NF_STATUS_CHECK_PERIOD_IN_MS    (500)       // (500) 500ms or 0.5seconds
#define NF_STATUS_CHECK_PERIOD_IN_US    (100)       // use high precision 100us to ensure that we do it quickly to recover/restore
#define DISPLAY_STATS_PERIOD_IN_MS      (1000)      // 1000ms or Every second
#define NF_LOAD_EVAL_PERIOD_IN_MS       (1)         // 1ms
#define USLEEP_INTERVAL_IN_US           (50)        // 50 micro seconds (even if set to 50, best precision >100micro)
//#define ARBITER_PERIOD_IN_US            (100)       // 250 micro seconds or 100 micro seconds
//Note: Running arbiter at 100micro to 250 micro seconds is fine provided we have the buffers available as:
//RTT (measured with bridge and 1 basic NF) =0.2ms B=10Gbps => B*delay ( 2*RTT*Bw) = 2*200*10^-6 * 10*10^9 = 4Mb = 0.5MB
//Assuming avg pkt size of 1000 bytes => 500 *10^3/1000 = 500 packets. (~512 packets)
//For smaller pkt size of 64 bytes => 500*10^3/64 = 7812 packets. (~8K packets)

struct rte_timer display_stats_timer;   //Timer to periodically Display the statistics  (1 second)
struct rte_timer nf_status_check_timer; //Timer to periodically check new NFs registered or old NFs de-registerd   (0.5 second)
struct rte_timer nf_load_eval_timer;    //Timer to periodically evaluate the NF Load characteristics    (1ms)
struct rte_timer main_arbiter_timer;    //Timer to periodically run the Arbiter   (100us to at-most 250 micro seconds)

int initialize_rx_timers(int index, void *data);
int initialize_tx_timers(int index, void *data);
int initialize_master_timers(void);

static void display_stats_timer_cb(__attribute__((unused)) struct rte_timer *ptr_timer,
        __attribute__((unused)) void *ptr_data);
static void nf_status_check_timer_cb(__attribute__((unused)) struct rte_timer *ptr_timer,
        __attribute__((unused)) void *ptr_data);
static void nf_load_stats_timer_cb(__attribute__((unused)) struct rte_timer *ptr_timer,
        __attribute__((unused)) void *ptr_data);
static void arbiter_timer_cb(__attribute__((unused)) struct rte_timer *ptr_timer,
        __attribute__((unused)) void *ptr_data);

static void
display_stats_timer_cb(__attribute__((unused)) struct rte_timer *ptr_timer,
        __attribute__((unused)) void *ptr_data) {

        static const unsigned diff_time_sec = (unsigned) (DISPLAY_STATS_PERIOD_IN_MS/1000);
        onvm_stats_display_all(diff_time_sec);
        return;
}

static void
nf_status_check_timer_cb(__attribute__((unused)) struct rte_timer *ptr_timer,
        __attribute__((unused)) void *ptr_data) {

        onvm_nf_check_status();
        return;
}

static void
nf_load_stats_timer_cb(__attribute__((unused)) struct rte_timer *ptr_timer,
        __attribute__((unused)) void *ptr_data) {
        static nf_stats_time_info_t nf_stat_time;
        if(nf_stat_time.in_read == 0) {
                if( onvm_util_get_cur_time(&nf_stat_time.prev_time) == 0) {
                        nf_stat_time.in_read = 1;
                }
                return ;
        }

        if(0 == onvm_util_get_cur_time(&nf_stat_time.cur_time)) {
                unsigned long difftime_us = onvm_util_get_difftime_us(&nf_stat_time.prev_time, &nf_stat_time.cur_time);
                if(difftime_us) {
                        onvm_nf_stats_update(difftime_us);
                }
                nf_stat_time.prev_time = nf_stat_time.cur_time;
        }
        return;
}

static void
arbiter_timer_cb(__attribute__((unused)) struct rte_timer *ptr_timer,
        __attribute__((unused)) void *ptr_data) {
#ifdef INTERRUPT_SEM
        check_and_enqueue_or_dequeue_nfs_from_bottleneck_watch_list();  // this sets time bound of arbiter timer interval
        compute_and_order_nf_wake_priority();
        handle_wakeup(NULL);

#endif
        //printf("\n Inside arbiter_timer_cb() %"PRIu64", on core [%d] \n", rte_rdtsc_precise(), rte_lcore_id());
        return;
}

int
initialize_master_timers(void) {

        rte_timer_init(&nf_status_check_timer);
        rte_timer_init(&display_stats_timer);
        rte_timer_init(&nf_load_eval_timer);
        rte_timer_init(&main_arbiter_timer);

        uint64_t ticks = 0;

        //ticks = ((uint64_t)NF_STATUS_CHECK_PERIOD_IN_MS *(rte_get_timer_hz()/1000));
        ticks = ((uint64_t)NF_STATUS_CHECK_PERIOD_IN_US *(rte_get_timer_hz()/1000000));
        rte_timer_reset_sync(&nf_status_check_timer,
                ticks,
                PERIODICAL,
                rte_lcore_id(), //timer_core
                &nf_status_check_timer_cb, NULL
                );

        ticks = ((uint64_t)DISPLAY_STATS_PERIOD_IN_MS *(rte_get_timer_hz()/1000));
        rte_timer_reset_sync(&display_stats_timer,
                ticks,
                PERIODICAL,
                rte_lcore_id(), //timer_core
                &display_stats_timer_cb, NULL
                );

        ticks = ((uint64_t)NF_LOAD_EVAL_PERIOD_IN_MS *(rte_get_timer_hz()/1000));
        rte_timer_reset_sync(&nf_load_eval_timer,
                ticks,
                PERIODICAL,
                rte_lcore_id(), //timer_core
                &nf_load_stats_timer_cb, NULL
                );

        if( 0 == ONVM_NUM_WAKEUP_THREADS) {
                ticks = ((uint64_t)ARBITER_PERIOD_IN_US *(rte_get_timer_hz()/1000000));
                rte_timer_reset_sync(&main_arbiter_timer,
                        ticks,
                        PERIODICAL,
                        rte_lcore_id(),
                        &arbiter_timer_cb, NULL
                        );
                //Note: This call effectively nullifies the timer
                //rte_timer_init(&main_arbiter_timer);
        }
        return 0;
}
#endif //ENABLE_USE_RTE_TIMER_MODE_FOR_MAIN_THREAD
/*******************************Worker threads********************************/

/*
 * Stats thread periodically prints per-port and per-NF stats.
 */
static void
master_thread_main(void) {
        const unsigned sleeptime = 1;

        RTE_LOG(INFO, APP, "Core %d: Running master thread\n", rte_lcore_id());

#ifdef ONVM_ENABLE_SPEACILA_NF
        start_special_nf0();
#endif

        /* Longer initial pause so above printf is seen */
        sleep(sleeptime * 3);

#ifdef ENABLE_USE_RTE_TIMER_MODE_FOR_MAIN_THREAD
        if(initialize_master_timers() == 0) {
                struct timespec req = {0,1000}, res = {0,0};
                while (nanosleep(&req, &res) == 0) { //while (usleep(USLEEP_INTERVAL_IN_US) == 0) { // while(1) {
                        rte_timer_manage();
#ifdef ONVM_ENABLE_SPEACILA_NF
                        (void)process_special_nf0_rx_packets();
#endif
                }
        } //else
#else

        /* Loop forever: sleep always returns 0 or <= param */
        while (sleep(sleeptime) <= sleeptime) {
                onvm_nf_check_status();
                onvm_stats_display_all(sleeptime);
        }
#endif //ENABLE_USE_RTE_TIMER_MODE_FOR_MAIN_THREAD
}

/*
 * Function to receive packets from the NIC
 * and distribute them to the default service
 */
static int
rx_thread_main(void *arg) {
        uint16_t i, rx_count;
        struct rte_mbuf *pkts[PACKET_READ_SIZE];
        struct thread_info *rx = (struct thread_info*)arg;

        RTE_LOG(INFO,
                APP,
                "Core %d: Running RX thread for RX queue %d\n",
                rte_lcore_id(),
                rx->queue_id);

        for (;;) {
                /* Read ports */
                for (i = 0; i < ports->num_ports; i++) {
                        rx_count = rte_eth_rx_burst(ports->id[i], rx->queue_id, \
                                        pkts, PACKET_READ_SIZE);

                        /* Now process the NIC packets read */
                        if (likely(rx_count > 0)) {
                                ports->rx_stats.rx[ports->id[i]] += rx_count;
                                // If there is no running NF, we drop all the packets of the batch.
                                if (likely(num_clients)) {
                                        onvm_pkt_process_rx_batch(rx, pkts, rx_count);
                                } else {
                                        (void)onv_pkt_send_to_special_nf0(rx, pkts, rx_count);
                                }
                        }
                }
        }
        return 0;
}

#define PACKET_READ_SIZE_TX ((uint16_t)(PACKET_READ_SIZE*4))
static int
tx_thread_main(void *arg) {
        struct client *cl;
        unsigned i, tx_count;
        struct rte_mbuf *pkts[PACKET_READ_SIZE];
        struct thread_info* tx = (struct thread_info*)arg;

        RTE_LOG(INFO,
               APP,
               "Core %d: Running TX thread for NFs %d to %d\n",
               rte_lcore_id(),
               tx->first_cl,
               tx->last_cl-1);

        for (;;) {
                /* Read packets from the client's tx queue and process them as needed */
                for (i = tx->first_cl; i < tx->last_cl; i++) {
                        cl = &clients[i];
                        if ((!onvm_nf_is_valid(cl))||(onvm_nf_is_paused(cl)))
                                continue;
#ifdef ENABLE_NFV_RESL
#if 0
                        if(unlikely(onvm_nf_is_valid(&clients[get_associated_active_or_standby_nf_id(i)]) )) {
                                /* When NF(i) is Primary but Secondary is also active: Then Do not process packets in primary until secondary is stopped; Later only Primary must process */
                                if((is_primary_active_nf_id(i))) {
                                        if(rte_atomic16_read(clients[get_associated_active_or_standby_nf_id(i)].shm_server)== 0)  {
                                                continue;
                                        }
                                }
                                /* When NF(i) is Secondary but Primary is also active: Then Do not process packets from Secondary; only Primary must process */
                                else { //if((!is_primary_active_nf_id(i))) {
                                        continue;
                                }
                        }
#endif
#endif
                        /* try dequeuing max possible packets first, if that fails, get the
                         * most we can. Loop body should only execute once, maximum
                        while (tx_count > 0 &&
                                unlikely(rte_ring_dequeue_bulk(cl->tx_q, (void **) pkts, tx_count) != 0)) {
                                tx_count = (uint16_t)RTE_MIN(rte_ring_count(cl->tx_q),
                                                PACKET_READ_SIZE);
                        }
                        */
                        tx_count = rte_ring_dequeue_burst(cl->tx_q, (void **) pkts, PACKET_READ_SIZE);

                        /* Now process the Client packets read */
                        if (likely(tx_count > 0)) {

                                #ifdef ENABLE_NF_BACKPRESSURE
                                #ifdef USE_BKPR_V2_IN_TIMER_MODE
                                onvm_check_and_reset_back_pressure_v2(pkts, tx_count, cl);
                                #else
                                onvm_check_and_reset_back_pressure(pkts, tx_count, cl);
                                #endif //USE_BKPR_V2_IN_TIMER_MODE
                                #endif // ENABLE_NF_BACKPRESSURE

                                onvm_pkt_process_tx_batch(tx, pkts, tx_count, cl);
                                //RTE_LOG(INFO,APP,"Core %d: processing %d TX packets for NF: %d \n", rte_lcore_id(),tx_count, i);
                        }
                        else continue;
                }

                /* Send a burst to every port */
                onvm_pkt_flush_all_ports(tx);

                /* Send a burst to every NF */
                onvm_pkt_flush_all_nfs(tx);
        }

        return 0;
}


/*******************************Main function*********************************/
int
main(int argc, char *argv[]) {
        unsigned cur_lcore, rx_lcores, tx_lcores;
        unsigned clients_per_tx, temp_num_clients;
        unsigned i;

        /* initialise the system */
        #ifdef INTERRUPT_SEM
        unsigned wakeup_lcores;        
        register_signal_handler();
        #endif        

        /* Reserve ID 0 for internal manager things */
        next_instance_id = 1;
        if (init(argc, argv) < 0 )
                return -1;
        RTE_LOG(INFO, APP, "Finished Process Init.\n");

        /* clear statistics */
        onvm_stats_clear_all_clients();

        /* Reserve n cores for: 1 main thread, ONVM_NUM_RX_THREADS for Rx, ONVM_NUM_WAKEUP_THREADS for wakeup and remaining for Tx */
        cur_lcore = rte_lcore_id();
        rx_lcores = ONVM_NUM_RX_THREADS;

        tx_lcores = rte_lcore_count() - rx_lcores - 1;
        #ifdef INTERRUPT_SEM
        wakeup_lcores = ONVM_NUM_WAKEUP_THREADS;
        tx_lcores -= wakeup_lcores; //tx_lcores= (tx_lcores>2)?(2):(tx_lcores);
        #endif

        /* Offset cur_lcore to start assigning TX cores */
        cur_lcore += (rx_lcores-1);

        RTE_LOG(INFO, APP, "%d cores available in total\n", rte_lcore_count());
        RTE_LOG(INFO, APP, "%d cores available for handling manager RX queues\n", rx_lcores);
        RTE_LOG(INFO, APP, "%d cores available for handling TX queues\n", tx_lcores);
        #ifdef INTERRUPT_SEM
        RTE_LOG(INFO, APP, "%d cores available for handling wakeup\n", wakeup_lcores);        
        #endif 
        RTE_LOG(INFO, APP, "%d cores available for handling stats(main)\n", 1);

        /* Evenly assign NFs to TX threads */

        /*
         * If num clients is zero, then we are running in dynamic NF mode.
         * We do not have a way to tell the total number of NFs running so
         * we have to calculate clients_per_tx using MAX_CLIENTS then.
         * We want to distribute the number of running NFs across available
         * TX threads
         */
        if (num_clients == 0) {
                clients_per_tx = ceil((float)MAX_CLIENTS/tx_lcores);
                temp_num_clients = (unsigned)MAX_CLIENTS;
        } else {
                clients_per_tx = ceil((float)num_clients/tx_lcores);
                temp_num_clients = (unsigned)num_clients;
        }

        //num_clients = temp_num_clients;
        for (i = 0; i < tx_lcores; i++) {
                struct thread_info *tx = calloc(1, sizeof(struct thread_info));
                tx->queue_id = i;
                tx->port_tx_buf = calloc(RTE_MAX_ETHPORTS, sizeof(struct packet_buf));
                tx->nf_rx_buf = calloc(MAX_CLIENTS, sizeof(struct packet_buf));

                tx->first_cl = RTE_MIN(i * clients_per_tx, temp_num_clients);       //(inclusive) read from NF[0] to NF[clients_per_tx-1]
                tx->last_cl = RTE_MIN((i+1) * clients_per_tx, temp_num_clients);

                //Dedicate 1 Tx for NF0 and next Tx for all NFs
                //if(i==0) tx->first_cl = 0;tx->last_cl=1;
                //else tx->first_cl = 1;tx->last_cl=temp_num_clients;

                cur_lcore = rte_get_next_lcore(cur_lcore, 1, 1);
                if (rte_eal_remote_launch(tx_thread_main, (void*)tx,  cur_lcore) == -EBUSY) {
                        RTE_LOG(ERR,
                                APP,
                                "Core %d is already busy, can't use for client %d TX\n",
                                cur_lcore,
                                tx->first_cl);
                        return -1;
                }
                thread_core_map.tx_t_core[i]=cur_lcore;
                RTE_LOG(INFO, APP, "Tx thread [%d] on core [%d] cores for [%d:%d]\n", i+1, cur_lcore, tx->first_cl, tx->last_cl);
        }
       
        /* Launch RX thread main function for each RX queue on cores */
        for (i = 0; i < rx_lcores; i++) {
                struct thread_info *rx = calloc(1, sizeof(struct thread_info));
                rx->queue_id = i;
                rx->port_tx_buf = NULL;
                rx->nf_rx_buf = calloc(MAX_CLIENTS, sizeof(struct packet_buf));
                cur_lcore = rte_get_next_lcore(cur_lcore, 1, 1);
                if (rte_eal_remote_launch(rx_thread_main, (void *)rx, cur_lcore) == -EBUSY) {
                        RTE_LOG(ERR,
                                APP,
                                "Core %d is already busy, can't use for RX queue id %d\n",
                                cur_lcore,
                                rx->queue_id);
                        return -1;
                }
                thread_core_map.rx_th_core[i]=cur_lcore;
        }
        
        #ifdef INTERRUPT_SEM
        if(wakeup_lcores) {
                int clients_per_wakethread = ceil(temp_num_clients / wakeup_lcores);
                wakeup_infos = (struct wakeup_info *)calloc(wakeup_lcores, sizeof(struct wakeup_info));
                if (wakeup_infos == NULL) {
                        printf("can not alloc space for wakeup_info\n");
                        exit(1);
                }
                for (i = 0; i < wakeup_lcores; i++) {
                        wakeup_infos[i].first_client = RTE_MIN(i * clients_per_wakethread + 1, temp_num_clients);
                        wakeup_infos[i].last_client = RTE_MIN((i+1) * clients_per_wakethread + 1, temp_num_clients);
                        cur_lcore = rte_get_next_lcore(cur_lcore, 1, 1);

                        thread_core_map.wk_th_core[i]=cur_lcore;
                        //initialize_wake_core_timers(i, (void*)&wakeup_infos); //better to do it inside the registred thread callback function.

                        rte_eal_remote_launch(wakemgr_main, (void*)&wakeup_infos[i], cur_lcore);
                        //printf("wakeup lcore_id=%d, first_client=%d, last_client=%d\n", cur_lcore, wakeup_infos[i].first_client, wakeup_infos[i].last_client);
                        RTE_LOG(INFO, APP, "Core %d: Running wakeup thread, first_client=%d, last_client=%d\n", cur_lcore, wakeup_infos[i].first_client, wakeup_infos[i].last_client);

                }
        }
        #endif

#ifdef ENABLE_BFD
        onvm_bfd_init(nf_mgr_id);
#endif

#ifdef ENABLE_VXLAN
        uint16_t nic_port = DISTRIBUTED_NIC_PORT;
        printf("Distributed Mode: nic_port: %u mac addr: %s\n", ports->id[nic_port],
        onvm_stats_print_MAC(ports->id[nic_port]));
        rte_eth_macaddr_get(nic_port, &ports->mac[nic_port]);
#ifdef ENABLE_ZOOKEEPER
        // Do Zookeeper init
        onvm_zk_connect(ZK_CONNECT_BLOCKING);
        RTE_LOG(INFO, APP, "Connected to ZooKeeper, id %" PRId64 "\n", onvm_zk_client_id());

        const char *port_mac = onvm_stats_print_MAC(ports->id[nic_port]);
        int ret = onvm_zk_init(port_mac);
        if (ret != ZOK) {
                RTE_LOG(ERR, APP, "Error doing zookeeper init, bailing. %s\n", zk_status_to_string(ret));
                return -1;
        }
#else
        printf("Zookeeper is disabled, use static setting\n");
        ether_addr_copy((struct ether_addr *)&remote_eth_addr, &remote_eth_addr_struct);
        onvm_print_ethaddr("remote addr:", &remote_eth_addr_struct);
#endif
#endif


        /* Master thread handles statistics and NF management */
        thread_core_map.mn_th_core=rte_lcore_id();
        master_thread_main();

#ifdef ENABLE_ZOOKEEPER
        onvm_zk_disconnect();
#endif
        return 0;
}

/*******************************Helper functions********************************/



