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

                                  onvm_init.c

                  File containing initialization functions.


******************************************************************************/


#include "onvm_mgr/onvm_init.h"


/********************************Global variables*****************************/


struct client *clients = NULL;
struct port_info *ports = NULL;

struct rte_mempool *pktmbuf_pool;
struct rte_mempool *nf_info_pool;

#ifdef ENABLE_NFV_RESL
struct rte_mempool *nf_state_pool;
#ifdef ENABLE_PER_SERVICE_MEMPOOL
struct rte_mempool *service_state_pool;
void **services_state_pool;
#endif //ENABLE_PER_SERVICE_MEMPOOL
#endif //#ifdef ENABLE_NFV_RESL

struct rte_ring *nf_info_queue;
uint16_t **services;
uint16_t *nf_per_service_count;

struct client_tx_stats *clients_stats;
struct onvm_service_chain *default_chain;
struct onvm_service_chain **default_sc_p;

#if defined (INTERRUPT_SEM) && defined (USE_SOCKET)
int onvm_socket_id;
#endif

#if defined (INTERRUPT_SEM) && defined (USE_ZMQ)
void *zmq_ctx;
void *onvm_socket_id;
void *onvm_socket_ctx;
#endif
/*********************************Prototypes**********************************/


static int init_mbuf_pools(void);
static int init_client_info_pool(void);
static int init_port(uint8_t port_num);
static int init_shm_rings(void);
static int init_info_queue(void);
static void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask);


#ifdef ENABLE_NFV_RESL
#ifdef ENABLE_NF_MGR_IDENTIFIER
#include <unistd.h>
uint32_t nf_mgr_id;
static uint32_t read_onvm_mgr_id_from_system(void);
#endif // ENABLE_NF_MGR_IDENTIFIER
static int init_nf_state_pool(void);
#ifdef ENABLE_PER_SERVICE_MEMPOOL
static int init_service_state_pool(void);
#endif //ENABLE_PER_SERVICE_MEMPOOL
#endif // ENABLE_NFV_RESL
/*********************************Interfaces**********************************/


int
init(int argc, char *argv[]) {
        int retval;
        const struct rte_memzone *mz;
        const struct rte_memzone *mz_scp;
        uint8_t i, total_ports;

        /* init EAL, parsing EAL args */
        retval = rte_eal_init(argc, argv);
        if (retval < 0)
                return -1;
        argc -= retval;
        argv += retval;

        /* get total number of ports */
        total_ports = rte_eth_dev_count();

        /* set up array for client tx data */
        mz = rte_memzone_reserve(MZ_CLIENT_INFO, sizeof(*clients_stats),
                                rte_socket_id(), NO_FLAGS);
        if (mz == NULL)
                rte_exit(EXIT_FAILURE, "Cannot reserve memory zone for client information\n");
        memset(mz->addr, 0, sizeof(*clients_stats));
        clients_stats = mz->addr;

        /* set up ports info */
        ports = rte_malloc(MZ_PORT_INFO, sizeof(*ports), 0);
        if (ports == NULL)
                rte_exit(EXIT_FAILURE, "Cannot allocate memory for ports details\n");

        /* parse additional, application arguments */
        retval = parse_app_args(total_ports, argc, argv);
        if (retval != 0)
                return -1;

        /* initialise mbuf pools */
        retval = init_mbuf_pools();
        if (retval != 0)
                rte_exit(EXIT_FAILURE, "Cannot create needed mbuf pools\n");

        /* initialise client info pool */
        retval = init_client_info_pool();
        if (retval != 0) {
                rte_exit(EXIT_FAILURE, "Cannot create client info mbuf pool: %s\n", rte_strerror(rte_errno));
        }

        /* now initialise the ports we will use */
        for (i = 0; i < ports->num_ports; i++) {
                retval = init_port(ports->id[i]);
                if (retval != 0)
                        rte_exit(EXIT_FAILURE, "Cannot initialise port %u\n",
                                        (unsigned)i);
        }

        check_all_ports_link_status(ports->num_ports, (~0x0));

        /* initialise the client queues/rings for inter-eu comms */
        init_shm_rings();

        /* initialise a queue for newly created NFs */
        init_info_queue();

        /*initialize a default service chain*/
        default_chain = onvm_sc_create();
#ifdef ONVM_ENABLE_SPEACILA_NF
        retval = onvm_sc_append_entry(default_chain, ONVM_NF_ACTION_TO_NF_INSTANCE, 0); //0= INSTANCE ID of SPECIAL_NF
        //retval = onvm_sc_append_entry(default_chain, ONVM_NF_ACTION_TONF, 0);   //0 = SERVICE ID of SPECIAL NF
        //retval = onvm_sc_append_entry(default_chain, ONVM_NF_ACTION_TONF, 1); //default: send to any NF with service ID=1
#else
        retval = onvm_sc_append_entry(default_chain, ONVM_NF_ACTION_TONF, 1);
#endif
        if (retval == ENOSPC) {
                printf("chain length can not be larger than the maximum chain length\n");
                exit(5);
        }
        printf("Default service chain: send to sdn NF\n");        
        
        /* set up service chain pointer shared to NFs*/
        mz_scp = rte_memzone_reserve(MZ_SCP_INFO, sizeof(struct onvm_service_chain *),
                                   rte_socket_id(), NO_FLAGS);
        if (mz_scp == NULL)
                rte_exit(EXIT_FAILURE, "Cannot reserve memory zone for service chain pointer\n");
        memset(mz_scp->addr, 0, sizeof(struct onvm_service_chain *));
        default_sc_p = mz_scp->addr;
        *default_sc_p = default_chain;
        onvm_sc_print(default_chain);

        onvm_flow_dir_init();

#if defined(ENABLE_USE_RTE_TIMER_MODE_FOR_MAIN_THREAD) || defined(ENABLE_USE_RTE_TIMER_MODE_FOR_WAKE_THREAD)
        rte_timer_subsystem_init();
#endif //ENABLE_USE_RTE_TIMER_MODE_FOR_MAIN_THREAD

#ifdef ENABLE_NFV_RESL
#ifdef ENABLE_NF_MGR_IDENTIFIER
        uint32_t my_id = read_onvm_mgr_id_from_system();
        printf("Read the ONVM_MGR Identifier as: [%d (0x%x)] \n", my_id,my_id);
#endif // ENABLE_NF_MGR_IDENTIFIER
#endif // ENABLE_NFV_RESL

        return 0;
}

/*****************************Internal functions******************************/


/**
 * Initialise the mbuf pool for packet reception for the NIC, and any other
 * buffer pools needed by the app - currently none.
 */
static int
init_mbuf_pools(void) {
        const unsigned num_mbufs = (MAX_CLIENTS * MBUFS_PER_CLIENT) \
                        + (ports->num_ports * MBUFS_PER_PORT);

        /* don't pass single-producer/single-consumer flags to mbuf create as it
         * seems faster to use a cache instead */
        printf("Creating mbuf pool '%s' [%u mbufs] ...\n",
                        PKTMBUF_POOL_NAME, num_mbufs);
        pktmbuf_pool = rte_mempool_create(PKTMBUF_POOL_NAME, num_mbufs,
                        MBUF_SIZE, MBUF_CACHE_SIZE,
                        sizeof(struct rte_pktmbuf_pool_private), rte_pktmbuf_pool_init,
                        NULL, rte_pktmbuf_init, NULL, rte_socket_id(), NO_FLAGS);

        return (pktmbuf_pool == NULL); /* 0  on success */
}

#ifdef ENABLE_NFV_RESL
static int init_nf_state_pool(void) {
        //printf("Cache size:[%d,max:%d], Creating mbuf pool '%s' ...\n", _NF_STATE_CACHE, RTE_MEMPOOL_CACHE_MAX_SIZE, _NF_MEMPOOL_NAME);
        //setting Cache size parameter seems to have inconsistent behavior; it is better to allocate first with cached; and on failure change to 0 cache size;
        nf_state_pool = rte_mempool_create(_NF_STATE_MEMPOOL_NAME, MAX_CLIENTS,
                        _NF_STATE_SIZE, _NF_STATE_CACHE,
                        0, NULL, NULL, NULL, NULL, rte_socket_id(), NO_FLAGS);

        if(NULL == nf_state_pool) {
                printf("Failed to Create mbuf NF state pool '%s' with cache size...\n", _NF_STATE_MEMPOOL_NAME);
                nf_state_pool = rte_mempool_create(_NF_STATE_MEMPOOL_NAME, MAX_CLIENTS,
                        _NF_STATE_SIZE, 0,
                        0, NULL, NULL, NULL, NULL, rte_socket_id(), NO_FLAGS);
        }

        if(nf_state_pool == NULL) { printf("Failed to Create mbuf state pool '%s' without cache size!...\n", _NF_STATE_MEMPOOL_NAME);}
        return (nf_state_pool == NULL); /* 0 on success */
}
#ifdef ENABLE_PER_SERVICE_MEMPOOL
static int init_service_state_pool(void) {
        service_state_pool = rte_mempool_create(_SERVICE_STATE_MEMPOOL_NAME, MAX_SERVICES,
                        _SERVICE_STATE_SIZE, _SERVICE_STATE_CACHE,
                        0, NULL, NULL, NULL, NULL, rte_socket_id(), NO_FLAGS);

        if(NULL == service_state_pool) {
                printf("Failed to Create mbuf service state pool '%s' with cache size...\n", _SERVICE_STATE_MEMPOOL_NAME);
                nf_state_pool = rte_mempool_create(_SERVICE_STATE_MEMPOOL_NAME, MAX_SERVICES,
                        _SERVICE_STATE_SIZE, 0,
                        0, NULL, NULL, NULL, NULL, rte_socket_id(), NO_FLAGS);
        }

        if(service_state_pool == NULL) { printf("Failed to Create mbuf Service state pool '%s' without cache size!...\n", _SERVICE_STATE_MEMPOOL_NAME);}
        return (service_state_pool == NULL); /* 0 on success */
}
#endif
#endif
/**
 * Set up a mempool to store nf_info structs
 */
static int
init_client_info_pool(void)
{
        /* don't pass single-producer/single-consumer flags to mbuf
         * create as it seems faster to use a cache instead */
        printf("Creating mbuf pool '%s' ...\n", _NF_MEMPOOL_NAME);

        //setting Cache size parameter seems to have inconsistent behavior; it is better to allocate first with cached; and on failure change to 0 cache size;
        nf_info_pool = rte_mempool_create(_NF_MEMPOOL_NAME, MAX_CLIENTS,
                        NF_INFO_SIZE, NF_INFO_CACHE,
                        0, NULL, NULL, NULL, NULL, rte_socket_id(), NO_FLAGS);

        if(NULL == nf_info_pool) {
                printf("Failed to Create mbuf state pool '%s' with cache size...\n", _NF_MEMPOOL_NAME);
                nf_info_pool = rte_mempool_create(_NF_MEMPOOL_NAME, MAX_CLIENTS,
                                NF_INFO_SIZE, 0,
                                0, NULL, NULL, NULL, NULL, rte_socket_id(), NO_FLAGS);
        }
#ifdef ENABLE_NFV_RESL
        if(init_nf_state_pool()) {
               rte_exit(EXIT_FAILURE, "Cannot create client state mbuf pool: %s\n", rte_strerror(rte_errno));
        }
#ifdef ENABLE_PER_SERVICE_MEMPOOL
        if(init_service_state_pool()) {
               rte_exit(EXIT_FAILURE, "Cannot create service state mbuf pool: %s\n", rte_strerror(rte_errno));
        }
#endif  //ENABLE_PER_SERVICE_MEMPOOL
#endif  //ENABLE_NFV_RESL

        return (nf_info_pool == NULL); /* 0 on success */
}

/**
 * Initialise an individual port:
 * - configure number of rx and tx rings
 * - set up each rx ring, to pull from the main mbuf pool
 * - set up each tx ring
 * - start the port and report its status to stdout
 */
static int
init_port(uint8_t port_num) {
        /* for port configuration all features are off by default */
        const struct rte_eth_conf port_conf = {
                .rxmode = {
                        .mq_mode = ETH_MQ_RX_RSS
                },
                .rx_adv_conf = {
                        .rss_conf = {
                                .rss_key = rss_symmetric_key,
                                .rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP,
                        }
                },
        };

        const uint16_t rx_rings = ONVM_NUM_RX_THREADS, tx_rings = MAX_CLIENTS;
        const uint16_t rx_ring_size = RTE_MP_RX_DESC_DEFAULT;
        const uint16_t tx_ring_size = RTE_MP_TX_DESC_DEFAULT;

        uint16_t q;
        int retval;

        printf("Port %u init ... \n", (unsigned)port_num);
        printf("Port %u socket id %u ... \n", (unsigned)port_num, (unsigned)rte_eth_dev_socket_id(port_num));
        printf("Port %u Rx rings %u ... \n", (unsigned)port_num, (unsigned)rx_rings);
        fflush(stdout);

        /* Standard DPDK port initialisation - config port, then set up
         * rx and tx rings */
        if ((retval = rte_eth_dev_configure(port_num, rx_rings, tx_rings,
                &port_conf)) != 0)
                return retval;

        for (q = 0; q < rx_rings; q++) {
                retval = rte_eth_rx_queue_setup(port_num, q, rx_ring_size,
                                rte_eth_dev_socket_id(port_num),
                                NULL, pktmbuf_pool);
                if (retval < 0) return retval;
        }

        for (q = 0; q < tx_rings; q++) {
                retval = rte_eth_tx_queue_setup(port_num, q, tx_ring_size,
                                rte_eth_dev_socket_id(port_num),
                                NULL);
                if (retval < 0) return retval;
        }

        rte_eth_promiscuous_enable(port_num);

        retval  = rte_eth_dev_start(port_num);
        if (retval < 0) return retval;

        printf("done: \n");

        return 0;
}

/**
 * Set up the DPDK rings which will be used to pass packets, via
 * pointers, between the multi-process server and client processes.
 * Each client needs one RX queue.
 */
static int
init_shm_rings(void) {
        unsigned i;
        unsigned socket_id;
        const char * rq_name;
        const char * tq_name;
        const unsigned ringsize = CLIENT_QUEUE_RINGSIZE;

        #ifdef INTERRUPT_SEM
        const char * sem_name;
        key_t key;
        int shmid;
        char *shm;

        #ifdef USE_SEMAPHORE
        sem_t *mutex;
        #endif
        #endif
        
#if defined(ENABLE_NFV_RESL) && defined(ENABLE_SHADOW_RINGS)
        const char * rsq_name;
        const char * tsq_name;
        const unsigned sringsize = CLIENT_SHADOW_RING_SIZE;
#endif

        // use calloc since we allocate for all possible clients
        // ensure that all fields are init to 0 to avoid reading garbage
        // TODO plopreiato, move to creation when a NF starts
        clients = rte_calloc("client details",
                MAX_CLIENTS, sizeof(*clients), 0);
        if (clients == NULL)
                rte_exit(EXIT_FAILURE, "Cannot allocate memory for client program details\n");

        services = rte_calloc("service to nf map",
                num_services, sizeof(uint16_t*), 0);
        nf_per_service_count = rte_calloc("count of NFs active per service",
                num_services, sizeof(uint16_t), 0);
        if (services == NULL || nf_per_service_count == NULL)
                rte_exit(EXIT_FAILURE, "Cannot allocate memory for service to NF mapping\n");
        for (i = 0; i < num_services; i++) {
                services[i] = rte_calloc("one service NFs",
                        MAX_CLIENTS_PER_SERVICE, sizeof(uint16_t), 0);
        }
        for (i = 0; i < MAX_CLIENTS; i++) {
                /* Create an RX queue for each client */
                socket_id = rte_socket_id();
                rq_name = get_rx_queue_name(i);
                tq_name = get_tx_queue_name(i);
                clients[i].instance_id = i;

#ifdef ENABLE_NFV_RESL
                if(i < MAX_ACTIVE_CLIENTS) { //if(is_primary_active_nf_id(i)) {
                        clients[i].rx_q = rte_ring_create(rq_name,
                                        ringsize, socket_id,
                                        RING_F_SC_DEQ);                 /* multi prod, single cons (Enqueue can be by either Rx/Tx Threads, but dequeue only by NF thread)*/
                        clients[i].tx_q = rte_ring_create(tq_name,
                                        ringsize, socket_id,
                                        RING_F_SP_ENQ|RING_F_SC_DEQ);      /* single prod, single cons (Enqueue only by NF Thread, and dequeue only by dedicated Tx thread) */
                        if(rte_mempool_get(nf_state_pool,&clients[i].nf_state_mempool) < 0) {
                                rte_exit(EXIT_FAILURE, "Failed to get client state memory");;
                        }
#ifdef ENABLE_SHADOW_RINGS
                        rsq_name = get_rx_squeue_name(i);
                        tsq_name = get_tx_squeue_name(i);
                        clients[i].rx_sq = rte_ring_create(rsq_name,
                                        sringsize, socket_id,
                                        RING_F_SP_ENQ|RING_F_SC_DEQ);                 /* single prod, single cons (Enqueue only by NF Thread, and dequeue only by NF thread)*/
                        clients[i].tx_sq = rte_ring_create(tsq_name,
                                        sringsize, socket_id,
                                        RING_F_SP_ENQ|RING_F_SC_DEQ);      /* single prod, single cons (Enqueue only by NF Thread, and dequeue only by dedicated Tx thread) */
#endif
                } else {
                        clients[i].rx_q = clients[get_associated_active_or_standby_nf_id(i)].rx_q;
                        clients[i].tx_q = clients[get_associated_active_or_standby_nf_id(i)].tx_q;
                        clients[i].nf_state_mempool = clients[get_associated_active_or_standby_nf_id(i)].nf_state_mempool;
                        fprintf(stderr, "re-using rx and tx queue rings for client %d with %d\n", i, get_associated_active_or_standby_nf_id(i));
#ifdef ENABLE_SHADOW_RINGS
                        clients[i].rx_sq = clients[get_associated_active_or_standby_nf_id(i)].rx_sq;
                        clients[i].tx_sq = clients[get_associated_active_or_standby_nf_id(i)].tx_sq;
#endif
                }
#else
                clients[i].rx_q = rte_ring_create(rq_name,
                                ringsize, socket_id,
                                //RING_F_SP_ENQ|RING_F_SC_DEQ);     /* single prod, single cons */
                                RING_F_SC_DEQ);                 /* multi prod, single cons (Enqueue can be by either Rx/Tx Threads, but dequeue only by NF thread)*/
                clients[i].tx_q = rte_ring_create(tq_name,
                                ringsize, socket_id,
                                RING_F_SP_ENQ|RING_F_SC_DEQ);      /* single prod, single cons (Enqueue only by NF Thread, and dequeue only by dedicated Tx thread) */
                                //RING_F_SC_DEQ);                 /* multi prod, single cons */
                                //but it should be RING_F_SP_ENQ

#endif
                if (clients[i].rx_q == NULL)
                        rte_exit(EXIT_FAILURE, "Cannot create rx ring queue for client %u\n", i);

                if (clients[i].tx_q == NULL)
                        rte_exit(EXIT_FAILURE, "Cannot create tx ring queue for client %u\n", i);


                #ifdef ENABLE_RING_WATERMARK
                rte_ring_set_water_mark(clients[i].rx_q, CLIENT_QUEUE_RING_WATER_MARK_SIZE);
                //rte_ring_set_water_mark(clients[i].tx_q, CLIENT_QUEUE_RING_WATER_MARK_SIZE);
                #endif

                #ifdef INTERRUPT_SEM
                sem_name = get_sem_name(i);
                clients[i].sem_name = sem_name;
                //fprintf(stderr, "sem_name=%s for client %d\n", sem_name, i);

                #ifdef USE_SEMAPHORE                
                mutex = sem_open(sem_name, O_CREAT, 06666, 0);
                if(mutex == SEM_FAILED) {
                        fprintf(stderr, "can not create semaphore for client %d\n", i);
                        sem_unlink(sem_name);
                        exit(1);
                }
                clients[i].mutex = mutex;
                #endif

                key = get_rx_shmkey(i);       
                if ((shmid = shmget(key, SHMSZ, IPC_CREAT | 0666)) < 0) {
                        fprintf(stderr, "can not create the shared memory segment for client %d\n", i);
                        exit(1);
                }
                
                if ((shm = shmat(shmid, NULL, 0)) == (char *) -1) {
                        fprintf(stderr, "can not attach the shared segment to the server space for client %d\n", i);
                               exit(1);
                    }

                clients[i].shm_server = (rte_atomic16_t *)shm;
                rte_atomic16_set(clients[i].shm_server, 0);
                #endif

                //#if defined (ENABLE_NF_BACKPRESSURE) && defined (NF_BACKPRESSURE_APPROACH_1)
                #ifdef ENABLE_NF_BACKPRESSURE
                memset(&clients[i].bft_list, 0, sizeof(clients[i].bft_list));
                clients[i].bft_list.max_len=CLIENT_QUEUE_RINGSIZE*2;
                #endif
        }
#if defined(ENABLE_NFV_RESL) && defined (ENABLE_PER_SERVICE_MEMPOOL)
        services_state_pool = rte_calloc("services_state_pool", num_services, sizeof(struct rte_mempool*), 0);
        if (services_state_pool == NULL)
                rte_exit(EXIT_FAILURE, "Cannot allocate memory for services_state_pool details\n");
        for(i=0; i< num_services; i++) {
                if(rte_mempool_get(service_state_pool,&services_state_pool[i]) < 0) {
                        rte_exit(EXIT_FAILURE, "Failed to get service state memory from service_state_pool");;
                }
        }
#endif
        return 0;
}

/**
 * Allocate a rte_ring for newly created NFs
 */
static int
init_info_queue(void)
{
        nf_info_queue = rte_ring_create(
                _NF_QUEUE_NAME,
                MAX_CLIENTS,
                rte_socket_id(),
                RING_F_SC_DEQ); // MP enqueue (default), SC dequeue

        if (nf_info_queue == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create nf info queue\n");

        return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask) {
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
        uint8_t portid, count, all_ports_up, print_flag = 0;
        struct rte_eth_link link;

        printf("\nChecking link status");
        fflush(stdout);
        for (count = 0; count <= MAX_CHECK_TIME; count++) {
                all_ports_up = 1;
                for (portid = 0; portid < port_num; portid++) {
                        if ((port_mask & (1 << ports->id[portid])) == 0)
                                continue;
                        memset(&link, 0, sizeof(link));
                        rte_eth_link_get_nowait(ports->id[portid], &link);
                        /* print link status if flag set */
                        if (print_flag == 1) {
                                if (link.link_status)
                                        printf("Port %d Link Up - speed %u "
                                                "Mbps - %s\n", ports->id[portid],
                                                (unsigned)link.link_speed,
                                (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                                        ("full-duplex") : ("half-duplex\n"));
                                else
                                        printf("Port %d Link Down\n",
                                                (uint8_t)ports->id[portid]);
                                continue;
                        }
                        /* clear all_ports_up flag if any link down */
                        if (link.link_status == 0) {
                                all_ports_up = 0;
                                break;
                        }
                }
                /* after finally printing all link status, get out */
                if (print_flag == 1)
                        break;

                if (all_ports_up == 0) {
                        printf(".");
                        fflush(stdout);
                        rte_delay_ms(CHECK_INTERVAL);
                }

                /* set the print_flag if all ports up or timeout */
                if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
                        print_flag = 1;
                        printf("done\n");
                }
        }
}

/**
 * Main init function for the multi-process server app,
 * calls subfunctions to do each stage of the initialisation.
 */


#ifdef ENABLE_NFV_RESL
#ifdef ENABLE_NF_MGR_IDENTIFIER
static uint32_t read_onvm_mgr_id_from_system(void) {
        nf_mgr_id = gethostid();
        return nf_mgr_id;
}
#endif // ENABLE_NF_MGR_IDENTIFIER
#endif // ENABLE_NFV_RESL
