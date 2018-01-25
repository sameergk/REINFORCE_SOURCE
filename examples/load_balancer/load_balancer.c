/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2017 George Washington University
 *            2015-2017 University of California Riverside
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
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
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
 *  load_balancer.c - an example Layer 3 round-robin load balancer.
 ********************************************************************/

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <assert.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_memory.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "onvm_flow_table.h"
#include "onvm_flow_dir.h"

#define NF_TAG "load_balancer"
#define TABLE_SIZE  SDN_FT_ENTRIES  //65536


/* Struct for backend servers */
typedef struct backend_server {
        uint8_t d_addr_bytes[ETHER_ADDR_LEN];
        uint32_t d_ip;
}backend_server_t;

/* Struct for flow info */
typedef struct flow_info {
        uint8_t dest;
        uint8_t s_addr_bytes[ETHER_ADDR_LEN];
        uint64_t last_pkt_cycles;
        int is_active;
}flow_info_t;

#ifdef ENABLE_NFV_RESL
#define MAX_BACKEND_SERVERS (10)
#define MAX_FILE_NAME_LEN (256)
#define MAX_IFACE_NAME_LEN  (256)
flow_info_t ft[TABLE_SIZE];
/* Struct for load balancer information */
struct loadbalance {
        //flow_info_t ft[TABLE_SIZE];
        flow_info_t *ft;

        /* backend server information */
        uint8_t server_count;
        struct backend_server server[MAX_BACKEND_SERVERS];

        /* for cleaning up connections */
        uint16_t num_stored;
        uint64_t elapsed_cycles;
        uint64_t last_cycles;
        uint32_t expire_time;

        /* port and ip values */
        uint32_t ip_lb_server;
        uint32_t ip_lb_client;
        uint8_t server_port;
        uint8_t client_port;

        /* config file, interface names */
        char cfg_filename[MAX_FILE_NAME_LEN];
        char client_iface_name[MAX_IFACE_NAME_LEN];
        char server_iface_name[MAX_IFACE_NAME_LEN];
};
#else
/* Struct for load balancer information */
struct loadbalance {
        struct onvm_ft *ft;

        /* backend server information */
        uint8_t server_count;
        struct backend_server *server;

        /* for cleaning up connections */
        uint16_t num_stored;
        uint64_t elapsed_cycles;
        uint64_t last_cycles;
        uint32_t expire_time;

        /* port and ip values */
        uint32_t ip_lb_server;
        uint32_t ip_lb_client;
        uint8_t server_port;
        uint8_t client_port;

        /* config file, interface names */ 
        char * cfg_filename;
        char * client_iface_name;
        char * server_iface_name;
};
#endif


/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

struct loadbalance *lb;
/* number of package between each print */
static uint32_t print_delay = 10000000;

/* onvm struct for port info lookup */
extern struct port_info *ports;

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage: %s [EAL args] -- [NF_LIB args] -- client_iface server_iface server_config -p <print_delay>\n\n", progname);
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c;

#ifndef ENABLE_NFV_RESL
        lb->cfg_filename = NULL;
        lb->client_iface_name = NULL;
        lb->server_iface_name = NULL;
#endif

        while ((c = getopt(argc, argv, "c:s:f:p:")) != -1) {
                switch (c) {
                case 'c':
#ifndef ENABLE_NFV_RESL
                        lb->client_iface_name = strdup(optarg);
#else
                        strncpy(lb->client_iface_name,optarg,sizeof(lb->client_iface_name));
#endif
                        break;
                case 's':
#ifndef ENABLE_NFV_RESL
                        lb->server_iface_name = strdup(optarg);
#else
                        strncpy(lb->server_iface_name,optarg,sizeof(lb->server_iface_name));
#endif
                        break;
                case 'f':
#ifndef ENABLE_NFV_RESL
                        lb->cfg_filename = strdup(optarg);
#else
                        strncpy(lb->cfg_filename,optarg,sizeof(lb->cfg_filename));
#endif
                        break;
                case 'p':
                        print_delay = strtoul(optarg, NULL, 10);
                        break;
                case '?':
                        usage(progname);
                        if (optopt == 'd')
                                RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                        else if (optopt == 'p')
                                RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                        else if (isprint(optopt))
                                RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
                        else
                                RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
                        return -1;
                default:
                        usage(progname);
                        return -1;
                }
        }

        if (!lb->cfg_filename) {
                RTE_LOG(INFO, APP, "Load balancer NF requires a backend server config file.\n");
                return -1;
 
        if (!lb->client_iface_name) {
                RTE_LOG(INFO, APP, "Load balancer NF requires a client interface name.\n");
                return -1;
        }
        if (!lb->server_iface_name) {
                RTE_LOG(INFO, APP, "Load balancer NF requires a backend server interface name.\n");
                return -1;
        }       }

        return optind;
}

/*
 * This function parses the backend config. It takes the filename 
 * and fills up the backend_server array. This includes the mac and ip 
 * address of the backend servers
 */
static int
parse_backend_config(void) {
        int ret, temp, i;
        char ip[32];
        char mac[32];
        FILE * cfg;

        cfg  = fopen(lb->cfg_filename, "r");
        if (cfg == NULL) {
                rte_exit(EXIT_FAILURE, "Error openning server \'%s\' config\n", lb->cfg_filename);
        }
        ret = fscanf(cfg, "%*s %d", &temp);
        if (temp <= 0) {
                rte_exit(EXIT_FAILURE, "Error parsing config, need at least one server configurations\n");
        }
        lb->server_count = temp;

#ifndef ENABLE_NFV_RESL
        lb->server = (struct backend_server *)rte_malloc("backend server info", sizeof(struct backend_server) * lb->server_count, 0);
        if (lb->server == NULL) {
                rte_exit(EXIT_FAILURE, "Malloc failed, can't allocate server information\n");
        }
#else
        lb->server_count = ((temp>MAX_BACKEND_SERVERS)?(MAX_BACKEND_SERVERS):(temp));
#endif
        for (i = 0; i < lb->server_count; i++) {
                ret = fscanf(cfg, "%s %s", ip, mac);
                if (ret != 2) {
                        rte_exit(EXIT_FAILURE, "Invalid backend config structure\n");
                }

                ret = onvm_pkt_parse_ip(ip, &lb->server[i].d_ip);
                if (ret < 0) {
                        rte_exit(EXIT_FAILURE, "Error parsing config IP address #%d\n", i);
                }

                ret =onvm_pkt_parse_mac(mac, lb->server[i].d_addr_bytes);
                if (ret < 0) {
                        rte_exit(EXIT_FAILURE, "Error parsing config MAC address #%d\n", i);
                }
        }

        fclose(cfg);
        printf("\nARP config:\n");
        for (i = 0; i < lb->server_count; i++) {
                printf("%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 " ", 
                        lb->server[i].d_ip & 0xFF, (lb->server[i].d_ip >> 8) & 0xFF, (lb->server[i].d_ip >> 16) & 0xFF, (lb->server[i].d_ip >> 24) & 0xFF);
                printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
                        lb->server[i].d_addr_bytes[0], lb->server[i].d_addr_bytes[1],
                        lb->server[i].d_addr_bytes[2], lb->server[i].d_addr_bytes[3],
                        lb->server[i].d_addr_bytes[4], lb->server[i].d_addr_bytes[5]);
        }

        return ret;
}

/*
 * This function displays stats. It uses ANSI terminal codes to clear
 * screen when called. It is called from a single non-master
 * thread in the server process, when the process is run with more
 * than one lcore enabled.
 */
static void
do_stats_display(struct rte_mbuf* pkt) {
        const char clr[] = { 27, '[', '2', 'J', '\0' };
        const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
        static uint64_t pkt_process = 0;
        struct ipv4_hdr* ip;

        pkt_process += print_delay;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("PACKETS\n");
        printf("-----\n");
        printf("Port : %d\n", pkt->port);
        printf("Size : %d\n", pkt->pkt_len);
        printf("N°   : %"PRIu64"\n", pkt_process);
        printf("\n\n");

        ip = onvm_pkt_ipv4_hdr(pkt);
        if (ip != NULL) {
                onvm_pkt_print(pkt);
        } else {
                printf("No IP4 header found\n");
        }
}

/*
 * Print flow information
 */
static void
print_flow_info(struct flow_info* f) {
        printf("Flow INFO\n");
        printf("Destination server: %d\n", f->dest);
        printf("Source mac %02x:%02x:%02x:%02x:%02x:%02x\n",
                f->s_addr_bytes[0], f->s_addr_bytes[1],
                f->s_addr_bytes[2], f->s_addr_bytes[3],
                f->s_addr_bytes[4], f->s_addr_bytes[5]);
} 

/*
 * Parse and assign load balancer server/client interface information
 */
static void
get_iface_inf(void) {
        int fd, i;
        struct ifreq ifr;
        uint8_t client_addr_bytes[ETHER_ADDR_LEN];
        uint8_t server_addr_bytes[ETHER_ADDR_LEN];
        uint8_t c_addr[ETHER_ADDR_LEN] = {0x8C, 0xDC, 0xD4, 0xAC, 0x6C, 0x7C};
        uint8_t s_addr[ETHER_ADDR_LEN] = {0x8C, 0xDC, 0xD4, 0xAC, 0x6C, 0x7D};

        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        ifr.ifr_addr.sa_family = AF_INET;

        /* Parse server interface */
        strncpy(ifr.ifr_name, lb->server_iface_name, IFNAMSIZ-1);

        ioctl(fd, SIOCGIFADDR, &ifr);
        lb->ip_lb_server  = *(uint32_t *)(&((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
        lb->ip_lb_server  = 50331658;

        ioctl(fd, SIOCGIFHWADDR, &ifr);
        for (i = 0; i < ETHER_ADDR_LEN; i++)
                //server_addr_bytes[i] = ifr.ifr_hwaddr.sa_data[i];
                server_addr_bytes[i] = s_addr[i];

        /* Parse client interface */
        strncpy(ifr.ifr_name, lb->client_iface_name, IFNAMSIZ-1);

        ioctl(fd, SIOCGIFADDR, &ifr);
        lb->ip_lb_client  = *(uint32_t *)(&((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
        lb->ip_lb_client  = 50334218;

        ioctl(fd, SIOCGIFHWADDR, &ifr);
        for (i = 0; i < ETHER_ADDR_LEN; i++)
                //client_addr_bytes[i] = ifr.ifr_hwaddr.sa_data[i];
                client_addr_bytes[i] = c_addr[i];

        /* Compare the interfaces to onvm_mgr ports by hwaddr and assign port id accordingly */
        if (memcmp(&client_addr_bytes, &ports->mac[0], ETHER_ADDR_LEN) == 0) {
                lb->client_port = ports->id[0];
                lb->server_port = ports->id[1];
        } else {
                lb->client_port = ports->id[1];
                lb->server_port = ports->id[0];
        }

        close(fd);

        printf("\nLoad balancer interfaces:\n");
        printf("Client iface \'%s\' ID: %d, IP: %" PRIu32 " (%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "), ",
                lb->client_iface_name, lb->client_port, lb->ip_lb_client,
                lb->ip_lb_client & 0xFF, (lb->ip_lb_client >> 8) & 0xFF, (lb->ip_lb_client >> 16) & 0xFF, (lb->ip_lb_client >> 24) & 0xFF);
        printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        client_addr_bytes[0], client_addr_bytes[1],
                        client_addr_bytes[2], client_addr_bytes[3],
                        client_addr_bytes[4], client_addr_bytes[5]);
        printf("Server iface \'%s\' ID: %d, IP: %" PRIu32 " (%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "), ",
                lb->server_iface_name, lb->server_port, lb->ip_lb_server,
                lb->ip_lb_server & 0xFF, (lb->ip_lb_server >> 8) & 0xFF, (lb->ip_lb_server >> 16) & 0xFF, (lb->ip_lb_server >> 24) & 0xFF);
        printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        server_addr_bytes[0], server_addr_bytes[1],
                        server_addr_bytes[2], server_addr_bytes[3],
                        server_addr_bytes[4], server_addr_bytes[5]);
}
#ifndef ENABLE_NFV_RESL
#define DIRTY_MAP_PER_CHUNK_SIZE ((sizeof(dirty_mon_state_map_tbl_t) + sizeof(struct loadbalance) + TABLE_SIZE*(sizeof(flow_info_t)))/(sizeof(uint64_t)*CHAR_BIT))
#endif
static inline uint64_t map_tag_index_to_dirty_chunk_bit_index(uint16_t ft_index) {
        uint32_t start_offset = sizeof(dirty_mon_state_map_tbl_t) + sizeof(struct loadbalance) + ft_index*sizeof(flow_info_t);
        uint32_t end_offset = start_offset + sizeof(flow_info_t);
        uint64_t dirty_map_bitmask = 0;
        dirty_map_bitmask |= (1<< (start_offset/DIRTY_MAP_PER_CHUNK_SIZE));
        dirty_map_bitmask |= (1<< (end_offset/DIRTY_MAP_PER_CHUNK_SIZE));
        //printf("\n For %d, 0x%lx\n",(int)vlan_tbl_index, dirty_map_bitmask);
        return dirty_map_bitmask;
}
static inline int update_dirty_state_index(uint16_t ft_index) {
        if(dirty_state_map) {
                dirty_state_map->dirty_index |= map_tag_index_to_dirty_chunk_bit_index(ft_index);
        }
        return ft_index;
}
/*
 * Updates flow info to be "active" or "expired"
 */
static int
update_status(uint64_t elapsed_cycles, struct flow_info *data) {
        if (unlikely(data == NULL)) {
                return -1;
        }
        if ((elapsed_cycles - data->last_pkt_cycles) / rte_get_timer_hz() >= lb->expire_time) {
                data->is_active = 0;
        } else {
                data->is_active = 1;
        }

        return 0;
}

/*
 * Clears expired entries from the flow table
 */
static int
clear_entries(void) {
        if (unlikely(lb == NULL)) {
                return -1;
        }

        printf("Clearing expired entries\n");

        struct flow_info *data = NULL;
        uint32_t next = 0;
        int ret = 0;
#ifndef ENABLE_NFV_RESL
        struct onvm_ft_ipv4_5tuple *key = NULL;
        while (onvm_ft_iterate(lb->ft, (const void **)&key, (void **)&data, &next) > -1) {
                if (update_status(lb->elapsed_cycles, data) < 0) {
                        return -1;
                }

                if (!data->is_active) {
                        ret = onvm_ft_remove_key(lb->ft, key);
                        lb->num_stored--;
                        if (ret < 0) {
                                printf("Key should have been removed, but was not\n");
                                lb->num_stored++;
                        }
                }
        }
#else //TODO:complete this call
        for(next=0; next < TABLE_SIZE; next++) {
                if (update_status(lb->elapsed_cycles, data) < 0) {
                        return -1;
                }
                if (!data->is_active) {
                        //ret = onvm_ft_remove_key(lb->ft, key);
                        lb->num_stored--;
                        if (ret < 0) {
                                printf("Key should have been removed, but was not\n");
                                lb->num_stored++;
                        }
                }
        }
#endif
        return 0;
}
static void set_lb_flow_info(struct flow_info *data);
static void set_lb_flow_info(struct flow_info *data) {
        lb->num_stored++;
        data->dest = lb->num_stored % lb->server_count;
        data->last_pkt_cycles = lb->elapsed_cycles;
        data->is_active = 0;
        return ;
}
/*
 * Adds an entry to the flow table. It first checks if the table is full, and
 * if so, it calls clear_entries() to free up space.
 */
static int
table_add_entry(struct onvm_ft_ipv4_5tuple* key, struct flow_info **flow) {
        struct flow_info *data = NULL;

        if (unlikely(key == NULL || lb == NULL)) {
                return -1;
        }

        if (TABLE_SIZE - 1 - lb->num_stored == 0) {
                int ret = clear_entries();
                if (ret < 0) {
                        return -1;
                }
        }

#ifndef ENABLE_NFV_RESL
        int tbl_index = onvm_ft_add_key(lb->ft, key, (char **)&data);
        if (tbl_index < 0) {
                return -1;
        }
#else
        //TODO:complete
        data = *flow;
#endif
        set_lb_flow_info(data);
        *flow = data;

        return 0;
}

/*
 * Looks up a packet hash to see if there is a matching key in the table.
 * If it finds one, it updates the metadata associated with the key entry,
 * and if it doesn't, it calls table_add_entry() to add it to the table.
 */
static int
table_lookup_entry(struct rte_mbuf* pkt, struct flow_info **flow, __attribute__((unused)) struct onvm_pkt_meta* meta) {
        struct flow_info *data = NULL;
        struct onvm_ft_ipv4_5tuple key;

        if (unlikely(pkt == NULL || lb == NULL || flow == NULL)) {
                return -1;
        }
 
#ifndef ENABLE_NFV_RESL
        int ret = onvm_ft_fill_key_symmetric(&key, pkt);
        if (ret < 0)  return -1;
        int tbl_index = onvm_ft_lookup_key(lb->ft, &key, (char **)&data);
        if (tbl_index == -ENOENT) {
                return table_add_entry(&key, flow);
        } else if (tbl_index < 0) {
                printf("Some other error occurred with the packet hashing\n");
                return -1;
        } else {
                data->last_pkt_cycles = lb->elapsed_cycles;
                *flow = data;
                update_dirty_state_index(tbl_index);
                return 0;
        }
#else
        //TODO:complete
        int tbl_index = -ENOENT;
        /** NOTE: Only catch is that: the caller relies on "is_active == 0 " to determine if this is client side or server side call.
         * Assumption is that client initiates first; is_active=0; and server response the same entry will jave is_Active=1; but
         * with two different entries for client and server; the only way to resolve is to check if the ft_key_flip has an entry with is_active=1 or map the flip key to same index.
         * TODO: either of the above two approaches.
         * */
#ifdef ENABLE_FT_INDEX_IN_META
        tbl_index = meta->ft_index; //(uint16_t) MAP_SDN_FT_INDEX_TO_VLAN_STATE_TBL_INDEX(meta->ft_index);
#else
        {
                //printf("\n\n Inserting Vlan Tag\n");
                struct onvm_flow_entry *flow_entry = NULL;
                onvm_flow_dir_get_pkt(pkt, &flow_entry);
                if(flow_entry) {
                        tbl_index = flow_entry->entry_index;
                }
        }
#endif

        if (tbl_index == -ENOENT) {
                return -1; //table_add_entry(&key, flow);
        }
        else if (tbl_index < 0) {
                printf("Some other error occurred with the packet hashing\n");
                return -1;
        }
        else {
                data = &lb->ft[tbl_index];
                *flow = data;
                if(data->is_active == 0) {
                        table_add_entry(&key, &data);
                } else {
                        data->last_pkt_cycles = lb->elapsed_cycles;
                }
                update_dirty_state_index(tbl_index);
        }
#endif
        return 0;
}

static
int lb_callback_handler(void);
static
int lb_callback_handler(void) {
        lb->elapsed_cycles = rte_get_tsc_cycles();

        if ((lb->elapsed_cycles - lb->last_cycles) / rte_get_timer_hz() > lb->expire_time) {
                lb->last_cycles = lb->elapsed_cycles;
        }

        return 0;
}
//static uint8_t client_mac_addr[6], server_mac_addr[6];
//static uint32_t client_ip_addr, server_ip_addr;
static int
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
        static uint32_t counter = 0;
        struct ipv4_hdr* ip;
        struct ether_hdr *ehdr;
        struct flow_info *flow_info;
        int i, ret;

        ehdr = onvm_pkt_ether_hdr(pkt);
        ip = onvm_pkt_ipv4_hdr(pkt);

        /* Ignore packets without ip header, also ignore packets with invalid ip */
        if (ip == NULL || ip->src_addr == 0 || ip->dst_addr == 0) {
                printf("\n Dropping Packet\n");
                meta->action = ONVM_NF_ACTION_DROP;
                meta->destination = 0;
                if (pkt->port == lb->client_port) meta->destination = lb->server_port;
                else meta->destination = lb->client_port;
                meta->action = ONVM_NF_ACTION_OUT;
                return 0;
        }

#ifndef ENABLE_NFV_RESL
        /*
         * Before hashing remove the Load Balancer ip from the pkt so that both
         * connections from client -> lbr and lbr <- server
         * will have the same hash
         */
        if (pkt->port == lb->client_port) {
                ip->dst_addr = 0;
        } else {
                ip->src_addr = 0;
        }
#endif

        /* Get the packet flow entry */
        ret = table_lookup_entry(pkt, &flow_info, meta);
        if (ret == -1) {
                printf("\n Dropping Packet2\n");
                meta->action = ONVM_NF_ACTION_DROP;
                meta->destination = 0;
                if (pkt->port == lb->client_port) meta->destination = lb->server_port;
                else meta->destination = lb->client_port;
                meta->action = ONVM_NF_ACTION_OUT;
                return 0;
        }

        /* If the flow entry is new, save the client information */
        if (flow_info->is_active == 0) {
                flow_info->is_active = 1;
                if (pkt->port == lb->client_port) {
                        for (i = 0; i < ETHER_ADDR_LEN; i++) {
                                flow_info->s_addr_bytes[i] = ehdr->s_addr.addr_bytes[i];
                                //client_mac_addr[i] = ehdr->s_addr.addr_bytes[i];
                        }
                        /* client_ip_addr = ip->src_addr;
                        printf("Client iface IP: %" PRIu32 " (%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "), ",
                                        client_ip_addr,
                                        client_ip_addr & 0xFF, (client_ip_addr >> 8) & 0xFF, (client_ip_addr >> 16) & 0xFF, (client_ip_addr >> 24) & 0xFF);
                        printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                                        client_mac_addr[0], client_mac_addr[1],
                                        client_mac_addr[2], client_mac_addr[3],
                                        client_mac_addr[4], client_mac_addr[5]);
                        */
                }
                else if (pkt->port == lb->server_port) {
                        for (i = 0; i < ETHER_ADDR_LEN; i++) {
                                flow_info->s_addr_bytes[i] = ehdr->d_addr.addr_bytes[i]; //ehdr->d_addr.addr_bytes[i] = flow_info->s_addr_bytes[i];
                                //server_mac_addr[i] = ehdr->s_addr.addr_bytes[i];
                        }
                        /*
                        server_ip_addr = ip->src_addr;
                        printf("Server iface IP: %" PRIu32 " (%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "), ",
                                        server_ip_addr,
                                        server_ip_addr & 0xFF, (client_ip_addr >> 8) & 0xFF, (client_ip_addr >> 16) & 0xFF, (client_ip_addr >> 24) & 0xFF);
                        printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                                        server_mac_addr[0], server_mac_addr[1],
                                        server_mac_addr[2], server_mac_addr[3],
                                        server_mac_addr[4], server_mac_addr[5]);
                        */
                }
        }
        /* If the packet is from Server: the replace the Source MAC, IP from servers to Load Balancers and forward to client port */
        if (pkt->port == lb->server_port) {
                //Change SRC IP and MAC from Backend server to Load Balancers
                ip->src_addr = lb->ip_lb_client;
                rte_eth_macaddr_get(lb->client_port, &ehdr->s_addr);

                //Change DST MAC and IP to Clients MAC and IP
                for (i = 0; i < ETHER_ADDR_LEN; i++) {
                        ehdr->d_addr.addr_bytes[i] = flow_info->s_addr_bytes[i]; //concern-- as it is not clients MAC; (still it works with this.. )anyway skip this and check.
                        //ehdr->d_addr.addr_bytes[i] = client_mac_addr[i];
                }
                meta->destination = lb->client_port;
        /* For packet from client: replace the destination MAC and IP from Load balancers to Server and forward to Server port */
        } else {
                for (i = 0; i < ETHER_ADDR_LEN; i++) {
                        ehdr->d_addr.addr_bytes[i] = lb->server[flow_info->dest].d_addr_bytes[i];
                }
                ip->dst_addr = lb->server[flow_info->dest].d_ip;
                meta->destination = lb->server_port;
        }

        /* Changing the pkt ip header so we want to recalculate pkt checksums */
        onvm_pkt_set_checksums(pkt);

        meta->action = ONVM_NF_ACTION_OUT;

        meta->destination = pkt->port;  //hack added for performance testing with moongen

        if (++counter == print_delay) {
                do_stats_display(pkt);
                print_flow_info(flow_info);
                counter = 0;
        }

        return 0;
}

int main(int argc, char *argv[]) {
        int arg_offset;
        const char *progname = argv[0];
        
        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG)) < 0)
                return -1;
        argc -= arg_offset;
        argv += arg_offset;

#ifdef ENABLE_NFV_RESL
        if(nf_info->nf_state_mempool) {
                dirty_state_map = (dirty_mon_state_map_tbl_t*)nf_info->nf_state_mempool;
                lb = (struct loadbalance*)(dirty_state_map+1);  //lb = (struct loadbalance*)nf_info->nf_state_mempool;
                lb->ft = (flow_info_t*)(lb +1);
        }
#else
        lb = rte_calloc("state", 1, sizeof(struct loadbalance), 0);
#endif
        if (lb == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Unable to initialize NF lb struct");
        }

        if (parse_app_args(argc, argv, progname) < 0)
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");

#ifndef ENABLE_NFV_RESL
        lb->ft = onvm_ft_create(TABLE_SIZE, sizeof(struct flow_info));
#endif
        if (lb->ft == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Unable to create flow table");
        }

        get_iface_inf();
        parse_backend_config();

        lb->expire_time = 32;
        lb->elapsed_cycles = rte_get_tsc_cycles();

        //onvm_nflib_run(nf_info, &packet_handler);
        onvm_nflib_run_callback(nf_info, &packet_handler, &lb_callback_handler);
        printf("If we reach here, program is ending\n");

        return 0;
}
