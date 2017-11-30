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

                                  onvm_args.c

    File containing the function parsing all DPDK and ONVM arguments.


******************************************************************************/


#include "onvm_mgr/onvm_args.h"


/******************************Global variables*******************************/


/* global var for number of clients - extern in header init.h */
volatile uint16_t num_clients;

/* global var for number of services - extern in header init.h */
uint16_t num_services = MAX_SERVICES;

/* global var for the default service id - extern in init.h */
uint16_t default_service = DEFAULT_SERVICE_ID;

/* global var: did user directly specify num clients? */
uint8_t is_static_clients;

/* global var for program name */
static const char *progname;


/***********************Internal Functions prototypes*************************/


static void
usage(void);


static int
parse_portmask(uint8_t max_ports, const char *portmask);


static int
parse_default_service(const char *services);


static int
parse_num_services(const char *services);

#define USE_STATIC_IDS
#ifdef USE_STATIC_IDS

static int
parse_num_clients(const char *clients);

#endif


/*********************************Interfaces**********************************/


int
parse_app_args(uint8_t max_ports, int argc, char *argv[]) {
        int option_index, opt;
        char **argvopt = argv;
        static struct option lgopts[] = { /* no long options */
                {NULL, 0, 0, 0 }
        };
        progname = argv[0];
        is_static_clients = DYNAMIC_CLIENTS;

#ifdef USE_STATIC_IDS
        while ((opt = getopt_long(argc, argvopt, "n:r:p:d:", lgopts, &option_index)) != EOF) {
#else
        while ((opt = getopt_long(argc, argvopt, "r:p:d:", lgopts, &option_index)) != EOF) {
#endif
                switch (opt) {
                        case 'p':
                                if (parse_portmask(max_ports, optarg) != 0) {
                                        usage();
                                        return -1;
                                }
                                break;
#ifdef USE_STATIC_IDS
                        case 'n':
                                if (parse_num_clients(optarg) != 0) {
                                        usage();
                                        return -1;
                                }
                                break;
#endif
                        case 'r':
                                if (parse_num_services(optarg) != 0) {
                                        usage();
                                        return -1;
                                }
                                break;
                        case 'd':
                                if (parse_default_service(optarg) != 0) {
                                        usage();
                                        return -1;
                                }
                                break;
                        default:
                                printf("ERROR: Unknown option '%c'\n", opt);
                                usage();
                                return -1;
                }
        }

        if (is_static_clients == STATIC_CLIENTS
               && num_clients == 0) {
                usage();
                return -1;
        }

        return 0;
}


/*****************************Internal functions******************************/


static void
usage(void) {
        printf(
            "%s [EAL options] -- -p PORTMASK "
#ifdef USE_STATIC_IDS
            "[-n NUM_CLIENTS] "
#endif
            "[-s NUM_SOCKETS] [-r NUM_SERVICES]\n"
            " -p PORTMASK: hexadecimal bitmask of ports to use\n"
#ifdef USE_STATIC_IDS
            " -n NUM_CLIENTS: number of client processes to use (optional)\n"
#endif
            " -r NUM_SERVICES: number of unique serivces allowed (optional)\n" // -s already used for num sockets
            , progname);
}


static int
parse_portmask(uint8_t max_ports, const char *portmask) {
        char *end = NULL;
        unsigned long pm;
        uint8_t count = 0;

        if (portmask == NULL)
                return -1;

        /* convert parameter to a number and verify */
        pm = strtoul(portmask, &end, 16);
        if (pm == 0) {
                printf("WARNING: No ports are being used.\n");
                return 0;
        }
        if (end == NULL || *end != '\0' || pm == 0)
                return -1;

        /* loop through bits of the mask and mark ports */
        while (pm != 0) {
                if (pm & 0x01) { /* bit is set in mask, use port */
                        if (count >= max_ports)
                                printf("WARNING: requested port %u not present"
                                " - ignoring\n", (unsigned)count);
                        else
                            ports->id[ports->num_ports++] = count;
                }
                pm = (pm >> 1);
                count++;
        }

        return 0;
}


static int
parse_default_service(const char *services) {
        char *end = NULL;
        unsigned long temp;

        temp = strtoul(services, &end, 10);
        if (end == NULL || *end != '\0' || temp == 0)
                return -1;

        default_service = (uint16_t)temp;
        return 0;
}


static int
parse_num_services(const char *services) {
        char *end = NULL;
        unsigned long temp;

        temp = strtoul(services, &end, 10);
        if (end == NULL || *end != '\0' || temp == 0)
                return -1;

        num_services = (uint16_t)temp;
        return 0;
}


#ifdef USE_STATIC_IDS
static int
parse_num_clients(const char *clients) {
        char *end = NULL;
        unsigned long temp;

        // If we want dynamic client numbering
        if (clients == NULL || *clients == '\0')
                return 0;

        temp = strtoul(clients, &end, 10);
        if (end == NULL || *end != '\0' || temp == 0)
                return -1;

        num_clients = (uint16_t)temp;
        is_static_clients = STATIC_CLIENTS;
        return 0;
}
#endif
