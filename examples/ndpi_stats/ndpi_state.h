#ifndef __NDPI_STATE_H__
#define __NDPI_STATE_H__

#include "onvm_nflib.h"
#include "ndpi_util.h"

#ifdef ENABLE_NFV_RESL
/*typedef struct dirty_mon_state_map_tbl {
        uint64_t dirty_index;
        // Bit index to every 1K LSB=0-1K, MSB=63-64K
}dirty_mon_state_map_tbl_t;*/

//#define DIRTY_MAP_PER_CHUNK_SIZE (_NF_STATE_SIZE/sizeof(uint64_t))
#define MAX_NF_STATE_ELEMENTS ((_NF_STATE_SIZE-sizeof(dirty_mon_state_map_tbl_t))/sizeof(ndpi_flow_info_t))
#define MAX_SERVICE_STATE_SIZE (_SERVICE_STATE_SIZE-sizeof(dirty_mon_state_map_tbl_t))
#define MAX_SERVICE_STATE_ELEMENTS MAX_SERVICE_STATE_SIZE/sizeof(ndpi_workflow_t)

extern dirty_mon_state_map_tbl_t *service_dirty_state_map;
extern dirty_mon_state_map_tbl_t *nf_dirty_state_map;
extern ndpi_workflow_t *service_state;
extern ndpi_flow_info_t *nf_flow_tbl;
extern int nf_flow_tbl_idx;
extern void *current_service_memory;

static inline uint64_t map_tag_index_to_dirty_chunk_bit_index(uint32_t flow_tbl_index) {
        uint32_t start_offset = sizeof(dirty_mon_state_map_tbl_t) + flow_tbl_index*sizeof(ndpi_flow_info_t);
        uint32_t end_offset = start_offset + sizeof(ndpi_flow_info_t);
        uint64_t dirty_map_bitmask = 0;
        dirty_map_bitmask |= (1<< (start_offset/DIRTY_MAP_PER_CHUNK_SIZE));
        dirty_map_bitmask |= (1<< (end_offset/DIRTY_MAP_PER_CHUNK_SIZE));
        return dirty_map_bitmask;
}

static inline int update_dirty_nf_state_index(uint32_t flow_index) {
        if(nf_dirty_state_map) {
                nf_dirty_state_map->dirty_index |= map_tag_index_to_dirty_chunk_bit_index(flow_index);
        }
        return flow_index;
}

static inline int update_dirty_service_state_index(uint32_t workflow_index) {
        return workflow_index;
}
#endif //ENABLE_NFV_RESL
#endif
