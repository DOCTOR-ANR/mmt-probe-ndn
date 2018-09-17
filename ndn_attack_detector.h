#ifndef NDN_ATTACK_H
#define	NDN_ATTACK_H

#ifdef	__cplusplus
extern "C" {
#endif
#include <string.h>	
#include <inttypes.h>
#include "mmt_core.h"
#define NAN_TIME 100000000;

typedef struct cs_metric_detector_struct
{
	uint64_t nb_cs_miss; // Number of OnContentStoreMiss
	uint64_t nb_cs_hit; // Number of OnContentStoreHit
	uint64_t nb_cs_insert; // Number of Insert in ContentStore
}cs_metric_detector_t;

typedef struct other_metric_detector_struct
{
	uint64_t nb_interest_loop; // Number of nb_interest_loop
	uint64_t nb_interest_unsatisfied; // Number of nb_interest_unsatisfied
	uint64_t nb_interest_drop; // Number of nb_interest_drop
	uint64_t nb_data_drop; // Number of nb_data_drop
	uint64_t nb_nack_drop; // Number of nb_nack_drop
	char * list_dropped_prefix; // list_dropped_prefix
}other_metric_detector_t;

typedef struct face_metric_detector_struct
{
	uint64_t nb_face_in_interest; // Number of Interest in
	uint64_t nb_face_in_data; // Number of Data in
	uint64_t nb_face_in_nack; // Number of Nack in
	uint64_t nb_face_out_interest; // Number of Interest out
	uint64_t nb_face_out_data; // Number of Data out
	uint64_t nb_face_out_nack; // Number of Nack out
	uint16_t face_id; // Number of Insert in ContentStore
}face_metric_detector_t;

typedef struct entry_metric_detector_struct
{
	struct timeval * create_time;  // Timeval create
	char * entry; // Prefix
	//short is_in_pit; // If it's currently in PIT
}entry_metric_detector_t;

typedef struct pit_metric_detector_struct
{
	uint64_t nb_pit_create; 
	uint64_t nb_pit_update; 
	uint64_t nb_pit_remove; 
	uint64_t nb_pit; 
	uint64_t pit_time; 
	char * list_updated_entries; // list_updated_entries
}pit_metric_detector_t;



typedef struct ndn_metrics_detector_struct
{
	uint64_t time_period; // Time period to update data
	uint64_t current_timestamp; // For build the output filename	
	struct timeval * last_updated_time; // Last updated time
	struct timeval * report_time; // Time report to Server = lastupdatetime + timeperiod
	cs_metric_detector_t * cs_metric;
	other_metric_detector_t * other_metric;
	pit_metric_detector_t * pit_metric;
	face_metric_detector_t * list_faces_metric;
	entry_metric_detector_t * list_entries_metric;
	uint16_t nb_faces; // Number of Faces
	uint64_t nb_entries; // Number of Faces
}ndn_metrics_detector_t;

ndn_metrics_detector_t * new_ndn_metrics_detector() ;

short ndn_metrics_detector_check_time_period(ndn_metrics_detector_t * ndn_metrics, struct timeval * current_time) ;

/**
 * Free an ndn_metrics detector structure
 * @param ndn_metrics ndn_metrics detecture struct to be freed
 */

void free_ndn_metrics_detector(ndn_metrics_detector_t * ndn_metrics);

int check_list_entries(ndn_metrics_detector_t * ndn_metrics,char * entry);

void print_list_id_entry(ndn_metrics_detector_t * ndn_metrics);

void add_entry_ndn_metrics(ndn_metrics_detector_t * ndn_metrics, char * entry,struct timeval * time);

short check_list_id_face(ndn_metrics_detector_t * ndn_metrics,uint16_t face_id);

void print_list_id_face(ndn_metrics_detector_t * ndn_metrics);

void add_face_ndn_metrics(ndn_metrics_detector_t * ndn_metrics, uint16_t face_id);


/**
*	CS_metric
*/



cs_metric_detector_t * new_cs_metric_detector() ;

void cs_metric_detector_update_data(cs_metric_detector_t * cs_metric, short id_metric) ;

/**
 * Free an cs_metric detector structure
 * @param cs_metric cs_metric detecture struct to be freed
 */
void free_cs_metric_detector(cs_metric_detector_t * cs_metric);

/**
*	other_metric
*/



other_metric_detector_t * new_other_metric_detector() ;

void other_metric_detector_update_data(ndn_metrics_detector_t * ndn_metrics, short id_metric, char * entry) ;

/**
 * Free an other_metric detector structure
 * @param other_metric other_metric detecture struct to be freed
 */
void free_other_metric_detector(other_metric_detector_t * other_metric);


/**
*	Face_metrics
*/

face_metric_detector_t * new_face_metric_detector(uint16_t face_id) ;

void face_metric_detector_update_data(ndn_metrics_detector_t * ndn_metrics, uint16_t face_id, short id_metric) ;

/**
 * Free an face_metric detector structure
 * @param face_metric face_metric detecture struct to be freed
 */
void free_face_metric_detector(face_metric_detector_t * face_metric);


/**
*	Entry_metrics
*/

entry_metric_detector_t * new_entry_metric_detector(char * entry,struct timeval * time) ;

void entry_metric_detector_update_data(ndn_metrics_detector_t * ndn_metrics, char * entry, short id_metric) ;

/**
 * Free an entry_metric detector structure
 * @param entry_metric entry_metric detecture struct to be freed
 */
void free_entry_metric_detector(entry_metric_detector_t * entry_metric);


/**
*	PIT_metrics
*/

pit_metric_detector_t * new_pit_metric_detector() ;

void pit_metric_detector_update_data(ndn_metrics_detector_t * ndn_metrics, short id_metric, char * entry, struct timeval * time) ;

/**
 * Free an pit_metric detector structure
 * @param pit_metric pit_metric detecture struct to be freed
 */
void free_pit_metric_detector(pit_metric_detector_t * pit_metric);



/**
 * Get time different (in milliseconds )
 * @param  last_updated_time time before
 * @param  current_time      time after
 * @return                   error if one of given time is NULL
 *                           time different in millisecond: current_time - last_update_time
 */
uint64_t get_diff_time_ndn_metric(struct timeval * last_updated_time, struct timeval * current_time);

uint64_t get_diff_time_ms_ndn_metric(struct timeval * last_updated_time, struct timeval * current_time);

char* extract_entry(char * token2);

void remove_entry(ndn_metrics_detector_t * ndn_metrics,int id_entry);

short filter_localhost(char * data);

void reset_compter(ndn_metrics_detector_t * ndn_metrics);

#define IDMETRIC_CS_MISS 1
#define IDMETRIC_CS_HIT 2
#define IDMETRIC_CS_INSERT 3
#define IDMETRIC_FACE_IN_INTEREST 4
#define IDMETRIC_FACE_IN_DATA 5
#define IDMETRIC_FACE_IN_NACK 6
#define IDMETRIC_FACE_OUT_INTEREST 7
#define IDMETRIC_FACE_OUT_DATA 8
#define IDMETRIC_FACE_OUT_NACK 9
#define IDMETRIC_PIT_CREATE 10
#define IDMETRIC_PIT_UPDATE 11
#define IDMETRIC_PIT_DELETE 12
#define IDMETRIC_PIT_EXIST_TIME 13
#define IDMETRIC_INTEREST_UNSATISFIED 14
#define IDMETRIC_INTEREST_DROP 15
#define IDMETRIC_DATA_DROP 16
#define IDMETRIC_NACK_DROP 17
#define IDMETRIC_PIT_NUMBER 18
#define IDMETRIC_INTEREST_LOOP 19
#define N_IDMETRIC 20

#define MAX_PIT 65535
#define MAX_FACE 65535

#ifdef	__cplusplus
}
#endif

#endif	/* NDN_ATTACK_H */