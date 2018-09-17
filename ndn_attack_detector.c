#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>

#include "ndn_attack_detector.h"
#include "dbg.h"

/**
* Get different in seconds
*/

uint64_t get_diff_time_ndn_metric(struct timeval * last_updated_time, struct timeval * current_time) {
	if (last_updated_time == NULL || current_time == NULL) {
		log_err( "[ERROR] One of input time is NULL\n");
		return NAN_TIME;
	}
	return (current_time)->tv_sec - (last_updated_time)->tv_sec;

}

/**
* Get different in Milliseconds
*/


uint64_t get_diff_time_ms_ndn_metric(struct timeval * last_updated_time, struct timeval * current_time) {
	if (last_updated_time == NULL || current_time == NULL) {
		log_err( "[ERROR] One of input time is NULL\n");
		return NAN_TIME;
	}
	return abs(round((current_time->tv_sec - last_updated_time->tv_sec) * 1000 + (current_time->tv_usec - last_updated_time->tv_usec) / 1000));
	//return round((current_time)->tv_sec*1000+(current_time)->tv_usec - (last_updated_time)->tv_sec*1000+(last_updated_time)->tv_usec);

}

/**
* NDN_SECURITY_METRICS
*/

ndn_metrics_detector_t * new_ndn_metrics_detector() {
	ndn_metrics_detector_t * ndn_metrics = (ndn_metrics_detector_t*)malloc(sizeof(ndn_metrics_detector_t));
	if (ndn_metrics == NULL) {
		log_err( "Cannot allocate memory while creating new ndn_metrics detector struct\n");
		return NULL;
	}
	ndn_metrics->last_updated_time = NULL;
	ndn_metrics->report_time = NULL;
	ndn_metrics->current_timestamp = 0;
	ndn_metrics->time_period = 0;

	ndn_metrics->cs_metric = (cs_metric_detector_t*)malloc(sizeof(cs_metric_detector_t));
	ndn_metrics->cs_metric = new_cs_metric_detector();

	ndn_metrics->other_metric = (other_metric_detector_t*)malloc(sizeof(other_metric_detector_t));
	ndn_metrics->other_metric = new_other_metric_detector();

	ndn_metrics->pit_metric = (pit_metric_detector_t*)malloc(sizeof(pit_metric_detector_t));
	ndn_metrics->pit_metric = new_pit_metric_detector();
	ndn_metrics->list_faces_metric = (face_metric_detector_t*)malloc(MAX_FACE*sizeof(face_metric_detector_t));
	ndn_metrics->list_entries_metric = (entry_metric_detector_t*)malloc(MAX_PIT*sizeof(entry_metric_detector_t));
	ndn_metrics->nb_faces=0;
	ndn_metrics->nb_entries=0;
	return ndn_metrics;
}

/**
* NDN_SECURITY_METRICS
*/

short check_list_id_face(ndn_metrics_detector_t * ndn_metrics,uint16_t face_id){
	int i;
	for(i = 0; i < ndn_metrics->nb_faces; i++) {
		face_metric_detector_t face_metric_tmp =ndn_metrics->list_faces_metric[i];
		if ((&face_metric_tmp)->face_id == face_id){
			return 0;
		}
	}
	return 1;
}
/**
* 	Print list of faces
*/
void print_list_id_face(ndn_metrics_detector_t * ndn_metrics){
	int i;
	for(i = 0; i < ndn_metrics->nb_faces; i++) {
		face_metric_detector_t face_metric_tmp =ndn_metrics->list_faces_metric[i];
		printf("print_list_id_face face_id %u : %" PRIu64 " \n",(&face_metric_tmp)->face_id, (&face_metric_tmp)->nb_face_in_interest);		
	}
}

/**
* 	add_face_ndn_metrics
*/

void add_face_ndn_metrics(ndn_metrics_detector_t * ndn_metrics, uint16_t face_id){
	if (check_list_id_face(ndn_metrics,face_id)>0){
		face_metric_detector_t * new_face=new_face_metric_detector(face_id);
		ndn_metrics->list_faces_metric[ndn_metrics->nb_faces]=*new_face;
		ndn_metrics->nb_faces++;
	}	
}



/**
 * Free an ndn_metrics detector structure
 * @param ndn_metrics ndn_metrics detecture struct to be freed
 */
void free_ndn_metrics_detector(ndn_metrics_detector_t * ndn_metrics) {

	if (ndn_metrics == NULL) return;

	ndn_metrics->last_updated_time = NULL;
	ndn_metrics->report_time = NULL;
	ndn_metrics->current_timestamp = 0;
	ndn_metrics->time_period = 0;

	ndn_metrics->cs_metric = NULL;
	ndn_metrics->other_metric = NULL;
	ndn_metrics->nb_faces=0;
	ndn_metrics->nb_entries=0;
	free(ndn_metrics->pit_metric);
	free(ndn_metrics->list_faces_metric);
	free(ndn_metrics->list_entries_metric);
	free(ndn_metrics);
	// ndn_metrics = NULL;
}

/**
*	Check time to send report
*/

short ndn_metrics_detector_check_time_period(ndn_metrics_detector_t * ndn_metrics, struct timeval * current_time) {
	if (ndn_metrics == NULL) {
		log_err( "[ndn_metrics-ERROR] ndn_metrics detector is NULL\n");
		return 0;
	}

	if (current_time == NULL) {
		log_err( "[ndn_metrics-ERROR] Updated time is NULL\n");
		return 0;
	}

	if (ndn_metrics->last_updated_time == NULL) {
		ndn_metrics->last_updated_time = (struct timeval*)malloc(sizeof(struct timeval));
		ndn_metrics->last_updated_time->tv_sec = current_time->tv_sec;
		ndn_metrics->last_updated_time->tv_usec = current_time->tv_usec;
		//printf("[ndn_metrics] ndn_metrics->last_updated_time->tv_sec: %ld\n", ndn_metrics->last_updated_time->tv_sec);
	} else {
		uint64_t diff_time = get_diff_time_ndn_metric(ndn_metrics->last_updated_time, current_time);
		//printf("[ndn_metrics] diff_time: %lu\n", diff_time);
		if (diff_time >= ndn_metrics->time_period) {
			if (ndn_metrics->report_time == NULL) {
				ndn_metrics->report_time = (struct timeval*)malloc(sizeof(struct timeval));
			}

			ndn_metrics->report_time->tv_sec = ndn_metrics->last_updated_time->tv_sec + ndn_metrics->time_period;
			ndn_metrics->report_time->tv_usec = ndn_metrics->last_updated_time->tv_usec;

			ndn_metrics->last_updated_time->tv_sec = current_time->tv_sec;
			ndn_metrics->last_updated_time->tv_usec = current_time->tv_usec;

			return 1;
		}
	}
	return 0;
}
/**
* CS_METRIC
*/

cs_metric_detector_t * new_cs_metric_detector() {
	cs_metric_detector_t * cs_metric = (cs_metric_detector_t*)malloc(sizeof(cs_metric_detector_t));
	if (cs_metric == NULL) {
		log_err( "Cannot allocate memory while creating new cs_metric detector struct\n");
		return NULL;
	}
	cs_metric->nb_cs_miss = 0;
	cs_metric->nb_cs_hit = 0;
	cs_metric->nb_cs_insert = 0;
	return cs_metric;
}

/**
 * Free an cs_metric detector structure
 * @param cs_metric cs_metric detecture struct to be freed
 */
void free_cs_metric_detector(cs_metric_detector_t * cs_metric) {

	if (cs_metric == NULL) return;

	cs_metric->nb_cs_miss = 0;
	cs_metric->nb_cs_hit = 0;
	cs_metric->nb_cs_insert = 0;
	free(cs_metric);
}

/**
*	Update CS Metrics
*/

void cs_metric_detector_update_data(cs_metric_detector_t * cs_metric, short id_metric) {
	if (cs_metric == NULL) {
		log_err( "[cs_metric-ERROR] cs_metric detector is NULL\n");
		return;
	}

	switch (id_metric) {
        case IDMETRIC_CS_MISS:
        	cs_metric->nb_cs_miss++;
        	break;
     	case IDMETRIC_CS_HIT:
        	cs_metric->nb_cs_hit++;
        	break;
        case IDMETRIC_CS_INSERT:
        	cs_metric->nb_cs_insert++;   
        	break;
	}
}

/**
* OTHER_METRIC
*/

other_metric_detector_t * new_other_metric_detector() {
	other_metric_detector_t * other_metric = (other_metric_detector_t*)malloc(sizeof(other_metric_detector_t));
	if (other_metric == NULL) {
		log_err( "Cannot allocate memory while creating new other_metric detector struct\n");
		return NULL;
	}
	other_metric->nb_interest_loop = 0;
	other_metric->nb_interest_unsatisfied = 0;
	other_metric->nb_interest_drop = 0;
	other_metric->nb_data_drop = 0;
	other_metric->nb_nack_drop = 0;
	other_metric->list_dropped_prefix = malloc(1024);
	strcpy(other_metric->list_dropped_prefix, " ");
	return other_metric;
}

/**
 * Free an other_metric detector structure
 * @param other_metric other_metric detecture struct to be freed
 */
void free_other_metric_detector(other_metric_detector_t * other_metric) {

	if (other_metric == NULL) return;

	other_metric->nb_interest_loop = 0;
	other_metric->nb_interest_unsatisfied = 0;
	other_metric->nb_interest_drop = 0;
	other_metric->nb_data_drop = 0;
	other_metric->nb_nack_drop = 0;
	free (other_metric->list_dropped_prefix);
	free(other_metric);
}

/**
*	Update other metrics (INTEREST_LOOP, INTEREST_UNSATISFIED, INTEREST_DROP, DATA_DROP, NACK_DROP)
*/


void other_metric_detector_update_data(ndn_metrics_detector_t * ndn_metrics, short id_metric, char * entry) {
	if (ndn_metrics->other_metric == NULL) {
		log_err( "[other_metric-ERROR] other_metric detector is NULL\n");
		return;
	}

	switch (id_metric) {
        case IDMETRIC_INTEREST_LOOP:
        	ndn_metrics->other_metric->nb_interest_loop++;
        	break;
     	case IDMETRIC_INTEREST_UNSATISFIED:
        	ndn_metrics->other_metric->nb_interest_unsatisfied++;
        	break;
        case IDMETRIC_INTEREST_DROP:
        	ndn_metrics->other_metric->nb_interest_drop++;   
        	break;
        case IDMETRIC_DATA_DROP:
			ndn_metrics->other_metric->nb_data_drop++;   
			if(strstr(ndn_metrics->other_metric->list_dropped_prefix, entry) != NULL) {
				/* ... */
			}else if(strstr(ndn_metrics->pit_metric->list_updated_entries, entry) != NULL){
				strcat(ndn_metrics->other_metric->list_dropped_prefix, entry);
				strcat(ndn_metrics->other_metric->list_dropped_prefix, " ");
				//printf("===%u list_dropped_prefix : %s\n",(uint32_t)(ndn_metrics->report_time)->tv_sec,ndn_metrics->other_metric->list_dropped_prefix);
			}else{
				//printf(">>>not updated entries : %s\n",entry);
			}
			
        	break;
        case IDMETRIC_NACK_DROP:
        	ndn_metrics->other_metric->nb_nack_drop++;   
        	break;
	}
}
/**
*	PIT METRIC
*/

pit_metric_detector_t * new_pit_metric_detector() {
	pit_metric_detector_t * pit_metric = (pit_metric_detector_t*)malloc(sizeof(pit_metric_detector_t));
	if (pit_metric == NULL) {
		log_err( "Cannot allocate memory while creating new pit_metric detector struct\n");
		return NULL;
	}
	pit_metric->nb_pit_create = 0;
	pit_metric->nb_pit_update = 0;
	pit_metric->nb_pit_remove = 0;
	pit_metric->nb_pit = 0;
	pit_metric->pit_time = 0;
	pit_metric->list_updated_entries = malloc(1024);
	strcpy(pit_metric->list_updated_entries, " ");
	return pit_metric;
}

/**
 * Free an pit_metric detector structure
 * @param pit_metric pit_metric detecture struct to be freed
 */
void free_pit_metric_detector(pit_metric_detector_t * pit_metric) {

	if (pit_metric == NULL) return;
	pit_metric->nb_pit_create = 0;
	pit_metric->nb_pit_update = 0;
	pit_metric->nb_pit_remove = 0;
	pit_metric->nb_pit = 0;
	pit_metric->pit_time = 0;
	free(pit_metric->list_updated_entries);
	free(pit_metric);
}

/**
* 	Update pit metric in case concerne PIT 
*	- PIT create = FC.In.Interest - OnInterestLoop
*	- PIT update = 2nd FC.In.Interest + CS.Insert + CS.Miss + InNACK
*	- PIT delete = On.In.Finalize
*/

void pit_metric_detector_update_data(ndn_metrics_detector_t * ndn_metrics, short id_metric, char * entry, struct timeval * time) {
	if (ndn_metrics == NULL) {
		log_err( "[ndn_metrics-ERROR] ndn_metrics detector is NULL\n");
		return;
	}
	int id_entry;
	switch (id_metric) {
        case IDMETRIC_FACE_IN_INTEREST:   
        	add_entry_ndn_metrics(ndn_metrics,entry,time);
        	break;
     	case IDMETRIC_CS_MISS:
     	case IDMETRIC_CS_INSERT:
     	case IDMETRIC_FACE_IN_NACK:
     		if (check_list_entries(ndn_metrics,entry)>-1){
     			ndn_metrics->pit_metric->nb_pit_update++;
     		}        	
        	break;
        case IDMETRIC_PIT_DELETE:
        	id_entry=check_list_entries(ndn_metrics,entry);
        	if (id_entry>=0){
     			//ndn_metrics->pit_metric->pit_time = round((ndn_metrics->pit_metric->pit_time * ndn_metrics->pit_metric->nb_pit_remove + get_diff_time_ms_ndn_metric((&ndn_metrics->list_entries_metric[id_entry])->create_time,time))/(ndn_metrics->pit_metric->nb_pit_remove+1));
     			if (get_diff_time_ms_ndn_metric((&ndn_metrics->list_entries_metric[id_entry])->create_time,time)>0)
     				ndn_metrics->pit_metric->pit_time = abs(ndn_metrics->pit_metric->pit_time) + abs(get_diff_time_ms_ndn_metric((&ndn_metrics->list_entries_metric[id_entry])->create_time,time));     			
     			if (ndn_metrics->pit_metric->pit_time<0)
     				ndn_metrics->pit_metric->pit_time=0;
     			//printf("get_diff_time_ms_ndn_metric : %"PRIu64"\n", get_diff_time_ms_ndn_metric((&ndn_metrics->list_entries_metric[id_entry])->create_time,time));
     			//printf("ndn_metrics->pit_metric->pit_time : %"PRIu64"\n", ndn_metrics->pit_metric->pit_time);
     			ndn_metrics->pit_metric->nb_pit_remove++; 
     			if (ndn_metrics->pit_metric->nb_pit>0)
     				ndn_metrics->pit_metric->nb_pit--;        			
     			remove_entry(ndn_metrics,id_entry);
     		}
        	break;
        case IDMETRIC_INTEREST_LOOP:
        	id_entry=check_list_entries(ndn_metrics,entry);
        	if (id_entry>=0){
     			remove_entry(ndn_metrics,id_entry);
     			if (ndn_metrics->pit_metric->nb_pit>0)
     				ndn_metrics->pit_metric->nb_pit--;  
     			if (ndn_metrics->pit_metric->nb_pit_create>0)
     				ndn_metrics->pit_metric->nb_pit_create--;
     		}
        	break;
	}
}

/**
*	PIT ENTRY METRIC
*/

entry_metric_detector_t * new_entry_metric_detector(char * entry,struct timeval * time) {
	entry_metric_detector_t * entry_metric = (entry_metric_detector_t*)malloc(sizeof(entry_metric_detector_t));
	if (entry_metric == NULL) {
		log_err( "Cannot allocate memory while creating new entry_metric detector struct\n");
		return NULL;
	}
	entry_metric->entry = malloc (sizeof(char)*(strlen(entry)+1));
	memcpy(entry_metric->entry,entry,strlen(entry));
	entry_metric->entry[strlen(entry)]='\0';
	entry_metric->create_time=malloc(sizeof(struct timeval));
	memcpy(entry_metric->create_time,time,sizeof(struct timeval));
	return entry_metric;
}

/**
 * Free an entry_metric detector structure
 * @param entry_metric entry_metric detecture struct to be freed
 */
void free_entry_metric_detector(entry_metric_detector_t * entry_metric) {

	if (entry_metric == NULL) return;
	//entry_metric->is_in_pit=0;
	free(entry_metric->create_time);
	free(entry_metric->entry);
	//free(entry_metric);
}

/**
*	Remove an entry from the list
*/

void remove_entry(ndn_metrics_detector_t * ndn_metrics,int id_entry){
	//printf("nb_entries %lu\n",ndn_metrics->nb_entries);
	/*int i;
	for(i = id_entry; i < ndn_metrics->nb_entries-1; i++) {
		entry_metric_detector_t * new_entry=new_entry_metric_detector((&ndn_metrics->list_entries_metric[i+1])->entry,(&ndn_metrics->list_entries_metric[i+1])->create_time);
		ndn_metrics->list_entries_metric[i]=* new_entry;		
	}*/
	free((&ndn_metrics->list_entries_metric[id_entry])->entry);
	free((&ndn_metrics->list_entries_metric[id_entry])->create_time);
	//free((&ndn_metrics->list_entries_metric[id_entry]));
	ndn_metrics->list_entries_metric[id_entry]=ndn_metrics->list_entries_metric[ndn_metrics->nb_entries-1];
	ndn_metrics->nb_entries--;
	return;
}

/**
*	Check if entry is in list, if yes return its id
*/

int check_list_entries(ndn_metrics_detector_t * ndn_metrics,char * entry){
	//printf("nb_entries %lu\n",ndn_metrics->nb_entries);
	int i;
	for(i = 0; i < ndn_metrics->nb_entries; i++) {
		entry_metric_detector_t * entry_metric_tmp = &ndn_metrics->list_entries_metric[i];
		if ((strcmp(entry_metric_tmp->entry, entry)==0) ){
			return i;
		}
	}
	return -1;
}

/**
*	Print list entries
*/

void print_list_id_entry(ndn_metrics_detector_t * ndn_metrics){
	int i;
	printf("===============print_list_id_entry=============\n");
	for(i = 0; i < ndn_metrics->nb_entries; i++) {
		printf("%s : %lu \n",(&ndn_metrics->list_entries_metric[i])->entry, (&ndn_metrics->list_entries_metric[i])->create_time->tv_sec);		
	}
}

/**
*	CREATE A NEW ENTRY METRIC
*/

void add_entry_ndn_metrics(ndn_metrics_detector_t * ndn_metrics, char * entry,struct timeval * time){
	if (check_list_entries(ndn_metrics,entry)<0){
		entry_metric_detector_t * new_entry=new_entry_metric_detector(entry,time);
		ndn_metrics->list_entries_metric[ndn_metrics->nb_entries] = *new_entry;
		ndn_metrics->nb_entries++;
		ndn_metrics->pit_metric->nb_pit_create++;
		ndn_metrics->pit_metric->nb_pit++;
	}else{
		if(strstr(ndn_metrics->pit_metric->list_updated_entries, entry) != NULL) {
				/* ... */
		}else {
			strcat(ndn_metrics->pit_metric->list_updated_entries, entry);
			strcat(ndn_metrics->pit_metric->list_updated_entries, " ");
			//printf("list_updated_entries : %s\n",ndn_metrics->pit_metric->list_updated_entries);
		}
		ndn_metrics->pit_metric->nb_pit_update++;
	}
}

/**
*	FACE METRIC
*/

face_metric_detector_t * new_face_metric_detector(uint16_t face_id) {
	face_metric_detector_t * face_metric = (face_metric_detector_t*)malloc(sizeof(face_metric_detector_t));
	if (face_metric == NULL) {
		log_err( "Cannot allocate memory while creating new face_metric detector struct\n");
		return NULL;
	}
	face_metric->face_id = face_id;
	face_metric->nb_face_in_interest = 0;
	face_metric->nb_face_in_data = 0;
	face_metric->nb_face_in_nack = 0;
	face_metric->nb_face_out_interest = 0;
	face_metric->nb_face_out_data = 0;
	face_metric->nb_face_out_nack = 0;
	return face_metric;
}

/**
 * Free an face_metric detector structure
 * @param face_metric face_metric detecture struct to be freed
 */
void free_face_metric_detector(face_metric_detector_t * face_metric) {

	if (face_metric == NULL) return;
	face_metric->face_id = 0;
	face_metric->nb_face_in_interest = 0;
	face_metric->nb_face_in_data = 0;
	face_metric->nb_face_in_nack = 0;
	face_metric->nb_face_out_interest = 0;
	face_metric->nb_face_out_data = 0;
	face_metric->nb_face_out_nack = 0;
	free(face_metric);
}

/**
*	Update FC.IN/OUT.INTEREST/DATA/NACK
*/

void face_metric_detector_update_data(ndn_metrics_detector_t * ndn_metrics, uint16_t face_id, short id_metric) {
	int i;
	for(i = 0; i < ndn_metrics->nb_faces; i++) {
		face_metric_detector_t face_metric_tmp =ndn_metrics->list_faces_metric[i];
		if ((&ndn_metrics->list_faces_metric[i])->face_id == face_id){
			switch (id_metric) {
		        case IDMETRIC_FACE_IN_INTEREST:
					(&ndn_metrics->list_faces_metric[i])->nb_face_in_interest++;
		            break;
		        case IDMETRIC_FACE_IN_DATA:
		            (&ndn_metrics->list_faces_metric[i])->nb_face_in_data++;
		            break;
		        case IDMETRIC_FACE_IN_NACK:
		            (&ndn_metrics->list_faces_metric[i])->nb_face_in_nack++;
		            break;
		        case IDMETRIC_FACE_OUT_INTEREST:
		            (&ndn_metrics->list_faces_metric[i])->nb_face_out_interest++;
		            break;
		        case IDMETRIC_FACE_OUT_DATA:
		            (&ndn_metrics->list_faces_metric[i])->nb_face_out_data++;
		            break;
		        case IDMETRIC_FACE_OUT_NACK:
		            (&ndn_metrics->list_faces_metric[i])->nb_face_out_nack++;
		            break;
		    }
			return;
		}
	}
	return;
	
}


void findSpecialChar(char special, char * val, int end_index, int * begin_pos, int * end_pos){
	//char special='/';
	int count_special=0;
	int i;
	*begin_pos=0;
	for (i=0;i<(strlen(val)-1);i++){
		char c = val[i];
		if (c == special){
			if (end_index==count_special){
				*end_pos=i;
				break;
			}else{
				*begin_pos=i;
			}
			count_special++;
		}
	}
}

/**
*	GET ENTRY PREFIX FROM NFD_LOG LINE
*/

char* extract_entry(char * token2){
	short i3=0;
	char * token3;
	char * entry=NULL;
	if (strlen(token2)>0){
		while ((token3 = strsep(&token2, "="))) {
			if (i3==1){
				char * token4=NULL;
				short i4=0;
				while ((token4 = strsep(&token3, "~"))) {
					if (i4==0){
						char * token5=NULL;
						short i5=0;
						while ((token5 = strsep(&token4, "\n"))) {
							if (i5==0){
								entry = malloc (sizeof(char)*(strlen(token5)+1));
								memcpy(entry,token5,strlen(token5));
								entry[strlen(token5)]='\0';
								//printf("extract_entry %s\n",entry);
								return entry;
								break;
							}
							i5++;
						}
						break;
					}
					i4++;
				}
				break;
			}
			i3++;
		}										
	}
	return entry;
}

/*short filter_localhost(char * data){
	int i2=0;
	char * token2;
	while ((token2 = strsep(&data, "/"))) {
		if (i2==1){
			// check if the interest is a internal exchange interest/data of NFD|| strcmp(token2,"localhop") ==0			
			if (strcmp(token2,"localhost") ==0 ){
				//printf("	VIOLATE: %s\n",token2);
				return 0;
			}else{
				return 1;
			}
			break;
		}
		i2++;
	}
	return 1;
}*/

short filter_localhost(char * data){
	int begin_pos=0;
	int end_pos=0;
	//printf("%s\n",data);
	findSpecialChar('/', data, 1, &begin_pos, &end_pos);
	char * tmp_str = malloc(sizeof(char) * (end_pos - begin_pos+1));
	strncpy(tmp_str, data + begin_pos, end_pos - begin_pos);
	tmp_str[end_pos - begin_pos]='\0';
	//printf("%s\n",tmp_str);
	if (strcmp(tmp_str,"/localhost") ==0 ){
		//printf("	VIOLATE: %s\n",tmp_str);
		free(tmp_str);
		return 0;
	}else{
		//printf("	OK: %s\n",tmp_str);
		free(tmp_str);
		return 1;
	}
}

void reset_compter(ndn_metrics_detector_t * ndn_metrics){
	ndn_metrics->cs_metric->nb_cs_miss = 0;
	ndn_metrics->cs_metric->nb_cs_hit = 0;
	ndn_metrics->cs_metric->nb_cs_insert = 0;
	ndn_metrics->other_metric->nb_interest_loop = 0;
	ndn_metrics->other_metric->nb_interest_unsatisfied = 0;
	ndn_metrics->other_metric->nb_interest_drop = 0;
	ndn_metrics->other_metric->nb_data_drop = 0;
	ndn_metrics->other_metric->nb_nack_drop = 0;
	ndn_metrics->pit_metric->nb_pit_create = 0;
	ndn_metrics->pit_metric->nb_pit_update = 0;
	ndn_metrics->pit_metric->nb_pit_remove = 0;
	free(ndn_metrics->pit_metric->list_updated_entries);
	ndn_metrics->pit_metric->list_updated_entries = malloc(1024);
	strcpy(ndn_metrics->pit_metric->list_updated_entries, " ");
	//ndn_metrics->pit_metric->nb_pit = 0;
	ndn_metrics->pit_metric->pit_time = 0;
	free(ndn_metrics->other_metric->list_dropped_prefix);
	ndn_metrics->other_metric->list_dropped_prefix = malloc(1024);
	strcpy(ndn_metrics->other_metric->list_dropped_prefix, " ");
	int i=0;
	for(i = 0; i < ndn_metrics->nb_faces; i++) {
		(&ndn_metrics->list_faces_metric[i])->nb_face_in_interest = 0;
		(&ndn_metrics->list_faces_metric[i])->nb_face_in_data = 0;
		(&ndn_metrics->list_faces_metric[i])->nb_face_in_nack = 0;
		(&ndn_metrics->list_faces_metric[i])->nb_face_out_interest = 0;
		(&ndn_metrics->list_faces_metric[i])->nb_face_out_data = 0;
		(&ndn_metrics->list_faces_metric[i])->nb_face_out_nack = 0;
	}
	
}