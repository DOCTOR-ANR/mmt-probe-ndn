/* Generated with MMT Plugin Generator */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nfd_log_mmt_plugin.h"
#include "extraction_lib.h"




/*
 * NFD_LOG data extraction routines
 */


classified_proto_t nfd_log_stack_classification(ipacket_t * ipacket) {
	classified_proto_t retval;
	retval.offset = 0;
	retval.proto_id = PROTO_NFD_LOG;
	retval.status = Classified;
	return retval;
}

void findSpace(char * val, int end_index, int * begin_pos, int * end_pos){
	char space=' ';
	int count_space=0;
	int i;
	*begin_pos=0;
	for (i=0;i<(strlen(val)-1);i++){
		char c = val[i];
		if (c == space){
			if (end_index==count_space){
				*end_pos=i;
				break;
			}else{
				*begin_pos=i;
			}
			count_space++;
		}
	}
}

/*
 * TIMEVAL of the event
 */

int nfd_log_time_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
	char * val;
	val = (char*)&ipacket->data[0];
	int i;
	int begin_pos=0;
	int end_pos=0;
	findSpace(val, 0, &begin_pos, &end_pos);
	char * tmp_str = malloc(sizeof(char) * (end_pos - begin_pos+1));
	strncpy(tmp_str, val + begin_pos, end_pos - begin_pos);
	tmp_str[end_pos - begin_pos]='\0';

	i=0;

	struct timeval * tv = (struct timeval*)malloc(sizeof(struct timeval));
	char * token2 = NULL;
	while ((token2 = strsep(&tmp_str, "."))) {
		if ((i==0)){
			tv->tv_sec = (time_t) strtol(token2, NULL, 10); 
		}else{
			tv->tv_usec = (suseconds_t) strtol(token2, NULL, 10); 
		}
		++i;
	}
	extracted_data->data=(struct timeval *) (tv);
	free(tmp_str);

    return 1;
}

/*
 * Level of log: DEBUG/ WARNING / INFO / ERROR ...
 */

int nfd_log_level_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
    char * val;
	val = (char*)&ipacket->data[0];
	int begin_pos=0;
	int end_pos=0;
	findSpace(val, 1, &begin_pos, &end_pos);
	char * tmp_str = malloc(sizeof(char) * (end_pos - begin_pos));
	strncpy(tmp_str, val + begin_pos+1, end_pos - begin_pos-1);
	tmp_str[end_pos - begin_pos-1]='\0';
	extracted_data->data=(char*)tmp_str;
    return 1;
}

/*
 * Module of log: Forwarder / ContentStore / ...
 */

int nfd_log_module_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
    char * val;
	val = (char*)&ipacket->data[0];
	int begin_pos=0;
	int end_pos=0;
	findSpace(val, 2, &begin_pos, &end_pos);
	char * tmp_str = malloc(sizeof(char) * (end_pos - begin_pos));
	strncpy(tmp_str, val + begin_pos+1, end_pos - begin_pos-1);
	tmp_str[end_pos - begin_pos-1]='\0';
	extracted_data->data=(char*)tmp_str;
    
    return 1;
}

/*
 * Action : OnContentStoreMiss/ OnContentStoreHit / Insert to ContentStore ...
 */

int nfd_log_action_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
    char * val;
	val = (char*)&ipacket->data[0];
	int begin_pos=0;
	int end_pos=0;
	findSpace(val, 3, &begin_pos, &end_pos);
	char * tmp_str = malloc(sizeof(char) * (end_pos - begin_pos));
	strncpy(tmp_str, val + begin_pos+1, end_pos - begin_pos-1);
	tmp_str[end_pos - begin_pos-1]='\0';
	extracted_data->data=(char*)tmp_str;
    
    return 1;
}

/*
 * Other Data, normally, name of Interest/Data
 */

int nfd_log_data_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
    char * val;
	val = (char*)&ipacket->data[0];
	int begin_pos=0;
	int end_pos=0;
	findSpace(val, 3, &begin_pos, &end_pos);
	char * tmp_str = malloc(sizeof(char) * (strlen(val) - end_pos));
	strncpy(tmp_str, val + end_pos+1, strlen(val) - end_pos-1);
	tmp_str[strlen(val) - end_pos-1]='\0';
	extracted_data->data=(char*)tmp_str;    
    return 1;
}

/*
 * Number of OnContentStoreMiss, extract from line of log, which is not extract directly from the line but from the handler in smp_main.
 */

int nfd_log_id_metric_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
    extracted_data->data=0;
    return 1;
}

/*
 * Number of OnContentStoreHit, extract from line of log, which is not extract directly from the line but from the handler in smp_main.
 */

int nfd_log_count_metric_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
    extracted_data->data=0;
    return 1;
}

/*
 * Number of OnContentStoreHit, extract from line of log, which is not extract directly from the line but from the handler in smp_main.
 */

int nfd_log_face_id_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
    extracted_data->data=0;
    return 1;
}

/*
 * Timestamp in sec.
 */

int nfd_log_timestamp_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){	
	extracted_data->data=0;
	return 1;
}

static attribute_metadata_t nfd_log_attributes_metadata[NFD_LOG_ATTRIBUTES_NB] = {

	{NFD_LOG_TIME, NFD_LOG_TIME_ALIAS, MMT_DATA_TIMEVAL, sizeof(struct timeval), 0, SCOPE_PACKET, nfd_log_time_extraction},

	{NFD_LOG_LEVEL, NFD_LOG_LEVEL_ALIAS, MMT_STRING_DATA, STRING_DATA_LEN, 0, SCOPE_PACKET, nfd_log_level_extraction},

	{NFD_LOG_MODULE, NFD_LOG_MODULE_ALIAS, MMT_STRING_DATA, STRING_DATA_LEN, 0, SCOPE_PACKET, nfd_log_module_extraction},

	{NFD_LOG_ACTION, NFD_LOG_ACTION_ALIAS, MMT_STRING_DATA, STRING_DATA_LEN, 0, SCOPE_PACKET, nfd_log_action_extraction},

	{NFD_LOG_DATA, NFD_LOG_DATA_ALIAS, MMT_STRING_DATA_POINTER, STRING_DATA_LEN, 0, SCOPE_PACKET, nfd_log_data_extraction},
	
	{NFD_LOG_ID_METRIC, NFD_LOG_ID_METRIC_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 0, SCOPE_PACKET, nfd_log_id_metric_extraction},

	{NFD_LOG_COUNT_METRIC, NFD_LOG_COUNT_METRIC_ALIAS, MMT_U64_DATA, sizeof(uint64_t), 0, SCOPE_PACKET, nfd_log_count_metric_extraction},

	{NFD_LOG_TIMESTAMP, NFD_LOG_TIMESTAMP_ALIAS, MMT_U32_DATA, sizeof(uint32_t), 0, SCOPE_PACKET, nfd_log_timestamp_extraction},

	{NFD_LOG_FACE_ID, NFD_LOG_FACE_ID_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 0, SCOPE_PACKET, nfd_log_face_id_extraction},

};


int init_nfd_log_proto_struct() {
	protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_NFD_LOG, PROTO_NFD_LOG_ALIAS);

	if (protocol_struct != NULL) {

		int i = 0;
		for(; i < NFD_LOG_ATTRIBUTES_NB; i ++) {
			register_attribute_with_protocol(protocol_struct, &nfd_log_attributes_metadata[i]);
		}


		register_protocol_stack(PROTO_NFD_LOG, PROTO_NFD_LOG_ALIAS, nfd_log_stack_classification);
		return register_protocol(protocol_struct, PROTO_NFD_LOG);
	} else {
		return -1;
	}
}

#ifndef CORE
int init_proto() {
	return init_nfd_log_proto_struct();
}
#endif //CORE

