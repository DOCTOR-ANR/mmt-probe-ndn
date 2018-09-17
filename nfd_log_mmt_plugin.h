/* Generated with MMT Plugin Generator */

#ifndef NFD_LOG_H
#define NFD_LOG_H
#ifdef	__cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"


#define PROTO_NFD_LOG 645

#define PROTO_NFD_LOG_ALIAS "NFD_LOG"


	enum nfd_log_attributes {

		NFD_LOG_TIME = 1,

		NFD_LOG_LEVEL,

		NFD_LOG_MODULE,

		NFD_LOG_ACTION,
		
		NFD_LOG_DATA,

		NFD_LOG_ID_METRIC,

		NFD_LOG_COUNT_METRIC,

		NFD_LOG_TIMESTAMP,
		
		NFD_LOG_FACE_ID,

		NFD_LOG_ATTRIBUTES_NB = NFD_LOG_FACE_ID,

	};


#define NFD_LOG_TIME_ALIAS "time"

#define NFD_LOG_LEVEL_ALIAS "level"

#define NFD_LOG_MODULE_ALIAS "module"

#define NFD_LOG_ACTION_ALIAS "action"

#define NFD_LOG_DATA_ALIAS "data"

#define NFD_LOG_ID_METRIC_ALIAS "id_metric"

#define NFD_LOG_COUNT_METRIC_ALIAS "count_metric"

#define NFD_LOG_TIMESTAMP_ALIAS "timestamp"

#define NFD_LOG_FACE_ID_ALIAS "face_id"

	struct attrs {
		uint8_t ID_METRIC;
		uint64_t COUNT_METRIC;
		uint32_t TIMESTAMP;
		uint16_t FACE_ID;
		char ACTION, LEVEL, MODULE, DATA ;
		struct timeval TIME;
	};

	int init_nfd_log_proto_struct();

#ifndef CORE
	int init_proto();
#endif //CORE



#ifdef	__cplusplus
}
#endif
#endif	/* NFD_LOG_H */


