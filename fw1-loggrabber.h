/******************************************************************************/
/* fw1-loggrabber - (C)2005 Torsten Fellhauer, Xiaodong Lin                   */
/******************************************************************************/
/* Version: 1.11                                                              */
/******************************************************************************/
/*                                                                            */
/* Copyright (c) 2005 Torsten Fellhauer, Xiaodong Lin                         */
/* All rights reserved.                                                       */
/*                                                                            */
/* Redistribution and use in source and binary forms, with or without         */
/* modification, are permitted provided that the following conditions         */
/* are met:                                                                   */
/* 1. Redistributions of source code must retain the above copyright          */
/*    notice, this list of conditions and the following disclaimer.           */
/* 2. Redistributions in binary form must reproduce the above copyright       */
/*    notice, this list of conditions and the following disclaimer in the     */
/*    documentation and/or other materials provided with the distribution.    */
/*                                                                            */
/* THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND     */
/* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE      */
/* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE */
/* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE    */
/* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL */
/* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS    */
/* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)      */
/* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT */
/* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY  */
/* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF     */
/* SUCH DAMAGE.                                                               */
/*                                                                            */
/******************************************************************************/


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

#define  SLEEP(sec) sleep(sec)
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <endian.h>
#include <syslog.h>

/*
 * OPSEC SDK related header files
 */
#include "opsec/opsec.h"
#include "opsec/opsec_event.h"
#include "opsec/lea.h"
#include "opsec/lea_filter.h"
#include "opsec/lea_filter_ext.h"

/*
 * fw1-loggrabber own header files
 */
#include "queue.h"
#include "thread.h"

/*
 * Constant definitions
 */
#define VERSION                        "1.11"

#define TRUE                    1
#define FALSE                   0

#define DATETIME_CP             0
#define DATETIME_UNIX           1
#define DATETIME_STD            2

#define LIDX_NUM                0
#define LIDX_TIME               1
#define LIDX_ACTION             2
#define LIDX_ORIG               3
#define LIDX_ALERT              4
#define LIDX_IF_DIR             5
#define LIDX_IF_NAME            6
#define LIDX_HAS_ACCOUNTING     7
#define LIDX_UUID               8
#define LIDX_PRODUCT            9
#define LIDX_POLICY_ID_TAG      10
#define LIDX_SRC                11
#define LIDX_S_PORT             12
#define LIDX_DST                13
#define LIDX_SERVICE            14
#define LIDX_TCP_FLAGS          15
#define LIDX_PROTO              16
#define LIDX_RULE               17
#define LIDX_XLATESRC           18
#define LIDX_XLATEDST           19
#define LIDX_XLATESPORT         20
#define LIDX_XLATEDPORT         21
#define LIDX_NAT_RULENUM        22
#define LIDX_RESOURCE           23
#define LIDX_ELAPSED            24
#define LIDX_PACKETS            25
#define LIDX_BYTES              26
#define LIDX_REASON             27
#define LIDX_SERVICE_NAME       28
#define LIDX_AGENT              29
#define LIDX_FROM               30
#define LIDX_TO                 31
#define LIDX_SYS_MSGS           32
#define LIDX_FW_MESSAGE         33
#define LIDX_INTERNAL_CA        34
#define LIDX_SERIAL_NUM         35
#define LIDX_DN                 36
#define LIDX_ICMP               37
#define LIDX_ICMP_TYPE          38
#define LIDX_ICMP_TYPE2         39
#define LIDX_ICMP_CODE          40
#define LIDX_ICMP_CODE2         41
#define LIDX_MSGID              42
#define LIDX_MESSAGE_INFO       43
#define LIDX_LOG_SYS_MESSAGE    44
#define LIDX_SESSION_ID         45
#define LIDX_DNS_QUERY          46
#define LIDX_DNS_TYPE           47
#define LIDX_SCHEME             48
#define LIDX_SRCKEYID           49
#define LIDX_DSTKEYID           50
#define LIDX_METHODS            51
#define LIDX_PEER_GATEWAY       52
#define LIDX_IKE                53
#define LIDX_IKE_IDS            54
#define LIDX_ENCRYPTION_FAILURE 55
#define LIDX_ENCRYPTION_FAIL_R  56
#define LIDX_COOKIEI            57
#define LIDX_COOKIER            58
#define LIDX_START_TIME         59
#define LIDX_SEGMENT_TIME       60
#define LIDX_CLIENT_IN_PACKETS  61
#define LIDX_CLIENT_OUT_PACKETS 62
#define LIDX_CLIENT_IN_BYTES    63
#define LIDX_CLIENT_OUT_BYTES   64
#define LIDX_CLIENT_IN_IF       65
#define LIDX_CLIENT_OUT_IF      66
#define LIDX_SERVER_IN_PACKETS  67
#define LIDX_SERVER_OUT_PACKETS 68
#define LIDX_SERVER_IN_BYTES    69
#define LIDX_SERVER_OUT_BYTES   70
#define LIDX_SERVER_IN_IF       71
#define LIDX_SERVER_OUT_IF      72
#define LIDX_MESSAGE            73
#define LIDX_NAT_ADDRULENUM     74
#define LIDX_USER               75
#define LIDX_SRCNAME            76
#define LIDX_VPN_USER           77
#define LIDX_OM                 78
#define LIDX_OM_METHOD          79
#define LIDX_ASSIGNED_IP        80
#define LIDX_MAC                81
#define LIDX_ATTACK             82
#define LIDX_ATTACK_INFO        83
#define LIDX_CLUSTER_INFO       84
#define LIDX_DCE_RPC_UUID       85
#define LIDX_DCE_RPC_UUID_1     86
#define LIDX_DCE_RPC_UUID_2     87
#define LIDX_DCE_RPC_UUID_3     88
#define LIDX_DURING_SEC         89
#define LIDX_FRAGMENTS_DROPPED  90
#define LIDX_IP_ID              91
#define LIDX_IP_LEN             92
#define LIDX_IP_OFFSET          93
#define LIDX_TCP_FLAGS2         94
#define LIDX_SYNC_INFO          95
#define LIDX_LOG                96
#define LIDX_CPMAD              97
#define LIDX_AUTH_METHOD        98
#define LIDX_TCP_PACKET_OOS     99
#define LIDX_RPC_PROG           100
#define LIDX_TH_FLAGS           101
#define LIDX_CP_MESSAGE         102
#define LIDX_REJECT_CATEGORY    103
#define LIDX_IKE_LOG            104
#define LIDX_NEGOTIATION_ID     105
#define LIDX_DECRYPTION_FAILURE 106
#define LIDX_LEN                107

// TODO: warning, untested fields
#define LIDX_ANALYZED_ON 108
#define LIDX_APP_CATEGORY 109
#define LIDX_APP_DESC 110
#define LIDX_APP_ID 111
#define LIDX_APPI_NAME 112
#define LIDX_APP_PROPERTIES 113
#define LIDX_APP_RISK 114
#define LIDX_APP_RULE_ID 115
#define LIDX_APP_RULE_NAME 116
#define LIDX_APP_SIG_ID 117
#define LIDX_AVERAGE_EMULATED_FILE_SIZE 118
#define LIDX_AVERAGE_EMULATED_FILE_SIZE_LAST_DAY 119
#define LIDX_AVERAGE_EMULATED_FILE_SIZE_LAST_MONTH 120
#define LIDX_AVERAGE_EMULATED_FILE_SIZE_LAST_WEEK 121
#define LIDX_AVERAGE_PROCESS_TIME 122
#define LIDX_AVERAGE_PROCESS_TIME_LAST_DAY 123
#define LIDX_AVERAGE_PROCESS_TIME_LAST_MONTH 124
#define LIDX_AVERAGE_PROCESS_TIME_LAST_WEEK 125
#define LIDX_AVERAGE_QUEUE_SIZE 126
#define LIDX_AVERAGE_QUEUE_SIZE_LAST_DAY 127
#define LIDX_AVERAGE_QUEUE_SIZE_LAST_MONTH 128
#define LIDX_AVERAGE_QUEUE_SIZE_LAST_WEEK 129
#define LIDX_BLADE_DESCRIPTION 130
#define LIDX_BLADE_STATUS 131
#define LIDX_CACHE_HIT_RATE 132
#define LIDX_CACHE_HIT_RATE_LAST_DAY 133
#define LIDX_CACHE_HIT_RATE_LAST_MONTH 134
#define LIDX_CACHE_HIT_RATE_LAST_WEEK 135
#define LIDX_CLOUD_HOURLY_QUOTA 136
#define LIDX_CLOUD_HOURLY_QUOTA_EXCEEDED 137
#define LIDX_CLOUD_HOURLY_QUOTA_USAGE_FOR_QUOTA_ID 138
#define LIDX_CLOUD_HOURLY_QUOTA_USAGE_FOR_THIS_GW 139
#define LIDX_CLOUD_HOURLY_REMAINING_QUOTA 140
#define LIDX_CLOUD_LAST_QUOTA_UPDATE_GMT_TIME 141
#define LIDX_CLOUD_MONTHLY_QUOTA 142
#define LIDX_CLOUD_MONTHLY_QUOTA_EXCEEDED 143
#define LIDX_CLOUD_MONTHLY_QUOTA_PERIOD_END 144
#define LIDX_CLOUD_MONTHLY_QUOTA_PERIOD_START 145
#define LIDX_CLOUD_MONTHLY_QUOTA_USAGE_FOR_QUOTA_ID 146
#define LIDX_CLOUD_MONTHLY_QUOTA_USAGE_FOR_THIS_GW 147
#define LIDX_CLOUD_QUOTA_DESCRIPTION 148
#define LIDX_CLOUD_QUOTA_IDENTIFIER 149
#define LIDX_CLOUD_QUOTA_STATUS 150
#define LIDX_CLOUD_REMAINING_QUOTA 151
#define LIDX_CONFIDENCE_LEVEL 152
#define LIDX_CONNECTION_STATE 153
#define LIDX_DB_VER 154
#define LIDX_DESCRIPTION 155
#define LIDX_DETECTED_ON 156
#define LIDX_DOWNLOADED_FILES_SCANNED 157
#define LIDX_EMAIL_SCANNED 158
#define LIDX_EMULATED_ON 159
#define LIDX_ENGINE_MAJOR_VERSION 160
#define LIDX_ENGINE_MINOR_VERSION 161
#define LIDX_ERROR_COUNT 162
#define LIDX_ERROR_COUNT_LAST_DAY 163
#define LIDX_ERROR_COUNT_LAST_MONTH 164
#define LIDX_ERROR_COUNT_LAST_WEEK 165
#define LIDX_FILE_MD5 166
#define LIDX_FILE_NAME 167
#define LIDX_FILE_NAME 168
#define LIDX_FILE_SHA1 169
#define LIDX_FILES_IN_QUEUE 170
#define LIDX_FILE_SIZE 171
#define LIDX_FILE_TYPE 172
#define LIDX_FILTER_BY_STATIC_ANALYSIS 173
#define LIDX_FILTER_BY_STATIC_ANALYSIS_LAST_DAY 174
#define LIDX_FILTER_BY_STATIC_ANALYSIS_LAST_MONTH 175
#define LIDX_FILTER_BY_STATIC_ANALYSIS_LAST_WEEK 176
#define LIDX_FIRST_HIT_TIME 177
#define LIDX_FREQUENCY 178
#define LIDX_HIT 179
#define LIDX_INZONE 180
#define LIDX_IS_FIRST_DOWNLOAD 181
#define LIDX_LAST_HIT_TIME 182
#define LIDX_LOG_ID 183
#define LIDX_MALWARE_ACTION 184
#define LIDX_MALWARE_DETECTED 185
#define LIDX_MALWARE_DETECTED_LAST_DAY 186
#define LIDX_MALWARE_DETECTED_LAST_MONTH 187
#define LIDX_MALWARE_DETECTED_LAST_WEEK 188
#define LIDX_MALWARE_DETECTED_ON_THREAT_CLOUD 189
#define LIDX_MALWARE_DETECTED_ON_THREAT_CLOUD_LAST_DAY 190
#define LIDX_MALWARE_DETECTED_ON_THREAT_CLOUD_LAST_MONTH 191
#define LIDX_MALWARE_DETECTED_ON_THREAT_CLOUD_LAST_WEEK 192
#define LIDX_MALWARE_FAMILY 193
#define LIDX_MALWARE_RULE_ID 194
#define LIDX_MATCHED_CATEGORY 195
#define LIDX_MAX_VMS_NUM 196
#define LIDX_NEXT_UPDATE_DESC 197
#define LIDX_NO_RESOURCE_COUNT 198
#define LIDX_NO_RESOURCE_COUNT_LAST_DAY 199
#define LIDX_NO_RESOURCE_COUNT_LAST_MONTH 200
#define LIDX_NO_RESOURCE_COUNT_LAST_WEEK 201
#define LIDX_NUMBER_OF_EMULATION_ENVIRONMENTS 202
#define LIDX_ORIGIN_SIC_NAME 203
#define LIDX_OUTZONE 204
#define LIDX_PACKET_CAPTURE_NAME 205
#define LIDX_PACKET_CAPTURE_TIME 206
#define LIDX_PACKET_CAPTURE_UNIQUE_ID 207
#define LIDX_PACKET_ORIGIN 208
#define LIDX_PEAK_QUEUE_SIZE 209
#define LIDX_PEAK_QUEUE_SIZE_LAST_DAY 210
#define LIDX_PEAK_QUEUE_SIZE_LAST_MONTH 211
#define LIDX_PEAK_QUEUE_SIZE_LAST_WEEK 212
#define LIDX_PERFORMANCE_IMPACT 213
#define LIDX_POLICY 214
#define LIDX_PORTAL_MESSAGE 215
#define LIDX_PROTECTION_ID 216
#define LIDX_PROTECTION_NAME 217
#define LIDX_PROTECTION_NAME 218
#define LIDX_PROTECTION_TYPE 219
#define LIDX_PROXY_SRC_IP 220
#define LIDX_RECEIVED_BYTES 221
#define LIDX_REFID 222
#define LIDX_RULE_UID 223
#define LIDX_SCAN_HOSTS_DAY 224
#define LIDX_SCAN_HOSTS_HOUR 225
#define LIDX_SCAN_HOSTS_WEEK 226
#define LIDX_SCAN_MAIL 227
#define LIDX_SCANNED 228
#define LIDX_SCANNED_FILES 229
#define LIDX_SCANNED_FILES_LAST_DAY 230
#define LIDX_SCANNED_FILES_LAST_MONTH 231
#define LIDX_SCANNED_FILES_LAST_WEEK 232
#define LIDX_SCANNED_FILES_ON_THREAT_CLOUD 233
#define LIDX_SCANNED_FILES_ON_THREAT_CLOUD_LAST_DAY 234
#define LIDX_SCANNED_FILES_ON_THREAT_CLOUD_LAST_MONTH 235
#define LIDX_SCANNED_FILES_ON_THREAT_CLOUD_LAST_WEEK 236
#define LIDX_SCANNED_LAST_DAY 237
#define LIDX_SCANNED_LAST_MONTH 238
#define LIDX_SCANNED_LAST_WEEK 239
#define LIDX_SCAN_RESULT 240
#define LIDX_SCOPE 241
#define LIDX_SENT_BYTES 242
#define LIDX_SERVICE_ID 243
#define LIDX_SESSION_ID 244
#define LIDX_SEVERITY 245
#define LIDX_SEVERITY 246
#define LIDX_SHORT_DESC 247
#define LIDX_SMARTDEFENSE_PROFILE 248
#define LIDX_SOURCE 249
#define LIDX_SPECIAL_PROPERTIES 250
#define LIDX_STATUS 251
#define LIDX_SUBSCRIPTION_DESCRIPTION 252
#define LIDX_SUBSCRIPTION_STATUS 253
#define LIDX_SUBS_EXP 254
#define LIDX_SUPPRESSED_LOGS 255
#define LIDX_TE_VERDICT_DETERMINED_BY 256
#define LIDX_THREATCLOUD_MALWARE 257
#define LIDX_THREATCLOUD_MALWARE_DETECTED_LAST_DAY 258
#define LIDX_THREATCLOUD_MALWARE_DETECTED_LAST_MONTH 259
#define LIDX_THREATCLOUD_MALWARE_DETECTED_LAST_WEEK 260
#define LIDX_THREATCLOUD_SCANNED 261
#define LIDX_THREATCLOUD_SCANNED_LAST_DAY 262
#define LIDX_THREATCLOUD_SCANNED_LAST_MONTH 263
#define LIDX_THREATCLOUD_SCANNED_LAST_WEEK 264
#define LIDX_TICKET_ID 265
#define LIDX_TOTAL_LOGS 266
#define LIDX_UNIQUE_DETECTED_DAY 267
#define LIDX_UNIQUE_DETECTED_HOUR 268
#define LIDX_UNIQUE_DETECTED_WEEK 269
#define LIDX_UPDATE_DESCRIPTION 270
#define LIDX_UPDATE_STATUS 271
#define LIDX_UPDATE_STATUS 272
#define LIDX_USERCHECK 273
#define LIDX_USERCHECK_CONFIRMATION_LEVEL 274
#define LIDX_USERCHECK_INCIDENT_UID 275
#define LIDX_VERDICT 276
#define LIDX_WEB_CLIENT_TYPE 277
#define LIDX_WEB_SERVER_TYPE 278

#define NUMBER_LIDX_FIELDS      279
// count of the above (i.e. one more than the last)

#define AIDX_NUM                0
#define AIDX_TIME               1
#define AIDX_ACTION             2
#define AIDX_ORIG               3
#define AIDX_IF_DIR             4
#define AIDX_IF_NAME            5
#define AIDX_HAS_ACCOUNTING     6
#define AIDX_UUID               7
#define AIDX_PRODUCT            8
#define AIDX_OBJECTNAME         9
#define AIDX_OBJECTTYPE         10
#define AIDX_OBJECTTABLE        11
#define AIDX_OPERATION          12
#define AIDX_UID                13
#define AIDX_ADMINISTRATOR      14
#define AIDX_MACHINE            15
#define AIDX_SUBJECT            16
#define AIDX_AUDIT_STATUS       17
#define AIDX_ADDITIONAL_INFO    18
#define AIDX_OPERATION_NUMBER   19
#define AIDX_FIELDSCHANGES      20

#define NUMBER_AIDX_FIELDS      21
// count of the above (i.e. one more than the last)

#define SCREEN                  0
#define LOGFILE                 1
#define SYSLOG                  2

#define INITIAL_CAPACITY   1024
#define CAPACITY_INCREMENT 4096

/*
 * Type definitions
 */
typedef struct stringlist
{
  char *data;
  struct stringlist *next;
}
stringlist;

typedef struct configvalues
{
  int debug_mode;
  int online_mode;
  int resolve_mode;
  int fw1_2000;
  int audit_mode;
  int showfiles_mode;
  int fieldnames_mode;
  int dateformat;
  int log_mode;
  int syslog_facility;
  char record_separator;
  char *config_filename;
  char *leaconfig_filename;
  char *fw1_logfile;
  char *output_file_prefix;
  long output_file_rotatesize;
  char *fields;
  int fw1_filter_count;
  char **fw1_filter_array;
  int audit_filter_count;
  char **audit_filter_array;
}
configvalues;

/*
 * Function prototypes
 */

/*
 * function to get the content of a given FW-1 Logfile
 */
int read_fw1_logfile (char **);

/*
 * event handler used by read_fw1_logfile to approve a rulebase
 */
int read_fw1_logfile_queryack (OpsecSession *, int, eLeaFilterAction, int);

/*
 * event handler used by read_fw1_logfile to get session end reason
 */
int read_fw1_logfile_end (OpsecSession *);

/*
 * event handler used by read_fw1_logfile to print returned log records
 */
int read_fw1_logfile_record (OpsecSession *, lea_record *, int[]);

/*
 * dummy event handler for debugging purposes
 */
int read_fw1_logfile_dict (OpsecSession *, int, LEA_VT, int);

/*
 * dummy event handler for debugging purposes
 */
int read_fw1_logfile_eof (OpsecSession *);

/*
 * dummy event handler for debugging purposes
 */
int read_fw1_logfile_switch (OpsecSession *);

/*
 * dummy event handler for debugging purposes
 */
int read_fw1_logfile_collogs (OpsecSession *);

/*
 * dummy event handler for debugging purposes
 */
int read_fw1_logfile_suspend (OpsecSession *);

/*
 * dummy event handler for debugging purposes
 */
int read_fw1_logfile_resume (OpsecSession *);

/*
 * dummy event handler for debugging purposes
 */
int read_fw1_logfile_start (OpsecSession *);

/*
 * dummy event handler for debugging purposes
 */
int read_fw1_logfile_failedconn (OpsecEntity * entity, long peer_ip,
                                 int sic_errno, char *sic_errmsg);

/*
 * dummy event handler for debugging purposes
 */
int read_fw1_logfile_established (OpsecSession *);

/*
 * function to get all available FW-1 Logfile Names
 */
int get_fw1_logfiles ();

/*
 * event handler used by get_fw1_logfiles to print the Logfile Names
 */
int get_fw1_logfiles_dict (OpsecSession *, int, LEA_VT, int);

/*
 * event handler used by get_fw1_logfiles to get session end reason
 */
int get_fw1_logfiles_end (OpsecSession *);

/*
 * user defined event handle, which is used for flow control
 * P.S.: It is only for NG FP3
 */
int fc_handler (OpsecEnv *pEnv, long eventid, void *raise_data, void *set_data);

/*
 * function to create a new rule for a filter rulebase
 */
LeaFilterRulebase *create_fw1_filter_rule (LeaFilterRulebase *, char[255]);
LeaFilterRulebase *create_audit_filter_rule (LeaFilterRulebase *, char[255]);

/*
 * function to clean up the opsec environment
 */
void cleanup_fw1_environment (OpsecEnv *, OpsecEntity *, OpsecEntity *);

/*
 * function to read configfile
 */
void check_config_files (char *, char *);
void read_config_file (char *, struct configvalues *);

/*
 * initilization function to define open, submit and close handler
 */
void logging_init_env (int);

/*
 * syslog initializations
 */
void open_syslog ();
void submit_syslog (char *);
void close_syslog ();

/*
 * screen initializations
 */
void open_screen ();
void submit_screen (char *);
void close_screen ();

/*
 * log file initializations
 */
void open_logfile ();
void submit_logfile (char *);
void close_logfile ();

/*
 * array initializations
 */
void initialize_lfield_headers (char ***);
void initialize_afield_headers (char ***);
void initialize_lfield_values (char ***);
void initialize_afield_values (char ***);
void initialize_lfield_output (int *);
void initialize_afield_output (int *);
void initialize_lfield_order (int *);
void initialize_afield_order (int *);
void free_lfield_arrays (char ***);
void free_afield_arrays (char ***);

/*
 * function to show help about this tool
 */
void usage (char *);

/*
 * cleanup functions
 */
void exit_loggrabber (int);

/*
 * helper functions for working with lists
 */
int stringlist_append (stringlist **, char *);
void stringlist_print (stringlist **);
stringlist *stringlist_search (stringlist **, char *, char **);
stringlist *stringlist_delete (stringlist **);

/*
 * helper function to work with strings
 */
char *string_get_token (char **, char);
char *string_duplicate (const char *);
unsigned int string_cat (char **, const char *, unsigned int);
char *string_left_trim (char *, char);
char *string_right_trim (char *, char);
char *string_trim (char *, char);
char *string_escape (char *, char);
char *string_rmchar (char *, char);
char *string_mask_newlines (char *);
int string_icmp (const char *, const char *);
int string_incmp (const char *, const char *, size_t);
char *string_toupper (const char *);
char getschar ();

/*
 * file operation functions
 */
// copy a file into another file
void fileCopy (const char *inputfile, const char *outputfile);

// check and see whether or not a file exists
int fileExist (const char *fileName);

// Worker thread function
ThreadFuncReturnType leaRecordProcessor( void *data );
                                                                                                                         
/*
 * pointers to functions
 */
//pointer to function open log pipe
void (*open_log) ();

//pointer to function submit
void (*submit_log) (char *message);

//pointer to function close log pipe
void (*close_log) ();

/*
 * Global definitions
 */
int debug_mode = -1;
int show_files = -1;
int online_mode = -1;
int resolve_mode = -1;
char *LogfileName = NULL;
int fw1_2000 = -1;
int audit_log = -1;
stringlist *sl = NULL;
char **filterarray = NULL;
int filtercount = 0;
int output_fields = 0;
int mysql_mode = -1;
int fieldnames_mode = -1;
int create_tables = FALSE;

OpsecSession* pSession = NULL;
OpsecEnv*     pEnv     = NULL;

/*
 * The following events are user defined:
 */
long initent, resumeent, shutdownent;

//A mutex for multithread thread synchronization
pthread_mutex_t mutex;

//LEA record worker thread id
ThreadIDType threadid;
//A flag to indicate whether LEA record worker thread should quit.
Bool alive = TRUE;

//A flag to indicate whether the established Opsec Session has been suspended.
Bool suspended = FALSE;

/**
 * A character array which is used to convert several variables to char array
 **/
char stringnumber[16384];
char headernumber[16384];

char s[1024];

char **lfield_headers[NUMBER_LIDX_FIELDS];
char **afield_headers[NUMBER_AIDX_FIELDS];
char **lfields[NUMBER_LIDX_FIELDS];
char **afields[NUMBER_AIDX_FIELDS];
int lfield_output[NUMBER_LIDX_FIELDS];
int afield_output[NUMBER_AIDX_FIELDS];
int lfield_order[NUMBER_LIDX_FIELDS];
int afield_order[NUMBER_AIDX_FIELDS];

configvalues cfgvalues = {
  0,                            // debug_mode
  FALSE,                        // online_mode
  TRUE,                         // resolve_mode
  FALSE,                        // fw1_2000
  FALSE,                        // audit_mode
  FALSE,                        // showfiles_mode
  TRUE,                         // fieldnames_mode
  DATETIME_STD,                 // dateformat
  SCREEN,                       // log_mode
  LOG_LOCAL1,                   // syslog_facility
  '|',                          // record_separator
  "fw1-loggrabber.conf",        // config_filename
  "lea.conf",                   // leaconfig_filename
  "fw.log",                     // fw1_logfile
  "fw1-loggrabber",             // output_file_prefix
  1048576,                      // output_file_rotatesize
  NULL,                         // fields
  0,                            // fw1_filter_count
  NULL,                         // fw1_filter_array
  0,                            // audit_filter_count
  NULL                          // audit_filter_array
};


/**
 * The current log file descriptor
 **/
FILE *logstream;

/**
 * The flag, which is used to control whether or not fw1-loggrabber needs to exit
 **/
int keepAlive = TRUE;

/**
 * The recover interval with unit of second
 **/
int recoverInterval = 10;

/**
 * The flag, which indicates whether or not the session has been established
 **/
int established = FALSE;

int initialCapacity = 1024;
int capacityIncrement = 4096;

