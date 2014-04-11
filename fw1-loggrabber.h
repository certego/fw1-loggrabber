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

#ifdef SOLARIS2
#        define  BIG_ENDIAN    4321
#        define  LITTLE_ENDIAN 1234
#        define  BYTE_ORDER BIG_ENDIAN
#        define  SLEEP(sec) sleep(sec)
#        include <netinet/in.h>
#        include <arpa/inet.h>
#        include <syslog.h>
#        include <unistd.h>
#elif WIN32
#        define  BIG_ENDIAN    4321
#        define  LITTLE_ENDIAN 1234
#        define  BYTE_ORDER LITTLE_ENDIAN
#        define  BUFSIZE MAX_PATH
#        define  SLEEP(sec) Sleep(1000*sec)
#        include <windows.h>
#        include <winsock.h>
#else
#        define  SLEEP(sec) sleep(sec)
#        include <netinet/in.h>
#        include <arpa/inet.h>
#        include <unistd.h>
#        include <endian.h>
#        include <syslog.h>
#endif

#ifdef USE_ODBC
#        include <sql.h>
#        include <sqlext.h>
#endif

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

#ifdef WIN32
#        define ODBCVERSION        "Windows-ODBC-support"
#elif STATIC_IODBC
#        define ODBCVERSION        "static iODBC-support"
#elif DYNAMIC_IODBC
#        define ODBCVERSION        "dynamic iODBC-support"
#elif STATIC_UNIXODBC
#        define ODBCVERSION        "static unixODBC-support"
#elif DYNAMIC_UNIXODBC
#        define ODBCVERSION        "dynamic unixODBC-support"
#else
#        define ODBCVERSION        "no ODBC-support"
#endif

#define TRUE                        1
#define FALSE                        0

#define DATETIME_CP                0
#define DATETIME_UNIX                1
#define DATETIME_STD                2

#define NUMBER_LIDX_FIELDS        108

#define LIDX_NUM                0
#define LIDX_TIME                1
#define LIDX_ACTION                2
#define LIDX_ORIG                3
#define LIDX_ALERT                4
#define LIDX_IF_DIR                5
#define LIDX_IF_NAME                6
#define LIDX_HAS_ACCOUNTING        7
#define LIDX_UUID                8
#define LIDX_PRODUCT                9
#define LIDX_POLICY_ID_TAG        10
#define LIDX_SRC                11
#define LIDX_S_PORT                12
#define LIDX_DST                13
#define LIDX_SERVICE                14
#define LIDX_TCP_FLAGS                15
#define LIDX_PROTO                16
#define LIDX_RULE                17
#define LIDX_XLATESRC                18
#define LIDX_XLATEDST                19
#define LIDX_XLATESPORT                20
#define LIDX_XLATEDPORT                21
#define LIDX_NAT_RULENUM        22
#define LIDX_RESOURCE                23
#define LIDX_ELAPSED                24
#define LIDX_PACKETS                25
#define LIDX_BYTES                26
#define LIDX_REASON                27
#define LIDX_SERVICE_NAME        28
#define LIDX_AGENT                29
#define LIDX_FROM                30
#define LIDX_TO                        31
#define LIDX_SYS_MSGS                32
#define LIDX_FW_MESSAGE                33
#define LIDX_INTERNAL_CA        34
#define LIDX_SERIAL_NUM                35
#define LIDX_DN                        36
#define LIDX_ICMP                37
#define LIDX_ICMP_TYPE                38
#define LIDX_ICMP_TYPE2                39
#define LIDX_ICMP_CODE                40
#define LIDX_ICMP_CODE2                41
#define LIDX_MSGID                42
#define LIDX_MESSAGE_INFO        43
#define LIDX_LOG_SYS_MESSAGE        44
#define LIDX_SESSION_ID                45
#define LIDX_DNS_QUERY                46
#define LIDX_DNS_TYPE                47
#define LIDX_SCHEME                48
#define LIDX_SRCKEYID                49
#define LIDX_DSTKEYID                50
#define LIDX_METHODS                51
#define LIDX_PEER_GATEWAY        52
#define LIDX_IKE                53
#define LIDX_IKE_IDS                54
#define LIDX_ENCRYPTION_FAILURE        55
#define LIDX_ENCRYPTION_FAIL_R  56
#define LIDX_COOKIEI                57
#define LIDX_COOKIER                58
#define LIDX_START_TIME                59
#define LIDX_SEGMENT_TIME        60
#define LIDX_CLIENT_IN_PACKETS        61
#define LIDX_CLIENT_OUT_PACKETS        62
#define LIDX_CLIENT_IN_BYTES        63
#define LIDX_CLIENT_OUT_BYTES        64
#define LIDX_CLIENT_IN_IF        65
#define LIDX_CLIENT_OUT_IF        66
#define LIDX_SERVER_IN_PACKETS        67
#define LIDX_SERVER_OUT_PACKETS        68
#define LIDX_SERVER_IN_BYTES        69
#define LIDX_SERVER_OUT_BYTES        70
#define LIDX_SERVER_IN_IF        71
#define LIDX_SERVER_OUT_IF        72
#define LIDX_MESSAGE                73
#define LIDX_NAT_ADDRULENUM        74
#define LIDX_USER                75
#define LIDX_SRCNAME                76
#define LIDX_VPN_USER                77
#define LIDX_OM                        78
#define LIDX_OM_METHOD                79
#define LIDX_ASSIGNED_IP        80
#define LIDX_MAC                81
#define LIDX_ATTACK                82
#define LIDX_ATTACK_INFO        83
#define LIDX_CLUSTER_INFO        84
#define LIDX_DCE_RPC_UUID        85
#define LIDX_DCE_RPC_UUID_1        86
#define LIDX_DCE_RPC_UUID_2        87
#define LIDX_DCE_RPC_UUID_3        88
#define LIDX_DURING_SEC                89
#define LIDX_FRAGMENTS_DROPPED        90
#define LIDX_IP_ID                91
#define LIDX_IP_LEN                92
#define LIDX_IP_OFFSET                93
#define LIDX_TCP_FLAGS2                94
#define LIDX_SYNC_INFO                95
#define LIDX_LOG                96
#define LIDX_CPMAD                97
#define LIDX_AUTH_METHOD        98
#define LIDX_TCP_PACKET_OOS        99
#define LIDX_RPC_PROG                100
#define LIDX_TH_FLAGS                101
#define LIDX_CP_MESSAGE                102
#define LIDX_REJECT_CATEGORY        103
#define LIDX_IKE_LOG                104
#define LIDX_NEGOTIATION_ID        105
#define LIDX_DECRYPTION_FAILURE        106
#define LIDX_LEN                107

#define NUMBER_AIDX_FIELDS        21

#define AIDX_NUM                0
#define AIDX_TIME                1
#define AIDX_ACTION                2
#define AIDX_ORIG                3
#define AIDX_IF_DIR                4
#define AIDX_IF_NAME                5
#define AIDX_HAS_ACCOUNTING        6
#define AIDX_UUID                7
#define AIDX_PRODUCT                8
#define AIDX_OBJECTNAME                9
#define AIDX_OBJECTTYPE                10
#define AIDX_OBJECTTABLE         11
#define AIDX_OPERATION                12
#define AIDX_UID                13
#define AIDX_ADMINISTRATOR        14
#define AIDX_MACHINE                15
#define AIDX_SUBJECT                16
#define AIDX_AUDIT_STATUS        17
#define AIDX_ADDITIONAL_INFO        18
#define AIDX_OPERATION_NUMBER        19
#define AIDX_FIELDSCHANGES        20

#define SCREEN                  0
#define LOGFILE                 1
#define SYSLOG                  2
#define ODBC                    3
#define SNMP                    4        // For future use

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
#ifndef WIN32
  int syslog_facility;
#endif
  char record_separator;
  char *config_filename;
  char *leaconfig_filename;
#ifdef USE_ODBC
  char *odbc_dsn;
#endif
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

#ifndef WIN32
/*
 * syslog initializations
 */
void open_syslog ();
void submit_syslog (char *);
void close_syslog ();
#endif

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

#ifdef USE_ODBC
/*
 * odbc initializations
 */
void open_odbc ();
void submit_odbc (char *);
void close_odbc ();
#endif

#ifdef USE_ODBC
/*
 * ODBC related functions
 */
int create_loggrabber_tables ();
int ODBC_Errors (char *);
#endif

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
#ifdef USE_ODBC
void initialize_lfield_dbheaders (char ***);
void initialize_afield_dbheaders (char ***);
void initialize_lfield_dblength (int *);
void initialize_afield_dblength (int *);
#endif

/*
 * function to show help about this tool
 */
void usage (char *);
void show_supported_fields ();

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

#ifdef USE_ODBC
/* 
 * global variables for ODBC
 */
SQLHENV henv;
SQLHDBC hdbc;
SQLHSTMT hstmt;
int connected = 0;
const char *infotable = "loggrabber";
const char *logtable = "fw1logs";
const char *audittable = "auditlogs";
char *dbms_name = NULL;
char *dbms_ver = NULL;
long int tableindex = -1;
#endif

OpsecSession* pSession = NULL;
OpsecEnv*     pEnv     = NULL;

/*
 * The following events are user defined:
 */
long initent, resumeent, shutdownent;

//A mutex for multithread thread synchronization
#ifdef WIN32
      HANDLE mutex;
#else
      pthread_mutex_t mutex;
#endif

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
#ifdef USE_ODBC
char **lfield_dbheaders[NUMBER_LIDX_FIELDS];
char **afield_dbheaders[NUMBER_AIDX_FIELDS];
int lfield_dblength[NUMBER_LIDX_FIELDS];
int afield_dblength[NUMBER_AIDX_FIELDS];
#endif

configvalues cfgvalues = {
  0,                                // debug_mode
  FALSE,                        // online_mode
  TRUE,                                // resolve_mode
  FALSE,                        // fw1_2000
  FALSE,                        // audit_mode
  FALSE,                        // showfiles_mode
  TRUE,                                // fieldnames_mode
  DATETIME_STD,                        // dateformat
  SCREEN,                        // log_mode
#ifndef WIN32
  LOG_LOCAL1,                        // syslog_facility
#endif
  '|',                                // record_separator
  "fw1-loggrabber.conf",        // config_filename
  "lea.conf",                        // leaconfig_filename
#ifdef USE_ODBC
  "FW1-LOGGRABBER",                // odbc_dsn
#endif
  "fw.log",                        // fw1_logfile
  "fw1-loggrabber",                // output_file_prefix
  1048576,                        // output_file_rotatesize
  NULL,                                // fields
  0,                                // fw1_filter_count
  NULL,                                // fw1_filter_array
  0,                                // audit_filter_count
  NULL                                // audit_filter_array
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
