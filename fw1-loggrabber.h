/******************************************************************************/
/* fw1-loggrabber                                                             */
/******************************************************************************/
/*                                                                            */
/* Copyright (c) 2003-2005 Torsten Fellhauer, Xiaodong Lin                    */
/* Copyright (c) 2014-2016 CERTEGO s.r.l.                                     */
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
#define VERSION             "2.1"

#define TRUE                1
#define FALSE               0

#define DATETIME_CP         0
#define DATETIME_UNIX       1
#define DATETIME_STD        2

#define NUMBER_FIELDS       128

#define SCREEN              0
#define LOGFILE             1
#define SYSLOG              2

#define INITIAL_CAPACITY    1024
#define CAPACITY_INCREMENT  4096

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
  int log_mode;
  int syslog_facility;
  char record_separator;
  char *config_filename;
  char *leaconfig_filename;
  char *fw1_logfile;
  char *output_file_prefix;
  long output_file_rotatesize;
  char *ignore_fields;
  int dateformat;
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
void init_field_headers (char ***);
void init_field_values (char ***);
void free_field_arrays (char ***);

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
int integer_cmp (const void *, const void *);
int find_in_int_array (int *, int, int);

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
int mysql_mode = -1;
int create_tables = FALSE;
char *ignore_fields = NULL;
int ignore_fields_count = 0;
char **ignore_fields_array = NULL;

int ignore_attr_id_count = 0;
int ignore_attr_id_array[NUMBER_FIELDS] = { 0 };

/*
 * Holds the attribute ID for the "time" field from the ATTRIB_ID databases.
 * The value is set in the read_fw1_logfile_dict function
 */
int time_attr_id = -1;

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

char **field_headers[NUMBER_FIELDS];
char **field_values[NUMBER_FIELDS];

configvalues cfgvalues = {
  0,                            // debug_mode
  FALSE,                        // online_mode
  TRUE,                         // resolve_mode
  FALSE,                        // fw1_2000
  FALSE,                        // audit_mode
  FALSE,                        // showfiles_mode
  SCREEN,                       // log_mode
  LOG_LOCAL1,                   // syslog_facility
  '|',                          // record_separator
  "fw1-loggrabber.conf",        // config_filename
  "lea.conf",                   // leaconfig_filename
  "fw.log",                     // fw1_logfile
  "fw1-loggrabber",             // output_file_prefix
  1048576,                      // output_file_rotatesize
  NULL,                         // ignore_fields
  DATETIME_STD,                 // dateformat
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

