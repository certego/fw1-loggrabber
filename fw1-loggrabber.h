/******************************************************************************/
/* fw1-loggrabber - (C)2004 Torsten Fellhauer                                 */
/******************************************************************************/
/* Version: 1.9.2                                                             */
/******************************************************************************/
/*                                                                            */
/* Copyright (c) 2004 Torsten Fellhauer <torsten@fellhauer-web.de>            */
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

#ifdef USE_MYSQL
#	include <mysql/mysql.h>
#endif

#ifdef SOLARIS2
#       define  BIG_ENDIAN    4321 
#       define  LITTLE_ENDIAN 1234 
#       define  BYTE_ORDER BIG_ENDIAN 
#       include <netinet/in.h>
#       include <arpa/inet.h>
#       include <unistd.h>
#elif WIN32
#       define  BIG_ENDIAN    4321 
#       define  LITTLE_ENDIAN 1234 
#       define  BYTE_ORDER LITTLE_ENDIAN 
#       include <winsock.h>
#else
#       include <netinet/in.h>
#       include <arpa/inet.h>
#       include <unistd.h>
#       include <endian.h>
#endif

#include "opsec/lea.h"
#include "opsec/lea_filter.h"
#include "opsec/lea_filter_ext.h"
#include "opsec/opsec.h"

/*
 * Constant definitions
 */
#define VERSION			"1.9.2"

#define TRUE			1
#define FALSE			0

#define DATETIME_CP		0
#define DATETIME_UNIX		1
#define DATETIME_STD		2

#define NUMBER_LIDX_FIELDS	93

#define LIDX_NUM		0
#define LIDX_TIME		1
#define LIDX_ACTION		2
#define LIDX_ORIG		3
#define LIDX_ALERT		4
#define LIDX_IF_DIR		5
#define LIDX_IF_NAME		6
#define LIDX_HAS_ACCOUNTING	7
#define LIDX_UUID		8
#define LIDX_PRODUCT		9
#define LIDX_POLICY_ID_TAG	10
#define LIDX_SRC		11
#define LIDX_S_PORT		12
#define LIDX_DST		13
#define LIDX_SERVICE		14
#define LIDX_TCP_FLAGS		15
#define LIDX_PROTO		16
#define LIDX_RULE		17
#define LIDX_XLATESRC		18
#define LIDX_XLATEDST		19
#define LIDX_XLATESPORT		20
#define LIDX_XLATEDPORT		21
#define LIDX_NAT_RULENUM	22
#define LIDX_RESOURCE		23
#define LIDX_ELAPSED		24
#define LIDX_PACKETS		25
#define LIDX_BYTES		26
#define LIDX_REASON		27
#define LIDX_SERVICE_NAME	28
#define LIDX_AGENT		29
#define LIDX_FROM		30
#define LIDX_TO			31
#define LIDX_SYS_MSGS		32
#define LIDX_FW_MESSAGE		33
#define LIDX_INTERNAL_CA	34
#define LIDX_SERIAL_NUM		35
#define LIDX_DN			36
#define LIDX_ICMP_TYPE		37
#define LIDX_ICMP_CODE		38
#define LIDX_MSGID		39
#define LIDX_MESSAGE_INFO	40
#define LIDX_LOG_SYS_MESSAGE	41
#define LIDX_SESSION_ID		42
#define LIDX_DNS_QUERY		43
#define LIDX_DNS_TYPE		44
#define LIDX_SCHEME		45
#define LIDX_SRCKEYID		46
#define LIDX_DSTKEYID		47
#define LIDX_METHODS		48
#define LIDX_PEER_GATEWAY	49
#define LIDX_IKE		50
#define LIDX_IKE_IDS		51
#define LIDX_ENCRYPTION_FAILURE	52
#define LIDX_ENCRYPTION_FAIL_R  53
#define LIDX_COOKIEI		54
#define LIDX_COOKIER		55
#define LIDX_START_TIME		56
#define LIDX_SEGMENT_TIME	57
#define LIDX_CLIENT_IN_PACKETS	58
#define LIDX_CLIENT_OUT_PACKETS	59
#define LIDX_CLIENT_IN_BYTES	60
#define LIDX_CLIENT_OUT_BYTES	61
#define LIDX_CLIENT_IN_IF	62
#define LIDX_CLIENT_OUT_IF	63
#define LIDX_SERVER_IN_PACKETS	64
#define LIDX_SERVER_OUT_PACKETS	65
#define LIDX_SERVER_IN_BYTES	66
#define LIDX_SERVER_OUT_BYTES	67
#define LIDX_SERVER_IN_IF	68
#define LIDX_SERVER_OUT_IF	69
#define LIDX_MESSAGE		70
#define LIDX_NAT_ADDRULENUM	71
#define LIDX_USER		72
#define LIDX_SRCNAME		73
#define LIDX_VPN_USER		74
#define LIDX_OM			75
#define LIDX_OM_METHOD		76
#define LIDX_ASSIGNED_IP	77
#define LIDX_MAC		78
#define LIDX_ATTACK		79
#define LIDX_ATTACK_INFO	80
#define LIDX_CLUSTER_INFO	81
#define LIDX_DCE_RPC_UUID	82
#define LIDX_DCE_RPC_UUID_1	83
#define LIDX_DCE_RPC_UUID_2	84
#define LIDX_DCE_RPC_UUID_3	85
#define LIDX_DURING_SEC		86
#define LIDX_FRAGMENTS_DROPPED	87
#define LIDX_IP_ID		88
#define LIDX_IP_LEN		89
#define LIDX_IP_OFFSET		90
#define LIDX_TCP_FLAGS2		91
#define LIDX_SYNC_INFO		92

#define NUMBER_AIDX_FIELDS	21

#define AIDX_NUM		0
#define AIDX_TIME		1
#define AIDX_ACTION		2
#define AIDX_ORIG		3
#define AIDX_IF_DIR		4
#define AIDX_IF_NAME		5
#define AIDX_HAS_ACCOUNTING	6
#define AIDX_UUID		7
#define AIDX_PRODUCT		8
#define AIDX_OBJECTNAME		9
#define AIDX_OBJECTTYPE		10
#define AIDX_OBJECTTABLE 	11
#define AIDX_OPERATION		12
#define AIDX_UID		13
#define AIDX_ADMINISTRATOR	14
#define AIDX_MACHINE		15
#define AIDX_SUBJECT		16
#define AIDX_AUDIT_STATUS	17
#define AIDX_ADDITIONAL_INFO	18
#define AIDX_OPERATION_NUMBER	19
#define AIDX_FIELDSCHANGES	20

/*
 * Type definitions
 */
typedef struct stringlist
{
	char *	data;
	struct stringlist * next;
} stringlist;

typedef struct configvalues
{
	int	debug_mode;
	int	online_mode;
	int	resolve_mode;
	int	mysql_mode;
	int	fw1_2000;
	int	audit_mode;
	int	auth_mode;
	int	auth_type;
	int	showfiles_mode;
	int 	fieldnames_mode;
	int 	dateformat;
	char	record_separator;
	char*	mysql_host;
	char*	mysql_database;
	char*	mysql_user;
	char*	mysql_password;
	char*	fw1_server;
	char*	fw1_port;
	char*	fw1_logfile;
	char*	opsec_certificate;
	char*	opsec_client_dn;
	char*	opsec_server_dn;
} configvalues;

/*
 * Function prototypes
 */

/*
 * function to get the content of a given FW-1 Logfile
 */
int 		   read_fw1_logfile(char **, char **, char **);

/*
 * event handler used by read_fw1_logfile to approve a rulebase
 */
int 		   read_fw1_logfile_queryack(OpsecSession *, int, eLeaFilterAction, int);

/*
 * event handler used by read_fw1_logfile to get session end reason
 */
int                read_fw1_logfile_end(OpsecSession *);

/*
 * event handler used by read_fw1_logfile to print returned log records
 */
int                read_fw1_logfile_n_record_stdout(OpsecSession *, lea_record *, int []);
int                read_fw1_logfile_a_record_stdout(OpsecSession *, lea_record *, int []);

/*
 * event handler used by read_fw1_logfile to store returned log records in MySQL database
 */
#ifdef USE_MYSQL
	int        read_fw1_logfile_record_mysql(OpsecSession *, lea_record *, int []);
#endif

/*
 * dummy event handler for debugging purposes
 */
int 		   read_fw1_logfile_dict(OpsecSession *, int , LEA_VT , int);

/*
 * dummy event handler for debugging purposes
 */
int                read_fw1_logfile_eof(OpsecSession *);

/*
 * dummy event handler for debugging purposes
 */
int                read_fw1_logfile_switch(OpsecSession *);

/*
 * dummy event handler for debugging purposes
 */
int                read_fw1_logfile_collogs(OpsecSession *);

/*
 * dummy event handler for debugging purposes
 */
int                read_fw1_logfile_suspend(OpsecSession *);

/*
 * dummy event handler for debugging purposes
 */
int                read_fw1_logfile_resume(OpsecSession *);

/*
 * dummy event handler for debugging purposes
 */
int                read_fw1_logfile_start(OpsecSession *);

/*
 * dummy event handler for debugging purposes
 */
int                read_fw1_logfile_failedconn(OpsecEntity *entity, long peer_ip, int sic_errno, char *sic_errmsg);

/*
 * dummy event handler for debugging purposes
 */
int                read_fw1_logfile_established(OpsecSession *);

/*
 * function to get all available FW-1 Logfile Names
 */
int                get_fw1_logfiles(char **, char **);

/*
 * event handler used by get_fw1_logfiles to print the Logfile Names
 */
int 		   get_fw1_logfiles_dict(OpsecSession *, int , LEA_VT , int);

/*
 * event handler used by get_fw1_logfiles to get session end reason
 */
int                get_fw1_logfiles_end(OpsecSession *);

/*
 * function to create a new rule for a filter rulebase
 */
LeaFilterRulebase* create_fw1_filter_rule(LeaFilterRulebase*, char[255]);

/* 
 * function to clean up the opsec environment
 */
void               cleanup_fw1_environment(OpsecEnv *, OpsecEntity *, OpsecEntity *);

/*
 * functions for database support
 */
#ifdef USE_MYSQL
	MYSQL*     connect_to_mysql(MYSQL *, long int *, configvalues*);
	void       disconnect_from_mysql(MYSQL *);
#endif

/*
 * function to read configfile
 */
void               read_config_file(char*, struct configvalues*);

/*
 * array initializations
 */
void		   initialize_lfield_headers(char***);
void		   initialize_afield_headers(char***);
void		   initialize_lfield_values(char***);
void		   initialize_afield_values(char***);
void		   initialize_lfield_output(int*);
void		   initialize_afield_output(int*);
void		   free_lfield_arrays(char***);
void		   free_afield_arrays(char***);

/*
 * function to show help about this tool
 */
void               usage(char *);

/*
 * helper functions for working with lists
 */
int 		   stringlist_append (stringlist **, char *);
void		   stringlist_print (stringlist **);
stringlist* 	   stringlist_search(stringlist **, char *, char **);

/*
 * helper function to work with strings
 */
char*		   string_get_token(char **, char);
char* 		   string_duplicate(const char *);
char* 		   string_left_trim(char *, char);
char* 		   string_right_trim(char *, char);
char* 		   string_trim(char *, char);
char* 		   string_escape(char*, char);


/*
 * Global definitions 
 */
int debug_mode 		= -1;
int show_files 		= -1;
int online_mode		= -1;
int resolve_mode        = -1;
char *ConfigfileName 	= NULL;
int auth_connection	= -1;
int auth_type		= -1;
int fw1_2000		= -1;
int audit_log		= -1;
stringlist *sl 		= NULL;
char **filterarray 	= NULL;
int filtercount 	= 0;
int output_fields	= 0;
int mysql_mode		= -1;
int fieldnames_mode     = -1;

char s[1024];

char** lfield_headers[NUMBER_LIDX_FIELDS];
char** afield_headers[NUMBER_AIDX_FIELDS];
char** lfields[NUMBER_LIDX_FIELDS];
char** afields[NUMBER_AIDX_FIELDS];
int lfield_output[NUMBER_LIDX_FIELDS];
int afield_output[NUMBER_AIDX_FIELDS];

#ifdef USE_MYSQL
	long int mysql_maxnumber= 0;
	MYSQL *mysqlconn, mysql;
#endif

configvalues cfgvalues = {0, 0, 1, 0, 0, 0, 1, OPSEC_SSLCA, 0, 1, 2, '|', "localhost", "fw1loggrabber", "fw1", "fw1", "localhost", "18184", "fw.log", "opsec.p12", "", ""};

