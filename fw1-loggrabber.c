/******************************************************************************/
/* fw1-loggrabber - (C)2004 Torsten Fellhauer, Xiaodong Lin                   */
/******************************************************************************/
/* Version: 1.10                                                              */
/******************************************************************************/
/*                                                                            */
/* Copyright (c) 2004 Torsten Fellhauer, Xiaodong Lin                         */
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
/* Description:                                                               */
/*                                                                            */
/* fw1-loggrabber is a simple LEA-Client which utilizes Checkpoints' OPSEC    */
/* SDK. It get any kind of Checkpoint FW-1 Log information from the Fire-     */
/* wall using the LEA-protocol.                                               */
/*                                                                            */
/* In order to use this program, you have to enable unauthorized connections  */
/* to your firewall within fwopsec.conf. Since Version 1.2 you can also use   */
/* authenticated and 3DES-encrypted connections.                              */
/* The current version also enables the usage of filter rule and an online    */
/* mode.                                                                      */
/*                                                                            */
/******************************************************************************/

#include "fw1-loggrabber.h"

/*
 * main function
 */
int main(int argc, char *argv[])
{
	int i;
	stringlist *lstptr;
	char *foundstring;
	char *field;

	/*
	 * initialize field arrays
	 */
	initialize_lfield_headers(lfield_headers);
	initialize_afield_headers(afield_headers);
	initialize_lfield_output(lfield_output);
	initialize_afield_output(afield_output);
	initialize_lfield_values(lfields);
	initialize_afield_values(afields);

        /* The default settings are shown as follows:
         * FW1_TYPE = NG release
         * Offline mode
         * Database is off
         * Print off log records
         */

	/*
	 * process command line arguments
	 */
	for (i=1 ; i<argc ; i++) {
	  if (strcmp(argv[i], "--help") == 0) {
	    usage(argv[0]);
	    exit_loggrabber(1);
	  }
	  else if (strcmp(argv[i], "--help-fields") == 0) {
		show_supported_fields();
		exit_loggrabber(1);
	  }
	  else if (strcmp(argv[i], "--resolve") == 0) {
	    resolve_mode = 1;
	  }
	  else if ((strcmp(argv[i], "--noresolve") == 0) || (strcmp(argv[i], "--no-resolve") == 0)) {
	    resolve_mode = 0;
	  }
	  else if (strcmp(argv[i], "--debug-level") == 0) {
	    i++;
	    if (argv[i] == NULL) {
		fprintf(stderr, "ERROR: Invalid argument: %s\n", argv[i-1]);
		usage(argv[0]);
		exit_loggrabber(1);
	    }
            if (argv[i][0] == '-') {
		fprintf(stderr, "ERROR: Value expected for argument %s\n", argv[i-1]);
		usage(argv[0]);
		exit_loggrabber(1);
	    }
	    debug_mode = atoi(argv[i]);
	  }
	  else if (strcmp(argv[i], "--showfiles") == 0) {
	    show_files = 1;
	  }
	  else if (strcmp(argv[i], "--showlogs") == 0) {
	    show_files = 0;
	  }
	  else if (strcmp(argv[i], "--2000") == 0) {
	    fw1_2000 = 1;
          }
	  else if (strcmp(argv[i], "--ng") == 0) {
	    fw1_2000 = 0;
          }
	  else if (strcmp(argv[i], "--online") == 0) {
	    online_mode = 1;
          }
	  else if (strcmp(argv[i], "--no-online") == 0) {
	    online_mode = 0;
          }
	  else if (strcmp(argv[i], "--auditlog") == 0) {
	    audit_log = 1;
          }
	  else if (strcmp(argv[i], "--normallog") == 0) {
	    audit_log = 0;
          }
	  else if (strcmp(argv[i], "--fieldnames") == 0) {
	    fieldnames_mode = 1;
          }
	  else if (strcmp(argv[i], "--nofieldnames") == 0) {
	    fieldnames_mode = 0;
          }
#ifdef USE_MYSQL
	  else if (strcmp(argv[i], "--mysql") == 0) {
	    mysql_mode = 1;
          }
	  else if (strcmp(argv[i], "--no-mysql") == 0) {
	    mysql_mode = 0;
          }
#endif
	  else if ((strcmp(argv[i], "-f") == 0) || (strcmp(argv[i], "--logfile") == 0)) {
	    i++;
	    if (argv[i] == NULL) {
		fprintf(stderr, "ERROR: Invalid argument: %s\n", argv[i-1]);
		usage(argv[0]);
		exit_loggrabber(1);
	    }
            if (argv[i][0] == '-') {
		fprintf(stderr, "ERROR: Value expected for argument %s\n", argv[i-1]);
		usage(argv[0]);
		exit_loggrabber(1);
	    }
	    LogfileName = string_duplicate(argv[i]);
	  }
	  else if ((strcmp(argv[i], "-c") == 0) || (strcmp(argv[i], "--configfile") == 0)) {
	    i++;
	    if (argv[i] == NULL) {
		fprintf(stderr, "ERROR: Invalid argument: %s\n", argv[i-1]);
		usage(argv[0]);
		exit_loggrabber(1);
	    }
            if (argv[i][0] == '-') {
		fprintf(stderr, "ERROR: Value expected for argument %s\n", argv[i-1]);
		usage(argv[0]);
		exit_loggrabber(1);
	    }
	    cfgvalues.config_filename = string_duplicate(argv[i]);
	  }
	  else if ((strcmp(argv[i], "-l") == 0) || (strcmp(argv[i], "--leaconfigfile") == 0)) {
	    i++;
	    if (argv[i] == NULL) {
		fprintf(stderr, "ERROR: Invalid argument: %s\n", argv[i-1]);
		usage(argv[0]);
		exit_loggrabber(1);
	    }
            if (argv[i][0] == '-') {
		fprintf(stderr, "ERROR: Value expected for argument %s\n", argv[i-1]);
		usage(argv[0]);
		exit_loggrabber(1);
	    }
	    cfgvalues.leaconfig_filename = string_duplicate(argv[i]);
	  }
	  else if (strcmp(argv[i], "--filter") == 0) {
	    i++;
	    if (argv[i] == NULL) {
		fprintf(stderr, "ERROR: Invalid argument: %s\n", argv[i-1]);
		usage(argv[0]);
		exit_loggrabber(1);
	    }
            if (argv[i][0] == '-') {
		fprintf(stderr, "ERROR: Value expected for argument %s\n", argv[i-1]);
		usage(argv[0]);
		exit_loggrabber(1);
	    }
	    filtercount++;
	    filterarray = (char**)realloc(filterarray, filtercount * sizeof(char *));
	    if (filterarray == NULL) {
		fprintf(stderr, "ERROR: Out of memory\n");
		exit_loggrabber(1);
	    }
	    filterarray[filtercount-1] = string_duplicate(argv[i]);
	  }
	  else if (strcmp(argv[i], "--fields") == 0) {
	    i++;
	    if (argv[i] == NULL) {
		fprintf(stderr, "ERROR: Invalid argument: %s\n", argv[i-1]);
		usage(argv[0]);
		exit_loggrabber(1);
	    }
            if (argv[i][0] == '-') {
		fprintf(stderr, "ERROR: Value expected for argument %s\n", argv[i-1]);
		usage(argv[0]);
		exit_loggrabber(1);
	    }
	    while (argv[i]) {
		output_fields = 1;

		field = string_trim(string_get_token(&argv[i], ';'), ' ');
		if (string_icmp(field, *lfield_headers[LIDX_NUM]) == 0) {
			lfield_output[LIDX_NUM] = 1;
			afield_output[AIDX_NUM] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_TIME]) == 0) {
			lfield_output[LIDX_TIME] = 1;
			afield_output[AIDX_TIME] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_ACTION]) == 0) {
			lfield_output[LIDX_ACTION] = 1;
			afield_output[AIDX_ACTION] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_ORIG]) == 0) {
			lfield_output[LIDX_ORIG] = 1;
			afield_output[AIDX_ORIG] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_ALERT]) == 0) {
			lfield_output[LIDX_ALERT] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_IF_DIR]) == 0) {
			lfield_output[LIDX_IF_DIR] = 1;
			afield_output[AIDX_IF_DIR] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_IF_NAME]) == 0) {
			lfield_output[LIDX_IF_NAME] = 1;
			afield_output[AIDX_IF_NAME] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_HAS_ACCOUNTING]) == 0) {
			lfield_output[LIDX_HAS_ACCOUNTING] = 1;
			afield_output[AIDX_HAS_ACCOUNTING] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_UUID]) == 0) {
			lfield_output[LIDX_UUID] = 1;
			afield_output[AIDX_UUID] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_PRODUCT]) == 0) {
			lfield_output[LIDX_PRODUCT] = 1;
			afield_output[AIDX_PRODUCT] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_POLICY_ID_TAG]) == 0) {
			lfield_output[LIDX_POLICY_ID_TAG] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_SRC]) == 0) {
			lfield_output[LIDX_SRC] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_S_PORT]) == 0) {
			lfield_output[LIDX_S_PORT] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_DST]) == 0) {
			lfield_output[LIDX_DST] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_SERVICE]) == 0) {
			lfield_output[LIDX_SERVICE] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_TCP_FLAGS]) == 0) {
			lfield_output[LIDX_TCP_FLAGS] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_PROTO]) == 0) {
			lfield_output[LIDX_PROTO] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_RULE]) == 0) {
			lfield_output[LIDX_RULE] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_XLATESRC]) == 0) {
			lfield_output[LIDX_XLATESRC] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_XLATEDST]) == 0) {
			lfield_output[LIDX_XLATEDST] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_XLATESPORT]) == 0) {
			lfield_output[LIDX_XLATESPORT] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_XLATEDPORT]) == 0) {
			lfield_output[LIDX_XLATEDPORT] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_NAT_RULENUM]) == 0) {
			lfield_output[LIDX_NAT_RULENUM] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_NAT_ADDRULENUM]) == 0) {
			lfield_output[LIDX_NAT_ADDRULENUM] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_RESOURCE]) == 0) {
			lfield_output[LIDX_RESOURCE] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_ELAPSED]) == 0) {
			lfield_output[LIDX_ELAPSED] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_PACKETS]) == 0) {
			lfield_output[LIDX_PACKETS] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_BYTES]) == 0) {
			lfield_output[LIDX_BYTES] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_REASON]) == 0) {
			lfield_output[LIDX_REASON] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_SERVICE_NAME]) == 0) {
			lfield_output[LIDX_SERVICE_NAME] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_AGENT]) == 0) {
			lfield_output[LIDX_AGENT] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_FROM]) == 0) {
			lfield_output[LIDX_FROM] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_TO]) == 0) {
			lfield_output[LIDX_TO] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_SYS_MSGS]) == 0) {
			lfield_output[LIDX_SYS_MSGS] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_FW_MESSAGE]) == 0) {
			lfield_output[LIDX_FW_MESSAGE] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_INTERNAL_CA]) == 0) {
			lfield_output[LIDX_INTERNAL_CA] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_SERIAL_NUM]) == 0) {
			lfield_output[LIDX_SERIAL_NUM] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_DN]) == 0) {
			lfield_output[LIDX_DN] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_ICMP]) == 0) {
			lfield_output[LIDX_ICMP] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_ICMP_TYPE]) == 0) {
			lfield_output[LIDX_ICMP_TYPE] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_ICMP_TYPE2]) == 0) {
			lfield_output[LIDX_ICMP_TYPE2] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_ICMP_CODE]) == 0) {
			lfield_output[LIDX_ICMP_CODE] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_ICMP_CODE2]) == 0) {
			lfield_output[LIDX_ICMP_CODE2] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_MSGID]) == 0) {
			lfield_output[LIDX_MSGID] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_MESSAGE_INFO]) == 0) {
			lfield_output[LIDX_MESSAGE_INFO] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_LOG_SYS_MESSAGE]) == 0) {
			lfield_output[LIDX_LOG_SYS_MESSAGE] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_SESSION_ID]) == 0) {
			lfield_output[LIDX_SESSION_ID] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_DNS_QUERY]) == 0) {
			lfield_output[LIDX_DNS_QUERY] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_DNS_TYPE]) == 0) {
			lfield_output[LIDX_DNS_TYPE] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_SCHEME]) == 0) {
			lfield_output[LIDX_SCHEME] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_SRCKEYID]) == 0) {
			lfield_output[LIDX_SRCKEYID] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_DSTKEYID]) == 0) {
			lfield_output[LIDX_DSTKEYID] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_METHODS]) == 0) {
			lfield_output[LIDX_METHODS] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_PEER_GATEWAY]) == 0) {
			lfield_output[LIDX_PEER_GATEWAY] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_IKE]) == 0) {
			lfield_output[LIDX_IKE] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_IKE_IDS]) == 0) {
			lfield_output[LIDX_IKE_IDS] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_ENCRYPTION_FAILURE]) == 0) {
			lfield_output[LIDX_ENCRYPTION_FAILURE] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_ENCRYPTION_FAIL_R]) == 0) {
			lfield_output[LIDX_ENCRYPTION_FAIL_R] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_COOKIEI]) == 0) {
			lfield_output[LIDX_COOKIEI] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_COOKIER]) == 0) {
			lfield_output[LIDX_COOKIER] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_START_TIME]) == 0) {
			lfield_output[LIDX_START_TIME] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_SEGMENT_TIME]) == 0) {
			lfield_output[LIDX_SEGMENT_TIME] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_CLIENT_IN_PACKETS]) == 0) {
			lfield_output[LIDX_CLIENT_IN_PACKETS] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_CLIENT_OUT_PACKETS]) == 0) {
			lfield_output[LIDX_CLIENT_OUT_PACKETS] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_CLIENT_IN_BYTES]) == 0) {
			lfield_output[LIDX_CLIENT_IN_BYTES] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_CLIENT_OUT_BYTES]) == 0) {
			lfield_output[LIDX_CLIENT_OUT_BYTES] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_CLIENT_IN_IF]) == 0) {
			lfield_output[LIDX_CLIENT_IN_IF] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_CLIENT_OUT_IF]) == 0) {
			lfield_output[LIDX_CLIENT_OUT_IF] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_SERVER_IN_PACKETS]) == 0) {
			lfield_output[LIDX_SERVER_IN_PACKETS] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_SERVER_OUT_PACKETS]) == 0) {
			lfield_output[LIDX_SERVER_OUT_PACKETS] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_SERVER_IN_BYTES]) == 0) {
			lfield_output[LIDX_SERVER_IN_BYTES] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_SERVER_OUT_BYTES]) == 0) {
			lfield_output[LIDX_SERVER_OUT_BYTES] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_SERVER_IN_IF]) == 0) {
			lfield_output[LIDX_SERVER_IN_IF] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_SERVER_OUT_IF]) == 0) {
			lfield_output[LIDX_SERVER_OUT_IF] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_MESSAGE]) == 0) {
			lfield_output[LIDX_MESSAGE] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_USER]) == 0) {
			lfield_output[LIDX_USER] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_SRCNAME]) == 0) {
			lfield_output[LIDX_SRCNAME] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_VPN_USER]) == 0) {
			lfield_output[LIDX_VPN_USER] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_OM]) == 0) {
			lfield_output[LIDX_OM] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_OM_METHOD]) == 0) {
			lfield_output[LIDX_OM_METHOD] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_ASSIGNED_IP]) == 0) {
			lfield_output[LIDX_ASSIGNED_IP] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_MAC]) == 0) {
			lfield_output[LIDX_MAC] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_ATTACK]) == 0) {
			lfield_output[LIDX_ATTACK] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_ATTACK_INFO]) == 0) {
			lfield_output[LIDX_ATTACK_INFO] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_CLUSTER_INFO]) == 0) {
			lfield_output[LIDX_CLUSTER_INFO] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_DCE_RPC_UUID]) == 0) {
			lfield_output[LIDX_DCE_RPC_UUID] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_DCE_RPC_UUID_1]) == 0) {
			lfield_output[LIDX_DCE_RPC_UUID_1] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_DCE_RPC_UUID_2]) == 0) {
			lfield_output[LIDX_DCE_RPC_UUID_2] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_DCE_RPC_UUID_3]) == 0) {
			lfield_output[LIDX_DCE_RPC_UUID_3] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_DURING_SEC]) == 0) {
			lfield_output[LIDX_DURING_SEC] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_FRAGMENTS_DROPPED]) == 0) {
			lfield_output[LIDX_FRAGMENTS_DROPPED] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_IP_ID]) == 0) {
			lfield_output[LIDX_IP_ID] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_IP_LEN]) == 0) {
			lfield_output[LIDX_IP_LEN] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_IP_OFFSET]) == 0) {
			lfield_output[LIDX_IP_OFFSET] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_TCP_FLAGS2]) == 0) {
			lfield_output[LIDX_TCP_FLAGS2] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_SYNC_INFO]) == 0) {
			lfield_output[LIDX_SYNC_INFO] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_LOG]) == 0) {
			lfield_output[LIDX_LOG] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_CPMAD]) == 0) {
			lfield_output[LIDX_CPMAD] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_AUTH_METHOD]) == 0) {
			lfield_output[LIDX_AUTH_METHOD] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_TCP_PACKET_OOS]) == 0) {
			lfield_output[LIDX_TCP_PACKET_OOS] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_RPC_PROG]) == 0) {
			lfield_output[LIDX_RPC_PROG] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_TH_FLAGS]) == 0) {
			lfield_output[LIDX_TH_FLAGS] = 1;
		} else if (string_icmp(field, *lfield_headers[LIDX_CP_MESSAGE]) == 0) {
			lfield_output[LIDX_CP_MESSAGE] = 1;
		} else if (string_icmp(field, *afield_headers[AIDX_OBJECTNAME]) == 0) {
			afield_output[AIDX_OBJECTNAME] = 1;
		} else if (string_icmp(field, *afield_headers[AIDX_OBJECTTYPE]) == 0) {
			afield_output[AIDX_OBJECTTYPE] = 1;
		} else if (string_icmp(field, *afield_headers[AIDX_OBJECTTABLE]) == 0) {
			afield_output[AIDX_OBJECTTABLE] = 1;
		} else if (string_icmp(field, *afield_headers[AIDX_OPERATION]) == 0) {
			afield_output[AIDX_OPERATION] = 1;
		} else if (string_icmp(field, *afield_headers[AIDX_UID]) == 0) {
			afield_output[AIDX_UID] = 1;
		} else if (string_icmp(field, *afield_headers[AIDX_ADMINISTRATOR]) == 0) {
			afield_output[AIDX_ADMINISTRATOR] = 1;
		} else if (string_icmp(field, *afield_headers[AIDX_MACHINE]) == 0) {
			afield_output[AIDX_MACHINE] = 1;
		} else if (string_icmp(field, *afield_headers[AIDX_SUBJECT]) == 0) {
			afield_output[AIDX_SUBJECT] = 1;
		} else if (string_icmp(field, *afield_headers[AIDX_AUDIT_STATUS]) == 0) {
			afield_output[AIDX_AUDIT_STATUS] = 1;
		} else if (string_icmp(field, *afield_headers[AIDX_ADDITIONAL_INFO]) == 0) {
			afield_output[AIDX_ADDITIONAL_INFO] = 1;
		} else if (string_icmp(field, *afield_headers[AIDX_OPERATION_NUMBER]) == 0) {
			afield_output[AIDX_OPERATION_NUMBER] = 1;
		} else if (string_icmp(field, *afield_headers[AIDX_FIELDSCHANGES]) == 0) {
			afield_output[AIDX_FIELDSCHANGES] = 1;
		} else {
			printf ("ERROR: Unsupported value for output fields: %s\n", field);
			exit_loggrabber(1);
		}
	    }
	  }
	  else {
	    fprintf(stderr, "ERROR: Invalid argument: %s\n", argv[i]);
	    usage(argv[0]);
	    exit_loggrabber(1);
          }
	}

	/*
	 * load configuration file
	 */
	read_config_file(cfgvalues.config_filename, &cfgvalues);

	/*
	 * check whether command line options override configfile options
 	 */
	cfgvalues.mysql_mode = (mysql_mode != -1) ? mysql_mode : cfgvalues.mysql_mode;
	cfgvalues.debug_mode = (debug_mode != 0) ? debug_mode : cfgvalues.debug_mode;
	cfgvalues.online_mode = (online_mode != -1) ? online_mode : cfgvalues.online_mode;
	cfgvalues.resolve_mode = (resolve_mode != -1) ? resolve_mode : cfgvalues.resolve_mode;
	cfgvalues.fw1_2000 = (fw1_2000 != -1) ? fw1_2000 : cfgvalues.fw1_2000;
	cfgvalues.showfiles_mode = (show_files != -1) ? show_files : cfgvalues.showfiles_mode;
	cfgvalues.audit_mode = (audit_log != -1) ? audit_log : cfgvalues.audit_mode;
	cfgvalues.fieldnames_mode = (fieldnames_mode != -1) ? fieldnames_mode : cfgvalues.fieldnames_mode;
	cfgvalues.fw1_logfile = (LogfileName != NULL) ? string_duplicate(LogfileName) : cfgvalues.fw1_logfile;

	/*
	 * free no more used char*
	 */
	if (LogfileName != NULL) {
		free(LogfileName);
		LogfileName = NULL;
	}

	/*
	 * if audit_mode set fw1_logfile to the correct setting
	 */
	if (cfgvalues.audit_mode) {
	  cfgvalues.fw1_logfile = string_duplicate("fw.adtlog");
	}

	/*
	 * perform validity check of given command line arguments
	 */

#ifdef WIN32
	if (cfgvalues.log_mode == SYSLOG) {
		//So far syslog is treated as the screen mode
		cfgvalues.log_mode = SCREEN;
	}
#endif

	if (cfgvalues.fw1_2000) {
		if (cfgvalues.showfiles_mode) {
			fprintf (stderr, "ERROR: --showfiles option is only available for connections\n"
					 "       to FW-1 NG. For connections to FW-1 4.1 (2000), please\n"
					 "       omit this parameter.\n");
			exit_loggrabber(1);
		}
		if (filtercount > 0) {
			fprintf (stderr, "ERROR: --filter options are only available for connections\n"
					 "       to FW-1 NG. For connections to FW-1 4.1 (2000), please\n"
					 "       omit these parameters.\n");
			exit_loggrabber(1);
		}
		if (cfgvalues.audit_mode) {
			fprintf (stderr, "ERROR: --auditlog option is only available for connections\n"
					 "       to FW-1 NG. For connections to FW-1 4.1 (2000), please\n"
					 "       omit this parameter.\n");
			exit_loggrabber(1);
		}
	}

	if (cfgvalues.online_mode && (!(cfgvalues.audit_mode)) && (strcmp(cfgvalues.fw1_logfile, "fw.log") != 0)) {
		fprintf (stderr, "ERROR: -f <FILENAME> option is not available in online mode. For use with Audit-Logfile, use --auditlog\n");
		exit_loggrabber(1);
	}

	if (cfgvalues.online_mode && cfgvalues.showfiles_mode) {
		fprintf (stderr, "ERROR: --showfiles option is not available in online mode.\n");
		exit_loggrabber(1);
	}

	if (!(cfgvalues.audit_mode) && (strcmp(cfgvalues.fw1_logfile, "fw.adtlog") == 0)) {
		fprintf (stderr, "ERROR: use --auditlog option to get data of fw.adtlog\n");
		exit_loggrabber(1);
	}

#ifdef USE_MYSQL
	if (cfgvalues.mysql_mode && cfgvalues.resolve_mode) {
		fprintf (stderr, "WARNING: it is recommended to you --no-resolve when using --mysql mode\n");
	}

	if (cfgvalues.mysql_mode && (!(cfgvalues.fieldnames_mode))) {
		fprintf (stderr, "WARNING: --nofieldnames option is not supported in MySQL mode. Ignoring...\n");
	}
#endif

        /*
         * set logging envionment
         */
	logging_init_env(cfgvalues.log_mode);

	open_log();

	/*
	 * set opsec debug level
	 */
	opsec_set_debug_level(cfgvalues.debug_mode);

	if (cfgvalues.debug_mode) {
		fprintf (stderr, "DEBUG: Logfilename      : %s\n", cfgvalues.fw1_logfile);
		fprintf (stderr, "DEBUG: Record Separator : %c\n", cfgvalues.record_separator);
		fprintf (stderr, "DEBUG: Resolve Addresses: %s\n", (cfgvalues.resolve_mode?"Yes":"No"));
		fprintf (stderr, "DEBUG: Show Filenames   : %s\n", (cfgvalues.showfiles_mode?"Yes":"No"));
		fprintf (stderr, "DEBUG: FW1-2000         : %s\n", (cfgvalues.fw1_2000?"Yes":"No"));
		fprintf (stderr, "DEBUG: Online-Mode      : %s\n", (cfgvalues.online_mode?"Yes":"No"));
		fprintf (stderr, "DEBUG: Audit-Log        : %s\n", (cfgvalues.audit_mode?"Yes":"No"));
		fprintf (stderr, "DEBUG: Show Fieldnames  : %s\n", (cfgvalues.fieldnames_mode?"Yes":"No"));
#ifdef USE_MYSQL
		fprintf (stderr, "DEBUG: Mysql-Mode       : %s\n", (cfgvalues.mysql_mode?"Yes":"No"));
#endif
	}

	/*
	 * connect to database if applicable
	 */
#ifdef USE_MYSQL
	if (cfgvalues.mysql_mode) {
		mysqlconn = connect_to_mysql(&mysql, &mysql_maxnumber, &cfgvalues);
		if (mysqlconn == NULL) {
			fprintf(stderr, "ERROR: Cannot connect to database\n");
			close_log();
			exit_loggrabber(1);
		}
	}
#endif

	/*
	 * function call to get available Logfile-Names (not available in FW1-4.1)
	 */
	if (cfgvalues.showfiles_mode) {
		if (!(cfgvalues.fw1_2000) && !(cfgvalues.online_mode)) {
			get_fw1_logfiles();
		} else {
			fprintf(stderr, "WARNING: This working mode, which lists all log files, are supported. \n");
			close_log();
			exit_loggrabber(1);
		}
		close_log();
		exit_loggrabber(0);
	}

	/*
	 * process all logfiles if ALL specified
	 */
	if (strcmp (cfgvalues.fw1_logfile, "ALL") == 0) {
		if (!(cfgvalues.fw1_2000) && !(cfgvalues.online_mode)) {
			get_fw1_logfiles();
		} else {
			fprintf(stderr, "WARNING: This working mode, which fetches all log files, are supported.\n");
			close_log();
			exit_loggrabber(1);
		}

		lstptr = sl;

		while (lstptr) {
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "DEBUG: Processing Logfile: %s\n", lstptr->data);
			}
        	read_fw1_logfile(&(lstptr->data));
			lstptr = lstptr->next;
		}
	}

	/*
	 * else search for given string in available logfile-names
	 */
	else {
		lstptr = stringlist_search(&sl,cfgvalues.fw1_logfile,&foundstring);

		/*
		 * get the data from the matching logfiles
		 */
        	if (!lstptr) {
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "DEBUG: Processing Logfile: %s\n", cfgvalues.fw1_logfile);
			}
        		read_fw1_logfile(&(cfgvalues.fw1_logfile));
	        }
		while (lstptr) {
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "DEBUG: Processing Logfile: %s\n", foundstring);
			}
        	read_fw1_logfile(&foundstring);
			lstptr = stringlist_search(&(lstptr->next), cfgvalues.fw1_logfile, &foundstring);
		}
	}

	close_log();

	exit_loggrabber(0);
	return(0);
}

/*
 * function read_fw1_logfile
 */
int read_fw1_logfile(char **LogfileName)
{
	OpsecEntity       *pClient    = NULL;
	OpsecEntity       *pServer    = NULL;
	OpsecSession      *pSession   = NULL;
	OpsecEnv          *pEnv       = NULL;
	LeaFilterRulebase *rb;
	int		  rbid = 1;
	int		  i;
	int opsecAlive;

	char*	tmpstr1;
	int capacity = initialCapacity;
	char* buffer=NULL;
	char* message=NULL;

	char*	auth_type;
	char*	fw1_server;
	char*	fw1_port;
	char*	opsec_certificate;
	char*	opsec_client_dn;
	char*	opsec_server_dn;
	char*	leaconf;

#ifdef WIN32
	TCHAR	buff[BUFSIZE];
	DWORD	dwRet;
#else
	long size;
#endif

#ifdef WIN32
	dwRet = GetCurrentDirectory(BUFSIZE, buff);

	if (dwRet == 0) {
		fprintf (stderr, "ERROR: Cannot get current working directory (error code: %d)\n", GetLastError());
		exit_loggrabber(1);
	}
	if (dwRet > BUFSIZE) {
		fprintf (stderr, "ERROR: Getting the current working directory failed failed since buffer too small, and it needs %d chars\n", dwRet);
		exit_loggrabber(1);
	}
	if ((leaconf = (char *)malloc(BUFSIZE)) == NULL) {
		fprintf (stderr, "ERROR: Out of memory\n");
		exit_loggrabber(1);
	}

	if (cfgvalues.leaconfig_filename == NULL) {
		strcpy(leaconf, buff);
		strcat(leaconf, "\\lea.conf");
	} else {
		if ((cfgvalues.leaconfig_filename[0] == '\\') ||
		   ((cfgvalues.leaconfig_filename[1] == ':') && (cfgvalues.leaconfig_filename[2] == '\\'))) {
			strcpy(leaconf, cfgvalues.leaconfig_filename);
		} else {
			strcpy(leaconf, buff);
			strcat(leaconf, "\\");
			strcat(leaconf, cfgvalues.leaconfig_filename);
		}
	}
#else
	size = pathconf(".", _PC_PATH_MAX);
	if ((leaconf = (char *)malloc((size_t)size)) == NULL) {
		fprintf (stderr, "ERROR: Out of memory\n");
		exit_loggrabber(1);
	}

	if (cfgvalues.leaconfig_filename == NULL) {
		if (getcwd(leaconf, (size_t)size) == NULL) {
			fprintf (stderr, "ERROR: Cannot get current working directory\n");
			exit_loggrabber(1);
		}
		strcat(leaconf, "/lea.conf");
	} else {
		if (cfgvalues.leaconfig_filename[0] == '/') {
			strcpy(leaconf, cfgvalues.leaconfig_filename);
		} else {
			if (getcwd(leaconf, (size_t)size) == NULL) {
				fprintf (stderr, "ERROR: Cannot get current working directory\n");
				exit_loggrabber(1);
			}
			strcat(leaconf, "/");
			strcat(leaconf, cfgvalues.leaconfig_filename);
		}
	}
#endif

	while(keepAlive) {

		/* create opsec environment for the main loop */
		if((pEnv = opsec_init(OPSEC_CONF_FILE, leaconf, OPSEC_EOL)) == NULL) {
			fprintf(stderr, "ERROR: unable to create environment (%s)\n", opsec_errno_str(opsec_errno));
			exit_loggrabber(1);
		}

		if (cfgvalues.debug_mode) {

			fprintf(stderr, "DEBUG: OPSEC LEA conf file is %s\n", leaconf);

			fw1_server = opsec_get_conf(pEnv,"lea_server","ip",NULL);
			if(fw1_server==NULL) {
				fprintf(stderr, "ERROR: The fw1 server ip address has not been set.\n");
				exit_loggrabber(1);
			}//end of if
			auth_type = opsec_get_conf(pEnv,"lea_server","auth_type",NULL);
			if (auth_type!=NULL) {
				//Authentication mode
				if (cfgvalues.fw1_2000) {
					//V4.1.2
					fw1_port = opsec_get_conf(pEnv,"lea_server","auth_port",NULL);
					if(fw1_port==NULL) {
						fprintf(stderr, "ERROR: The parameters about authentication mode have not been set.\n");
						exit_loggrabber(1);
					} else {
						fprintf (stderr, "DEBUG: Authentication mode has been used.\n");
						fprintf (stderr, "DEBUG: Server-IP     : %s\n", fw1_server);
						fprintf (stderr, "DEBUG: Server-Port     : %s\n", fw1_port);
						fprintf (stderr, "DEBUG: Authentication type: %s\n", auth_type);
					}//end of inner if
				} else {
					//NG
					fw1_port = opsec_get_conf(pEnv,"lea_server","auth_port",NULL);
					opsec_certificate = opsec_get_conf(pEnv,"opsec_sslca_file",NULL);
					opsec_client_dn = opsec_get_conf(pEnv,"opsec_sic_name",NULL);
					opsec_server_dn = opsec_get_conf(pEnv,"lea_server","opsec_entity_sic_name",NULL);
					if((fw1_port==NULL)||(opsec_certificate==NULL)||(opsec_client_dn==NULL)||(opsec_server_dn==NULL)) {
						fprintf(stderr, "ERROR: The parameters about authentication mode have not been set.\n");
						exit_loggrabber(1);
					} else {
						fprintf (stderr, "DEBUG: Authentication mode has been used.\n");
						fprintf (stderr, "DEBUG: Server-IP     : %s\n", fw1_server);
						fprintf (stderr, "DEBUG: Server-Port     : %s\n", fw1_port);
						fprintf (stderr, "DEBUG: Authentication type: %s\n", auth_type);
						fprintf (stderr, "DEBUG: OPSEC sic certificate file name : %s\n", opsec_certificate);
						fprintf (stderr, "DEBUG: Server DN (sic name) : %s\n", opsec_server_dn);
						fprintf (stderr, "DEBUG: OPSEC LEA client DN (sic name) : %s\n", opsec_client_dn);
					}//end of inner if
				}
			} else {
				//Clear Text mode, i.e. non-auth mode
				fw1_port = opsec_get_conf(pEnv,"lea_server","port",NULL);
				if(fw1_port!=NULL) {
					fprintf (stderr, "DEBUG: Clear text mode has been used.\n");
					fprintf (stderr, "DEBUG: Server-IP        : %s\n", fw1_server);
					fprintf (stderr, "DEBUG: Server-Port      : %s\n", fw1_port);
				} else {
					fprintf(stderr, "ERROR: The fw1 server lea service port has not been set.\n");
					exit_loggrabber(1);
				}//end of inner if
			}//end of middle if
		}//end of if

		/*
		 * initialize opsec-client
		 */
	#ifdef USE_MYSQL
		if (cfgvalues.mysql_mode) {
			pClient = opsec_init_entity(pEnv, LEA_CLIENT,
								LEA_RECORD_HANDLER, read_fw1_logfile_record_mysql,
					LEA_DICT_HANDLER, read_fw1_logfile_dict,
					LEA_EOF_HANDLER, read_fw1_logfile_eof,
					LEA_SWITCH_HANDLER, read_fw1_logfile_switch,
					LEA_FILTER_QUERY_ACK, ((filtercount > 0) ? read_fw1_logfile_queryack : NULL),
					LEA_COL_LOGS_HANDLER, read_fw1_logfile_collogs,
					LEA_SUSPEND_HANDLER, read_fw1_logfile_suspend,
					LEA_RESUME_HANDLER, read_fw1_logfile_resume,
					OPSEC_SESSION_START_HANDLER, read_fw1_logfile_start,
					OPSEC_SESSION_END_HANDLER, read_fw1_logfile_end,
					OPSEC_SESSION_ESTABLISHED_HANDLER, read_fw1_logfile_established,
					OPSEC_EOL);
		} else {
	#endif
			pClient = opsec_init_entity(pEnv, LEA_CLIENT,
								LEA_RECORD_HANDLER, ((cfgvalues.audit_mode) ? read_fw1_logfile_a_record_stdout : read_fw1_logfile_n_record_stdout),
					LEA_DICT_HANDLER, read_fw1_logfile_dict,
					LEA_EOF_HANDLER, read_fw1_logfile_eof,
					LEA_SWITCH_HANDLER, read_fw1_logfile_switch,
					LEA_FILTER_QUERY_ACK, ((filtercount > 0) ? read_fw1_logfile_queryack : NULL),
					LEA_COL_LOGS_HANDLER, read_fw1_logfile_collogs,
					LEA_SUSPEND_HANDLER, read_fw1_logfile_suspend,
					LEA_RESUME_HANDLER, read_fw1_logfile_resume,
					OPSEC_SESSION_START_HANDLER, read_fw1_logfile_start,
					OPSEC_SESSION_END_HANDLER, read_fw1_logfile_end,
					OPSEC_SESSION_ESTABLISHED_HANDLER, read_fw1_logfile_established,
					OPSEC_EOL);
	#ifdef USE_MYSQL
		}
	#endif

		/*
		 * initialize opsec-server for authenticated and unauthenticated connections
		 */

		pServer = opsec_init_entity(pEnv, LEA_SERVER, OPSEC_ENTITY_NAME, "lea_server", OPSEC_EOL);

		/*
		 * continue only if opsec initializations were successful
		 */
		if ((!pClient) || (!pServer))
		{
			fprintf(stderr, "ERROR: failed to initialize client/server-pair (%s)\n", opsec_errno_str(opsec_errno));
			cleanup_fw1_environment(pEnv, pClient, pServer);
			exit_loggrabber(1);
		}

		/*
		 * create LEA-session. differs for connections to FW-1 4.1 and FW-1 NG
		 */
		if (cfgvalues.fw1_2000) {
			if (cfgvalues.online_mode) {
				pSession = lea_new_session(pClient, pServer, LEA_ONLINE, LEA_FILENAME, *LogfileName, LEA_AT_END);
			} else {
				pSession = lea_new_session(pClient, pServer, LEA_OFFLINE, LEA_FILENAME, *LogfileName, LEA_AT_START);
			}
			if (!pSession) {
				fprintf(stderr, "ERROR: failed to create session (%s)\n", opsec_errno_str(opsec_errno));
				cleanup_fw1_environment(pEnv, pClient, pServer);
				exit_loggrabber(1);
			}
		} else {
			/*
			 * create a suspended session, i.e. not log data will be sent to client
			 */
			if (cfgvalues.online_mode) {
				pSession = lea_new_suspended_session(pClient, pServer, LEA_ONLINE, LEA_UNIFIED_SINGLE, *LogfileName, LEA_AT_END);
			} else {
				pSession = lea_new_suspended_session(pClient, pServer, LEA_OFFLINE, LEA_UNIFIED_SINGLE, *LogfileName, LEA_AT_START);
			}
			if (!pSession) {
				fprintf(stderr, "ERROR: failed to create session (%s)\n", opsec_errno_str(opsec_errno));
				cleanup_fw1_environment(pEnv, pClient, pServer);
				exit_loggrabber(1);
			}

			/*
			 * If filters were defined, create the rulebase and register it.
			 * the session will be resumed, as soon as the server sends the
			 * filter_ack-event.
			 * In the case when no filters are used, the suspended session
			 * will be continued immediately.
			 */
			if (filtercount > 0) {
				if ((rb = lea_filter_rulebase_create()) == NULL) {
					fprintf(stderr, "ERROR: failed to create rulebase\n");
					exit_loggrabber(1);
				}

				for (i=0 ; i < filtercount ; i++) {
					if (cfgvalues.audit_mode) {
						if ((rb = create_audit_filter_rule(rb,filterarray[i])) == NULL) {
							fprintf(stderr, "ERROR: failed to create rule\n");
							exit_loggrabber(1);
						}
					} else {
						if ((rb = create_fw1_filter_rule(rb,filterarray[i])) == NULL) {
							fprintf(stderr, "ERROR: failed to create rule\n");
							exit_loggrabber(1);
						}
					}
				}

				if (lea_filter_rulebase_register(pSession, rb, &rbid) == LEA_FILTER_ERR) {
					fprintf(stderr, "ERROR: Cannot register rulebase\n");
				}
			} else {
				lea_session_resume(pSession);
			}
		}

		/*
		 * display header line if cfgvalues.fieldnames_mode == 0
		 */
		if (!(cfgvalues.fieldnames_mode)) {
			// This last plus one is needed to hold the terminator, '\0' //
			message = (char *) malloc(capacity+1);
			if (message == NULL) {
				fprintf(stderr, "ERROR: Out of memory\n");
				exit_loggrabber(1);
			}
			*message='\0';

			if (cfgvalues.audit_mode) {
				if ((!output_fields) || (afield_output[AIDX_NUM])) {
					tmpstr1 = string_escape(*afield_headers[AIDX_NUM], cfgvalues.record_separator);
					if(capacity>=(strlen(message)+strlen(tmpstr1))) {
						strcat(message,tmpstr1);
					} else {
						capacity = ((capacity+capacityIncrement) >= (strlen(message)+strlen(tmpstr1))) ? (capacity+capacityIncrement) : (strlen(message)+strlen(tmpstr1));
						buffer = (char *) malloc(strlen(message)+1);
						if (buffer == NULL) {
							fprintf(stderr, "ERROR: Out of memory\n");
							exit_loggrabber(1);
						}
						strcpy(buffer,message);
						free(message);
						// This last plus one is needed to hold the terminator, '\0' //
						message = (char *) malloc(capacity+1);
						if (message == NULL) {
							fprintf(stderr, "ERROR: Out of memory\n");
							exit_loggrabber(1);
						}
						strcpy(message,buffer);
						free(buffer);
						strcat(message,tmpstr1);
					}
					free(tmpstr1);
						}

					for (i=1 ; i< NUMBER_AIDX_FIELDS ; i++) {
							if ((!output_fields) || (afield_output[i])) {
						tmpstr1 = string_escape(*afield_headers[i], cfgvalues.record_separator);
						sprintf(stringnumber, "%c%s", cfgvalues.record_separator, tmpstr1);
						if(capacity>=(strlen(message)+strlen(stringnumber))) {
							strcat(message,stringnumber);
						} else {
							capacity = ((capacity+capacityIncrement) >= (strlen(message)+strlen(stringnumber))) ? (capacity+capacityIncrement) : (strlen(message)+strlen(stringnumber));
							buffer = (char *) malloc(strlen(message)+1);
							if (buffer == NULL) {
								fprintf(stderr, "ERROR: Out of memory\n");
								exit_loggrabber(1);
							}
							strcpy(buffer,message);
							free(message);
							// This last plus one is needed to hold the terminator, '\0' //
							message = (char *) malloc(capacity+1);
							if (message == NULL) {
								fprintf(stderr, "ERROR: Out of memory\n");
								exit_loggrabber(1);
							}
							strcpy(message,buffer);
							free(buffer);
							strcat(message,stringnumber);
						}
						free(tmpstr1);
								}
						}
			} else {
				if ((!output_fields) || (lfield_output[LIDX_NUM])) {
					tmpstr1 = string_escape(*lfield_headers[LIDX_NUM], cfgvalues.record_separator);
					if(capacity>=(strlen(message)+strlen(tmpstr1))) {
						strcat(message,tmpstr1);
					} else {
						capacity = ((capacity+capacityIncrement) >= (strlen(message)+strlen(tmpstr1))) ? (capacity+capacityIncrement) : (strlen(message)+strlen(tmpstr1));
						buffer = (char *) malloc(strlen(message)+1);
						if (buffer == NULL) {
							fprintf(stderr, "ERROR: Out of memory\n");
							exit_loggrabber(1);
						}
						strcpy(buffer,message);
						free(message);
						// This last plus one is needed to hold the terminator, '\0' //
						message = (char *) malloc(capacity+1);
						if (message == NULL) {
							fprintf(stderr, "ERROR: Out of memory\n");
							exit_loggrabber(1);
						}
						strcpy(message,buffer);
						free(buffer);
						strcat(message,tmpstr1);
					}
					free(tmpstr1);
						}

					for (i=1 ; i< NUMBER_LIDX_FIELDS ; i++) {
							if ((!output_fields) || (lfield_output[i])) {
						tmpstr1 = string_escape(*lfield_headers[i], cfgvalues.record_separator);
						sprintf(stringnumber, "%c%s", cfgvalues.record_separator, tmpstr1);
						if(capacity>=(strlen(message)+strlen(stringnumber))) {
							strcat(message,stringnumber);
						} else {
							capacity = ((capacity+capacityIncrement) >= (strlen(message)+strlen(stringnumber))) ? (capacity+capacityIncrement) : (strlen(message)+strlen(stringnumber));
							buffer = (char *) malloc(strlen(message)+1);
							if (buffer == NULL) {
								fprintf(stderr, "ERROR: Out of memory\n");
								exit_loggrabber(1);
							}
							strcpy(buffer,message);
							free(message);
							// This last plus one is needed to hold the terminator, '\0' //
							message = (char *) malloc(capacity+1);
							if (message == NULL) {
								fprintf(stderr, "ERROR: Out of memory\n");
								exit_loggrabber(1);
							}
							strcpy(message,buffer);
							free(buffer);
							strcat(message,stringnumber);
						}
						free(tmpstr1);
								}
						}
			}

			submit_log(message);

			//clean used memory
			free(message);
		}

		opsecAlive = opsec_start_keep_alive(pSession, 0);

		/*
		 * start the opsec loop
		 */
		opsec_mainloop(pEnv);

		/*
		 * remove opsec stuff
		 */
		cleanup_fw1_environment(pEnv, pClient, pServer);

		SLEEP(recoverInterval);

	}

#ifdef USE_MYSQL
	/*
	 * close database connection
	 */
	if (cfgvalues.mysql_mode) {
		disconnect_from_mysql(mysqlconn);
	}
#endif

	free(leaconf);

	return 0;
}

/*
 * function read_fw1_logfile_queryack
 */
int read_fw1_logfile_queryack(OpsecSession *psession, int filterID, eLeaFilterAction filterAction, int filterResult)
{
	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: LEA logfile query ack handler was invoked\n");
	}
	lea_session_resume(psession);
	return OPSEC_SESSION_OK;
}

/*
 * function read_fw1_logfile_record_mysql
 */
#ifdef USE_MYSQL
int read_fw1_logfile_record_mysql(OpsecSession *pSession, lea_record *pRec, int pnAttribPerm[])
{
	int          	i;
	char        	*szResValue;
	char        	*szAttrib;
	unsigned long 	ul;
	unsigned short 	us;
	char 		tmpdata[16];

	char 		fields[4096];
	char		values[4096];
	char		sqlstatement[8300];
	int		state;
	int		skip;
	char		year[5];
	char		month[4];
	char		day[3];
	char		hour[3];
	char		minute[3];
	char		second[3];
	char		datetime[20];

	/*
	 * print number of logentry
	 */
	strcpy(fields,"");
	strcpy(values,"");
	strcat(fields,"number");
	sprintf(values,"%ld", ++mysql_maxnumber);

	/*
	 * process all fields of logentry
	 */
	for (i=0; i<pRec->n_fields; i++)
	{
		skip = 0;
		szAttrib = lea_attr_name(pSession, pRec->fields[i].lea_attr_id);
		if (strcmp(szAttrib, "time") == 0) {
		} else if (strcmp(szAttrib, "action") == 0) {
		} else if (strcmp(szAttrib, "orig") == 0) {
		} else if (strcmp(szAttrib, "i/f_dir") == 0) {
			strcpy(szAttrib,"if_dir");
		} else if (strcmp(szAttrib, "i/f_name") == 0) {
			strcpy(szAttrib,"if_name");
		} else if (strcmp(szAttrib, "service") == 0) {
		} else if (strcmp(szAttrib, "s_port") == 0) {
		} else if (strcmp(szAttrib, "src") == 0) {
		} else if (strcmp(szAttrib, "dst") == 0) {
		} else if (strcmp(szAttrib, "proto") == 0) {
		} else if (strcmp(szAttrib, "rule") == 0) {
		} else if (strcmp(szAttrib, "xlatesrc") == 0) {
		} else if (strcmp(szAttrib, "xlatedst") == 0) {
		} else if (strcmp(szAttrib, "xlatesport") == 0) {
		} else if (strcmp(szAttrib, "xlatedport") == 0) {
		} else if (strcmp(szAttrib, "nat_rulenum") == 0) {
		} else if (strcmp(szAttrib, "resource") == 0) {
		} else if (strcmp(szAttrib, "elapsed") == 0) {
		} else if (strcmp(szAttrib, "packets") == 0) {
		} else if (strcmp(szAttrib, "bytes") == 0) {
		} else if (strcmp(szAttrib, "reason") == 0) {
		} else if (strcmp(szAttrib, "service_name") == 0) {
		} else if (strcmp(szAttrib, "agent") == 0) {
		} else if (strcmp(szAttrib, "from") == 0) {
			strcpy(szAttrib,"fw1from");
		} else if (strcmp(szAttrib, "to") == 0) {
			strcpy(szAttrib,"fw1to");
		} else if (strcmp(szAttrib, "product") == 0) {
		} else if (strcmp(szAttrib, "Operation") == 0) {
		} else if (strcmp(szAttrib, "Administrator") == 0) {
		} else if (strcmp(szAttrib, "Machine") == 0) {
		} else if (strcmp(szAttrib, "Additional Info") == 0) {
			strcpy(szAttrib,"Additional_Info");
		} else if (strcmp(szAttrib, "FieldsChanges") == 0) {
		} else if (strcmp(szAttrib, "ObjectName") == 0) {
		} else if (strcmp(szAttrib, "ObjectType") == 0) {
		} else if (strcmp(szAttrib, "sys_msgs") == 0) {
		} else {
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "WARNING: Unsupported field detected in mysql-mode: %s\n", szAttrib);
			}
			skip = 1;
		}

		if (!skip) {
			if (!(cfgvalues.resolve_mode)) {
				switch (pRec->fields[i].lea_val_type) {
				  /*
				   * create dotted string of IP address. this differs between
				   * Linux and Solaris.
				   */
       			          case LEA_VT_IP_ADDR:
					ul = pRec->fields[i].lea_value.ul_value;
					if (BYTE_ORDER == LITTLE_ENDIAN) {
						sprintf(tmpdata,"%d.%d.%d.%d", (int)((ul & 0xff) >> 0), (int)((ul & 0xff00) >> 8), (int)((ul & 0xff0000) >> 16), (int)((ul & 0xff000000) >> 24));
					} else {
						sprintf(tmpdata,"%d.%d.%d.%d", (int)((ul & 0xff000000) >> 24), (int)((ul & 0xff0000) >> 16), (int)((ul & 0xff00) >> 8), (int)((ul & 0xff) >> 0));
					}
					strcat(fields, ",");
					strcat(fields, szAttrib);
					strcat(values, ",\"");
					strcat(values, tmpdata);
					strcat(values, "\"");
					break;
				  /*
				   * print out the port number of the used service
				   */
				  case LEA_VT_TCP_PORT:
				  case LEA_VT_UDP_PORT:
					us = pRec->fields[i].lea_value.ush_value;
					if (BYTE_ORDER == LITTLE_ENDIAN) {
						us = (us >> 8) + ((us & 0xff) << 8);
					}
					sprintf(tmpdata,"%d", us);
					strcat(fields, ",");
					strcat(fields, szAttrib);
					strcat(values, ",\"");
					strcat(values, tmpdata);
					strcat(values, "\"");
					break;
				  /*
				   * for all other data types, use the normal behaviour
				   */
				  default:
					strcat(fields, ",");
					strcat(fields, szAttrib);
					szResValue = lea_resolve_field(pSession, pRec->fields[i]);
					if (strcmp(szAttrib, "time") == 0) {
						day[0]=(szResValue==' ')?'0':szResValue[0];day[1]=szResValue[1];day[2]=0;
						month[0]=szResValue[2];month[1]=szResValue[3];month[2]=szResValue[4];month[3]=0;
						if (strcmp(month,"Jan") == 0) { strcpy(month, "01\0"); }
						else if (strcmp(month,"Feb") == 0) { strcpy(month, "02\0"); }
						else if (strcmp(month,"Mar") == 0) { strcpy(month, "03\0"); }
						else if (strcmp(month,"Apr") == 0) { strcpy(month, "04\0"); }
						else if (strcmp(month,"May") == 0) { strcpy(month, "05\0"); }
						else if (strcmp(month,"Jun") == 0) { strcpy(month, "06\0"); }
						else if (strcmp(month,"Jul") == 0) { strcpy(month, "07\0"); }
						else if (strcmp(month,"Aug") == 0) { strcpy(month, "08\0"); }
						else if (strcmp(month,"Sep") == 0) { strcpy(month, "09\0"); }
						else if (strcmp(month,"Oct") == 0) { strcpy(month, "10\0"); }
						else if (strcmp(month,"Nov") == 0) { strcpy(month, "11\0"); }
						else if (strcmp(month,"Dec") == 0) { strcpy(month, "12\0"); }
						year[0]=szResValue[5];year[1]=szResValue[6];year[2]=szResValue[7];year[3]=szResValue[8];year[4]=0;
						hour[0]=szResValue[10];hour[1]=szResValue[11];hour[2]=0;
						minute[0]=szResValue[13];minute[1]=szResValue[14];minute[2]=0;
						second[0]=szResValue[16];second[1]=szResValue[17];second[2]=0;
						sprintf (datetime, "%s-%s-%s %s:%s:%s", year, month, day, hour, minute, second);
						strcat(values, ",\"");
						strcat(values, datetime);
						strcat(values, "\"");
					} else {
						strcat(values, ",\"");
						strcat(values, szResValue);
						strcat(values, "\"");
					}
				}
			} else {
				/*
				 * just use the normal resolving behaviour for all fields
				 */
				strcat(fields, ",");
				strcat(fields, szAttrib);
				szResValue = lea_resolve_field(pSession, pRec->fields[i]);
				if (strcmp(szAttrib, "time") == 0) {
					day[0]=(szResValue[0]==' ')?'0':szResValue[0];day[1]=szResValue[1];day[2]=0;
					month[0]=szResValue[2];month[1]=szResValue[3];month[2]=szResValue[4];month[3]=0;
					if (strcmp(month,"Jan") == 0) { strcpy(month, "01\0"); }
					else if (strcmp(month,"Feb") == 0) { strcpy(month, "02\0"); }
					else if (strcmp(month,"Mar") == 0) { strcpy(month, "03\0"); }
					else if (strcmp(month,"Apr") == 0) { strcpy(month, "04\0"); }
					else if (strcmp(month,"May") == 0) { strcpy(month, "05\0"); }
					else if (strcmp(month,"Jun") == 0) { strcpy(month, "06\0"); }
					else if (strcmp(month,"Jul") == 0) { strcpy(month, "07\0"); }
					else if (strcmp(month,"Aug") == 0) { strcpy(month, "08\0"); }
					else if (strcmp(month,"Sep") == 0) { strcpy(month, "09\0"); }
					else if (strcmp(month,"Oct") == 0) { strcpy(month, "10\0"); }
					else if (strcmp(month,"Nov") == 0) { strcpy(month, "11\0"); }
					else if (strcmp(month,"Dec") == 0) { strcpy(month, "12\0"); }
					year[0]=szResValue[5];year[1]=szResValue[6];year[2]=szResValue[7];year[3]=szResValue[8];year[4]=0;
					hour[0]=szResValue[10];hour[1]=szResValue[11];hour[2]=0;
					minute[0]=szResValue[13];minute[1]=szResValue[14];minute[2]=0;
					second[0]=szResValue[16];second[1]=szResValue[17];second[2]=0;
					sprintf (datetime, "%s-%s-%s %s:%s:%s", year, month, day, hour, minute, second);
					strcat(values, ",\"");
					strcat(values, datetime);
					strcat(values, "\"");
				} else {
					strcat(values, ",\"");
					strcat(values, szResValue);
					strcat(values, "\"");
				}
			}
		}
	}

	if (cfgvalues.audit_mode) {
		sprintf(sqlstatement, "INSERT INTO auditentries (%s) VALUES (%s)", fields, values);
	} else {
		sprintf(sqlstatement, "INSERT INTO logentries (%s) VALUES (%s)", fields, values);
	}

	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: %s\n", sqlstatement);
	}

	state = mysql_query(mysqlconn, sqlstatement);
	if (state != 0) {
 		printf(mysql_error(mysqlconn));
		disconnect_from_mysql(mysqlconn);
		exit_loggrabber(1);
	}
	return OPSEC_SESSION_OK;
}
#endif

/*
 * function read_fw1_logfile_n_record_stdout
 */
int read_fw1_logfile_n_record_stdout(OpsecSession *pSession, lea_record *pRec, int pnAttribPerm[])
{
	char* 		szAttrib;
	char 		szNum[20];
	int 		i,j,match;
	unsigned long	ul;
	unsigned short	us;
	char 		tmpdata[16];
	time_t 		logtime;
	struct tm*	datetime;
	char 		timestring[21];
	char*		tmpstr1;
	char*		tmpstr2;

	int		capacity = initialCapacity;
	char*		buffer=NULL;
	char*		message=NULL;

	// This last plus one is needed to hold the terminator, '\0' //
	message = (char *) malloc(capacity+1);
	if (message == NULL) {
		fprintf(stderr, "ERROR: Out of memory\n");
		exit_loggrabber(1);
	}
        *message='\0';

	/*
	 * get record position
	 */
	sprintf(szNum, "%d", lea_get_record_pos(pSession) -1);
	*lfields[LIDX_NUM] = string_duplicate(szNum);

	/*
         * process all fields of logentry
         */
	for (i=0 ; i < pRec->n_fields ; i++)
	{
		j = 0;
		match = FALSE;
		strcpy(tmpdata, "\0");
		szAttrib = lea_attr_name (pSession, pRec->fields[i].lea_attr_id);

                if (!(cfgvalues.resolve_mode)) {
                        switch (pRec->fields[i].lea_val_type) {
                          /*
                           * create dotted string of IP address. this differs between
                           * Linux and Solaris.
                           */
                          case LEA_VT_IP_ADDR:
                                ul = pRec->fields[i].lea_value.ul_value;
                                if (BYTE_ORDER == LITTLE_ENDIAN) {
                                        sprintf(tmpdata,"%d.%d.%d.%d", (int)((ul & 0xff) >> 0), (int)((ul & 0xff00) >> 8), (int)((ul & 0xff0000) >> 16), (int)((ul & 0xff000000) >> 24));
                                } else {
                                        sprintf(tmpdata,"%d.%d.%d.%d", (int)((ul & 0xff000000) >> 24), (int)((ul & 0xff0000) >> 16), (int)((ul & 0xff00) >> 8), (int)((ul & 0xff) >> 0));
                                }
                                break;

                          /*
                           * print out the port number of the used service
                           */
                          case LEA_VT_TCP_PORT:
                          case LEA_VT_UDP_PORT:
                                us = pRec->fields[i].lea_value.ush_value;
                                if (BYTE_ORDER == LITTLE_ENDIAN) {
                                        us = (us >> 8) + ((us & 0xff) << 8);
                                }
                                sprintf(tmpdata,"%d", us);
                                break;
                        }
		}

		/*
		 * transfer values to array
		 */
		while (!match && (j < NUMBER_LIDX_FIELDS)) {
			if (strcmp(szAttrib, *lfield_headers[LIDX_TIME]) == 0) {
				switch (cfgvalues.dateformat) {
				  case DATETIME_CP:
					*lfields[LIDX_TIME] = string_duplicate(lea_resolve_field(pSession, pRec->fields[i]));
					break;
				  case DATETIME_UNIX:
					sprintf(timestring, "%lu", pRec->fields[i].lea_value.ul_value);
					*lfields[LIDX_TIME] = string_duplicate(timestring);
					break;
				  case DATETIME_STD:
					logtime = (time_t)pRec->fields[i].lea_value.ul_value;
					datetime = localtime(&logtime);
					strftime (timestring, 20, "%Y-%m-%d %H:%M:%S", datetime);
					*lfields[LIDX_TIME] = string_duplicate(timestring);
					break;
				  default:
					fprintf(stderr, "ERROR: Unsupported dateformat chosen\n");
					exit_loggrabber(1);
				}
				match = TRUE;
			}
			else if (strcmp(szAttrib, *lfield_headers[j]) == 0) {
				if (tmpdata[0]) {
					*lfields[j] = string_duplicate(tmpdata);
				} else {
					*lfields[j] = string_duplicate(lea_resolve_field(pSession, pRec->fields[i]));
				}
				match = TRUE;
			}
			j++;
		}

		if (cfgvalues.debug_mode && (!match)) {
			fprintf(stderr, "DEBUG: Unsupported field found (Position %d): %s=%s\n", i-1, szAttrib, lea_resolve_field(pSession, pRec->fields[i]));
		}
	}

	/*
	 * print logentry to stdout
	 */
	if ((!output_fields) || (lfield_output[LIDX_NUM])) {
		if (cfgvalues.fieldnames_mode) {
			tmpstr1 = string_escape(*lfield_headers[LIDX_NUM], cfgvalues.record_separator);
			tmpstr2 = string_escape(*lfields[LIDX_NUM], cfgvalues.record_separator);
			sprintf(stringnumber, "%s=%s", tmpstr1, tmpstr2);
			if(capacity>=(strlen(message)+strlen(stringnumber))) {
				strcat(message,stringnumber);
			} else {
				capacity = ((capacity+capacityIncrement) >= (strlen(message)+strlen(stringnumber))) ? (capacity+capacityIncrement) : (strlen(message)+strlen(stringnumber));
				buffer = (char *) malloc(strlen(message)+1);
				if (buffer == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
				strcpy(buffer,message);
				free(message);
				// This last plus one is needed to hold the terminator, '\0' //
				message = (char *) malloc(capacity+1);
				if (message == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
				strcpy(message,buffer);
				free(buffer);
				strcat(message,stringnumber);
			}

			free(tmpstr1);
			free(tmpstr2);
		} else {
			tmpstr1 = string_escape(*lfields[LIDX_NUM], cfgvalues.record_separator);
			if(capacity>=(strlen(message)+strlen(tmpstr1))) {
				strcat(message,tmpstr1);
			} else {
				capacity = ((capacity+capacityIncrement) >= (strlen(message)+strlen(tmpstr1))) ? (capacity+capacityIncrement) : (strlen(message)+strlen(tmpstr1));
				buffer = (char *) malloc(strlen(message)+1);
				if (buffer == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
				strcpy(buffer,message);
				free(message);
				// This last plus one is needed to hold the terminator, '\0' //
				message = (char *) malloc(capacity+1);
				if (message == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
				strcpy(message,buffer);
				free(buffer);
				strcat(message,tmpstr1);
			}
			free(tmpstr1);
		}
	}
	if (*lfields[LIDX_NUM] != NULL) {
		free(*lfields[LIDX_NUM]);
		*lfields[LIDX_NUM] = NULL;
	}

	for (i=1 ; i< NUMBER_LIDX_FIELDS ; i++) {
		if ((!output_fields) || (lfield_output[i])) {
			if (*lfields[i]) {
				if (cfgvalues.fieldnames_mode) {
					tmpstr1 = string_escape(*lfield_headers[i], cfgvalues.record_separator);
					tmpstr2 = string_escape(*lfields[i], cfgvalues.record_separator);
					sprintf(stringnumber, "%c%s=%s", cfgvalues.record_separator, tmpstr1, tmpstr2);
					if(capacity>=(strlen(message)+strlen(stringnumber))) {
						strcat(message,stringnumber);
					} else {
						capacity = ((capacity+capacityIncrement) >= (strlen(message)+strlen(stringnumber))) ? (capacity+capacityIncrement) : (strlen(message)+strlen(stringnumber));
						buffer = (char *) malloc(strlen(message)+1);
						if (buffer == NULL) {
							fprintf(stderr, "ERROR: Out of memory\n");
							exit_loggrabber(1);
						}
						strcpy(buffer,message);
						free(message);
						// This last plus one is needed to hold the terminator, '\0' //
						message = (char *) malloc(capacity+1);
						if (message == NULL) {
							fprintf(stderr, "ERROR: Out of memory\n");
							exit_loggrabber(1);
						}
						strcpy(message,buffer);
						free(buffer);
						strcat(message,stringnumber);
					}
					free(tmpstr1);
					free(tmpstr2);
				} else {
					tmpstr1 = string_escape(*lfields[i], cfgvalues.record_separator);

					sprintf(stringnumber, "%c%s", cfgvalues.record_separator, tmpstr1);
					if(capacity>=(strlen(message)+strlen(stringnumber))) {
						strcat(message,stringnumber);
					} else {
						capacity = ((capacity+capacityIncrement) >= (strlen(message)+strlen(stringnumber))) ? (capacity+capacityIncrement) : (strlen(message)+strlen(stringnumber));
						buffer = (char *) malloc(strlen(message)+1);
						if (buffer == NULL) {
							fprintf(stderr, "ERROR: Out of memory\n");
							exit_loggrabber(1);
						}
						strcpy(buffer,message);
						free(message);
						// This last plus one is needed to hold the terminator, '\0' //
						message = (char *) malloc(capacity+1);
						if (message == NULL) {
							fprintf(stderr, "ERROR: Out of memory\n");
							exit_loggrabber(1);
						}
						strcpy(message,buffer);
						free(buffer);
						strcat(message,stringnumber);
					}
					free(tmpstr1);
				}
			} else {
				if (!(cfgvalues.fieldnames_mode)) {
					sprintf(stringnumber, "%c", cfgvalues.record_separator);
					if(capacity>=(strlen(message)+strlen(stringnumber))) {
						strcat(message,stringnumber);
					} else {
						capacity = ((capacity+capacityIncrement) >= (strlen(message)+strlen(stringnumber))) ? (capacity+capacityIncrement) : (strlen(message)+strlen(stringnumber));
						buffer = (char *) malloc(strlen(message)+1);
						if (buffer == NULL) {
							fprintf(stderr, "ERROR: Out of memory\n");
							exit_loggrabber(1);
						}
						strcpy(buffer,message);
						free(message);
						// This last plus one is needed to hold the terminator, '\0' //
						message = (char *) malloc(capacity+1);
						if (message == NULL) {
							fprintf(stderr, "ERROR: Out of memory\n");
							exit_loggrabber(1);
						}//end of inner if
						strcpy(message,buffer);
						free(buffer);
						strcat(message,stringnumber);
					}//end of middle if
				}
			}
		}
		if (*lfields[i] != NULL) {
			free(*lfields[i]);
			*lfields[i] = NULL;
		}
	}

	submit_log(message);

	//clean used memory
	free(message);

	return OPSEC_SESSION_OK;
}

/*
 * function read_fw1_logfile_a_record_stdout
 */
int read_fw1_logfile_a_record_stdout(OpsecSession *pSession, lea_record *pRec, int pnAttribPerm[])
{
	char* 		szAttrib;
	char 		szNum[20];
	int 		i,j,match;
	unsigned long	ul;
	unsigned short	us;
	char 		tmpdata[16];
	time_t 		logtime;
	struct tm*	datetime;
	char 		timestring[21];
	char*		tmpstr1;
	char*		tmpstr2;

	int		capacity = initialCapacity;
	char*		buffer=NULL;
	char*		message=NULL;

	// This last plus one is needed to hold the terminator, '\0' //
	message = (char *) malloc(capacity+1);
	if (message == NULL) {
		fprintf(stderr, "ERROR: Out of memory\n");
		exit_loggrabber(1);
	}
        *message='\0';

	/*
	 * get record position
	 */
	sprintf(szNum, "%d", lea_get_record_pos(pSession) -1);
	*afields[AIDX_NUM] = string_duplicate(szNum);

	/*
         * process all fields of logentry
         */
	for (i=0 ; i < pRec->n_fields ; i++)
	{
		j = 0;
		match = FALSE;
		strcpy(tmpdata, "\0");
		szAttrib = lea_attr_name (pSession, pRec->fields[i].lea_attr_id);

                if (!(cfgvalues.resolve_mode)) {
                        switch (pRec->fields[i].lea_val_type) {
                          /*
                           * create dotted string of IP address. this differs between
                           * Linux and Solaris.
                           */
                          case LEA_VT_IP_ADDR:
                                ul = pRec->fields[i].lea_value.ul_value;
                                if (BYTE_ORDER == LITTLE_ENDIAN) {
                                        sprintf(tmpdata,"%d.%d.%d.%d", (int)((ul & 0xff) >> 0), (int)((ul & 0xff00) >> 8), (int)((ul & 0xff0000) >> 16), (int)((ul & 0xff000000) >> 24));
                                } else {
                                        sprintf(tmpdata,"%d.%d.%d.%d", (int)((ul & 0xff000000) >> 24), (int)((ul & 0xff0000) >> 16), (int)((ul & 0xff00) >> 8), (int)((ul & 0xff) >> 0));
                                }
                                break;

                          /*
                           * print out the port number of the used service
                           */
                          case LEA_VT_TCP_PORT:
                          case LEA_VT_UDP_PORT:
                                us = pRec->fields[i].lea_value.ush_value;
                                if (BYTE_ORDER == LITTLE_ENDIAN) {
                                        us = (us >> 8) + ((us & 0xff) << 8);
                                }
                                sprintf(tmpdata,"%d", us);
                                break;
                        }
		}

		/*
		 * transfer values to array
		 */
		while (!match && (j < NUMBER_AIDX_FIELDS)) {
			if (strcmp(szAttrib, *afield_headers[AIDX_TIME]) == 0) {
				switch (cfgvalues.dateformat) {
				  case DATETIME_CP:
					*afields[AIDX_TIME] = string_duplicate(lea_resolve_field(pSession, pRec->fields[i]));
					break;
				  case DATETIME_UNIX:
					sprintf(timestring, "%lu", pRec->fields[i].lea_value.ul_value);
					*afields[AIDX_TIME] = string_duplicate(timestring);
					break;
				  case DATETIME_STD:
					logtime = (time_t)pRec->fields[i].lea_value.ul_value;
					datetime = localtime(&logtime);
					strftime (timestring, 20, "%Y-%m-%d %H:%M:%S", datetime);
					*afields[AIDX_TIME] = string_duplicate(timestring);
					break;
				  default:
					fprintf(stderr, "ERROR: Unsupported dateformat chosen\n");
					exit_loggrabber(1);
				}
				match = TRUE;
			}
			else if (strcmp(szAttrib, *afield_headers[j]) == 0) {
				if (tmpdata[0]) {
					*afields[j] = string_duplicate(tmpdata);
				} else {
					*afields[j] = string_duplicate(lea_resolve_field(pSession, pRec->fields[i]));
				}
				match = TRUE;
			}
			j++;
		}

		if (cfgvalues.debug_mode && (!match)) {
			fprintf(stderr, "DEBUG: Unsupported field found (Position %d): %s=%s\n", i-1, szAttrib, lea_resolve_field(pSession, pRec->fields[i]));
		}
	}

	/*
	 * print logentry to stdout
	 */
	if ((!output_fields) || (afield_output[AIDX_NUM])) {
		if (cfgvalues.fieldnames_mode) {
			tmpstr1 = string_escape(*afield_headers[AIDX_NUM], cfgvalues.record_separator);
			tmpstr2 = string_escape(*afields[AIDX_NUM], cfgvalues.record_separator);
			sprintf(stringnumber, "%s=%s", tmpstr1, tmpstr2);
			if(capacity>=(strlen(message)+strlen(stringnumber))) {
				strcat(message,stringnumber);
			} else {
				capacity = ((capacity+capacityIncrement) >= (strlen(message)+strlen(stringnumber))) ? (capacity+capacityIncrement) : (strlen(message)+strlen(stringnumber));
				buffer = (char *) malloc(strlen(message)+1);
				if (buffer == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
				strcpy(buffer,message);
				free(message);
				// This last plus one is needed to hold the terminator, '\0' //
				message = (char *) malloc(capacity+1);
				if (message == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
				strcpy(message,buffer);
				free(buffer);
				strcat(message,stringnumber);
			}
			free(tmpstr1);
			free(tmpstr2);
		} else {
			tmpstr1 = string_escape(*afields[AIDX_NUM], cfgvalues.record_separator);
			if(capacity>=(strlen(message)+strlen(tmpstr1))) {
				strcat(message,tmpstr1);
			} else {
				capacity = ((capacity+capacityIncrement) >= (strlen(message)+strlen(tmpstr1))) ? (capacity+capacityIncrement) : (strlen(message)+strlen(tmpstr1));
				buffer = (char *) malloc(strlen(message)+1);
				if (buffer == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
				strcpy(buffer,message);
				free(message);
				// This last plus one is needed to hold the terminator, '\0' //
				message = (char *) malloc(capacity+1);
				if (message == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
				strcpy(message,buffer);
				free(buffer);
				strcat(message,tmpstr1);
			}
			free(tmpstr1);
		}
	}
	if (*afields[AIDX_NUM] != NULL) {
		free(*afields[AIDX_NUM]);
		*afields[AIDX_NUM] = NULL;
	}

	for (i=1 ; i< NUMBER_AIDX_FIELDS ; i++) {
		if ((!output_fields) || (afield_output[i])) {
			if (*afields[i]) {
				if (cfgvalues.fieldnames_mode) {
					tmpstr1 = string_escape(*afield_headers[i], cfgvalues.record_separator);
					tmpstr2 = string_escape(*afields[i], cfgvalues.record_separator);
					sprintf(stringnumber, "%c%s=%s", cfgvalues.record_separator, tmpstr1, tmpstr2);
					if(capacity>=(strlen(message)+strlen(stringnumber))) {
						strcat(message,stringnumber);
					} else {
						capacity = ((capacity+capacityIncrement) >= (strlen(message)+strlen(stringnumber))) ? (capacity+capacityIncrement) : (strlen(message)+strlen(stringnumber));
						buffer = (char *) malloc(strlen(message)+1);
						if (buffer == NULL) {
							fprintf(stderr, "ERROR: Out of memory\n");
							exit_loggrabber(1);
						}
						strcpy(buffer,message);
						free(message);
						// This last plus one is needed to hold the terminator, '\0' //
						message = (char *) malloc(capacity+1);
						if (message == NULL) {
							fprintf(stderr, "ERROR: Out of memory\n");
							exit_loggrabber(1);
						}
						strcpy(message,buffer);
						free(buffer);
						strcat(message,stringnumber);
					}
					free(tmpstr1);
					free(tmpstr2);
				} else {
					tmpstr1 = string_escape(*afields[i], cfgvalues.record_separator);
					sprintf(stringnumber, "%c%s", cfgvalues.record_separator, tmpstr1);
					if(capacity>=(strlen(message)+strlen(stringnumber))) {
						strcat(message,stringnumber);
					} else {
						capacity = ((capacity+capacityIncrement) >= (strlen(message)+strlen(stringnumber))) ? (capacity+capacityIncrement) : (strlen(message)+strlen(stringnumber));
						buffer = (char *) malloc(strlen(message)+1);
						if (buffer == NULL) {
							fprintf(stderr, "ERROR: Out of memory\n");
							exit_loggrabber(1);
						}
						strcpy(buffer,message);
						free(message);
						// This last plus one is needed to hold the terminator, '\0' //
						message = (char *) malloc(capacity+1);
						if (message == NULL) {
							fprintf(stderr, "ERROR: Out of memory\n");
							exit_loggrabber(1);
						}
						strcpy(message,buffer);
						free(buffer);
						strcat(message,stringnumber);
					}
					free(tmpstr1);
				}
			} else {
				if (!(cfgvalues.fieldnames_mode)) {
					sprintf(stringnumber, "%c", cfgvalues.record_separator);
					if(capacity>=(strlen(message)+strlen(stringnumber))) {
						strcat(message,stringnumber);
					} else {
						capacity = ((capacity+capacityIncrement) >= (strlen(message)+strlen(stringnumber))) ? (capacity+capacityIncrement) : (strlen(message)+strlen(stringnumber));
						buffer = (char *) malloc(strlen(message)+1);
						if (buffer == NULL) {
							fprintf(stderr, "ERROR: Out of memory\n");
							exit_loggrabber(1);
						}
						strcpy(buffer,message);
						free(message);
						// This last plus one is needed to hold the terminator, '\0' //
						message = (char *) malloc(capacity+1);
						if (message == NULL) {
							fprintf(stderr, "ERROR: Out of memory\n");
							exit_loggrabber(1);
						}//end of inner if
						strcpy(message,buffer);
						free(buffer);
						strcat(message,stringnumber);
					}
				}
			}
		}
		if (*afields[i] != NULL) {
			free(*afields[i]);
			*afields[i] = NULL;
		}
	}

	submit_log(message);
	//clean used memory
	free(message);

	return OPSEC_SESSION_OK;
}

/*
 * function read_fw1_logfile_dict
 */
int read_fw1_logfile_dict(OpsecSession *psession, int dict_id, LEA_VT val_type, int n_d_entries)
{
	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: LEA logfile dict handler was invoked\n");
	}
	return OPSEC_SESSION_OK;
}

/*
 * function read_fw1_logfile_eof
 */
int read_fw1_logfile_eof(OpsecSession *psession)
{
	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: LEA end of logfile handler was invoked\n");
	}
	return OPSEC_SESSION_OK;
}

/*
 * function read_fw1_logfile_switch
 */
int read_fw1_logfile_switch(OpsecSession *psession)
{
	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: LEA logfile switch handler was invoked\n");
	}
	return OPSEC_SESSION_OK;
}

/*
 * function read_fw1_logfile_collogs
 */
int read_fw1_logfile_collogs(OpsecSession *psession)
{
	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: LEA collected logfile handler was invoked\n");
	}
	return OPSEC_SESSION_OK;
}

/*
 * function read_fw1_logfile_suspend
 */
int read_fw1_logfile_suspend(OpsecSession *psession)
{
	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: LEA suspended session handler was invoked\n");
	}
	return OPSEC_SESSION_OK;
}

/*
 * function read_fw1_logfile_resume
 */
int read_fw1_logfile_resume(OpsecSession *psession)
{
	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: LEA resumed session handler was invoked\n");
	}
	return OPSEC_SESSION_OK;
}

/*
 * function get_fw1_logfiles_end
 */
int get_fw1_logfiles_end(OpsecSession *psession)
{
	int	end_reason	 = 0;
	int	sic_errno	 = 0;
	char*	sic_errmsg	 = NULL;

	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: OPSEC_SESSION_END_HANDLER called\n");
	}

	// Check what is the reason of opsec session end
	end_reason = opsec_session_end_reason(psession);
	switch(end_reason) {
		case END_BY_APPLICATION:
		case SESSION_TIMEOUT:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "DEBUG: The session has been ended.\n");
			}
			break;
		case SESSION_NOT_ENDED:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "WARNING: The session has not been terminated.\n");
			}
			break;
		case UNABLE_TO_ATTACH_COMM:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "ERROR: Failed to establish connection.\n");
			}
			break;
		case ENTITY_TYPE_SESSION_INIT_FAIL:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "ERROR: OPSEC API-specific library code on other side of connection failed when attempting to initialize the session.\n");
			}
			break;
		case ENTITY_SESSION_INIT_FAIL:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "ERROR: Third-party start handler on other side of connection failed.\n");
			}
			break;
		case COMM_FAILURE:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "ERROR: Communication failure.\n");
			}
			break;
		case BAD_VERSION:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "ERROR: Incorrect version at other side.\n");
			}
			break;
		case PEER_SEND_DROP:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "ERROR: The peer dropped the connection.\n");
			}
			break;
		case PEER_ENDED:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "ERROR: The peer ends.\n");
			}
			break;
		case PEER_SEND_RESET:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "ERROR: The peer reset the connection.\n");
			}
			break;
		case COMM_IS_DEAD:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "ERROR: No communication.\n");
			}
			break;
		case SIC_FAILURE:
			if (!opsec_get_sic_error(psession, &sic_errno, &sic_errmsg)) {
				if (cfgvalues.debug_mode) {
					fprintf(stderr, "ERROR: SIC ERROR %d - %s\n", sic_errno, sic_errmsg);
				}
			}
			break;
		default:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "Warning: Unknown reason of session end.\n");
			}
			break;
	}//end of switch

	return OPSEC_SESSION_OK;
}

/*
 * function read_fw1_logfile_end
 */
int read_fw1_logfile_end(OpsecSession *psession)
{
	int	end_reason	 = 0;
	int	sic_errno	 = 0;
	char*	sic_errmsg	 = NULL;

	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: OPSEC_SESSION_END_HANDLER called\n");
	}

	// Check what is the reason of opsec session end
	end_reason = opsec_session_end_reason(psession);
	switch(end_reason) {
		case END_BY_APPLICATION:
		case SESSION_TIMEOUT:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "DEBUG: The session has been ended.\n");
			}
			keepAlive = FALSE;
			break;
		case SESSION_NOT_ENDED:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "WARNING: The session has not been terminated.\n");
			}
			keepAlive = FALSE;
			break;
		case UNABLE_TO_ATTACH_COMM:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "ERROR: Failed to establish connection.\n");
			}
			if(established) {
				keepAlive = TRUE;
			} else {
				keepAlive = FALSE;
			};
			break;
		case ENTITY_TYPE_SESSION_INIT_FAIL:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "ERROR: OPSEC API-specific library code on other side of connection failed when attempting to initialize the session.\n");
			}
			keepAlive = FALSE;
			break;
		case ENTITY_SESSION_INIT_FAIL:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "ERROR: Third-party start handler on other side of connection failed.\n");
			}
			keepAlive = FALSE;
			break;
		case COMM_FAILURE:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "ERROR: Communication failure.\n");
			}
			if(established) {
				keepAlive = TRUE;
			} else {
				keepAlive = FALSE;
			};
			break;
		case BAD_VERSION:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "ERROR: Incorrect version at other side.\n");
			}
			keepAlive = FALSE;
			break;
		case PEER_SEND_DROP:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "ERROR: The peer dropped the connection.\n");
			}
			if(established) {
				keepAlive = TRUE;
			} else {
				keepAlive = FALSE;
			};
			break;
		case PEER_ENDED:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "ERROR: The peer ends.\n");
			}
			keepAlive = FALSE;
			break;
		case PEER_SEND_RESET:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "ERROR: The peer reset the connection.\n");
			}
			if(established) {
				keepAlive = TRUE;
			} else {
				keepAlive = FALSE;
			};
			break;
		case COMM_IS_DEAD:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "ERROR: No communication.\n");
			}
			if(established) {
				keepAlive = TRUE;
			} else {
				keepAlive = FALSE;
			};
			break;
		case SIC_FAILURE:
			if (!opsec_get_sic_error(psession, &sic_errno, &sic_errmsg)) {
				if (cfgvalues.debug_mode) {
					fprintf(stderr, "ERROR: SIC ERROR %d - %s\n", sic_errno, sic_errmsg);
				}
			}
			keepAlive = FALSE;
			break;
		default:
			if (cfgvalues.debug_mode) {
				fprintf(stderr, "Warning: Unknown reason of session end.\n");
			}
			keepAlive = FALSE;
			break;
	}//end of switch

	return OPSEC_SESSION_OK;

}

/*
 * function read_fw1_logfile_start
 */
int read_fw1_logfile_start(OpsecSession *psession)
{
	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: OPSEC session start handler was invoked\n");
	}
	return OPSEC_SESSION_OK;
}

/*
 * function read_fw1_logfile_established
 */
int read_fw1_logfile_established(OpsecSession *psession)
{
	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: OPSEC session established handler was invoked\n");
	}
	established = TRUE;
	return OPSEC_SESSION_OK;
}

/*
 * function read_fw1_logfile_failedconn
 */
int read_fw1_logfile_failedconn(OpsecEntity *entity, long peer_ip, int sic_errno, char *sic_errmsg)
{
	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: OPSEC failed connection handler was invoked\n");
	}
	return OPSEC_SESSION_OK;
}

/*
 * function get_fw1_logfiles
 */
int get_fw1_logfiles()
{
	OpsecEntity       *pClient    = NULL;
	OpsecEntity       *pServer    = NULL;
	OpsecSession      *pSession   = NULL;
	OpsecEnv          *pEnv       = NULL;
	int opsecAlive;

	char*   auth_type;
	char*   fw1_server;
	char*   fw1_port;
	char*   opsec_certificate;
	char*   opsec_client_dn;
	char*   opsec_server_dn;
	char*   leaconf;

#ifdef WIN32
	TCHAR	buff[BUFSIZE];
	DWORD	dwRet;
#else
	long size;
#endif

#ifdef WIN32
	dwRet = GetCurrentDirectory(BUFSIZE, buff);

	if (dwRet == 0) {
		fprintf (stderr, "ERROR: Cannot get current working directory (error code: %d)\n", GetLastError());
		exit_loggrabber(1);
	}
	if (dwRet > BUFSIZE) {
		fprintf (stderr, "ERROR: Getting the current working directory failed failed since buffer too small, and it needs %d chars\n", dwRet);
		exit_loggrabber(1);
	}
	if ((leaconf = (char *)malloc(BUFSIZE)) == NULL) {
		fprintf (stderr, "ERROR: Out of memory\n");
		exit_loggrabber(1);
	}

	if (cfgvalues.leaconfig_filename == NULL) {
		strcpy(leaconf, buff);
		strcat(leaconf, "\\lea.conf");
	} else {
		if ((cfgvalues.leaconfig_filename[0] == '\\') ||
		   ((cfgvalues.leaconfig_filename[1] == ':') && (cfgvalues.leaconfig_filename[2] == '\\'))) {
			strcpy(leaconf, cfgvalues.leaconfig_filename);
		} else {
			strcpy(leaconf, buff);
			strcat(leaconf, "\\");
			strcat(leaconf, cfgvalues.leaconfig_filename);
		}
	}
#else
	size = pathconf(".", _PC_PATH_MAX);
	if ((leaconf = (char *)malloc((size_t)size)) == NULL) {
		fprintf (stderr, "ERROR: Out of memory\n");
		exit_loggrabber(1);
	}

	if (cfgvalues.leaconfig_filename == NULL) {
		if (getcwd(leaconf, (size_t)size) == NULL) {
			fprintf (stderr, "ERROR: Cannot get current working directory\n");
			exit_loggrabber(1);
		}
		strcat(leaconf, "/lea.conf");
	} else {
		if (cfgvalues.leaconfig_filename[0] == '/') {
			strcpy(leaconf, cfgvalues.leaconfig_filename);
		} else {
			if (getcwd(leaconf, (size_t)size) == NULL) {
				fprintf (stderr, "ERROR: Cannot get current working directory\n");
				exit_loggrabber(1);
			}
			strcat(leaconf, "/");
			strcat(leaconf, cfgvalues.leaconfig_filename);
		}
	}
#endif

	/* create opsec environment for the main loop */
	if((pEnv = opsec_init(OPSEC_CONF_FILE, leaconf, OPSEC_EOL)) == NULL) {
		fprintf(stderr, "ERROR: unable to create environment (%s)\n", opsec_errno_str(opsec_errno));
		exit_loggrabber(1);
	}

	if (cfgvalues.debug_mode) {

		fprintf(stderr, "DEBUG: OPSEC LEA conf file is %s\n", leaconf);

		fw1_server = opsec_get_conf(pEnv,"lea_server","ip",NULL);
		if(fw1_server==NULL) {
			fprintf(stderr, "ERROR: The fw1 server ip address has not been set.\n");
			exit_loggrabber(1);
		}//end of if
		auth_type = opsec_get_conf(pEnv,"lea_server","auth_type",NULL);
		if (auth_type!=NULL) {
			//Authentication mode
			fw1_port = opsec_get_conf(pEnv,"lea_server","auth_port",NULL);
			opsec_certificate = opsec_get_conf(pEnv,"opsec_sslca_file",NULL);
			opsec_client_dn = opsec_get_conf(pEnv,"opsec_sic_name",NULL);
			opsec_server_dn = opsec_get_conf(pEnv,"lea_server","opsec_entity_sic_name",NULL);
			if((fw1_port==NULL)||(opsec_certificate==NULL)||(opsec_client_dn==NULL)||(opsec_server_dn==NULL)) {
				fprintf(stderr, "ERROR: The parameters about authentication mode have not been set.\n");
				exit_loggrabber(1);
			} else {
				fprintf (stderr, "DEBUG: Authentication mode has been used.\n");
				fprintf (stderr, "DEBUG: Server-IP     : %s\n", fw1_server);
				fprintf (stderr, "DEBUG: Server-Port     : %s\n", fw1_port);
				fprintf (stderr, "DEBUG: Authentication type: %s\n", auth_type);
				fprintf (stderr, "DEBUG: OPSEC sic certificate file name : %s\n", opsec_certificate);
				fprintf (stderr, "DEBUG: Server DN (sic name) : %s\n", opsec_server_dn);
				fprintf (stderr, "DEBUG: OPSEC LEA client DN (sic name) : %s\n", opsec_client_dn);
			}//end of inner if
		} else {
			//Clear Text mode, i.e. non-auth mode
			fw1_port = opsec_get_conf(pEnv,"lea_server","port",NULL);
			if(fw1_port!=NULL) {
				fprintf (stderr, "DEBUG: Clear text mode has been used.\n");
				fprintf (stderr, "DEBUG: Server-IP        : %s\n", fw1_server);
				fprintf (stderr, "DEBUG: Server-Port      : %s\n", fw1_port);
			} else {
				fprintf(stderr, "ERROR: The fw1 server lea service port has not been set.\n");
				exit_loggrabber(1);
			}//end of inner if
		}//end of middle if
	}//end of if


	/*
	 * initialize opsec-client
	 */
	pClient = opsec_init_entity(pEnv, LEA_CLIENT,
				LEA_DICT_HANDLER, get_fw1_logfiles_dict,
				OPSEC_SESSION_END_HANDLER, get_fw1_logfiles_end,
				OPSEC_EOL);

	/*
	 * initialize opsec-server for authenticated and unauthenticated connections
	 */
	pServer = opsec_init_entity(pEnv, LEA_SERVER, OPSEC_ENTITY_NAME, "lea_server", OPSEC_EOL);

	/*
	 * continue only if opsec initializations were successful
	 */
	if ((!pClient) || (!pServer))
	{
		fprintf(stderr, "ERROR: failed to initialize client/server-pair (%s)\n", opsec_errno_str(opsec_errno));
		cleanup_fw1_environment(pEnv, pClient, pServer);
		exit_loggrabber(1);
	}

	/*
	 * create LEA-session
	 */
	if (!(pSession = lea_new_session(pClient, pServer, LEA_OFFLINE, LEA_FILENAME, LEA_NORMAL, LEA_AT_START))) {
		fprintf(stderr, "ERROR: failed to create session (%s)\n", opsec_errno_str(opsec_errno));
		cleanup_fw1_environment(pEnv, pClient, pServer);
		exit_loggrabber(1);
	}

	opsecAlive = opsec_start_keep_alive(pSession, 0);

	/*
	 * start the opsec loop
	 */
	opsec_mainloop(pEnv);

	/*
	 * remove opsec stuff
	 */
	cleanup_fw1_environment(pEnv, pClient, pServer);

	free(leaconf);

	return 0;
}

/*
 * function get_fw1_logfiles_dict
 */
int get_fw1_logfiles_dict(OpsecSession *pSession, int nDictId, LEA_VT nValType, int nEntries)
{
        int learesult	= 0;
	int nID		= 0;
	int aID		= 0;
	char * logfile  = NULL;

	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: Available FW-1 Logfiles\n");
	}

	if (cfgvalues.showfiles_mode) {
		fprintf(stderr, "Available FW-1 Logfiles\n");
	}

	/*
	 * get names of available logfiles and create list of these names
	 */
        learesult = lea_get_first_file_info(pSession, &logfile, &nID, &aID);
        while (learesult == 0) {
          if (cfgvalues.debug_mode) {
          	fprintf(stderr, "DEBUG: - %s\n",logfile);
	  }
          if (cfgvalues.showfiles_mode) {
          	fprintf(stderr, "- %s\n",logfile);
	  }
	  stringlist_append(&sl, logfile);
          learesult = lea_get_next_file_info(pSession, &logfile, &nID, &aID);
	}

	/*
	 * end opsec-session
	 */
	opsec_end_session(pSession);

        return OPSEC_SESSION_OK;
}

/*
 * function cleanup_fw1_environment
 */
void cleanup_fw1_environment(OpsecEnv *env, OpsecEntity *client, OpsecEntity *server)
{
	if (client) opsec_destroy_entity(client);
	if (server) opsec_destroy_entity(server);
	if (env)    opsec_env_destroy(env);
}

/*
 * function show_supported_fields
 */
void show_supported_fields()
{
	int i;

	fprintf(stderr, "\nFW1-Loggrabber v%s, (C)2004, Torsten Fellhauer, Xiaodong Lin\n", VERSION);
	fprintf(stderr, "Supported Fields for normal logs:\n");
	for (i=0 ; i < NUMBER_LIDX_FIELDS ; i++) {
		fprintf(stderr, "  - %s\n", *lfield_headers[i]);
	}
	fprintf(stderr, "Supported Fields for audit logs:\n");
	for (i=0 ; i < NUMBER_AIDX_FIELDS ; i++) {
		fprintf(stderr, "  - %s\n", *afield_headers[i]);
	}
}

/*
 * function usage
 */
void usage(char *szProgName)
{
	fprintf(stderr, "\nFW1-Loggrabber v%s, (C)2004, Torsten Fellhauer, Xiaodong Lin\n", VERSION);
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, " %s [ options ]\n", szProgName);
	fprintf(stderr, "  -c|--configfile <file>     : Name of Configfile (default: fw1-loggrabber.conf)\n");
	fprintf(stderr, "  -l|--leaconfigfile <file>  : Name of Configfile (default: fw1-loggrabber.conf)\n");
	fprintf(stderr, "  -f|--logfile Logfile|ALL   : Name of Logfile (default: fw.log)\n");
	fprintf(stderr, "  --resolve|--no-resolve     : Resolve Port Numbers and IP-Addresses (Default: Resolve)\n");
	fprintf(stderr, "  --showfiles|--showlogs     : Show only Filenames of all available FW-1 Logfiles (default: showlogs)\n");
	fprintf(stderr, "  --2000|--ng                : Connect to a CP FW-1 4.1 (2000) (default is ng)\n");
	fprintf(stderr, "  --filter \"...\"             : Specify filters to be applied\n");
	fprintf(stderr, "  --fields \"...\"             : Specify fields to be printed\n");
	fprintf(stderr, "  --online|--no-online       : Enable Online mode (default: no-online)\n");
	fprintf(stderr, "  --auditlog|--normallog     : Get data of audit-logfile (fw.adtlog)(default: normallog)\n");
	fprintf(stderr, "  --fieldnames|--nofieldnames: Print fieldnames in each line or once at beginning\n");
#ifdef USE_MYSQL
	fprintf(stderr, "  --mysql|--no-mysql         : EXPERIMENTAL! Store log entries in MySQL database (default: no-mysql)\n");
#endif
	fprintf(stderr, "  --debug-level <level>      : Specify Debuglevel (default: 0 - no debugging)\n");
	fprintf(stderr, "  --help                     : Show usage informations\n");
	fprintf(stderr, "  --help-fields              : Show supported log fields\n");
}

/*
 * function stringlist_append
 */
int stringlist_append (stringlist **lst, char *data) {
	/*
	 * move to last element of list
	 */
	while (*lst)
		lst = &((*lst)->next);
	/*
	 * allocate memory for new element
	 */
	*lst = (stringlist*)malloc(sizeof(stringlist));
	if (*lst == NULL) return 0;
	/*
	 * append new element
	 */
	(*lst)->data = string_duplicate(data);
	(*lst)->next = NULL;
	return 1;
}

/*
 * function stringlist_print
 */
void stringlist_print (stringlist **lst) {
	while (*lst) {
		printf("%s\n",(*lst)->data);
		lst = &((*lst)->next);
	}
}

/*
 * function stringlist_delete
 */
stringlist* stringlist_delete(stringlist **lst) {
	stringlist* first;

	if (*lst) {
		first = (*lst)->next;
		free((*lst)->data);
		free(*lst);
		return (first);
	} else {
		return (NULL);
	}
}


/*
 * function stringlist_search
 */
stringlist* stringlist_search(stringlist **lst, char *searchstring, char **result) {
	/*
	 * compare all elements of list with given string
	 */
	while (*lst) {
		if (strstr((*lst)->data, searchstring)) {
			*result = (*lst)->data;
//			*result = string_duplicate((*lst)->data);
			return (*lst);
		}
		lst = &((*lst)->next);
	}
	return NULL;
}

/*
 * function create_fw1_filter_rule
 */
LeaFilterRulebase* create_fw1_filter_rule(LeaFilterRulebase *prulebase, char filterstring[255]) {
	LeaFilterRule *prule;
	LeaFilterPredicate *ppred;
	char* filterargument;
        char* argumentvalue;
	char* argumentname;
	unsigned int tempint;
	unsigned int tmpint1;
	unsigned int tmpint2;
	unsigned short tempushort;
	unsigned short tmpushort1;
	unsigned short tmpushort2;
	unsigned long templong;
	lea_value_ex_t **val_arr;
	lea_value_ex_t *lea_value;
	char* argumentsinglevalue;
	int argumentcount;
	int negation;
	char* tmpstring1;
	char* tmpstring2;
	struct tm timestruct;
	char tempchararray[10];

	/*
	 * create an empty rule with action "pass"
	 */
        if ((prule = lea_filter_rule_create(LEA_FILTER_ACTION_PASS)) == NULL) {
 		fprintf(stderr, "ERROR: failed to create rule\n");
		lea_filter_rulebase_destroy(prulebase);
		return NULL;
	}

	/*
	 * split filter string in arguments separated by ";"
	 */
	filterargument = strtok(filterstring, ";");
	while (filterargument != NULL) {
	  /*
	   * split argument into name and value separated by "="
	   */
          argumentvalue = strchr(filterargument, '=');
	  if (argumentvalue == NULL) {
		fprintf(stderr, "ERROR: syntax error in rule argument '%s'.\n"
				"       Required syntax: 'argument=value'\n", filterargument);
		return NULL;
	  }
	  argumentvalue++;
          argumentname = filterargument;
	  argumentname[argumentvalue-filterargument-1]='\0';
	  argumentvalue = string_trim(argumentvalue, ' ');
	  argumentname = string_trim(argumentname, ' ');
 	  filterargument = strtok(NULL, ";");
	  val_arr = NULL;

	  if (argumentname[strlen(argumentname)-1] == '!') {
		negation = 1;
		argumentname = string_trim(argumentname, '!');
	  } else {
		negation = 0;
	  }

	  /*
	   * change argument name to lower case letters
	   */
	  for (tempint = 0 ; tempint < strlen(argumentname) ; tempint++) {
	    argumentname[tempint] = tolower(argumentname[tempint]);
	  }

	  /*
	   * process arguments of type "product"
	   */
	  if (strcmp(argumentname, "product") == 0) {
		argumentcount = 0;
		/*
		 * get argument values separated by ","
		 */
		while (argumentvalue) {
			argumentsinglevalue = string_trim(string_get_token(&argumentvalue, ','), ' ');
			argumentcount++;
			if (val_arr) {
				val_arr = (lea_value_ex_t**)realloc(val_arr, argumentcount * sizeof(lea_value_ex_t*));
				if (val_arr == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
			} else {
				val_arr = (lea_value_ex_t**)malloc(argumentcount * sizeof(lea_value_ex_t*));
				if (val_arr == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
			}

			/*
			 * check validity of argument value
			 */
			if (!(  (strcmp(argumentsinglevalue, "VPN-1 & FireWall-1") == 0) || \
				(strcmp(argumentsinglevalue, "SmartDefense") == 0) ))
			{
				fprintf(stderr, "ERROR: invalid value for product: '%s'\n", argumentsinglevalue);
				return NULL;
			}

			/*
			 * create extended opsec value
			 */
			val_arr[argumentcount-1] = lea_value_ex_create();
			if (lea_value_ex_set(val_arr[argumentcount-1], LEA_VT_STRING, argumentsinglevalue) == OPSEC_SESSION_ERR) {
				fprintf(stderr, "ERROR: failed to set rule value (%s)\n", opsec_errno_str(opsec_errno));
				lea_value_ex_destroy(val_arr[argumentcount-1]);
				lea_filter_rule_destroy(prule);
				return NULL;
			}
		}

		/*
		 * create filter predicate
		 */
		if ((ppred = lea_filter_predicate_create("product", -1, negation, LEA_FILTER_PRED_BELONGS_TO, argumentcount, val_arr)) == NULL) {
			fprintf(stderr, "ERROR: failed to create predicate\n");
			lea_value_ex_destroy(val_arr[argumentcount-1]);
			lea_filter_rule_destroy(prule);
			return NULL;
		}

		lea_value_ex_destroy(val_arr[argumentcount-1]);

		/*
		 * add current predicate to current rule
		 */
		if (lea_filter_rule_add_predicate(prule, ppred) == LEA_FILTER_ERR) {
			fprintf(stderr, "ERROR: failed to add predicate to rule\n");
			lea_filter_rule_destroy(prule);
			lea_filter_predicate_destroy(ppred);
			return NULL;
		}

		lea_filter_predicate_destroy(ppred);
	  }

	  /*
	   * process arguments of type "action"
	   */
	  else if (strcmp(argumentname, "action") == 0) {
	    	argumentcount = 0;
		/*
		 * get argument values separated by ","
		 */
	    	while (argumentvalue) {
			argumentsinglevalue = string_trim(string_get_token(&argumentvalue, ','), ' ');
			argumentcount++;
			if (val_arr) {
				val_arr = (lea_value_ex_t**)realloc(val_arr, argumentcount * sizeof(lea_value_ex_t*));
				if (val_arr == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
			} else {
				val_arr = (lea_value_ex_t**)malloc(argumentcount * sizeof(lea_value_ex_t*));
				if (val_arr == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
			}

			/*
			 * transform values (accept, drop, reject) into corresponding values
			 */
			if (strcmp(argumentsinglevalue,"accept") == 0) {
				tempint = 4;
			}
			else if (strcmp(argumentsinglevalue,"drop") == 0) {
				tempint = 2;
			}
			else if (strcmp(argumentsinglevalue,"reject") == 0) {
				tempint = 3;
			}
			else {
				fprintf(stderr, "ERROR: invalid value for action: '%s'\n", argumentsinglevalue);
				return NULL;
			}

			/*
			 * create extended opsec value
			 */
			val_arr[argumentcount-1] = lea_value_ex_create();
			if (lea_value_ex_set(val_arr[argumentcount-1], LEA_VT_ACTION, tempint) == OPSEC_SESSION_ERR) {
				fprintf(stderr, "ERROR: failed to set rule value (%s)\n", opsec_errno_str(opsec_errno));
				lea_value_ex_destroy(val_arr[argumentcount-1]);
				lea_filter_rule_destroy(prule);
				return NULL;
			}
		}

		/*
		 * create filter predicate
		 */
		if ((ppred = lea_filter_predicate_create("action", -1, negation, LEA_FILTER_PRED_BELONGS_TO, argumentcount, val_arr)) == NULL) {
			fprintf(stderr, "ERROR: failed to create predicate\n");
			lea_value_ex_destroy(val_arr[argumentcount-1]);
			lea_filter_rule_destroy(prule);
			return NULL;
		}

		lea_value_ex_destroy(val_arr[argumentcount-1]);

		/*
		 * add current predicate to current rule
		 */
		if (lea_filter_rule_add_predicate(prule, ppred) == LEA_FILTER_ERR) {
			fprintf(stderr, "ERROR: failed to add predicate to rule\n");
			lea_filter_rule_destroy(prule);
			lea_filter_predicate_destroy(ppred);
			return NULL;
		}

		lea_filter_predicate_destroy(ppred);
	  }

	  /*
	   * process arguments of type "dst"
	   */
	  else if ((strcmp(argumentname, "dst") == 0) && (!(cfgvalues.audit_mode))) {
		/*
		 * check whether values are valid
		 */
		if ((strchr(argumentvalue,',')) && (strchr(argumentvalue,'/'))) {
			fprintf(stderr, "ERROR: use either netmask OR multiple IP addresses");
			lea_filter_rule_destroy(prule);
			return NULL;
		}

		/*
		 * if the value specifies a network, create the filter predicate directly
		 */
		if (strchr(argumentvalue,'/')) {
			tmpstring1 = string_trim(string_get_token(&argumentvalue, '/'), ' ');
			tmpstring2 = string_trim(string_get_token(&argumentvalue, '/'), ' ');
			if ((strlen(tmpstring1) == 0) || (strlen(tmpstring2) == 0)) {
				fprintf(stderr, "ERROR: syntax error in rule value of argument dst: '%s/%s'.\n"
						"       Required syntax: 'dst=aaa.bbb.ccc.ddd/eee.fff.ggg.hhh'\n", tmpstring1, tmpstring2);
				return NULL;
			}
			if ((ppred = lea_filter_predicate_create("dst", -1, negation, LEA_FILTER_PRED_BELONGS_TO_MASK, inet_addr(tmpstring1), inet_addr(tmpstring2))) == NULL) {
				fprintf(stderr, "ERROR: failed to create predicate\n");
				lea_value_ex_destroy(val_arr[argumentcount-1]);
				lea_filter_rule_destroy(prule);
				return NULL;
			}
		} else {
	    		argumentcount = 0;
			/*
			 * get argument values separated by ","
			 */
		    	while (argumentvalue) {
				argumentsinglevalue = string_trim(string_get_token(&argumentvalue, ','), ' ');
				if (strlen(argumentsinglevalue) == 0) {
					fprintf(stderr, "ERROR: syntax error in rule value of argument dst: '%s'.\n"
							"       Required syntax: 'dst=aaa.bbb.ccc.ddd'\n", argumentsinglevalue);
					return NULL;
				}
				argumentcount++;
				if (val_arr) {
					val_arr = (lea_value_ex_t**)realloc(val_arr, argumentcount * sizeof(lea_value_ex_t*));
					if (val_arr == NULL) {
						fprintf(stderr, "ERROR: Out of memory\n");
						exit_loggrabber(1);
					}
				} else {
					val_arr = (lea_value_ex_t**)malloc(argumentcount * sizeof(lea_value_ex_t*));
					if (val_arr == NULL) {
						fprintf(stderr, "ERROR: Out of memory\n");
						exit_loggrabber(1);
					}
				}

				/*
				 * create extended opsec value
				 */
				val_arr[argumentcount-1] = lea_value_ex_create();
				if (lea_value_ex_set(val_arr[argumentcount-1], LEA_VT_IP_ADDR, inet_addr(argumentsinglevalue)) == OPSEC_SESSION_ERR) {
					fprintf(stderr, "ERROR: failed to set rule value (%s)\n", opsec_errno_str(opsec_errno));
					lea_value_ex_destroy(val_arr[argumentcount-1]);
					lea_filter_rule_destroy(prule);
					return NULL;
				}
			}

			/*
			 * create filter predicate
			 */
			if ((ppred = lea_filter_predicate_create("dst", -1, negation, LEA_FILTER_PRED_BELONGS_TO, argumentcount, val_arr)) == NULL) {
				fprintf(stderr, "ERROR: failed to create predicate\n");
				lea_value_ex_destroy(val_arr[argumentcount-1]);
				lea_filter_rule_destroy(prule);
				return NULL;
			}

			lea_value_ex_destroy(val_arr[argumentcount-1]);
		}

		/*
		 * add current predicate to current rule
		 */
		if (lea_filter_rule_add_predicate(prule, ppred) == LEA_FILTER_ERR) {
			fprintf(stderr, "ERROR: failed to add predicate to rule\n");
			lea_filter_rule_destroy(prule);
			lea_filter_predicate_destroy(ppred);
			return NULL;
		}

		lea_filter_predicate_destroy(ppred);
	  }

	  /*
	   * process arguments of type "proto"
	   */
	  else if ((strcmp(argumentname, "proto") == 0) && (!(cfgvalues.audit_mode))) {
	    	argumentcount = 0;
		/*
		 * get argument values separated by ","
		 */
	    	while (argumentvalue) {
			argumentsinglevalue = string_trim(string_get_token(&argumentvalue, ','), ' ');
			argumentcount++;
			if (val_arr) {
				val_arr = (lea_value_ex_t**)realloc(val_arr, argumentcount * sizeof(lea_value_ex_t*));
				if (val_arr == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
			} else {
				val_arr = (lea_value_ex_t**)malloc(argumentcount * sizeof(lea_value_ex_t*));
				if (val_arr == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
			}

			/*
			 * transform values (icmp, tcp, udp) into corresponding values
			 */
			if (strcmp(argumentsinglevalue,"icmp") == 0) {
				tempint = 1;
			}
			else if (strcmp(argumentsinglevalue,"tcp") == 0) {
				tempint = 6;
			}
			else if (strcmp(argumentsinglevalue,"udp") == 0) {
				tempint = 17;
			}
			else {
				fprintf(stderr, "ERROR: invalid value for action: '%s'\n", argumentsinglevalue);
				return NULL;
			}

			/*
			 * create extended opsec value
			 */
			val_arr[argumentcount-1] = lea_value_ex_create();
			if (lea_value_ex_set(val_arr[argumentcount-1], LEA_VT_IP_PROTO, tempint) == OPSEC_SESSION_ERR) {
				fprintf(stderr, "ERROR: failed to set rule value (%s)\n", opsec_errno_str(opsec_errno));
				lea_value_ex_destroy(val_arr[argumentcount-1]);
				lea_filter_rule_destroy(prule);
				return NULL;
			}
		}

		/*
		 * create filter predicate
		 */
		if ((ppred = lea_filter_predicate_create("proto", -1, negation, LEA_FILTER_PRED_BELONGS_TO, argumentcount, val_arr)) == NULL) {
			fprintf(stderr, "ERROR: failed to create predicate\n");
			lea_value_ex_destroy(val_arr[argumentcount-1]);
			lea_filter_rule_destroy(prule);
			return NULL;
		}

		lea_value_ex_destroy(val_arr[argumentcount-1]);

		/*
		 * add current predicate to current rule
		 */
		if (lea_filter_rule_add_predicate(prule, ppred) == LEA_FILTER_ERR) {
			fprintf(stderr, "ERROR: failed to add predicate to rule\n");
			lea_filter_rule_destroy(prule);
			lea_filter_predicate_destroy(ppred);
			return NULL;
		}

		lea_filter_predicate_destroy(ppred);
	  }

	  /*
	   * process arguments of type "starttime"
	   */
	  else if (strcmp(argumentname, "starttime") == 0) {
		argumentsinglevalue = string_trim(argumentvalue, ' ');
		if (strlen(argumentsinglevalue) != 14) {
			fprintf(stderr, "ERROR: syntax error in rule value of argument rule: '%s'.\n"
					"       Required syntax: 'starttime=YYYYMMDDhhmmss'\n", argumentsinglevalue);
			return NULL;
		}

		/*
		 * convert starttime parameter to proper form (unixtime)
		 */
		strncpy(tempchararray, argumentsinglevalue, 4);
		tempchararray[4] = '\0';
		timestruct.tm_year = strtol(tempchararray, (char**)NULL, 10) - 1900;
		argumentsinglevalue += 4 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_mon = strtol(tempchararray, (char**)NULL, 10) - 1;
		argumentsinglevalue += 2 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_mday = strtol(tempchararray, (char**)NULL, 10);
		argumentsinglevalue += 2 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_hour = strtol(tempchararray, (char**)NULL, 10);
		argumentsinglevalue += 2 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_min = strtol(tempchararray, (char**)NULL, 10);
		argumentsinglevalue += 2 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_sec = strtol(tempchararray, (char**)NULL, 10);

		/*
		 * convert starttime parameter to long int
		 */
		if ((timestruct.tm_mon > 11) || (timestruct.tm_mday > 31) || (timestruct.tm_hour > 23) || (timestruct.tm_min > 59) || (timestruct.tm_sec > 59)) {
			fprintf(stderr, "ERROR: illegal date format in argumentvalue\n");
			return NULL;
		}
		templong = (unsigned long)mktime(&timestruct);
		if (templong == -1) {
			fprintf(stderr, "ERROR: illegal date format in argumentvalue\n");
			return NULL;
		}

		/*
		 * create extended opsec value
		 */
		lea_value = lea_value_ex_create();
		if (lea_value_ex_set(lea_value, LEA_VT_TIME, templong) == OPSEC_SESSION_ERR) {
			fprintf(stderr, "ERROR: failed to set starttime value (%s)\n", opsec_errno_str(opsec_errno));
			lea_value_ex_destroy(lea_value);
			lea_filter_rule_destroy(prule);
			return NULL;
		}

		/*
		 * create filter predicate
		 */
		if ((ppred = lea_filter_predicate_create("time", -1, negation, LEA_FILTER_PRED_GREATER_EQUAL, lea_value)) == NULL) {
			fprintf(stderr, "ERROR: failed to create predicate\n");
			lea_value_ex_destroy(val_arr[argumentcount-1]);
			lea_filter_rule_destroy(prule);
			return NULL;
		}

		lea_value_ex_destroy(lea_value);

		/*
		 * add current predicate to current rule
		 */
		if (lea_filter_rule_add_predicate(prule, ppred) == LEA_FILTER_ERR) {
			fprintf(stderr, "ERROR: failed to add predicate to rule\n");
			lea_filter_rule_destroy(prule);
			lea_filter_predicate_destroy(ppred);
			return NULL;
		}

		lea_filter_predicate_destroy(ppred);
	  }

	  /*
	   * process arguments of type "endtime"
	   */
	  else if (strcmp(argumentname, "endtime") == 0) {
		argumentsinglevalue = string_trim(argumentvalue, ' ');
		if (strlen(argumentsinglevalue) != 14) {
			fprintf(stderr, "ERROR: syntax error in rule value of argument rule: '%s'.\n"
					"       Required syntax: 'endtime=YYYYMMDDhhmmss'\n", argumentsinglevalue);
			return NULL;
		}

		/*
		 * convert starttime parameter to proper form (unixtime)
		 */
		strncpy(tempchararray, argumentsinglevalue, 4);
		tempchararray[4] = '\0';
		timestruct.tm_year = strtol(tempchararray, (char**)NULL, 10) - 1900;
		argumentsinglevalue += 4 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_mon = strtol(tempchararray, (char**)NULL, 10) - 1;
		argumentsinglevalue += 2 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_mday = strtol(tempchararray, (char**)NULL, 10);
		argumentsinglevalue += 2 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_hour = strtol(tempchararray, (char**)NULL, 10);
		argumentsinglevalue += 2 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_min = strtol(tempchararray, (char**)NULL, 10);
		argumentsinglevalue += 2 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_sec = strtol(tempchararray, (char**)NULL, 10);

		/*
		 * convert starttime parameter to long int
		 */
		if ((timestruct.tm_mon > 11) || (timestruct.tm_mday > 31) || (timestruct.tm_hour > 23) || (timestruct.tm_min > 59) || (timestruct.tm_sec > 59)) {
			fprintf(stderr, "ERROR: illegal date format in argumentvalue\n");
			return NULL;
		}
		templong = (unsigned long)mktime(&timestruct);
		if (templong == -1) {
			fprintf(stderr, "ERROR: illegal date format in argumentvalue\n");
			return NULL;
		}

		/*
		 * create extended opsec value
		 */
		lea_value = lea_value_ex_create();
		if (lea_value_ex_set(lea_value, LEA_VT_TIME, templong) == OPSEC_SESSION_ERR) {
			fprintf(stderr, "ERROR: failed to set endtime value (%s)\n", opsec_errno_str(opsec_errno));
			lea_value_ex_destroy(lea_value);
			lea_filter_rule_destroy(prule);
			return NULL;
		}

		/*
		 * create filter predicate
		 */
		if ((ppred = lea_filter_predicate_create("time", -1, negation, LEA_FILTER_PRED_SMALLER_EQUAL, lea_value)) == NULL) {
			fprintf(stderr, "ERROR: failed to create predicate\n");
			lea_value_ex_destroy(val_arr[argumentcount-1]);
			lea_filter_rule_destroy(prule);
			return NULL;
		}

		lea_value_ex_destroy(lea_value);

		/*
		 * add current predicate to current rule
		 */
		if (lea_filter_rule_add_predicate(prule, ppred) == LEA_FILTER_ERR) {
			fprintf(stderr, "ERROR: failed to add predicate to rule\n");
			lea_filter_rule_destroy(prule);
			lea_filter_predicate_destroy(ppred);
			return NULL;
		}

		lea_filter_predicate_destroy(ppred);
	  }

	  /*
	   * process arguments of type "rule"
	   */
	  else if ((strcmp(argumentname, "rule") == 0) && (!(cfgvalues.audit_mode))) {
	    	argumentcount = 0;
		/*
		 * get argument values separated by ","
		 */
	    	while (argumentvalue) {
			argumentsinglevalue = string_trim(string_get_token(&argumentvalue, ','), ' ');
			if (strlen(argumentsinglevalue) == 0) {
				fprintf(stderr, "ERROR: syntax error in rule value of argument rule: '%s'.\n"
						"       Required syntax: 'rule=x'\n", argumentsinglevalue);
				return NULL;
			}

			/*
			 * get ranges separated by "-", if there is no "-" start and end value of the
			 * range is the same.
			 */
			tmpstring1 = string_trim(string_get_token(&argumentsinglevalue, '-'), ' ');
			tmpstring2 = (argumentsinglevalue == NULL) ? tmpstring1 : string_trim(string_get_token(&argumentsinglevalue, '-'), ' ');
			tmpint1 = (int)strtol(tmpstring1, (char**)NULL, 10);
			tmpint2 = (int)strtol(tmpstring2, (char**)NULL, 10);

			for (tempint = tmpint1; tempint <= tmpint2 ; tempint++) {
				argumentcount++;
				if (val_arr) {
					val_arr = (lea_value_ex_t**)realloc(val_arr, argumentcount * sizeof(lea_value_ex_t*));
					if (val_arr == NULL) {
						fprintf(stderr, "ERROR: Out of memory\n");
						exit_loggrabber(1);
					}
				} else {
					val_arr = (lea_value_ex_t**)malloc(argumentcount * sizeof(lea_value_ex_t*));
					if (val_arr == NULL) {
						fprintf(stderr, "ERROR: Out of memory\n");
						exit_loggrabber(1);
					}
				}

				/*
				 * create extended opsec value
				 */
				val_arr[argumentcount-1] = lea_value_ex_create();
				if (lea_value_ex_set(val_arr[argumentcount-1], LEA_VT_RULE, tempint) == OPSEC_SESSION_ERR) {
					fprintf(stderr, "ERROR: failed to set rule value (%s)\n", opsec_errno_str(opsec_errno));
					lea_value_ex_destroy(val_arr[argumentcount-1]);
					lea_filter_rule_destroy(prule);
					return NULL;
				}
			}
		}

		/*
		 * create filter predicate
		 */
		if ((ppred = lea_filter_predicate_create("rule", -1, negation, LEA_FILTER_PRED_BELONGS_TO, argumentcount, val_arr)) == NULL) {
			fprintf(stderr, "ERROR: failed to create predicate\n");
			lea_value_ex_destroy(val_arr[argumentcount-1]);
			lea_filter_rule_destroy(prule);
			return NULL;
		}

		lea_value_ex_destroy(val_arr[argumentcount-1]);

		/*
		 * add current predicate to current rule
		 */
		if (lea_filter_rule_add_predicate(prule, ppred) == LEA_FILTER_ERR) {
			fprintf(stderr, "ERROR: failed to add predicate to rule\n");
			lea_filter_rule_destroy(prule);
			lea_filter_predicate_destroy(ppred);
			return NULL;
		}

		lea_filter_predicate_destroy(ppred);
	  }

	  /*
	   * process arguments of type "service"
	   */
	  else if ((strcmp(argumentname, "service") == 0) && (!(cfgvalues.audit_mode))) {
	    	argumentcount = 0;
		/*
		 * get argument values separated by ","
		 */
	    	while (argumentvalue) {
			argumentsinglevalue = string_trim(string_get_token(&argumentvalue, ','), ' ');
			if (strlen(argumentsinglevalue) == 0) {
				fprintf(stderr, "ERROR: syntax error in rule value of argument service: '%s'.\n"
						"       Required syntax: 'service=<Port-Number>'\n", argumentsinglevalue);
				return NULL;
			}

			/*
			 * get ranges separated by "-", if there is no "-" start and end value of the
			 * range is the same.
			 */
			tmpstring1 = string_trim(string_get_token(&argumentsinglevalue, '-'), ' ');
			tmpstring2 = (argumentsinglevalue == NULL) ? tmpstring1 : string_trim(string_get_token(&argumentsinglevalue, '-'), ' ');
			tmpushort1 = (unsigned short)strtol(tmpstring1, (char**)NULL, 10);
			tmpushort2 = (unsigned short)strtol(tmpstring2, (char**)NULL, 10);

			for (tempushort = tmpushort1; tempushort <= tmpushort2 ; tempushort++) {
				argumentcount++;
				if (val_arr) {
					val_arr = (lea_value_ex_t**)realloc(val_arr, argumentcount * sizeof(lea_value_ex_t*));
					if (val_arr == NULL) {
						fprintf(stderr, "ERROR: Out of memory\n");
						exit_loggrabber(1);
					}
				} else {
					val_arr = (lea_value_ex_t**)malloc(argumentcount * sizeof(lea_value_ex_t*));
					if (val_arr == NULL) {
						fprintf(stderr, "ERROR: Out of memory\n");
						exit_loggrabber(1);
					}
				}

				/*
				 * create extended opsec value
				 */
				val_arr[argumentcount-1] = lea_value_ex_create();
				if (lea_value_ex_set(val_arr[argumentcount-1], LEA_VT_USHORT, tempushort) == OPSEC_SESSION_ERR) {
					fprintf(stderr, "ERROR: failed to set rule value (%s)\n", opsec_errno_str(opsec_errno));
					lea_value_ex_destroy(val_arr[argumentcount-1]);
					lea_filter_rule_destroy(prule);
					return NULL;
				}
			}
		}

		/*
		 * create filter predicate
		 */
		if ((ppred = lea_filter_predicate_create("service", -1, negation, LEA_FILTER_PRED_BELONGS_TO, argumentcount, val_arr)) == NULL) {
			fprintf(stderr, "ERROR: failed to create predicate\n");
			lea_value_ex_destroy(val_arr[argumentcount-1]);
			lea_filter_rule_destroy(prule);
			return NULL;
		}

		lea_value_ex_destroy(val_arr[argumentcount-1]);

		/*
		 * add current predicate to current rule
		 */
		if (lea_filter_rule_add_predicate(prule, ppred) == LEA_FILTER_ERR) {
			fprintf(stderr, "ERROR: failed to add predicate to rule\n");
			lea_filter_rule_destroy(prule);
			lea_filter_predicate_destroy(ppred);
			return NULL;
		}

		lea_filter_predicate_destroy(ppred);
	  }

	  /*
	   * process arguments of type "src"
	   */
	  else if ((strcmp(argumentname, "src") == 0) && (!(cfgvalues.audit_mode))) {
		/*
		 * check whether values are valid
		 */
		if ((strchr(argumentvalue,',')) && (strchr(argumentvalue,'/'))) {
			fprintf(stderr, "ERROR: use either netmask OR multiple IP addresses");
			lea_filter_rule_destroy(prule);
			return NULL;
		}

		/*
		 * if the value specifies a network, create the filter predicate directly
		 */
		if (strchr(argumentvalue,'/')) {
			tmpstring1 = string_trim(string_get_token(&argumentvalue, '/'), ' ');
			tmpstring2 = string_trim(string_get_token(&argumentvalue, '/'), ' ');
			if ((strlen(tmpstring1) == 0) || (strlen(tmpstring2) == 0)) {
				fprintf(stderr, "ERROR: syntax error in rule value of argument src: '%s/%s'.\n"
						"       Required syntax: 'src=aaa.bbb.ccc.ddd/eee.fff.ggg.hhh'\n", tmpstring1, tmpstring2);
				return NULL;
			}
			if ((ppred = lea_filter_predicate_create("src", -1, negation, LEA_FILTER_PRED_BELONGS_TO_MASK, inet_addr(tmpstring1), inet_addr(tmpstring2))) == NULL) {
				fprintf(stderr, "ERROR: failed to create predicate\n");
				lea_value_ex_destroy(val_arr[argumentcount-1]);
				lea_filter_rule_destroy(prule);
				return NULL;
			}
		} else {
	    		argumentcount = 0;
			/*
			 * get argument values separated by ","
			 */
		    	while (argumentvalue) {
				argumentsinglevalue = string_trim(string_get_token(&argumentvalue, ','), ' ');
				if (strlen(argumentsinglevalue) == 0) {
					fprintf(stderr, "ERROR: syntax error in rule value of argument src: '%s'.\n"
							"       Required syntax: 'src=aaa.bbb.ccc.ddd'\n", argumentsinglevalue);
					return NULL;
				}
				argumentcount++;
				if (val_arr) {
					val_arr = (lea_value_ex_t**)realloc(val_arr, argumentcount * sizeof(lea_value_ex_t*));
					if (val_arr == NULL) {
						fprintf(stderr, "ERROR: Out of memory\n");
						exit_loggrabber(1);
					}
				} else {
					val_arr = (lea_value_ex_t**)malloc(argumentcount * sizeof(lea_value_ex_t*));
					if (val_arr == NULL) {
						fprintf(stderr, "ERROR: Out of memory\n");
						exit_loggrabber(1);
					}
				}

				/*
				 * create extended opsec value
				 */
				val_arr[argumentcount-1] = lea_value_ex_create();
				if (lea_value_ex_set(val_arr[argumentcount-1], LEA_VT_IP_ADDR, inet_addr(argumentsinglevalue)) == OPSEC_SESSION_ERR) {
					fprintf(stderr, "ERROR: failed to set rule value (%s)\n", opsec_errno_str(opsec_errno));
					lea_value_ex_destroy(val_arr[argumentcount-1]);
					lea_filter_rule_destroy(prule);
					return NULL;
				}
			}

			/*
			 * create filter predicate
			 */
			if ((ppred = lea_filter_predicate_create("src", -1, negation, LEA_FILTER_PRED_BELONGS_TO, argumentcount, val_arr)) == NULL) {
				fprintf(stderr, "ERROR: failed to create predicate\n");
				lea_value_ex_destroy(val_arr[argumentcount-1]);
				lea_filter_rule_destroy(prule);
				return NULL;
			}

			lea_value_ex_destroy(val_arr[argumentcount-1]);
		}

		/*
		 * add current predicate to current rule
		 */
		if (lea_filter_rule_add_predicate(prule, ppred) == LEA_FILTER_ERR) {
			fprintf(stderr, "ERROR: failed to add predicate to rule\n");
			lea_filter_rule_destroy(prule);
			lea_filter_predicate_destroy(ppred);
			return NULL;
		}

		lea_filter_predicate_destroy(ppred);
	  }

	  /*
	   * process unknown arguments
	   */
	  else {
		fprintf(stderr, "ERROR: Unknown filterargument: '%s'\n", argumentname);
		return NULL;
	  }
	}

	/*
	 * add current rule to rulebase
	 */
	if (lea_filter_rulebase_add_rule(prulebase, prule) != OPSEC_SESSION_OK) {
		fprintf(stderr, "failed to add rule to rulebase\n");
		lea_filter_rulebase_destroy(prulebase);
		lea_filter_rule_destroy(prule);
		return NULL;
	}

	lea_filter_rule_destroy(prule);

	return prulebase;
}

/*
 * function create_audit_filter_rule
 */
LeaFilterRulebase* create_audit_filter_rule(LeaFilterRulebase *prulebase, char filterstring[255]) {
	LeaFilterRule *prule;
	LeaFilterPredicate *ppred;
	char* filterargument;
        char* argumentvalue;
	char* argumentname;
	unsigned int tempint;
	unsigned long templong;
	lea_value_ex_t **val_arr;
	lea_value_ex_t *lea_value;
	char* argumentsinglevalue;
	int argumentcount;
	int negation;
	struct tm timestruct;
	char tempchararray[10];

	/*
	 * create an empty rule with action "pass"
	 */
        if ((prule = lea_filter_rule_create(LEA_FILTER_ACTION_PASS)) == NULL) {
 		fprintf(stderr, "ERROR: failed to create rule\n");
		lea_filter_rulebase_destroy(prulebase);
		return NULL;
	}

	/*
	 * split filter string in arguments separated by ";"
	 */
	filterargument = strtok(filterstring, ";");
	while (filterargument != NULL) {
	  /*
	   * split argument into name and value separated by "="
	   */
          argumentvalue = strchr(filterargument, '=');
	  if (argumentvalue == NULL) {
		fprintf(stderr, "ERROR: syntax error in rule argument '%s'.\n"
				"       Required syntax: 'argument=value'\n", filterargument);
		return NULL;
	  }
	  argumentvalue++;
          argumentname = filterargument;
	  argumentname[argumentvalue-filterargument-1]='\0';
	  argumentvalue = string_trim(argumentvalue, ' ');
	  argumentname = string_trim(argumentname, ' ');
 	  filterargument = strtok(NULL, ";");
	  val_arr = NULL;

	  if (argumentname[strlen(argumentname)-1] == '!') {
		negation = 1;
		argumentname = string_trim(argumentname, '!');
	  } else {
		negation = 0;
	  }

	  /*
	   * change argument name to lower case letters
	   */
	  for (tempint = 0 ; tempint < strlen(argumentname) ; tempint++) {
	    argumentname[tempint] = tolower(argumentname[tempint]);
	  }

	  /*
	   * process arguments of type "product"
	   */
	  if (strcmp(argumentname, "product") == 0) {
		argumentcount = 0;
		/*
		 * get argument values separated by ","
		 */
		while (argumentvalue) {
			argumentsinglevalue = string_trim(string_get_token(&argumentvalue, ','), ' ');
			argumentcount++;
			if (val_arr) {
				val_arr = (lea_value_ex_t**)realloc(val_arr, argumentcount * sizeof(lea_value_ex_t*));
				if (val_arr == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
			} else {
				val_arr = (lea_value_ex_t**)malloc(argumentcount * sizeof(lea_value_ex_t*));
				if (val_arr == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
			}

			/*
			 * check validity of argument value
			 */
			if (!(  (strcmp(argumentsinglevalue, "SmartDashboard") == 0) || \
				(strcmp(argumentsinglevalue, "Policy Editor") == 0) || \
				(strcmp(argumentsinglevalue, "SmartView Tracker") == 0) || \
				(strcmp(argumentsinglevalue, "SmartView Status") == 0) || \
				(strcmp(argumentsinglevalue, "SmartView Monitor") == 0) || \
				(strcmp(argumentsinglevalue, "System Monitor") == 0) || \
				(strcmp(argumentsinglevalue, "cpstat_monitor") == 0) || \
				(strcmp(argumentsinglevalue, "SmartUpdate") == 0) || \
				(strcmp(argumentsinglevalue, "CPMI Client") == 0) ))
			{
				fprintf(stderr, "ERROR: invalid value for product: '%s'\n", argumentsinglevalue);
				return NULL;
			}

			/*
			 * create extended opsec value
			 */
			val_arr[argumentcount-1] = lea_value_ex_create();
			if (lea_value_ex_set(val_arr[argumentcount-1], LEA_VT_STRING, argumentsinglevalue) == OPSEC_SESSION_ERR) {
				fprintf(stderr, "ERROR: failed to set rule value (%s)\n", opsec_errno_str(opsec_errno));
				lea_value_ex_destroy(val_arr[argumentcount-1]);
				lea_filter_rule_destroy(prule);
				return NULL;
			}
		}

		/*
		 * create filter predicate
		 */
		if ((ppred = lea_filter_predicate_create("product", -1, negation, LEA_FILTER_PRED_BELONGS_TO, argumentcount, val_arr)) == NULL) {
			fprintf(stderr, "ERROR: failed to create predicate\n");
			lea_value_ex_destroy(val_arr[argumentcount-1]);
			lea_filter_rule_destroy(prule);
			return NULL;
		}

		lea_value_ex_destroy(val_arr[argumentcount-1]);

		/*
		 * add current predicate to current rule
		 */
		if (lea_filter_rule_add_predicate(prule, ppred) == LEA_FILTER_ERR) {
			fprintf(stderr, "ERROR: failed to add predicate to rule\n");
			lea_filter_rule_destroy(prule);
			lea_filter_predicate_destroy(ppred);
			return NULL;
		}

		lea_filter_predicate_destroy(ppred);
	  }

	  /*
	   * process arguments of type "Administrator"
	   */
	  else if (strcmp(argumentname, "administrator") == 0) {
		argumentcount = 0;
		/*
		 * get argument values separated by ","
		 */
		while (argumentvalue) {
			argumentsinglevalue = string_trim(string_get_token(&argumentvalue, ','), ' ');
			argumentcount++;
			if (val_arr) {
				val_arr = (lea_value_ex_t**)realloc(val_arr, argumentcount * sizeof(lea_value_ex_t*));
				if (val_arr == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
			} else {
				val_arr = (lea_value_ex_t**)malloc(argumentcount * sizeof(lea_value_ex_t*));
				if (val_arr == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
			}

			/*
			 * create extended opsec value
			 */
			val_arr[argumentcount-1] = lea_value_ex_create();
			if (lea_value_ex_set(val_arr[argumentcount-1], LEA_VT_STRING, argumentsinglevalue) == OPSEC_SESSION_ERR) {
				fprintf(stderr, "ERROR: failed to set rule value (%s)\n", opsec_errno_str(opsec_errno));
				lea_value_ex_destroy(val_arr[argumentcount-1]);
				lea_filter_rule_destroy(prule);
				return NULL;
			}
		}

		/*
		 * create filter predicate
		 */
		if ((ppred = lea_filter_predicate_create("Administrator", -1, negation, LEA_FILTER_PRED_BELONGS_TO, argumentcount, val_arr)) == NULL) {
			fprintf(stderr, "ERROR: failed to create predicate\n");
			lea_value_ex_destroy(val_arr[argumentcount-1]);
			lea_filter_rule_destroy(prule);
			return NULL;
		}

		lea_value_ex_destroy(val_arr[argumentcount-1]);

		/*
		 * add current predicate to current rule
		 */
		if (lea_filter_rule_add_predicate(prule, ppred) == LEA_FILTER_ERR) {
			fprintf(stderr, "ERROR: failed to add predicate to rule\n");
			lea_filter_rule_destroy(prule);
			lea_filter_predicate_destroy(ppred);
			return NULL;
		}

		lea_filter_predicate_destroy(ppred);
	  }

	  /*
	   * process arguments of type "action"
	   */
	  else if (strcmp(argumentname, "action") == 0) {
	    	argumentcount = 0;
		/*
		 * get argument values separated by ","
		 */
	    	while (argumentvalue) {
			argumentsinglevalue = string_trim(string_get_token(&argumentvalue, ','), ' ');
			argumentcount++;
			if (val_arr) {
				val_arr = (lea_value_ex_t**)realloc(val_arr, argumentcount * sizeof(lea_value_ex_t*));
				if (val_arr == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
			} else {
				val_arr = (lea_value_ex_t**)malloc(argumentcount * sizeof(lea_value_ex_t*));
				if (val_arr == NULL) {
					fprintf(stderr, "ERROR: Out of memory\n");
					exit_loggrabber(1);
				}
			}

			/*
			 * transform values (accept, drop, reject) into corresponding values
			 */
			if (strcmp(argumentsinglevalue,"accept") == 0) {
				tempint = 4;
			}
			else if (strcmp(argumentsinglevalue,"drop") == 0) {
				tempint = 2;
			}
			else if (strcmp(argumentsinglevalue,"reject") == 0) {
				tempint = 3;
			}
			else {
				fprintf(stderr, "ERROR: invalid value for action: '%s'\n", argumentsinglevalue);
				return NULL;
			}

			/*
			 * create extended opsec value
			 */
			val_arr[argumentcount-1] = lea_value_ex_create();
			if (lea_value_ex_set(val_arr[argumentcount-1], LEA_VT_ACTION, tempint) == OPSEC_SESSION_ERR) {
				fprintf(stderr, "ERROR: failed to set rule value (%s)\n", opsec_errno_str(opsec_errno));
				lea_value_ex_destroy(val_arr[argumentcount-1]);
				lea_filter_rule_destroy(prule);
				return NULL;
			}
		}

		/*
		 * create filter predicate
		 */
		if ((ppred = lea_filter_predicate_create("action", -1, negation, LEA_FILTER_PRED_BELONGS_TO, argumentcount, val_arr)) == NULL) {
			fprintf(stderr, "ERROR: failed to create predicate\n");
			lea_value_ex_destroy(val_arr[argumentcount-1]);
			lea_filter_rule_destroy(prule);
			return NULL;
		}

		lea_value_ex_destroy(val_arr[argumentcount-1]);

		/*
		 * add current predicate to current rule
		 */
		if (lea_filter_rule_add_predicate(prule, ppred) == LEA_FILTER_ERR) {
			fprintf(stderr, "ERROR: failed to add predicate to rule\n");
			lea_filter_rule_destroy(prule);
			lea_filter_predicate_destroy(ppred);
			return NULL;
		}

		lea_filter_predicate_destroy(ppred);
	  }

	  /*
	   * process arguments of type "starttime"
	   */
	  else if (strcmp(argumentname, "starttime") == 0) {
		argumentsinglevalue = string_trim(argumentvalue, ' ');
		if (strlen(argumentsinglevalue) != 14) {
			fprintf(stderr, "ERROR: syntax error in rule value of argument rule: '%s'.\n"
					"       Required syntax: 'starttime=YYYYMMDDhhmmss'\n", argumentsinglevalue);
			return NULL;
		}

		/*
		 * convert starttime parameter to proper form (unixtime)
		 */
		strncpy(tempchararray, argumentsinglevalue, 4);
		tempchararray[4] = '\0';
		timestruct.tm_year = strtol(tempchararray, (char**)NULL, 10) - 1900;
		argumentsinglevalue += 4 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_mon = strtol(tempchararray, (char**)NULL, 10) - 1;
		argumentsinglevalue += 2 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_mday = strtol(tempchararray, (char**)NULL, 10);
		argumentsinglevalue += 2 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_hour = strtol(tempchararray, (char**)NULL, 10);
		argumentsinglevalue += 2 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_min = strtol(tempchararray, (char**)NULL, 10);
		argumentsinglevalue += 2 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_sec = strtol(tempchararray, (char**)NULL, 10);

		/*
		 * convert starttime parameter to long int
		 */
		if ((timestruct.tm_mon > 11) || (timestruct.tm_mday > 31) || (timestruct.tm_hour > 23) || (timestruct.tm_min > 59) || (timestruct.tm_sec > 59)) {
			fprintf(stderr, "ERROR: illegal date format in argumentvalue\n");
			return NULL;
		}
		templong = (unsigned long)mktime(&timestruct);
		if (templong == -1) {
			fprintf(stderr, "ERROR: illegal date format in argumentvalue\n");
			return NULL;
		}

		/*
		 * create extended opsec value
		 */
		lea_value = lea_value_ex_create();
		if (lea_value_ex_set(lea_value, LEA_VT_TIME, templong) == OPSEC_SESSION_ERR) {
			fprintf(stderr, "ERROR: failed to set starttime value (%s)\n", opsec_errno_str(opsec_errno));
			lea_value_ex_destroy(lea_value);
			lea_filter_rule_destroy(prule);
			return NULL;
		}

		/*
		 * create filter predicate
		 */
		if ((ppred = lea_filter_predicate_create("time", -1, negation, LEA_FILTER_PRED_GREATER_EQUAL, lea_value)) == NULL) {
			fprintf(stderr, "ERROR: failed to create predicate\n");
			lea_value_ex_destroy(val_arr[argumentcount-1]);
			lea_filter_rule_destroy(prule);
			return NULL;
		}

		lea_value_ex_destroy(lea_value);

		/*
		 * add current predicate to current rule
		 */
		if (lea_filter_rule_add_predicate(prule, ppred) == LEA_FILTER_ERR) {
			fprintf(stderr, "ERROR: failed to add predicate to rule\n");
			lea_filter_rule_destroy(prule);
			lea_filter_predicate_destroy(ppred);
			return NULL;
		}

		lea_filter_predicate_destroy(ppred);
	  }

	  /*
	   * process arguments of type "endtime"
	   */
	  else if (strcmp(argumentname, "endtime") == 0) {
		argumentsinglevalue = string_trim(argumentvalue, ' ');
		if (strlen(argumentsinglevalue) != 14) {
			fprintf(stderr, "ERROR: syntax error in rule value of argument rule: '%s'.\n"
					"       Required syntax: 'endtime=YYYYMMDDhhmmss'\n", argumentsinglevalue);
			return NULL;
		}

		/*
		 * convert starttime parameter to proper form (unixtime)
		 */
		strncpy(tempchararray, argumentsinglevalue, 4);
		tempchararray[4] = '\0';
		timestruct.tm_year = strtol(tempchararray, (char**)NULL, 10) - 1900;
		argumentsinglevalue += 4 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_mon = strtol(tempchararray, (char**)NULL, 10) - 1;
		argumentsinglevalue += 2 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_mday = strtol(tempchararray, (char**)NULL, 10);
		argumentsinglevalue += 2 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_hour = strtol(tempchararray, (char**)NULL, 10);
		argumentsinglevalue += 2 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_min = strtol(tempchararray, (char**)NULL, 10);
		argumentsinglevalue += 2 * sizeof(char);
		strncpy(tempchararray, argumentsinglevalue, 2);
		tempchararray[2] = '\0';
		timestruct.tm_sec = strtol(tempchararray, (char**)NULL, 10);

		/*
		 * convert starttime parameter to long int
		 */
		if ((timestruct.tm_mon > 11) || (timestruct.tm_mday > 31) || (timestruct.tm_hour > 23) || (timestruct.tm_min > 59) || (timestruct.tm_sec > 59)) {
			fprintf(stderr, "ERROR: illegal date format in argumentvalue\n");
			return NULL;
		}
		templong = (unsigned long)mktime(&timestruct);
		if (templong == -1) {
			fprintf(stderr, "ERROR: illegal date format in argumentvalue\n");
			return NULL;
		}

		/*
		 * create extended opsec value
		 */
		lea_value = lea_value_ex_create();
		if (lea_value_ex_set(lea_value, LEA_VT_TIME, templong) == OPSEC_SESSION_ERR) {
			fprintf(stderr, "ERROR: failed to set endtime value (%s)\n", opsec_errno_str(opsec_errno));
			lea_value_ex_destroy(lea_value);
			lea_filter_rule_destroy(prule);
			return NULL;
		}

		/*
		 * create filter predicate
		 */
		if ((ppred = lea_filter_predicate_create("time", -1, negation, LEA_FILTER_PRED_SMALLER_EQUAL, lea_value)) == NULL) {
			fprintf(stderr, "ERROR: failed to create predicate\n");
			lea_value_ex_destroy(val_arr[argumentcount-1]);
			lea_filter_rule_destroy(prule);
			return NULL;
		}

		lea_value_ex_destroy(lea_value);

		/*
		 * add current predicate to current rule
		 */
		if (lea_filter_rule_add_predicate(prule, ppred) == LEA_FILTER_ERR) {
			fprintf(stderr, "ERROR: failed to add predicate to rule\n");
			lea_filter_rule_destroy(prule);
			lea_filter_predicate_destroy(ppred);
			return NULL;
		}

		lea_filter_predicate_destroy(ppred);
	  }

	  /*
	   * process unknown arguments
	   */
	  else {
		fprintf(stderr, "ERROR: Unknown filterargument: '%s'\n", argumentname);
		return NULL;
	  }
	}

	/*
	 * add current rule to rulebase
	 */
	if (lea_filter_rulebase_add_rule(prulebase, prule) != OPSEC_SESSION_OK) {
		fprintf(stderr, "failed to add rule to rulebase\n");
		lea_filter_rulebase_destroy(prulebase);
		lea_filter_rule_destroy(prule);
		return NULL;
	}

	lea_filter_rule_destroy(prule);

	return prulebase;
}

/*
 * BEGIN: function string_get_token
 */
char* string_get_token(char **tokstring, char separator) {
  	char* tempstring = NULL;
	char* returnstring;
	int strlength;

  	/*
	 * search for first separator
	 */
	tempstring = strchr(*tokstring, separator);

	/*
	 * calculate string length
	 */
	if (tempstring) {
		tempstring = tempstring + 1;
		strlength = strlen(*tokstring) - strlen(tempstring);
	} else {
		strlength = strlen(*tokstring) + 1;
	}

	returnstring = (char*)malloc(strlength + 1);
	if (returnstring == NULL) {
		fprintf(stderr, "ERROR: Out of memory\n");
		exit_loggrabber(1);
	}
	strncpy(returnstring, *tokstring, strlength);
        returnstring[strlength - 1] = '\0';

	*tokstring = tempstring;
	return returnstring;
}

/*
 * BEGIN: function string_duplicate
 */
char* string_duplicate(const char *src)
{
	size_t length;
	char *dst;

	length = strlen(src)+1;
	dst = malloc(length);
	if (!dst) {
		fprintf(stderr, "ERROR: out of memory\n");
		exit_loggrabber(1);
	}
	return memcpy(dst, src, length);
}

/*
 * BEGIN: function string_left_trim
 */
char* string_left_trim(char *string, char character)
{
	char* tmp;

	if (! string) {
		return NULL;
	}
	tmp = string+strlen(string);
	while ((string[0] == character) && (string < tmp)) string++;
	return(string);
}

/*
 * BEGIN: function string_right_trim
 */
char* string_right_trim(char *string, char character)
{
	int tmp;

	if (! string) {
		return NULL;
	}
	tmp = strlen(string);
	while ((string[tmp-1] == character) && (tmp != 0)) tmp--;
	string[tmp]='\0';
	return(string);
}

/*
 * BEGIN: function string_trim
 */
char* string_trim(char *string, char character)
{
	return(string_right_trim(string_left_trim(string, character), character));
}

/*
 * BEGIN: function string_escape
 */
char* string_escape(char* string, char character) {
	int i = strlen(string);
	int z1,z2;
	char* s = (char*)malloc(i*2+1);

	if (!s) {
		fprintf(stderr, "ERROR: out of memory\n");
		exit_loggrabber(1);
	}

	for (z1=0,z2=0 ; z1 < i ; z1++) {
		if ((string[z1] == character) || (string[z1] == '\\')) {
			s[z2++] = '\\';
		}
		s[z2++] = string[z1];
	}

	s[z2] = '\0';

	return(s);
}

/*
 * BEGIN: function string_icmp
 */
int string_icmp(const char *str1, const char *str2) {
	char*	tempstr1;
	char*	tempstr2;
	int 	cmpresult;
	int	i;

	tempstr1 = string_duplicate(str1);
	tempstr2 = string_duplicate(str2);

	for (i=0 ; i < strlen(tempstr1) ; i++) {
		tempstr1[i] = tolower(tempstr1[i]);
	}

	for (i=0 ; i < strlen(tempstr2) ; i++) {
		tempstr2[i] = tolower(tempstr2[i]);
	}

	cmpresult = strcmp(tempstr1, tempstr2);

	free (tempstr1);
	free (tempstr2);

	return (cmpresult);
}

/*
 * BEGIN: function connect_to_mysql
 */
#ifdef USE_MYSQL
MYSQL* connect_to_mysql(MYSQL* mysql, long int* maxno, configvalues* cfgvalues)
{
	MYSQL* connection;
	MYSQL_RES* result;
	MYSQL_ROW row;
	int state;
	char* end;

	mysql_init(mysql);
	connection = mysql_real_connect(mysql,cfgvalues->mysql_host,cfgvalues->mysql_user,cfgvalues->mysql_password,cfgvalues->mysql_database,0,NULL,0);
	if (connection == NULL) {
		fprintf(stderr, "ERROR: Cannot connect to MySQL database (%s)\n", mysql_error(mysql));
		exit_loggrabber(1);
	}

	if (cfgvalues->audit_mode) {
		state = mysql_query(connection, "SELECT MAX(NUMBER) FROM auditentries");
	} else {
		state = mysql_query(connection, "SELECT MAX(NUMBER) FROM logentries");
	}

	if (state != 0) {
		fprintf(stderr, "ERROR: Cannot access MySQL database (%s)\n", mysql_error(connection));
		exit_loggrabber(1);
	}

	result = mysql_store_result(connection);

	while ((row = mysql_fetch_row(result)) != NULL) {
		*maxno = (row[0] == NULL) ? 0 : strtol(row[0], &end, 10);
	}

	mysql_free_result(result);

	return (connection);
}

/*
 * BEGIN: function disconnect_from_mysql
 */
void disconnect_from_mysql(MYSQL* mysql)
{
	mysql_close(mysql);
}
#endif

/*
 * BEGIN: function to read configuration file
 */
void read_config_file(char* filename, configvalues* cfgvalues)
{
	FILE* configfile;
	char line[256];
	char* position;
	char* configparameter;
	char* configvalue;
	char* tmpstr;
	char* loggrabberconf;

#ifdef WIN32
	TCHAR	buff[BUFSIZE];
	DWORD	dwRet;
#else
	long size;
#endif

#ifdef WIN32
	dwRet = GetCurrentDirectory(BUFSIZE, buff);

	if (dwRet == 0) {
		fprintf (stderr, "ERROR: Cannot get current working directory (error code: %d)\n", GetLastError());
		exit_loggrabber(1);
	}
	if (dwRet > BUFSIZE) {
		fprintf (stderr, "ERROR: Getting the current working directory failed failed since buffer too small, and it needs %d chars\n", dwRet);
		exit_loggrabber(1);
	}
	if ((loggrabberconf = (char *)malloc(BUFSIZE)) == NULL) {
		fprintf (stderr, "ERROR: Out of memory\n");
		exit_loggrabber(1);
	}

	if (filename == NULL) {
		strcpy(loggrabberconf, buff);
		strcat(loggrabberconf, "\\fw1-loggrabber.conf");
	} else {
		if ((filename[0] == '\\') ||
		   ((filename[1] == ':') && (filename[2] == '\\'))) {
			strcpy(loggrabberconf, filename);
		} else {
			strcpy(loggrabberconf, buff);
			strcat(loggrabberconf, "\\");
			strcat(loggrabberconf, filename);
		}
	}
#else
	size = pathconf(".", _PC_PATH_MAX);
	if ((loggrabberconf = (char *)malloc((size_t)size)) == NULL) {
		fprintf (stderr, "ERROR: Out of memory\n");
		exit_loggrabber(1);
	}

	if (filename == NULL) {
		if (getcwd(loggrabberconf, (size_t)size) == NULL) {
			fprintf (stderr, "ERROR: Cannot get current working directory\n");
			exit_loggrabber(1);
		}
		strcat(loggrabberconf, "/fw1-loggrabber.conf");
	} else {
		if (filename[0] == '/') {
			strcpy(loggrabberconf, filename);
		} else {
			if (getcwd(loggrabberconf, (size_t)size) == NULL) {
				fprintf (stderr, "ERROR: Cannot get current working directory\n");
				exit_loggrabber(1);
			}
			strcat(loggrabberconf, "/");
			strcat(loggrabberconf, filename);
		}
	}
#endif

	if (debug_mode) {
		fprintf(stderr, "DEBUG: fw1-loggrabber conf file is %s\n", loggrabberconf);
	}

	if ((configfile = fopen(loggrabberconf,"r")) == NULL) {
		fprintf(stderr, "ERROR: Cannot open configfile (%s)\n", loggrabberconf);
		exit_loggrabber(1);
	}

	while (fgets(line, sizeof line, configfile)) {
		position = strchr(line, '\n');
		if (position) {
			*position = 0;
		}

		position = strchr(line, '#');
		if (position) {
			*position = 0;
		}

		configparameter = string_trim(strtok(line, "="), ' ');
		if (configparameter) {
			configvalue = string_trim(strtok(NULL, ""), ' ');
		}

		if (configparameter && configvalue) {
			if (debug_mode == 1) {
				fprintf(stderr, "DEBUG: %s=%s\n", configparameter, configvalue);
			}
			if (strcmp(configparameter, "RECORD_SEPARATOR") == 0) {
				tmpstr = string_trim(configvalue, '"');
				if (tmpstr) {
					cfgvalues->record_separator = tmpstr[0];
				}
#ifdef USE_MYSQL
			} else if (strcmp(configparameter, "MYSQL_HOST") == 0) {
				cfgvalues->mysql_host = string_duplicate(string_trim(configvalue, '"'));
			} else if (strcmp(configparameter, "MYSQL_DATABASE") == 0) {
				cfgvalues->mysql_database = string_duplicate(string_trim(configvalue, '"'));
			} else if (strcmp(configparameter, "MYSQL_USER") == 0) {
				cfgvalues->mysql_user = string_duplicate(string_trim(configvalue, '"'));
			} else if (strcmp(configparameter, "MYSQL_PASSWORD") == 0) {
				cfgvalues->mysql_password = string_duplicate(string_trim(configvalue, '"'));
			} else if (strcmp(configparameter, "MYSQL_MODE") == 0) {
				configvalue = string_duplicate(string_trim(configvalue, '"'));
				if (string_icmp(configvalue, "no") == 0) {
					cfgvalues->mysql_mode = 0;
				} else if (string_icmp(configvalue,"yes") == 0) {
					cfgvalues->mysql_mode = 1;
				} else {
					fprintf(stderr, "WARNING: Illegal entry in configuration file: %s=%s\n", configparameter, configvalue);
					exit_loggrabber(1);
				}
				free(configvalue);
#endif
			} else if (strcmp(configparameter, "DEBUG_LEVEL") == 0) {
				cfgvalues->debug_mode = atoi(string_trim(configvalue, '"'));
			} else if (strcmp(configparameter, "SHOW_FIELDNAMES") == 0) {
				configvalue = string_duplicate(string_trim(configvalue, '"'));
				if (string_icmp(configvalue, "no") == 0) {
					cfgvalues->fieldnames_mode = 0;
				} else if (string_icmp(configvalue,"yes") == 0) {
					cfgvalues->fieldnames_mode = 1;
				} else {
					fprintf(stderr, "WARNING: Illegal entry in configuration file: %s=%s\n", configparameter, configvalue);
					exit_loggrabber(1);
				}
				free(configvalue);
			} else if (strcmp(configparameter, "ONLINE_MODE") == 0) {
				configvalue = string_duplicate(string_trim(configvalue, '"'));
				if (string_icmp(configvalue, "no") == 0) {
					cfgvalues->online_mode = 0;
				} else if (string_icmp(configvalue,"yes") == 0) {
					cfgvalues->online_mode = 1;
				} else {
					fprintf(stderr, "WARNING: Illegal entry in configuration file: %s=%s\n", configparameter, configvalue);
				}
				free(configvalue);
			} else if (strcmp(configparameter, "RESOLVE_MODE") == 0) {
				configvalue = string_duplicate(string_trim(configvalue, '"'));
				if (string_icmp(configvalue, "no") == 0) {
					cfgvalues->resolve_mode = 0;
				} else if (string_icmp(configvalue,"yes") == 0) {
					cfgvalues->resolve_mode = 1;
				} else {
					fprintf(stderr, "WARNING: Illegal entry in configuration file: %s=%s\n", configparameter, configvalue);
				}
				free(configvalue);
			} else if (strcmp(configparameter, "FW1_TYPE") == 0) {
				configvalue = string_duplicate(string_trim(configvalue, '"'));
				if (string_icmp(configvalue, "ng") == 0) {
					cfgvalues->fw1_2000 = 0;
				} else if (string_icmp(configvalue, "2000") == 0) {
					cfgvalues->fw1_2000 = 1;
				} else {
					fprintf(stderr, "WARNING: Illegal entry in configuration file: %s=%s\n", configparameter, configvalue);
				}
				free(configvalue);
			} else if (strcmp(configparameter, "FW1_MODE") == 0) {
				configvalue = string_duplicate(string_trim(configvalue, '"'));
				if (string_icmp(configvalue, "normal") == 0) {
					cfgvalues->audit_mode = 0;
				} else if (string_icmp(configvalue, "audit") == 0) {
					cfgvalues->audit_mode = 1;
				} else {
					fprintf(stderr, "WARNING: Illegal entry in configuration file: %s=%s\n", configparameter, configvalue);
				}
				free(configvalue);
			} else if (strcmp(configparameter, "DATEFORMAT") == 0) {
				configvalue = string_duplicate(string_trim(configvalue, '"'));
				if (string_icmp(configvalue, "cp") == 0) {
					cfgvalues->dateformat = DATETIME_CP;
				} else if (string_icmp(configvalue, "unix") == 0) {
					cfgvalues->dateformat = DATETIME_UNIX;
				} else if (string_icmp(configvalue, "std") == 0) {
					cfgvalues->dateformat = DATETIME_STD;
				} else {
					fprintf(stderr, "WARNING: Illegal entry in configuration file: %s=%s\n", configparameter, configvalue);
				}
				free(configvalue);
			} else if (strcmp(configparameter, "LOGGING_CONFIGURATION") == 0) {
				configvalue = string_duplicate(string_trim(configvalue, '"'));
				if (string_icmp(configvalue, "screen") == 0) {
					cfgvalues->log_mode = SCREEN;
				} else if (string_icmp(configvalue, "file") == 0) {
					cfgvalues->log_mode = LOGFILE;
				} else if (string_icmp(configvalue, "syslog") == 0) {
					cfgvalues->log_mode = SYSLOG;
				} else {
					fprintf(stderr, "WARNING: Illegal entry in configuration file: %s=%s\n", configparameter, configvalue);
				}
			} else if (strcmp(configparameter, "OUTPUT_FILE_PREFIX") == 0) {
				cfgvalues->output_file_prefix = string_duplicate(string_trim(configvalue, '"'));
			} else if (strcmp(configparameter, "OUTPUT_FILE_ROTATESIZE") == 0) {
				cfgvalues->output_file_rotatesize = atol(string_trim(configvalue, '"'));
			} else if (strcmp(configparameter, "FW1_OUTPUT") == 0) {
				configvalue = string_duplicate(string_trim(configvalue, '"'));
				if (string_icmp(configvalue, "files") == 0) {
					cfgvalues->showfiles_mode = 1;
				} else if (string_icmp(configvalue, "logs") == 0) {
					cfgvalues->showfiles_mode = 0;
				} else {
					fprintf(stderr, "WARNING: Illegal entry in configuration file: %s=%s\n", configparameter, configvalue);
				}
				free(configvalue);
			} else if (strcmp(configparameter, "FW1_LOGFILE") == 0) {
				cfgvalues->fw1_logfile = string_duplicate(string_trim(configvalue, '"'));
			} else {
				fprintf(stderr, "WARNING: Illegal entry in configuration file: %s=%s\n", configparameter, configvalue);
			}
		}
	}

	fclose(configfile);

	free(loggrabberconf);
}

/*
 * BEGIN: function to initialize fields headers of logfile fields
 */
void initialize_lfield_headers (char** headers[NUMBER_LIDX_FIELDS]) {
	int i;

	for (i=0 ; i < NUMBER_LIDX_FIELDS ; i++) {
		headers[i] = malloc(sizeof(char*));
		*headers[i] = NULL;
	}

	*headers[LIDX_NUM] = string_duplicate("loc");
	*headers[LIDX_TIME] = string_duplicate("time");
	*headers[LIDX_ACTION] = string_duplicate("action");
	*headers[LIDX_ORIG] = string_duplicate("orig");
	*headers[LIDX_ALERT] = string_duplicate("alert");
	*headers[LIDX_IF_DIR] = string_duplicate("i/f_dir");
	*headers[LIDX_IF_NAME] = string_duplicate("i/f_name");
	*headers[LIDX_HAS_ACCOUNTING] = string_duplicate("has_accounting");
	*headers[LIDX_UUID] = string_duplicate("uuid");
	*headers[LIDX_PRODUCT] = string_duplicate("product");
	*headers[LIDX_POLICY_ID_TAG] = string_duplicate("__policy_id_tag");
	*headers[LIDX_SRC] = string_duplicate("src");
	*headers[LIDX_S_PORT] = string_duplicate("s_port");
	*headers[LIDX_DST] = string_duplicate("dst");
	*headers[LIDX_SERVICE] = string_duplicate("service");
	*headers[LIDX_TCP_FLAGS] = string_duplicate("tcp_flags");
	*headers[LIDX_PROTO] = string_duplicate("proto");
	*headers[LIDX_RULE] = string_duplicate("rule");
	*headers[LIDX_XLATESRC] = string_duplicate("xlatesrc");
	*headers[LIDX_XLATEDST] = string_duplicate("xlatedst");
	*headers[LIDX_XLATESPORT] = string_duplicate("xlatesport");
	*headers[LIDX_XLATEDPORT] = string_duplicate("xlatedport");
	*headers[LIDX_NAT_RULENUM] = string_duplicate("NAT_rulenum");
	*headers[LIDX_NAT_ADDRULENUM] = string_duplicate("NAT_addtnl_rulenum");
	*headers[LIDX_RESOURCE] = string_duplicate("resource");
	*headers[LIDX_ELAPSED] = string_duplicate("elapsed");
	*headers[LIDX_PACKETS] = string_duplicate("packets");
	*headers[LIDX_BYTES] = string_duplicate("bytes");
	*headers[LIDX_REASON] = string_duplicate("reason");
	*headers[LIDX_SERVICE_NAME] = string_duplicate("service_name");
	*headers[LIDX_AGENT] = string_duplicate("agent");
	*headers[LIDX_FROM] = string_duplicate("from");
	*headers[LIDX_TO] = string_duplicate("to");
	*headers[LIDX_SYS_MSGS] = string_duplicate("sys_msgs");
	*headers[LIDX_FW_MESSAGE] = string_duplicate("fw_message");
	*headers[LIDX_INTERNAL_CA] = string_duplicate("Internal_CA:");
	*headers[LIDX_SERIAL_NUM] = string_duplicate("serial_num:");
	*headers[LIDX_DN] = string_duplicate("dn:");
	*headers[LIDX_ICMP] = string_duplicate("ICMP");
	*headers[LIDX_ICMP_TYPE] = string_duplicate("icmp-type");
	*headers[LIDX_ICMP_TYPE2] = string_duplicate("ICMP Type");
	*headers[LIDX_ICMP_CODE] = string_duplicate("icmp-code");
	*headers[LIDX_ICMP_CODE2] = string_duplicate("ICMP Code");
	*headers[LIDX_MSGID] = string_duplicate("msgid");
	*headers[LIDX_MESSAGE_INFO] = string_duplicate("message_info");
	*headers[LIDX_LOG_SYS_MESSAGE] = string_duplicate("log_sys_message");
	*headers[LIDX_SESSION_ID] = string_duplicate("session_id:");
	*headers[LIDX_DNS_QUERY] = string_duplicate("dns_query");
	*headers[LIDX_DNS_TYPE] = string_duplicate("dns_type");
	*headers[LIDX_SCHEME] = string_duplicate("scheme:");
	*headers[LIDX_SRCKEYID] = string_duplicate("srckeyid");
	*headers[LIDX_DSTKEYID] = string_duplicate("dstkeyid");
	*headers[LIDX_METHODS] = string_duplicate("methods:");
	*headers[LIDX_PEER_GATEWAY] = string_duplicate("peer gateway");
	*headers[LIDX_IKE] = string_duplicate("IKE:");
	*headers[LIDX_IKE_IDS] = string_duplicate("IKE IDs:");
	*headers[LIDX_ENCRYPTION_FAILURE] = string_duplicate("encryption failure:");
	*headers[LIDX_ENCRYPTION_FAIL_R] = string_duplicate("encryption fail reason:");
	*headers[LIDX_COOKIEI] = string_duplicate("CookieI");
	*headers[LIDX_COOKIER] = string_duplicate("CookieR");
	*headers[LIDX_START_TIME] = string_duplicate("start_time");
	*headers[LIDX_SEGMENT_TIME] = string_duplicate("segment_time");
	*headers[LIDX_CLIENT_IN_PACKETS] = string_duplicate("client_inbound_packets");
	*headers[LIDX_CLIENT_OUT_PACKETS] = string_duplicate("client_outbound_packets");
	*headers[LIDX_CLIENT_IN_BYTES] = string_duplicate("client_inbound_bytes");
	*headers[LIDX_CLIENT_OUT_BYTES] = string_duplicate("client_outbound_bytes");
	*headers[LIDX_CLIENT_IN_IF] = string_duplicate("client_inbound_interface");
	*headers[LIDX_CLIENT_OUT_IF] = string_duplicate("client_outbound_interface");
	*headers[LIDX_SERVER_IN_PACKETS] = string_duplicate("server_inbound_packets");
	*headers[LIDX_SERVER_OUT_PACKETS] = string_duplicate("server_outbound_packets");
	*headers[LIDX_SERVER_IN_BYTES] = string_duplicate("server_inbound_bytes");
	*headers[LIDX_SERVER_OUT_BYTES] = string_duplicate("server_outbound_bytes");
	*headers[LIDX_SERVER_IN_IF] = string_duplicate("server_inbound_interface");
	*headers[LIDX_SERVER_OUT_IF] = string_duplicate("server_outbound_interface");
	*headers[LIDX_MESSAGE] = string_duplicate("message");
	*headers[LIDX_USER] = string_duplicate("user");
	*headers[LIDX_SRCNAME] = string_duplicate("srcname");
	*headers[LIDX_OM] = string_duplicate("OM:");
	*headers[LIDX_OM_METHOD] = string_duplicate("om_method:");
	*headers[LIDX_ASSIGNED_IP] = string_duplicate("assigned_IP:");
	*headers[LIDX_VPN_USER] = string_duplicate("vpn_user");
	*headers[LIDX_MAC] = string_duplicate("MAC:");
	*headers[LIDX_ATTACK] = string_duplicate("attack");
	*headers[LIDX_ATTACK_INFO] = string_duplicate("Attack Info");
	*headers[LIDX_CLUSTER_INFO] = string_duplicate("Cluster_Info");
	*headers[LIDX_DCE_RPC_UUID] = string_duplicate("DCE-RPC Interface UUID");
	*headers[LIDX_DCE_RPC_UUID_1] = string_duplicate("DCE-RPC Interface UUID-1");
	*headers[LIDX_DCE_RPC_UUID_2] = string_duplicate("DCE-RPC Interface UUID-2");
	*headers[LIDX_DCE_RPC_UUID_3] = string_duplicate("DCE-RPC Interface UUID-3");
	*headers[LIDX_DURING_SEC] = string_duplicate("during_sec");
	*headers[LIDX_FRAGMENTS_DROPPED] = string_duplicate("fragments_dropped");
	*headers[LIDX_IP_ID] = string_duplicate("ip_id");
	*headers[LIDX_IP_LEN] = string_duplicate("ip_len");
	*headers[LIDX_IP_OFFSET] = string_duplicate("ip_offset");
	*headers[LIDX_TCP_FLAGS2] = string_duplicate("TCP flags");
	*headers[LIDX_SYNC_INFO] = string_duplicate("sync_info:");
	*headers[LIDX_LOG] = string_duplicate("log");
	*headers[LIDX_CPMAD] = string_duplicate("cpmad");
	*headers[LIDX_AUTH_METHOD] = string_duplicate("auth_method");
	*headers[LIDX_TCP_PACKET_OOS] = string_duplicate("TCP packet out of state");
	*headers[LIDX_RPC_PROG] = string_duplicate("rpc_prog");
	*headers[LIDX_TH_FLAGS] = string_duplicate("th_flags");
	*headers[LIDX_CP_MESSAGE] = string_duplicate("cp_message:");
}

/*
 * BEGIN: function to free pointers in logfile arrays
 */
void free_lfield_arrays (char** headers[NUMBER_LIDX_FIELDS]) {
	int i;

 	for (i=0 ; i < NUMBER_LIDX_FIELDS ; i++) {
		if (*headers[i] != NULL) {
			free(*headers[i]);
			*headers[i] = NULL;
		}
		free(headers[i]);
	}
}

/*
 * BEGIN: function to initialize fields headers of audit fields
 */
void initialize_afield_headers (char** headers[NUMBER_AIDX_FIELDS]) {
	int i;

	for (i=0 ; i < NUMBER_AIDX_FIELDS ; i++) {
		headers[i] = malloc(sizeof(char*));
		*headers[i] = NULL;
	}

	*headers[AIDX_NUM] = string_duplicate("loc");
	*headers[AIDX_TIME] = string_duplicate("time");
	*headers[AIDX_ACTION] = string_duplicate("action");
	*headers[AIDX_ORIG] = string_duplicate("orig");
	*headers[AIDX_IF_DIR] = string_duplicate("i/f_dir");
	*headers[AIDX_IF_NAME] = string_duplicate("i/f_name");
	*headers[AIDX_HAS_ACCOUNTING] = string_duplicate("has_accounting");
	*headers[AIDX_UUID] = string_duplicate("uuid");
	*headers[AIDX_PRODUCT] = string_duplicate("product");
	*headers[AIDX_OBJECTNAME] = string_duplicate("ObjectName");
	*headers[AIDX_OBJECTTYPE] = string_duplicate("ObjectType");
	*headers[AIDX_OBJECTTABLE] = string_duplicate("ObjectTable");
	*headers[AIDX_OPERATION] = string_duplicate("Operation");
	*headers[AIDX_UID] = string_duplicate("Uid");
	*headers[AIDX_ADMINISTRATOR] = string_duplicate("Administrator");
	*headers[AIDX_MACHINE] = string_duplicate("Machine");
	*headers[AIDX_SUBJECT] = string_duplicate("Subject");
	*headers[AIDX_AUDIT_STATUS] = string_duplicate("Audit Status");
	*headers[AIDX_ADDITIONAL_INFO] = string_duplicate("Additional Info");
	*headers[AIDX_OPERATION_NUMBER] = string_duplicate("Operation Number");
	*headers[AIDX_FIELDSCHANGES] = string_duplicate("FieldsChanges");
}

/*
 * BEGIN: function to free pointers in audit arrays
 */
void free_afield_arrays (char** headers[NUMBER_AIDX_FIELDS]) {
	int i;

 	for (i=0 ; i < NUMBER_AIDX_FIELDS ; i++) {
		if (*headers[i] != NULL) {
			free(*headers[i]);
			*headers[i] = NULL;
		}
		free(headers[i]);
	}
}

/*
 * BEGIN: function to initialize fields values of logfile fields
 */
void initialize_lfield_values (char** values[NUMBER_LIDX_FIELDS]) {
	int i;

	for (i=0 ; i < NUMBER_LIDX_FIELDS ; i++) {
		values[i] = malloc(sizeof(char*));
		*values[i] = NULL;
	}
}

/*
 * BEGIN: function to initialize fields values of audit fields
 */
void initialize_afield_values (char** values[NUMBER_AIDX_FIELDS]) {
	int i;

	for (i=0 ; i < NUMBER_AIDX_FIELDS ; i++) {
		values[i] = malloc(sizeof(char*));
		*values[i] = NULL;
	}
}

/*
 * BEGIN: function to initialize output values of logfile fields
 */
void initialize_lfield_output (int* output) {
	int i;

	for (i=0 ; i < NUMBER_LIDX_FIELDS ; i++) {
		lfield_output[i] = 0;
	}
}

/*
 * BEGIN: function to initialize output values of audit fields
 */
void initialize_afield_output (int* output) {
	int i;

	for (i=0 ; i < NUMBER_AIDX_FIELDS ; i++) {
		afield_output[i] = 0;
	}
}

/*
 * BEGIN: function to cleanup environment and exit fw1-loggrabber
 */
void exit_loggrabber (int errorcode) {
	int i;
	free_lfield_arrays(lfield_headers);
	free_afield_arrays(afield_headers);
	free_lfield_arrays(lfields);
	free_afield_arrays(afields);

	if (LogfileName) {
		free(LogfileName);
	}
#ifdef USE_MYSQL
	if (cfgvalues.mysql_host) {
		free(cfgvalues.mysql_host);
	}
	if (cfgvalues.mysql_database) {
		free(cfgvalues.mysql_database);
	}
	if (cfgvalues.mysql_user) {
		free(cfgvalues.mysql_user);
	}
	if (cfgvalues.mysql_password) {
		free(cfgvalues.mysql_password);
	}
#endif
//	if (cfgvalues.fw1_logfile) {
//		free(cfgvalues.fw1_logfile);
//	}

	for (i=0 ; i < filtercount ; i++) {
		if (filterarray[i]) {
			free(filterarray[i]);
		}
	}

	while (sl) {
		sl = stringlist_delete(&sl);
	}

	exit (errorcode);
}

/*
 * initilization function to define open, submit and close handler
 */
void logging_init_env(int logging) {
	// Specifies which logging operation shall be executed.
	switch(logging)
	{
		case SCREEN :
			open_log        = &open_screen;
			submit_log      = &submit_screen;
			close_log       = &close_screen;
			break;
		case LOGFILE :
			open_log        = &open_logfile;
			submit_log      = &submit_logfile;
			close_log       = &close_logfile;
			break;
#ifndef WIN32
		case SYSLOG :
			open_log        = &open_syslog;
			submit_log      = &submit_syslog;
			close_log       = &close_syslog;
			break;
#endif
		default:
			open_log        = &open_screen;
			submit_log      = &submit_screen;
			close_log       = &close_screen;
			break;
	}
	return;
}

#ifndef WIN32
/*
 * syslog initializations
 */
void open_syslog(){
	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: Open connection to Syslog.\n");
	}
	openlog ("fw1-loggrabber", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
	return;
}

void submit_syslog(char* message) {
	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: Submit message to Syslog.\n");
	}
	syslog (LOG_NOTICE, message);
	return;
}

void close_syslog() {
	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: Close connection to Syslog.\n");
	}
	closelog ();
	return;
}
#endif

/*
 * screen initializations
 */
void open_screen(){
	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: Open connection to screen.\n");
	}
	//We don't need to do anything here
	return;
}

void submit_screen(char* message){
	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: Submit message to screen.\n");
	}
	fprintf(stdout, "%s\n",message);
	fflush(NULL);
	return;
}

void close_screen(){
	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: Close connection to screen.\n");
	}
	//We don't need to do anything here
	return;
}

/*
 * log file initializations
 */
void open_logfile(){

	char*	output_file_name;

	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: Initilize log file and open log file.\n");
	}

	//create current output filename
	output_file_name = (char *) malloc(strlen(cfgvalues.output_file_prefix) + 5);
	if (output_file_name == NULL) {
		fprintf(stderr, "ERROR: Out of memory\n");
		exit_loggrabber(1);
	}
	strcpy(output_file_name, cfgvalues.output_file_prefix);
	strcat(output_file_name, ".log");

	if ((logstream = fopen(output_file_name, "a+")) == NULL) {
		fprintf(stderr,"ERROR: Fail to open the log file.\n");
		exit_loggrabber(1);
	}

	return;
}

void submit_logfile(char* message){

	int i;
	long fsize;
	char sn[100];
	char* output_file_name;

	time_t time_date;
	struct tm *current_date;
	int month;                  // 1 through 12
	int day;                    // 1 through max_days
	int year;                   // 1500 through 2200
	int hour;                   // 0 through 23
	int minute;                 // 0 through 59
	int second;                 // 0 through 59

	if (cfgvalues.debug_mode) {
		fprintf(stderr, "DEBUG: Submit message to log file.\n");
	}


	fprintf(logstream, "%s\n",message);

	//Check and see if it reaches the log file limitation
	fseek(logstream, 0, SEEK_CUR);
	fsize = ftell(logstream);
	/* File size check and see whether or not it reaches maximum */
	if(fsize > cfgvalues.output_file_rotatesize){
		//The log file will be refreshed.
		fclose(logstream);
		time_date        = time(NULL);
		current_date = localtime(&time_date);
		month    = current_date->tm_mon + 1;
		day              = current_date->tm_mday;
		year     = current_date->tm_year + 1900;
		hour     = current_date->tm_hour;
		minute   = current_date->tm_min;
		second   = current_date->tm_sec;
		//create current output filename
		output_file_name = (char *) malloc(strlen(cfgvalues.output_file_prefix) + 5);
		strcpy(output_file_name, cfgvalues.output_file_prefix);
		strcat(output_file_name, ".log");
		//Copy log file
		sprintf(sn, "%s-%4.4d-%2.2d-%2.2d_%2.2d%2.2d%2.2d.log", cfgvalues.output_file_prefix,year,month,day,hour,minute,second);
		if(fileExist(sn)) {
			//Unfortunately, events come in too fast
			i=1;
			sprintf(sn, "%s-%4.4d-%2.2d-%2.2d_%2.2d%2.2d%2.2d_%d.log", cfgvalues.output_file_prefix,year,month,day,hour,minute,second,i);

			while(fileExist(sn)) {
				i++;
				sprintf(sn, "%s-%4.4d-%2.2d-%2.2d_%2.2d%2.2d%2.2d_%d.log", cfgvalues.output_file_prefix,year,month,day,hour,minute,second,i);
			}//end of while
		}//end of inner if
		fileCopy(output_file_name, sn);
		//Clean log file
		if ((logstream = fopen(output_file_name, "w")) == NULL) {;
			fprintf(stderr,"ERROR: Fail to open the log file.\n");
			exit_loggrabber(1);
		}//end of inner if
	}//end of if

	return;
}

void close_logfile(){

	if(cfgvalues.debug_mode) {
		fprintf(stderr,"DEBUG: Close the log file.\n");
	}
	fclose(logstream);

	return;
}

void fileCopy(const char *inputFile, const char *outputFile) {

	// The most recent character from input file to output file
	char x;

	// fpi points to the input file, fpo points to the output file
	FILE *fpi, *fpo;
	// Open input file, read-only
	fpi = fopen(inputFile, "r");
	// Open output file, write-only
	fpo = fopen(outputFile, "w");

	// Get next char from input file, store in x, until we reach EOF
	while((x=getc(fpi))!=-1)
	{
		putc(x, fpo);
	}

	//After we have done, close both files
	fclose(fpi);
	fclose(fpo);

	return;
}

int fileExist(const char * fileName)
{
	FILE * infile;

	infile = fopen (fileName, "r");
	if (infile == NULL)   {
		return FALSE;
	} else   {
		fclose (infile);
		return TRUE;
	}//end of if
}

