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

#include "fw1-loggrabber.h"

/*
 * main function
 */
int
main (int argc, char *argv[])
{
  int i;
  stringlist *lstptr;
  char *foundstring;
  char *field;

  /*
   * initialize field arrays
   */
  init_field_headers (field_headers);
  init_field_values (field_values);

  /* The default settings are shown as follows:
   * FW1_TYPE = NG release
   * Offline mode
   * Database is off
   * Print off log records
   */

  /*
   * process command line arguments
   */
  for (i = 1; i < argc; i++)
    {
      if (strcmp (argv[i], "--help") == 0)
        {
          usage (argv[0]);
          exit_loggrabber (1);
        }
      else if (strcmp (argv[i], "--resolve") == 0)
        {
          resolve_mode = 1;
        }
      else if ((strcmp (argv[i], "--noresolve") == 0)
               || (strcmp (argv[i], "--no-resolve") == 0))
        {
          resolve_mode = 0;
        }
      else if (strcmp (argv[i], "--debug-level") == 0)
        {
          i++;
          if (argv[i] == NULL)
            {
              fprintf (stderr, "ERROR: Invalid argument: %s\n", argv[i - 1]);
              usage (argv[0]);
              exit_loggrabber (1);
            }
          if (argv[i][0] == '-')
            {
              fprintf (stderr, "ERROR: Value expected for argument %s\n",
                       argv[i - 1]);
              usage (argv[0]);
              exit_loggrabber (1);
            }
          debug_mode = atoi (argv[i]);
        }
      else if (strcmp (argv[i], "--showfiles") == 0)
        {
          show_files = 1;
        }
      else if (strcmp (argv[i], "--showlogs") == 0)
        {
          show_files = 0;
        }
      else if (strcmp (argv[i], "--2000") == 0)
        {
          fw1_2000 = 1;
        }
      else if (strcmp (argv[i], "--ng") == 0)
        {
          fw1_2000 = 0;
        }
      else if (strcmp (argv[i], "--online") == 0)
        {
          online_mode = 1;
        }
      else if (strcmp (argv[i], "--no-online") == 0)
        {
          online_mode = 0;
        }
      else if (strcmp (argv[i], "--auditlog") == 0)
        {
          audit_log = 1;
        }
      else if (strcmp (argv[i], "--normallog") == 0)
        {
          audit_log = 0;
        }
      else if ((strcmp (argv[i], "-f") == 0)
               || (strcmp (argv[i], "--logfile") == 0))
        {
          i++;
          if (argv[i] == NULL)
            {
              fprintf (stderr, "ERROR: Invalid argument: %s\n", argv[i - 1]);
              usage (argv[0]);
              exit_loggrabber (1);
            }
          if (argv[i][0] == '-')
            {
              fprintf (stderr, "ERROR: Value expected for argument %s\n",
                       argv[i - 1]);
              usage (argv[0]);
              exit_loggrabber (1);
            }
          LogfileName = string_duplicate (argv[i]);
        }
      else if ((strcmp (argv[i], "-c") == 0)
               || (strcmp (argv[i], "--configfile") == 0))
        {
          i++;
          if (argv[i] == NULL)
            {
              fprintf (stderr, "ERROR: Invalid argument: %s\n", argv[i - 1]);
              usage (argv[0]);
              exit_loggrabber (1);
            }
          if (argv[i][0] == '-')
            {
              fprintf (stderr, "ERROR: Value expected for argument %s\n",
                       argv[i - 1]);
              usage (argv[0]);
              exit_loggrabber (1);
            }
          cfgvalues.config_filename = string_duplicate (argv[i]);
        }
      else if ((strcmp (argv[i], "-l") == 0)
               || (strcmp (argv[i], "--leaconfigfile") == 0))
        {
          i++;
          if (argv[i] == NULL)
            {
              fprintf (stderr, "ERROR: Invalid argument: %s\n", argv[i - 1]);
              usage (argv[0]);
              exit_loggrabber (1);
            }
          if (argv[i][0] == '-')
            {
              fprintf (stderr, "ERROR: Value expected for argument %s\n",
                       argv[i - 1]);
              usage (argv[0]);
              exit_loggrabber (1);
            }
          cfgvalues.leaconfig_filename = string_duplicate (argv[i]);
        }
      else if (strcmp (argv[i], "--filter") == 0)
        {
          i++;
          if (argv[i] == NULL)
            {
              fprintf (stderr, "ERROR: Invalid argument: %s\n", argv[i - 1]);
              usage (argv[0]);
              exit_loggrabber (1);
            }
          if (argv[i][0] == '-')
            {
              fprintf (stderr, "ERROR: Value expected for argument %s\n",
                       argv[i - 1]);
              usage (argv[0]);
              exit_loggrabber (1);
            }
          filtercount++;
          filterarray =
            (char **) realloc (filterarray, filtercount * sizeof (char *));
          if (filterarray == NULL)
            {
              fprintf (stderr, "ERROR: Out of memory\n");
              exit_loggrabber (1);
            }
          filterarray[filtercount - 1] = string_duplicate (argv[i]);
        }
      else if (strcmp (argv[i], "--ignore-fields") == 0)
        {
          i++;
          if (argv[i] == NULL)
            {
              fprintf (stderr, "ERROR: Invalid argument: %s\n", argv[i - 1]);
              usage (argv[0]);
              exit_loggrabber (1);
            }
          if (argv[i][0] == '-')
            {
              fprintf (stderr, "ERROR: Value expected for argument %s\n",
                       argv[i - 1]);
              usage (argv[0]);
              exit_loggrabber (1);
            }
          cfgvalues.ignore_fields = string_duplicate (argv[i]);
        }
      else
        {
          fprintf (stderr, "ERROR: Invalid argument: %s\n", argv[i]);
          usage (argv[0]);
          exit_loggrabber (1);
        }
    }

  /*
   * check configuration files
   */
  check_config_files (cfgvalues.config_filename,
                      cfgvalues.leaconfig_filename);
  /*
   * load configuration file
   */
  read_config_file (cfgvalues.config_filename, &cfgvalues);

  /*
   * check whether command line options override configfile options
   */
  cfgvalues.debug_mode =
    (debug_mode != -1) ? debug_mode : cfgvalues.debug_mode;
  cfgvalues.online_mode =
    (online_mode != -1) ? online_mode : cfgvalues.online_mode;
  cfgvalues.resolve_mode =
    (resolve_mode != -1) ? resolve_mode : cfgvalues.resolve_mode;
  cfgvalues.fw1_2000 = (fw1_2000 != -1) ? fw1_2000 : cfgvalues.fw1_2000;
  cfgvalues.showfiles_mode =
    (show_files != -1) ? show_files : cfgvalues.showfiles_mode;
  cfgvalues.audit_mode = (audit_log != -1) ? audit_log : cfgvalues.audit_mode;
  cfgvalues.fw1_logfile =
    (LogfileName !=
     NULL) ? string_duplicate (LogfileName) : cfgvalues.fw1_logfile;
  if (filtercount > 0)
    {
      cfgvalues.fw1_filter_count = filtercount;
      cfgvalues.fw1_filter_array = filterarray;
      cfgvalues.audit_filter_count = filtercount;
      cfgvalues.audit_filter_array = filterarray;
    }

  /*
   * free no more used char*
   */
  if (LogfileName != NULL)
    {
      free (LogfileName);
      LogfileName = NULL;
    }

  /*
   * if audit_mode set fw1_logfile to the correct setting
   */
  if (cfgvalues.audit_mode)
    {
      cfgvalues.fw1_logfile = string_duplicate ("fw.adtlog");
    }

  /*
   * perform validity check of given command line arguments
   */
  if (cfgvalues.fw1_2000)
    {
      if (cfgvalues.showfiles_mode)
        {
          fprintf (stderr,
                   "ERROR: --showfiles option is only available for connections\n"
                   "       to FW-1 NG. For connections to FW-1 4.1 (2000), please\n"
                   "       omit this parameter.\n");
          exit_loggrabber (1);
        }
      if ((cfgvalues.fw1_filter_count > 0)
          || (cfgvalues.audit_filter_count > 0))
        {
          fprintf (stderr,
                   "WARNING: --filter options are only available for connections\n"
                   "         to FW-1 NG. Available filterrules will be disabled!\n");
          cfgvalues.fw1_filter_count = 0;
          cfgvalues.audit_filter_count = 0;
        }
      if (cfgvalues.audit_mode)
        {
          fprintf (stderr,
                   "ERROR: --auditlog option is only available for connections\n"
                   "       to FW-1 NG. For connections to FW-1 4.1 (2000), please\n"
                   "       omit this parameter.\n");
          exit_loggrabber (1);
        }
    }

  if (cfgvalues.online_mode && (!(cfgvalues.audit_mode))
      && (strcmp (cfgvalues.fw1_logfile, "fw.log") != 0))
    {
      fprintf (stderr,
               "ERROR: -f <FILENAME> option is not available in online mode. For use with Audit-Logfile, use --auditlog\n");
      exit_loggrabber (1);
    }

  if (cfgvalues.online_mode && cfgvalues.showfiles_mode)
    {
      fprintf (stderr,
               "ERROR: --showfiles option is not available in online mode.\n");
      exit_loggrabber (1);
    }

  if (!(cfgvalues.audit_mode)
      && (strcmp (cfgvalues.fw1_logfile, "fw.adtlog") == 0))
    {
      fprintf (stderr,
               "ERROR: use --auditlog option to get data of fw.adtlog\n");
      exit_loggrabber (1);
    }

  // Process the ignore_fields string if it exists
  if (cfgvalues.ignore_fields)
    {
      ignore_fields = string_duplicate (cfgvalues.ignore_fields);
      field = strtok (ignore_fields, ";");
      while (field != NULL)
        {
          ignore_fields_count++;
          if (ignore_fields_count >= NUMBER_FIELDS)
            {
              break;
            }

          ignore_fields_array =
            (char **) realloc (ignore_fields_array, ignore_fields_count * sizeof (char *));
          if (ignore_fields_array == NULL)
            {
              fprintf (stderr, "ERROR: Out of memory\n");
              exit_loggrabber (1);
            }
          ignore_fields_array[ignore_fields_count - 1] = string_duplicate (field);
          field = strtok (NULL, ";");
        }
    }

/* A mutex object to provide safe manipulation of Check Point FW-1 event queue across multiple threads.  */
  pthread_mutex_init(&mutex, NULL);

  /*
   * set logging envionment
   */
  logging_init_env (cfgvalues.log_mode);

  open_log ();

  createThread(&threadid, leaRecordProcessor, NULL);

  /*
   * set opsec debug level
   */
  opsec_set_debug_level (cfgvalues.debug_mode);

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr, "DEBUG: Logfilename      : %s\n",
               cfgvalues.fw1_logfile);
      fprintf (stderr, "DEBUG: Record Separator : %c\n",
               cfgvalues.record_separator);
      fprintf (stderr, "DEBUG: Resolve Addresses: %s\n",
               (cfgvalues.resolve_mode ? "Yes" : "No"));
      fprintf (stderr, "DEBUG: Show Filenames   : %s\n",
               (cfgvalues.showfiles_mode ? "Yes" : "No"));
      fprintf (stderr, "DEBUG: FW1-2000         : %s\n",
               (cfgvalues.fw1_2000 ? "Yes" : "No"));
      fprintf (stderr, "DEBUG: Online-Mode      : %s\n",
               (cfgvalues.online_mode ? "Yes" : "No"));
      fprintf (stderr, "DEBUG: Audit-Log        : %s\n",
               (cfgvalues.audit_mode ? "Yes" : "No"));
    }

  /*
   * function call to get available Logfile-Names (not available in FW1-4.1)
   */
  if (!(cfgvalues.fw1_2000) && !(cfgvalues.online_mode))
    {
      get_fw1_logfiles ();
    }

  if (cfgvalues.showfiles_mode)
    {
      if ((cfgvalues.fw1_2000) || (cfgvalues.online_mode))
        {
          fprintf (stderr,
                   "ERROR: Option --showfiles is not supported for Checkpoint FW-1 2000 or in online mode.\n");
        }
      close_log ();
      exit_loggrabber (0);
    }

  /*
   * process all logfiles if ALL specified
   */
  if (strcmp (cfgvalues.fw1_logfile, "ALL") == 0)
    {
      lstptr = sl;

      while (lstptr)
        {
          if (cfgvalues.debug_mode)
            {
              fprintf (stderr, "DEBUG: Processing Logfile: %s\n",
                       lstptr->data);
            }
          read_fw1_logfile (&(lstptr->data));
          lstptr = lstptr->next;
        }
    }

  /*
   * else search for given string in available logfile-names
   */
  else
    {
      lstptr = stringlist_search (&sl, cfgvalues.fw1_logfile, &foundstring);

      /*
       * get the data from the matching logfiles
       */
      if (!lstptr)
        {
          if (cfgvalues.debug_mode)
            {
              fprintf (stderr, "DEBUG: Processing Logfile: %s\n",
                       cfgvalues.fw1_logfile);
            }
          read_fw1_logfile (&(cfgvalues.fw1_logfile));
        }
      while (lstptr)
        {
          if (cfgvalues.debug_mode)
            {
              fprintf (stderr, "DEBUG: Processing Logfile: %s\n",
                       foundstring);
            }
          read_fw1_logfile (&foundstring);
          lstptr =
            stringlist_search (&(lstptr->next), cfgvalues.fw1_logfile,
                               &foundstring);
        }
    }

  close_log ();

  exit_loggrabber (0);
  return (0);
}

/*
 * function read_fw1_logfile
 */
int
read_fw1_logfile (char **LogfileName)
{
  OpsecEntity *pClient = NULL;
  OpsecEntity *pServer = NULL;
  LeaFilterRulebase *rb;
  int rbid = 1;
  int i;

  char *auth_type;
  char *fw1_server;
  char *fw1_port;
  char *opsec_certificate;
  char *opsec_client_dn;
  char *opsec_server_dn;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function read_fw1_logfile\n");
    }

  keepAlive = TRUE;

  while (keepAlive)
    {
      /* create opsec environment for the main loop */
      if ((pEnv =
           opsec_init (OPSEC_CONF_FILE, cfgvalues.leaconfig_filename,
                       OPSEC_EOL)) == NULL)
        {
          fprintf (stderr, "ERROR: unable to create environment (%s)\n",
                   opsec_errno_str (opsec_errno));
          exit_loggrabber (1);
        }

      /* create user defined events */
      initent         = opsec_new_event_id();
      resumeent       = opsec_new_event_id();
      shutdownent     = opsec_new_event_id();

      /* trigger persistent INIT event */
      opsec_raise_event (pEnv, initent, (void *) 0);

      opsec_set_event_handler ( pEnv, initent, (void *) fc_handler, 0);
      opsec_set_event_handler ( pEnv, resumeent, (void *) fc_handler, 0);
      opsec_set_event_handler ( pEnv, shutdownent, (void *) fc_handler, 0);

      if (cfgvalues.debug_mode)
        {

          fprintf (stderr, "DEBUG: OPSEC LEA conf file is %s\n",
                   cfgvalues.leaconfig_filename);

          fw1_server = opsec_get_conf (pEnv, "lea_server", "ip", NULL);
          if (fw1_server == NULL)
            {
              fprintf (stderr,
                       "ERROR: The fw1 server ip address has not been set.\n");
              exit_loggrabber (1);
            }                        //end of if
          auth_type = opsec_get_conf (pEnv, "lea_server", "auth_type", NULL);
          if (auth_type != NULL)
            {
              //Authentication mode
              if (cfgvalues.fw1_2000)
                {
                  //V4.1.2
                  fw1_port =
                    opsec_get_conf (pEnv, "lea_server", "auth_port", NULL);
                  if (fw1_port == NULL)
                    {
                      fprintf (stderr,
                               "ERROR: The parameters about authentication mode have not been set.\n");
                      exit_loggrabber (1);
                    }
                  else
                    {
                      fprintf (stderr,
                               "DEBUG: Authentication mode has been used.\n");
                      fprintf (stderr, "DEBUG: Server-IP     : %s\n",
                               fw1_server);
                      fprintf (stderr, "DEBUG: Server-Port     : %s\n",
                               fw1_port);
                      fprintf (stderr, "DEBUG: Authentication type: %s\n",
                               auth_type);
                    }                //end of inner if
                }
              else
                {
                  //NG
                  fw1_port =
                    opsec_get_conf (pEnv, "lea_server", "auth_port", NULL);
                  opsec_certificate =
                    opsec_get_conf (pEnv, "opsec_sslca_file", NULL);
                  opsec_client_dn =
                    opsec_get_conf (pEnv, "opsec_sic_name", NULL);
                  opsec_server_dn =
                    opsec_get_conf (pEnv, "lea_server",
                                    "opsec_entity_sic_name", NULL);
                  if ((fw1_port == NULL) || (opsec_certificate == NULL)
                      || (opsec_client_dn == NULL)
                      || (opsec_server_dn == NULL))
                    {
                      fprintf (stderr,
                               "ERROR: The parameters about authentication mode have not been set.\n");
                      exit_loggrabber (1);
                    }
                  else
                    {
                      fprintf (stderr,
                               "DEBUG: Authentication mode has been used.\n");
                      fprintf (stderr, "DEBUG: Server-IP     : %s\n",
                               fw1_server);
                      fprintf (stderr, "DEBUG: Server-Port     : %s\n",
                               fw1_port);
                      fprintf (stderr, "DEBUG: Authentication type: %s\n",
                               auth_type);
                      fprintf (stderr,
                               "DEBUG: OPSEC sic certificate file name : %s\n",
                               opsec_certificate);
                      fprintf (stderr, "DEBUG: Server DN (sic name) : %s\n",
                               opsec_server_dn);
                      fprintf (stderr,
                               "DEBUG: OPSEC LEA client DN (sic name) : %s\n",
                               opsec_client_dn);
                    }            //end of inner if
                }
            }
          else
            {
              //Clear Text mode, i.e. non-auth mode
              fw1_port = opsec_get_conf (pEnv, "lea_server", "port", NULL);
              if (fw1_port != NULL)
                {
                  fprintf (stderr, "DEBUG: Clear text mode has been used.\n");
                  fprintf (stderr, "DEBUG: Server-IP        : %s\n",
                           fw1_server);
                  fprintf (stderr, "DEBUG: Server-Port      : %s\n",
                           fw1_port);
                }
              else
                {
                  fprintf (stderr,
                           "ERROR: The fw1 server lea service port has not been set.\n");
                  exit_loggrabber (1);
                }                //end of inner if
            }                    //end of middle if
        }                        //end of if

      /*
       * initialize opsec-client
       */
      pClient = opsec_init_entity (pEnv, LEA_CLIENT,
                                   LEA_RECORD_HANDLER,
                                   read_fw1_logfile_record,
                                   LEA_DICT_HANDLER, read_fw1_logfile_dict,
                                   LEA_EOF_HANDLER, read_fw1_logfile_eof,
                                   LEA_SWITCH_HANDLER,
                                   read_fw1_logfile_switch,
                                   LEA_FILTER_QUERY_ACK,
                                   ((cfgvalues.
                                     audit_mode) ? ((cfgvalues.
                                                     audit_filter_count >
                                                     0) ?
                                                    read_fw1_logfile_queryack
                                                    : NULL) : ((cfgvalues.
                                                                fw1_filter_count
                                                                >
                                                                0) ?
                                                               read_fw1_logfile_queryack
                                                               : NULL)),
                                   LEA_COL_LOGS_HANDLER,
                                   read_fw1_logfile_collogs,
                                   LEA_SUSPEND_HANDLER,
                                   read_fw1_logfile_suspend,
                                   LEA_RESUME_HANDLER,
                                   read_fw1_logfile_resume,
                                   OPSEC_SESSION_START_HANDLER,
                                   read_fw1_logfile_start,
                                   OPSEC_SESSION_END_HANDLER,
                                   read_fw1_logfile_end,
                                   OPSEC_SESSION_ESTABLISHED_HANDLER,
                                   read_fw1_logfile_established, OPSEC_EOL);

      /*
       * initialize opsec-server for authenticated and unauthenticated connections
       */

      pServer =
        opsec_init_entity (pEnv, LEA_SERVER, OPSEC_ENTITY_NAME, "lea_server",
                           OPSEC_EOL);

      /*
       * continue only if opsec initializations were successful
       */
      if ((!pClient) || (!pServer))
        {
          fprintf (stderr,
                   "ERROR: failed to initialize client/server-pair (%s)\n",
                   opsec_errno_str (opsec_errno));
          cleanup_fw1_environment (pEnv, pClient, pServer);
          exit_loggrabber (1);
        }

      /*
       * create LEA-session. differs for connections to FW-1 4.1 and FW-1 NG
       */
      if (cfgvalues.fw1_2000)
        {
          if (cfgvalues.online_mode)
            {
              pSession =
                lea_new_session (pClient, pServer, LEA_ONLINE, LEA_FILENAME,
                                 *LogfileName, LEA_AT_END);
            }
          else
            {
              pSession =
                lea_new_session (pClient, pServer, LEA_OFFLINE, LEA_FILENAME,
                                 *LogfileName, LEA_AT_START);
            }
          if (!pSession)
            {
              fprintf (stderr, "ERROR: failed to create session (%s)\n",
                       opsec_errno_str (opsec_errno));
              cleanup_fw1_environment (pEnv, pClient, pServer);
              exit_loggrabber (1);
            }
        }
      else
        {
          /*
           * create a suspended session, i.e. not log data will be sent to client
           */
          if (cfgvalues.online_mode)
            {
              pSession =
                lea_new_suspended_session (pClient, pServer, LEA_ONLINE,
                                           LEA_UNIFIED_SINGLE, *LogfileName,
                                           LEA_AT_END);
            }
          else
            {
              pSession =
                lea_new_suspended_session (pClient, pServer, LEA_OFFLINE,
                                           LEA_UNIFIED_SINGLE, *LogfileName,
                                           LEA_AT_START);
            }
          if (!pSession)
            {
              fprintf (stderr, "ERROR: failed to create session (%s)\n",
                       opsec_errno_str (opsec_errno));
              cleanup_fw1_environment (pEnv, pClient, pServer);
              exit_loggrabber (1);
            }

          /*
           * If filters were defined, create the rulebase and register it.
           * the session will be resumed, as soon as the server sends the
           * filter_ack-event.
           * In the case when no filters are used, the suspended session
           * will be continued immediately.
           */
          if (cfgvalues.audit_mode)
            {
              if (cfgvalues.audit_filter_count > 0)
                {
                  if ((rb = lea_filter_rulebase_create ()) == NULL)
                    {
                      fprintf (stderr, "ERROR: failed to create rulebase\n");
                      exit_loggrabber (1);
                    }

                  for (i = 0; i < cfgvalues.audit_filter_count; i++)
                    {
                      if ((rb =
                           create_audit_filter_rule (rb,
                                                     cfgvalues.
                                                     audit_filter_array[i]))
                          == NULL)
                        {
                          fprintf (stderr, "ERROR: failed to create rule\n");
                          exit_loggrabber (1);
                        }
                    }

                  if (lea_filter_rulebase_register (pSession, rb, &rbid) ==
                      LEA_FILTER_ERR)
                    {
                      fprintf (stderr, "ERROR: Cannot register rulebase\n");
                    }
                }
              else
                {
                  lea_session_resume (pSession);
                }
            }
          else
            {
              if (cfgvalues.fw1_filter_count > 0)
                {
                  if ((rb = lea_filter_rulebase_create ()) == NULL)
                    {
                      fprintf (stderr, "ERROR: failed to create rulebase\n");
                      exit_loggrabber (1);
                    }

                  for (i = 0; i < cfgvalues.fw1_filter_count; i++)
                    {
                      if ((rb =
                           create_fw1_filter_rule (rb,
                                                     cfgvalues.
                                                     fw1_filter_array[i])) ==
                          NULL)
                        {
                          fprintf (stderr, "ERROR: failed to create rule\n");
                          exit_loggrabber (1);
                        }
                    }

                  if (lea_filter_rulebase_register (pSession, rb, &rbid) ==
                      LEA_FILTER_ERR)
                    {
                      fprintf (stderr, "ERROR: Cannot register rulebase\n");
                    }
                }
              else
                {
                  lea_session_resume (pSession);
                }
            }
        }

      opsec_start_keep_alive (pSession, 0);

      /*
       * start the opsec loop
       */
      opsec_mainloop (pEnv);

      /*
       * remove opsec stuff
       */
      cleanup_fw1_environment (pEnv, pClient, pServer);

      if (keepAlive)
        {
          SLEEP (recoverInterval);
        }
    }

  return 0;
}

/*
 * function read_fw1_logfile_queryack
 */
int
read_fw1_logfile_queryack (OpsecSession * psession, int filterID,
                           eLeaFilterAction filterAction, int filterResult)
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function read_fw1_logfile_queryack\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr, "DEBUG: LEA logfile query ack handler was invoked\n");
    }
  lea_session_resume (psession);
  return OPSEC_SESSION_OK;
}

/*
 * function string_cat
 */
unsigned int
string_cat (char **dst, const char *src, unsigned int cap)
{
  char *buffer = NULL;
  unsigned int capacity = cap;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function string_cat\n");
    }

  // allocate memory for the string if NULL
  if (*dst == NULL)
    {
      *dst = (char *) malloc (INITIAL_CAPACITY + 1);
      if (*dst == NULL)
        {
          fprintf (stderr, "ERROR: Out of memory\n");
          exit_loggrabber (1);
        }
      **dst = '\0';
      capacity = INITIAL_CAPACITY;
    }

  // is src NULL, just return the capacity of dst
  if (!src)
    {
      return (capacity);
    }

  // is the capacity big enough for both src and dst?
  if (capacity >= strlen (*dst) + strlen (src))
    {
      strcat (*dst, src);
      return (capacity);
    }

  // otherwise define the new capacity
  capacity =
    ((capacity + CAPACITY_INCREMENT) >=
     (strlen (*dst) + strlen (src))) ? (capacity +
                                        CAPACITY_INCREMENT) : (strlen (*dst) +
                                                               strlen (src));

  // and allocate a temp buffer for dst
  buffer = (char *) malloc (strlen (*dst) + 1);
  if (!buffer)
    {
      fprintf (stderr, "ERROR: Out of memory\n");
      exit_loggrabber (1);
    }

  // copy dst to the tempbuffer and destroy dst
  strcpy (buffer, *dst);
  free (*dst);

  // recreate dst with the new capacity
  *dst = (char *) malloc (capacity + 1);
  if (*dst == NULL)
    {
      fprintf (stderr, "ERROR: Out of memory\n");
      exit_loggrabber (1);
    }

  // finally copy buffered dst and src back to dest and destroy temp buffer
  strcpy (*dst, buffer);
  free (buffer);
  strcat (*dst, src);

  // retrung new capacity
  return (capacity);
}

/*
 * function read_fw1_logfile_record
 */
int
read_fw1_logfile_record (OpsecSession * pSession, lea_record * pRec,
                         int pnAttribPerm[])
{
  char *szAttrib;
  int i;
  unsigned long ul;
  unsigned short us;
  char tmpdata[21];
  char *tmpstr1;
  char *tmpstr2;
  short first = TRUE;
  char *message = NULL;
  char *mymsg = NULL;
  int number_fields;
  short ignore;
  unsigned int messagecap = 0;
  time_t logtime;
  struct tm *datetime;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function read_fw1_logfile_record\n");
    }

  /*
   * process all fields of logentry
   */
  number_fields = pRec->n_fields;
  for (i = 0; i < number_fields; i++)
    {
      ignore = FALSE;
      strcpy (tmpdata, "\0");

      /*
       * Compare the field attribute id with the list of ignored fields.
       * If the IDs match, then skip over processing this field.
       */
      if (ignore_attr_id_count)
        {
          ignore = find_in_int_array(ignore_attr_id_array, ignore_attr_id_count, pRec->fields[i].lea_attr_id);

          if (ignore)
            {
              continue;
            }
        }

      if (!(cfgvalues.resolve_mode))
        {
          switch (pRec->fields[i].lea_val_type)
            {
              /*
               * create dotted string of IP address. this differs between
               * Linux and Solaris.
               */
            case LEA_VT_IP_ADDR:
              ul = pRec->fields[i].lea_value.ul_value;
              if (BYTE_ORDER == LITTLE_ENDIAN)
                {
                  sprintf (tmpdata, "%d.%d.%d.%d",
                           (int) ((ul & 0xff) >> 0),
                           (int) ((ul & 0xff00) >> 8),
                           (int) ((ul & 0xff0000) >> 16),
                           (int) ((ul & 0xff000000) >> 24));
                }
              else
                {
                  sprintf (tmpdata, "%d.%d.%d.%d",
                           (int) ((ul & 0xff000000) >> 24),
                           (int) ((ul & 0xff0000) >> 16),
                           (int) ((ul & 0xff00) >> 8),
                           (int) ((ul & 0xff) >> 0));
                }
              break;

              /*
               * print out the port number of the used service
               */
            case LEA_VT_TCP_PORT:
            case LEA_VT_UDP_PORT:
              us = pRec->fields[i].lea_value.ush_value;
              if (BYTE_ORDER == LITTLE_ENDIAN)
                {
                  us = (us >> 8) + ((us & 0xff) << 8);
                }
              sprintf (tmpdata, "%d", us);
              break;
            }
        }

      /*
       * Check if the current field is the 'time' field based
       * on its lea_attr_id value
       */
      if (time_attr_id == pRec->fields[i].lea_attr_id)
        {
          switch (cfgvalues.dateformat)
            {
              case DATETIME_CP:
                break;
              case DATETIME_UNIX:
                sprintf (tmpdata, "%lu",
                     (long unsigned int) pRec->fields[i].lea_value.ul_value);
                break;
              case DATETIME_STD:
                logtime = (time_t) pRec->fields[i].lea_value.ul_value;
                datetime = localtime (&logtime);
                strftime (tmpdata, 20, "%Y-%m-%d %H:%M:%S", datetime);
                break;
              default:
                fprintf (stderr, "ERROR: Unsupported dateformat chosen\n");
                exit_loggrabber (1);
            }
        }

      szAttrib = lea_attr_name (pSession, pRec->fields[i].lea_attr_id);

      *field_headers[i] = string_duplicate (szAttrib);

      if (tmpdata[0])
        {
          *field_values[i] = string_duplicate (tmpdata);
        }
      else
        {
          *field_values[i] =
            string_duplicate (lea_resolve_field
                              (pSession, pRec->fields[i]));
        }
    }

  /*
   * print logentry to stdout
   */
  for (i = 0; i < number_fields; i++)
    {
      if (*field_values[i])
        {
          tmpstr1 =
            string_escape (*field_headers[i],
                           cfgvalues.record_separator);
          tmpstr2 =
            string_escape (*field_values[i],
                           cfgvalues.record_separator);
          if (first)
            {
              sprintf (stringnumber, "%s=%s", tmpstr1, tmpstr2);
              first = FALSE;
            }
          else
            {
              sprintf (stringnumber, "%c%s=%s",
                       cfgvalues.record_separator, tmpstr1, tmpstr2);
            }

          messagecap =
            string_cat (&message, stringnumber, messagecap);

          free (tmpstr1);
          free (tmpstr2);
        }
    }

  // empty string fields
  for (i = 0; i < number_fields; i++)
    {
      if (*field_headers[i] != NULL)
        {
          free (*field_headers[i]);
          *field_headers[i] = NULL;
        }

      if (*field_values[i] != NULL)
        {
          free (*field_values[i]);
          *field_values[i] = NULL;
        }
    }

  if ((message != NULL) && (strlen (message) > 0))
    {
      mymsg = string_mask_newlines (message);
      free (message);

      pthread_mutex_lock(&mutex);
      //enter critical section
      add(mymsg);
      pthread_mutex_unlock(&mutex);
      //end critical section
      if (!(cfgvalues.fw1_2000))
        {
          if(isFull())
            {
              lea_session_suspend(pSession);
              suspended = TRUE;
            }
        }
    }

  return OPSEC_SESSION_OK;
}

/*
 * function read_fw1_logfile_dict
 */
int
read_fw1_logfile_dict (OpsecSession * psession, int dict_id, LEA_VT val_type,
                       int n_d_entries)
{
  lea_value_t d_value;
  int i;
  int x;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function read_fw1_logfile_dict\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr, "DEBUG: LEA logfile dict handler was invoked\n");
    }

  if (dict_id == LEA_ATTRIB_ID)
    {
      i = 0;

      if (cfgvalues.debug_mode)
        {
          fprintf (stderr, "DEBUG: Checking attribute id for time\n");
        }
      if ((lea_reverse_dictionary_lookup(psession, LEA_ATTRIB_ID, "time",
                                         &d_value)) != LEA_NOT_FOUND)
        {
          if (cfgvalues.debug_mode)
            {
              fprintf (stderr, "DEBUG: Got attribute id %i\n", d_value.i_value);
            }
          time_attr_id = d_value.i_value;
        }
      else
        {
          if (cfgvalues.debug_mode)
            {
              fprintf (stderr, "DEBUG: No attribute id found\n");
            }
          time_attr_id = -1;
        }

      for (x = 0; x < ignore_fields_count; x++)
        {
          if (cfgvalues.debug_mode)
            {
              fprintf (stderr, "DEBUG: Checking attribute id for %s\n", ignore_fields_array[x]);
            }
          if ((lea_reverse_dictionary_lookup(psession, LEA_ATTRIB_ID, ignore_fields_array[x],
                                             &d_value)) != LEA_NOT_FOUND)
            {
              if (cfgvalues.debug_mode)
                {
                  fprintf (stderr, "DEBUG: Got attribute id %i\n", d_value.i_value);
                }
              ignore_attr_id_array[i] = d_value.i_value;
              i++;
            }
          else
            {
              if (cfgvalues.debug_mode)
                {
                  fprintf (stderr, "DEBUG: No attribute id found\n");
                }
            }
        }

      if (i)
        {
          ignore_attr_id_count = i;

          // sorting the array allows faster value lookups in O(log n) time
          qsort(ignore_attr_id_array, ignore_attr_id_count, sizeof(int), integer_cmp);
        }
    }

  return OPSEC_SESSION_OK;
}

/*
 * function read_fw1_logfile_eof
 */
int
read_fw1_logfile_eof (OpsecSession * psession)
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function read_fw1_logfile_eof\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr, "DEBUG: LEA end of logfile handler was invoked\n");
    }
  return OPSEC_SESSION_OK;
}

/*
 * function read_fw1_logfile_switch
 */
int
read_fw1_logfile_switch (OpsecSession * psession)
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function read_fw1_logfile_switch\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr, "DEBUG: LEA logfile switch handler was invoked\n");
    }
  return OPSEC_SESSION_OK;
}

/*
 * function read_fw1_logfile_collogs
 */
int
read_fw1_logfile_collogs (OpsecSession * psession)
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function read_fw1_logfile_collogs\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr, "DEBUG: LEA collected logfile handler was invoked\n");
    }
  return OPSEC_SESSION_OK;
}

/*
 * function read_fw1_logfile_suspend
 */
int
read_fw1_logfile_suspend (OpsecSession * psession)
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function read_fw1_logfile_suspend\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr, "DEBUG: LEA suspended session handler was invoked\n");
    }
  return OPSEC_SESSION_OK;
}

/*
 * function read_fw1_logfile_resume
 */
int
read_fw1_logfile_resume (OpsecSession * psession)
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function read_fw1_logfile_resume\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr, "DEBUG: LEA resumed session handler was invoked\n");
    }
  return OPSEC_SESSION_OK;
}

/*
 * function get_fw1_logfiles_end
 */
int
get_fw1_logfiles_end (OpsecSession * psession)
{
        int end_reason = 0;
        int sic_errno = 0;
        char *sic_errmsg = NULL;

        if (cfgvalues.debug_mode >= 2) {
                fprintf (stderr, "DEBUG: function get_fw1_logfiles_end\n");
        }

        if (cfgvalues.debug_mode) {
                fprintf (stderr, "DEBUG: OPSEC_SESSION_END_HANDLER called\n");
        }

        // Check what is the reason of opsec session end
        end_reason = opsec_session_end_reason (psession);
        switch (end_reason) {
                case END_BY_APPLICATION:
                case SESSION_TIMEOUT:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "DEBUG: The session has been ended.\n");
                        }
                        break;
                case SESSION_NOT_ENDED:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "WARNING: The session has not been terminated.\n");
                        }
                        break;
                case UNABLE_TO_ATTACH_COMM:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "ERROR: Failed to establish connection.\n");
                        }
                        break;
                case ENTITY_TYPE_SESSION_INIT_FAIL:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "ERROR: OPSEC API-specific library code on other side of connection failed when attempting to initialize the session.\n");
                        }
                        break;
                case ENTITY_SESSION_INIT_FAIL:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "ERROR: Third-party start handler on other side of connection failed.\n");
                        }
                        break;
                case COMM_FAILURE:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "ERROR: Communication failure.\n");
                        }
                        break;
                case BAD_VERSION:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "ERROR: Incorrect version at other side.\n");
                        }
                        break;
                case PEER_SEND_DROP:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "ERROR: The peer dropped the connection.\n");
                        }
                        break;
                case PEER_ENDED:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "ERROR: The peer ends.\n");
                        }
                        break;
                case PEER_SEND_RESET:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "ERROR: The peer reset the connection.\n");
                        }
                        break;
                case COMM_IS_DEAD:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "ERROR: No communication.\n");
                        }
                        break;
                case SIC_FAILURE:
                        if (!opsec_get_sic_error (psession, &sic_errno, &sic_errmsg)) {
                                if (cfgvalues.debug_mode) {
                                        fprintf (stderr, "ERROR: SIC ERROR %d - %s\n", sic_errno, sic_errmsg);
                                }
                        }
                        break;
                default:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "Warning: Unknown reason of session end.\n");
                        }
                        break;
        }                                //end of switch

        opsec_del_event_handler (pEnv, initent, (void *) fc_handler, 0);
        opsec_del_event_handler (pEnv, resumeent, (void *) fc_handler, 0);
        opsec_del_event_handler (pEnv, shutdownent, (void *) fc_handler, 0);

        return OPSEC_SESSION_OK;

}

/*
 * function fc_handler
 */
int fc_handler (OpsecEnv *pEnv, long eventid, void *raise_data, void *set_data) {

        if (eventid == initent) {
                /* init event */
                if (cfgvalues.debug_mode) {
                        fprintf (stderr, "Info: User defined event has been initialized.\n");
                }
                return 0;
        }

        if (eventid == resumeent) {
                /* resume event*/
                if (cfgvalues.debug_mode) {
                        fprintf (stderr, "Info: Resume event has been received.\n");
                }

                if(pSession!=NULL) {
                        lea_session_resume(pSession);
                }
                return 0;
        }

        if (eventid == shutdownent) {
                /* shut down event */
                if (cfgvalues.debug_mode) {
                        fprintf (stderr, "Info: Shutdown event has been received.\n");
                }
                opsec_del_event_handler (pEnv, initent, (void *) fc_handler, 0);
                opsec_del_event_handler (pEnv, resumeent, (void *) fc_handler, 0);
                opsec_del_event_handler (pEnv, shutdownent, (void *) fc_handler, 0);

                if(pSession!=NULL) {
                        opsec_end_session(pSession);
                }

                return 0;
        }

        return 0;
}

/*
 * function read_fw1_logfile_end
 */
int
read_fw1_logfile_end (OpsecSession * psession)
{
        int end_reason = 0;
        int sic_errno = 0;
        char *sic_errmsg = NULL;

        if (cfgvalues.debug_mode >= 2) {
                fprintf (stderr, "DEBUG: function read_fw1_logfile_end\n");
        }

        if (cfgvalues.debug_mode) {
                fprintf (stderr, "DEBUG: OPSEC_SESSION_END_HANDLER called\n");
        }

        // Check what is the reason of opsec session end
        end_reason = opsec_session_end_reason (psession);
        switch (end_reason) {
                case END_BY_APPLICATION:
                case SESSION_TIMEOUT:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "DEBUG: The session has been ended.\n");
                        }
                        keepAlive = FALSE;
                        break;
                case SESSION_NOT_ENDED:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "WARNING: The session has not been terminated.\n");
                        }
                        keepAlive = FALSE;
                        break;
                case UNABLE_TO_ATTACH_COMM:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "ERROR: Failed to establish connection.\n");
                        }
                        if (established) {
                                keepAlive = TRUE;
                        } else {
                                keepAlive = FALSE;
                        };
                        break;
                case ENTITY_TYPE_SESSION_INIT_FAIL:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "ERROR: OPSEC API-specific library code on other side of connection failed when attempting to initialize the session.\n");
                        }
                        keepAlive = FALSE;
                        break;
                case ENTITY_SESSION_INIT_FAIL:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "ERROR: Third-party start handler on other side of connection failed.\n");
                        }
                        keepAlive = FALSE;
                        break;
                case COMM_FAILURE:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "ERROR: Communication failure.\n");
                        }
                        if (established) {
                                keepAlive = TRUE;
                        } else {
                                keepAlive = FALSE;
                        };
                        break;
                case BAD_VERSION:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "ERROR: Incorrect version at other side.\n");
                        }
                        keepAlive = FALSE;
                        break;
                case PEER_SEND_DROP:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "ERROR: The peer dropped the connection.\n");
                        }
                        if (established) {
                                keepAlive = TRUE;
                        } else {
                                keepAlive = FALSE;
                        };
                        break;
                case PEER_ENDED:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "ERROR: The peer ends.\n");
                        }
                        keepAlive = FALSE;
                        break;
                case PEER_SEND_RESET:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "ERROR: The peer reset the connection.\n");
                        }
                        if (established) {
                                keepAlive = TRUE;
                        } else {
                                keepAlive = FALSE;
                        };
                        break;
                case COMM_IS_DEAD:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "ERROR: No communication.\n");
                        }
                        if (established) {
                                keepAlive = TRUE;
                        } else {
                                keepAlive = FALSE;
                        };
                        break;
                case SIC_FAILURE:
                        if (!opsec_get_sic_error (psession, &sic_errno, &sic_errmsg)) {
                                if (cfgvalues.debug_mode) {
                                        fprintf (stderr, "ERROR: SIC ERROR %d - %s\n", sic_errno, sic_errmsg);
                                }
                        }
                        keepAlive = FALSE;
                        break;
                default:
                        if (cfgvalues.debug_mode) {
                                fprintf (stderr, "Warning: Unknown reason of session end.\n");
                        }
                        keepAlive = FALSE;
                        break;
        } //end of switch

        opsec_del_event_handler (pEnv, initent, (void *) fc_handler, 0);
        opsec_del_event_handler (pEnv, resumeent, (void *) fc_handler, 0);
        opsec_del_event_handler (pEnv, shutdownent, (void *) fc_handler, 0);

        return OPSEC_SESSION_OK;

}

/*
 * function read_fw1_logfile_start
 */
int
read_fw1_logfile_start (OpsecSession * psession)
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function read_fw1_logfile_start\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr, "DEBUG: OPSEC session start handler was invoked\n");
    }
  return OPSEC_SESSION_OK;
}

/*
 * function read_fw1_logfile_established
 */
int
read_fw1_logfile_established (OpsecSession * psession)
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function read_fw1_logfile_established\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr,
               "DEBUG: OPSEC session established handler was invoked\n");
    }
  established = TRUE;
  return OPSEC_SESSION_OK;
}

/*
 * function read_fw1_logfile_failedconn
 */
int
read_fw1_logfile_failedconn (OpsecEntity * entity, long peer_ip,
                             int sic_errno, char *sic_errmsg)
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function read_fw1_logfile_failedconn\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr,
               "DEBUG: OPSEC failed connection handler was invoked\n");
    }
  return OPSEC_SESSION_OK;
}

/*
 * function get_fw1_logfiles
 */
int
get_fw1_logfiles ()
{
  OpsecEntity *pClient = NULL;
  OpsecEntity *pServer = NULL;
  //OpsecSession *pSession = NULL;
  //OpsecEnv *pEnv = NULL;

  char *auth_type;
  char *fw1_server;
  char *fw1_port;
  char *opsec_certificate;
  char *opsec_client_dn;
  char *opsec_server_dn;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function get_fw1_logfiles\n");
    }

  /* create opsec environment for the main loop */
  if ((pEnv =
       opsec_init (OPSEC_CONF_FILE, cfgvalues.leaconfig_filename,
                   OPSEC_EOL)) == NULL)
    {
      fprintf (stderr, "ERROR: unable to create environment (%s)\n",
               opsec_errno_str (opsec_errno));
      exit_loggrabber (1);
    }

  if (cfgvalues.debug_mode)
    {

      fprintf (stderr, "DEBUG: OPSEC LEA conf file is %s\n",
               cfgvalues.leaconfig_filename);

      fw1_server = opsec_get_conf (pEnv, "lea_server", "ip", NULL);
      if (fw1_server == NULL)
        {
          fprintf (stderr,
                   "ERROR: The fw1 server ip address has not been set.\n");
          exit_loggrabber (1);
        }                        //end of if
      auth_type = opsec_get_conf (pEnv, "lea_server", "auth_type", NULL);
      if (auth_type != NULL)
        {
          //Authentication mode
          fw1_port = opsec_get_conf (pEnv, "lea_server", "auth_port", NULL);
          opsec_certificate = opsec_get_conf (pEnv, "opsec_sslca_file", NULL);
          opsec_client_dn = opsec_get_conf (pEnv, "opsec_sic_name", NULL);
          opsec_server_dn =
            opsec_get_conf (pEnv, "lea_server", "opsec_entity_sic_name",
                            NULL);
          if ((fw1_port == NULL) || (opsec_certificate == NULL)
              || (opsec_client_dn == NULL) || (opsec_server_dn == NULL))
            {
              fprintf (stderr,
                       "ERROR: The parameters about authentication mode have not been set.\n");
              exit_loggrabber (1);
            }
          else
            {
              fprintf (stderr, "DEBUG: Authentication mode has been used.\n");
              fprintf (stderr, "DEBUG: Server-IP     : %s\n", fw1_server);
              fprintf (stderr, "DEBUG: Server-Port     : %s\n", fw1_port);
              fprintf (stderr, "DEBUG: Authentication type: %s\n", auth_type);
              fprintf (stderr,
                       "DEBUG: OPSEC sic certificate file name : %s\n",
                       opsec_certificate);
              fprintf (stderr, "DEBUG: Server DN (sic name) : %s\n",
                       opsec_server_dn);
              fprintf (stderr, "DEBUG: OPSEC LEA client DN (sic name) : %s\n",
                       opsec_client_dn);
            }                        //end of inner if
        }
      else
        {
          //Clear Text mode, i.e. non-auth mode
          fw1_port = opsec_get_conf (pEnv, "lea_server", "port", NULL);
          if (fw1_port != NULL)
            {
              fprintf (stderr, "DEBUG: Clear text mode has been used.\n");
              fprintf (stderr, "DEBUG: Server-IP        : %s\n", fw1_server);
              fprintf (stderr, "DEBUG: Server-Port      : %s\n", fw1_port);
            }
          else
            {
              fprintf (stderr,
                       "ERROR: The fw1 server lea service port has not been set.\n");
              exit_loggrabber (1);
            }                        //end of inner if
        }                        //end of middle if
    }                                //end of if


  /*
   * initialize opsec-client
   */
  pClient = opsec_init_entity (pEnv, LEA_CLIENT,
                               LEA_DICT_HANDLER, get_fw1_logfiles_dict,
                               OPSEC_SESSION_END_HANDLER,
                               get_fw1_logfiles_end, OPSEC_EOL);

  /*
   * initialize opsec-server for authenticated and unauthenticated connections
   */
  pServer =
    opsec_init_entity (pEnv, LEA_SERVER, OPSEC_ENTITY_NAME, "lea_server",
                       OPSEC_EOL);

  /*
   * continue only if opsec initializations were successful
   */
  if ((!pClient) || (!pServer))
    {
      fprintf (stderr,
               "ERROR: failed to initialize client/server-pair (%s)\n",
               opsec_errno_str (opsec_errno));
      cleanup_fw1_environment (pEnv, pClient, pServer);
      exit_loggrabber (1);
    }

  /*
   * create LEA-session
   */
  if (!
      (pSession =
       lea_new_session (pClient, pServer, LEA_OFFLINE, LEA_FILENAME,
                        LEA_NORMAL, LEA_AT_START)))
    {
      fprintf (stderr, "ERROR: failed to create session (%s)\n",
               opsec_errno_str (opsec_errno));
      cleanup_fw1_environment (pEnv, pClient, pServer);
      exit_loggrabber (1);
    }

  opsec_start_keep_alive (pSession, 0);

  /*
   * start the opsec loop
   */
  opsec_mainloop (pEnv);

  /*
   * remove opsec stuff
   */
  cleanup_fw1_environment (pEnv, pClient, pServer);

  return 0;
}

/*
 * function get_fw1_logfiles_dict
 */
int
get_fw1_logfiles_dict (OpsecSession * pSession, int nDictId, LEA_VT nValType,
                       int nEntries)
{
  int learesult = 0;
  int nID = 0;
  int aID = 0;
  char *logfile = NULL;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function get_fw1_logfiles_dict\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr, "DEBUG: Available FW-1 Logfiles\n");
    }

  if (cfgvalues.showfiles_mode)
    {
      fprintf (stderr, "Available FW-1 Logfiles\n");
    }

  /*
   * get names of available logfiles and create list of these names
   */
  learesult = lea_get_first_file_info (pSession, &logfile, &nID, &aID);
  while (learesult == 0)
    {
      if (cfgvalues.debug_mode)
        {
          fprintf (stderr, "DEBUG: - %s\n", logfile);
        }
      if (cfgvalues.showfiles_mode)
        {
          fprintf (stderr, "- %s\n", logfile);
        }
      stringlist_append (&sl, logfile);
      learesult = lea_get_next_file_info (pSession, &logfile, &nID, &aID);
    }

  /*
   * end opsec-session
   */
  opsec_end_session (pSession);

  return OPSEC_SESSION_OK;
}

/*
 * function cleanup_fw1_environment
 */
void
cleanup_fw1_environment (OpsecEnv * env, OpsecEntity * client,
                         OpsecEntity * server)
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function cleanup_fw1_environment\n");
    }

  if (client)
    opsec_destroy_entity (client);
  if (server)
    opsec_destroy_entity (server);
  if (env)
    opsec_env_destroy (env);
}

/*
 * function usage
 */
void
usage (char *szProgName)
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function usage\n");
    }

  fprintf (stderr, "\nFW1-LogGrabber v%s\n", VERSION);
  fprintf (stderr, "    Copyright (c) 2003-2005 Torsten Fellhauer, Xiaodong Lin\n");
  fprintf (stderr, "    Copyright (c) 2014-2016 CERTEGO s.r.l.\n\n");
  fprintf (stderr, "Usage:\n");
  fprintf (stderr, " %s [ options ]\n", szProgName);
  fprintf (stderr,
           "  -c|--configfile <file>     : Name of Configfile (default: fw1-loggrabber.conf)\n");
  fprintf (stderr,
           "  -l|--leaconfigfile <file>  : Name of Leaconfigfile (default: lea.conf)\n");
  fprintf (stderr,
           "  -f|--logfile Logfile|ALL   : Name of Logfile (default: fw.log)\n");
  fprintf (stderr,
           "  --resolve|--no-resolve     : Resolve Port Numbers and IP-Addresses (Default: Resolve)\n");
  fprintf (stderr,
           "  --showfiles|--showlogs     : Show only Filenames of all available FW-1 Logfiles (default: showlogs)\n");
  fprintf (stderr,
           "  --2000|--ng                : Connect to a CP FW-1 4.1 (2000) (default is ng)\n");
  fprintf (stderr,
           "  --filter \"...\"             : Specify filters to be applied\n");
  fprintf (stderr,
           "  --ignore-fields \"...\"      : Specify ; separated list of field names to not output to the log\n");
  fprintf (stderr,
           "  --online|--no-online       : Enable Online mode (default: no-online)\n");
  fprintf (stderr,
           "  --auditlog|--normallog     : Get data of audit-logfile (fw.adtlog)(default: normallog)\n");
  fprintf (stderr,
           "  --debug-level <level>      : Specify Debuglevel (default: 0 - no debugging)\n");
  fprintf (stderr,
           "  --help                     : Show usage information\n");
}

/*
 * function stringlist_append
 */
int
stringlist_append (stringlist ** lst, char *data)
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function stringlist_append\n");
    }

  /*
   * return if data is NULL
   */
  if (data == NULL)
    {
      return 0;
    }

  /*
   * move to last element of list
   */
  while (*lst)
    lst = &((*lst)->next);
  /*
   * allocate memory for new element
   */
  *lst = (stringlist *) malloc (sizeof (stringlist));
  if (*lst == NULL)
    return 0;
  /*
   * append new element
   */
  (*lst)->data = string_duplicate (data);
  (*lst)->next = NULL;
  return 1;
}

/*
 * function stringlist_print
 */
void
stringlist_print (stringlist ** lst)
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function stringlist_print\n");
    }

  while (*lst)
    {
      printf ("%s\n", (*lst)->data);
      lst = &((*lst)->next);
    }
}

/*
 * function stringlist_delete
 */
stringlist *
stringlist_delete (stringlist ** lst)
{
  stringlist *first;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function stringlist_delete\n");
    }

  if (*lst)
    {
      first = (*lst)->next;
      free ((*lst)->data);
      free (*lst);
      return (first);
    }
  else
    {
      return (NULL);
    }
}

/*
 * function stringlist_search
 */
stringlist *
stringlist_search (stringlist ** lst, char *searchstring, char **result)
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function stringlist_search\n");
    }

  /*
   * return if searchstring is NULL
   */
  if (searchstring == NULL)
    {
      return NULL;
    }

  /*
   * compare all elements of list with given string
   */
  while (*lst)
    {
      if (strstr ((*lst)->data, searchstring))
        {
          *result = (*lst)->data;
//                      *result = string_duplicate((*lst)->data);
          return (*lst);
        }
      lst = &((*lst)->next);
    }
  return NULL;
}

/*
 * function create_fw1_filter_rule
 */
LeaFilterRulebase *
create_fw1_filter_rule (LeaFilterRulebase * prulebase, char filterstring[255])
{
  LeaFilterRule *prule;
  LeaFilterPredicate *ppred;
  char *filterargument;
  char *argumentvalue;
  char *argumentname;
  unsigned int tempint;
  unsigned int tmpint1;
  unsigned int tmpint2;
  unsigned short tempushort;
  unsigned short tmpushort1;
  unsigned short tmpushort2;
  unsigned long templong;
  lea_value_ex_t **val_arr;
  lea_value_ex_t *lea_value;
  char *argumentsinglevalue;
  int argumentcount;
  int negation;
  char *tmpstring1;
  char *tmpstring2;
  struct tm timestruct;
  char tempchararray[10];

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function create_fw1_filter_rule\n");
    }

  /*
   * create an empty rule with action "pass"
   */
  if ((prule = lea_filter_rule_create (LEA_FILTER_ACTION_PASS)) == NULL)
    {
      fprintf (stderr, "ERROR: failed to create rule\n");
      lea_filter_rulebase_destroy (prulebase);
      return NULL;
    }

  /*
   * split filter string in arguments separated by ";"
   */
  filterargument = strtok (filterstring, ";");
  while (filterargument != NULL)
    {
      /*
       * split argument into name and value separated by "="
       */
      argumentvalue = strchr (filterargument, '=');
      if (argumentvalue == NULL)
        {
          fprintf (stderr, "ERROR: syntax error in rule argument '%s'.\n"
                   "       Required syntax: 'argument=value'\n",
                   filterargument);
          return NULL;
        }
      argumentvalue++;
      argumentname = filterargument;
      argumentname[argumentvalue - filterargument - 1] = '\0';
      argumentvalue = string_trim (argumentvalue, ' ');
      argumentname = string_trim (argumentname, ' ');
      filterargument = strtok (NULL, ";");
      val_arr = NULL;

      if (argumentname[strlen (argumentname) - 1] == '!')
        {
          negation = 1;
          argumentname = string_trim (argumentname, '!');
        }
      else
        {
          negation = 0;
        }

      /*
       * change argument name to lower case letters
       */
      for (tempint = 0; tempint < strlen (argumentname); tempint++)
        {
          argumentname[tempint] = tolower (argumentname[tempint]);
        }

      /*
       * process arguments of type "product"
       */
      if (strcmp (argumentname, "product") == 0)
        {
          argumentcount = 0;
          /*
           * get argument values separated by ","
           */
          while (argumentvalue)
            {
              argumentsinglevalue =
                string_trim (string_get_token (&argumentvalue, ','), ' ');
              argumentcount++;
              if (val_arr)
                {
                  val_arr =
                    (lea_value_ex_t **) realloc (val_arr,
                                                 argumentcount *
                                                 sizeof (lea_value_ex_t *));
                  if (val_arr == NULL)
                    {
                      fprintf (stderr, "ERROR: Out of memory\n");
                      exit_loggrabber (1);
                    }
                }
              else
                {
                  val_arr =
                    (lea_value_ex_t **) malloc (argumentcount *
                                                sizeof (lea_value_ex_t *));
                  if (val_arr == NULL)
                    {
                      fprintf (stderr, "ERROR: Out of memory\n");
                      exit_loggrabber (1);
                    }
                }

              /*
               * check validity of argument value
               */
              if (!
                  ((strcmp (argumentsinglevalue, "VPN-1 & FireWall-1") == 0)
                   || (strcmp (argumentsinglevalue, "SmartDefense") == 0)
                   || (strcmp (argumentsinglevalue, "URL Filtering") == 0)
                   || (strcmp (argumentsinglevalue, "Identity Awareness") == 0)
                   || (strcmp (argumentsinglevalue, "Identity Logging") == 0)
                   || (strcmp (argumentsinglevalue, "New Anti Virus") == 0)
                   || (strcmp (argumentsinglevalue, "FDE") == 0)
                   || (strcmp (argumentsinglevalue, "Anti Malware") == 0)
                   || (strcmp (argumentsinglevalue, "Application Control") == 0)
                   || (strcmp (argumentsinglevalue, "Application Control(+)URL Filtering") == 0)
                   || (strcmp (argumentsinglevalue, "Connectra") == 0)
                   || (strcmp (argumentsinglevalue, "ESOD") == 0)
                   || (strcmp (argumentsinglevalue, "Linux OS") == 0)
                   || (strcmp (argumentsinglevalue, "Policy Server") == 0)
                   || (strcmp (argumentsinglevalue, "Security Gateway/Management") == 0)
                   || (strcmp (argumentsinglevalue, "Syslog") == 0)
                   || (strcmp (argumentsinglevalue, "Threat Emulation") == 0)
                   || (strcmp (argumentsinglevalue, "Threat Extraction") == 0)))
                {
                  fprintf (stderr, "ERROR: invalid value for product: '%s'\n",
                           argumentsinglevalue);
                  return NULL;
                }

              /*
               * create extended opsec value
               */
              val_arr[argumentcount - 1] = lea_value_ex_create ();
              if (lea_value_ex_set
                  (val_arr[argumentcount - 1], LEA_VT_STRING,
                   argumentsinglevalue) == OPSEC_SESSION_ERR)
                {
                  fprintf (stderr, "ERROR: failed to set rule value (%s)\n",
                           opsec_errno_str (opsec_errno));
                  lea_value_ex_destroy (val_arr[argumentcount - 1]);
                  lea_filter_rule_destroy (prule);
                  return NULL;
                }
            }

          /*
           * create filter predicate
           */
          if ((ppred =
               lea_filter_predicate_create ("product", -1, negation,
                                            LEA_FILTER_PRED_BELONGS_TO,
                                            argumentcount, val_arr)) == NULL)
            {
              fprintf (stderr, "ERROR: failed to create predicate\n");
              lea_value_ex_destroy (val_arr[argumentcount - 1]);
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          lea_value_ex_destroy (val_arr[argumentcount - 1]);

          /*
           * add current predicate to current rule
           */
          if (lea_filter_rule_add_predicate (prule, ppred) == LEA_FILTER_ERR)
            {
              fprintf (stderr, "ERROR: failed to add predicate to rule\n");
              lea_filter_rule_destroy (prule);
              lea_filter_predicate_destroy (ppred);
              return NULL;
            }

          lea_filter_predicate_destroy (ppred);
        }

      /*
       * process arguments of type "action"
       */
      else if (strcmp (argumentname, "action") == 0)
        {
          argumentcount = 0;
          /*
           * get argument values separated by ","
           */
          while (argumentvalue)
            {
              argumentsinglevalue =
                string_trim (string_get_token (&argumentvalue, ','), ' ');
              argumentcount++;
              if (val_arr)
                {
                  val_arr =
                    (lea_value_ex_t **) realloc (val_arr,
                                                 argumentcount *
                                                 sizeof (lea_value_ex_t *));
                  if (val_arr == NULL)
                    {
                      fprintf (stderr, "ERROR: Out of memory\n");
                      exit_loggrabber (1);
                    }
                }
              else
                {
                  val_arr =
                    (lea_value_ex_t **) malloc (argumentcount *
                                                sizeof (lea_value_ex_t *));
                  if (val_arr == NULL)
                    {
                      fprintf (stderr, "ERROR: Out of memory\n");
                      exit_loggrabber (1);
                    }
                }

              /*
               * transform values (accept, drop, reject) into corresponding values
               */
              if (strcmp (argumentsinglevalue, "ctl") == 0)
                {
                  tempint = 0;
                }
              else if (strcmp (argumentsinglevalue, "drop") == 0)
                {
                  tempint = 2;
                }
              else if (strcmp (argumentsinglevalue, "reject") == 0)
                {
                  tempint = 3;
                }
              else if (strcmp (argumentsinglevalue, "accept") == 0)
                {
                  tempint = 4;
                }
              else if (strcmp (argumentsinglevalue, "encrypt") == 0)
                {
                  tempint = 5;
                }
              else if (strcmp (argumentsinglevalue, "decrypt") == 0)
                {
                  tempint = 6;
                }
              else if (strcmp (argumentsinglevalue, "keyinst") == 0)
                {
                  tempint = 7;
                }
              else
                {
                  fprintf (stderr, "ERROR: invalid value for action: '%s'\n",
                           argumentsinglevalue);
                  return NULL;
                }

              /*
               * create extended opsec value
               */
              val_arr[argumentcount - 1] = lea_value_ex_create ();
              if (lea_value_ex_set
                  (val_arr[argumentcount - 1], LEA_VT_ACTION,
                   tempint) == OPSEC_SESSION_ERR)
                {
                  fprintf (stderr, "ERROR: failed to set rule value (%s)\n",
                           opsec_errno_str (opsec_errno));
                  lea_value_ex_destroy (val_arr[argumentcount - 1]);
                  lea_filter_rule_destroy (prule);
                  return NULL;
                }
            }

          /*
           * create filter predicate
           */
          if ((ppred =
               lea_filter_predicate_create ("action", -1, negation,
                                            LEA_FILTER_PRED_BELONGS_TO,
                                            argumentcount, val_arr)) == NULL)
            {
              fprintf (stderr, "ERROR: failed to create predicate\n");
              lea_value_ex_destroy (val_arr[argumentcount - 1]);
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          lea_value_ex_destroy (val_arr[argumentcount - 1]);

          /*
           * add current predicate to current rule
           */
          if (lea_filter_rule_add_predicate (prule, ppred) == LEA_FILTER_ERR)
            {
              fprintf (stderr, "ERROR: failed to add predicate to rule\n");
              lea_filter_rule_destroy (prule);
              lea_filter_predicate_destroy (ppred);
              return NULL;
            }

          lea_filter_predicate_destroy (ppred);
        }

      /*
       * process arguments of type "orig"
       */
      else if (strcmp (argumentname, "orig") == 0)
        {
          /*
           * if the value specifies a network, create the filter predicate directly
           */
          argumentcount = 0;
          /*
           * get argument values separated by ","
           */
          while (argumentvalue)
            {
              argumentsinglevalue =
                string_trim (string_get_token (&argumentvalue, ','), ' ');
              if (strlen (argumentsinglevalue) == 0)
                {
                  fprintf (stderr,
                           "ERROR: syntax error in rule value of argument orig: '%s'.\n"
                           "       Required syntax: 'orig=aaa.bbb.ccc.ddd'\n",
                           argumentsinglevalue);
                  return NULL;
                }
              argumentcount++;
              if (val_arr)
                {
                  val_arr =
                    (lea_value_ex_t **) realloc (val_arr,
                                                 argumentcount *
                                                 sizeof (lea_value_ex_t *));
                  if (val_arr == NULL)
                    {
                      fprintf (stderr, "ERROR: Out of memory\n");
                      exit_loggrabber (1);
                    }
                }
              else
                {
                  val_arr =
                    (lea_value_ex_t **) malloc (argumentcount *
                                                sizeof (lea_value_ex_t *));
                  if (val_arr == NULL)
                    {
                      fprintf (stderr, "ERROR: Out of memory\n");
                      exit_loggrabber (1);
                    }
                }

              /*
               * create extended opsec value
               */
              val_arr[argumentcount - 1] = lea_value_ex_create ();
              if (lea_value_ex_set
                  (val_arr[argumentcount - 1], LEA_VT_IP_ADDR,
                   inet_addr (argumentsinglevalue)) == OPSEC_SESSION_ERR)
                {
                  fprintf (stderr,
                           "ERROR: failed to set rule value (%s)\n",
                           opsec_errno_str (opsec_errno));
                  lea_value_ex_destroy (val_arr[argumentcount - 1]);
                  lea_filter_rule_destroy (prule);
                  return NULL;
                }
            }

          /*
           * create filter predicate
           */
          if ((ppred =
               lea_filter_predicate_create ("orig", -1, negation,
                                            LEA_FILTER_PRED_BELONGS_TO,
                                            argumentcount, val_arr)) == NULL)
            {
              fprintf (stderr, "ERROR: failed to create predicate\n");
              lea_value_ex_destroy (val_arr[argumentcount - 1]);
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          lea_value_ex_destroy (val_arr[argumentcount - 1]);

          /*
           * add current predicate to current rule
           */
          if (lea_filter_rule_add_predicate (prule, ppred) == LEA_FILTER_ERR)
            {
              fprintf (stderr, "ERROR: failed to add predicate to rule\n");
              lea_filter_rule_destroy (prule);
              lea_filter_predicate_destroy (ppred);
              return NULL;
            }

          lea_filter_predicate_destroy (ppred);
        }

      /*
       * process arguments of type "dst"
       */
      else if (strcmp (argumentname, "dst") == 0)
        {
          /*
           * check whether values are valid
           */
          if ((strchr (argumentvalue, ',')) && (strchr (argumentvalue, '/')))
            {
              fprintf (stderr,
                       "ERROR: use either netmask OR multiple IP addresses");
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          /*
           * if the value specifies a network, create the filter predicate directly
           */
          if (strchr (argumentvalue, '/'))
            {
              tmpstring1 =
                string_trim (string_get_token (&argumentvalue, '/'), ' ');
              tmpstring2 =
                string_trim (string_get_token (&argumentvalue, '/'), ' ');
              if ((strlen (tmpstring1) == 0) || (strlen (tmpstring2) == 0))
                {
                  fprintf (stderr,
                           "ERROR: syntax error in rule value of argument dst: '%s/%s'.\n"
                           "       Required syntax: 'dst=aaa.bbb.ccc.ddd/eee.fff.ggg.hhh'\n",
                           tmpstring1, tmpstring2);
                  return NULL;
                }
              if ((ppred =
                   lea_filter_predicate_create ("dst", -1, negation,
                                                LEA_FILTER_PRED_BELONGS_TO_MASK,
                                                inet_addr (tmpstring1),
                                                inet_addr (tmpstring2))) ==
                  NULL)
                {
                  fprintf (stderr, "ERROR: failed to create predicate\n");
                  lea_value_ex_destroy (val_arr[argumentcount - 1]);
                  lea_filter_rule_destroy (prule);
                  return NULL;
                }
            }
          else
            {
              argumentcount = 0;
              /*
               * get argument values separated by ","
               */
              while (argumentvalue)
                {
                  argumentsinglevalue =
                    string_trim (string_get_token (&argumentvalue, ','), ' ');
                  if (strlen (argumentsinglevalue) == 0)
                    {
                      fprintf (stderr,
                               "ERROR: syntax error in rule value of argument dst: '%s'.\n"
                               "       Required syntax: 'dst=aaa.bbb.ccc.ddd'\n",
                               argumentsinglevalue);
                      return NULL;
                    }
                  argumentcount++;
                  if (val_arr)
                    {
                      val_arr =
                        (lea_value_ex_t **) realloc (val_arr,
                                                     argumentcount *
                                                     sizeof (lea_value_ex_t
                                                             *));
                      if (val_arr == NULL)
                        {
                          fprintf (stderr, "ERROR: Out of memory\n");
                          exit_loggrabber (1);
                        }
                    }
                  else
                    {
                      val_arr =
                        (lea_value_ex_t **) malloc (argumentcount *
                                                    sizeof (lea_value_ex_t
                                                            *));
                      if (val_arr == NULL)
                        {
                          fprintf (stderr, "ERROR: Out of memory\n");
                          exit_loggrabber (1);
                        }
                    }

                  /*
                   * create extended opsec value
                   */
                  val_arr[argumentcount - 1] = lea_value_ex_create ();
                  if (lea_value_ex_set
                      (val_arr[argumentcount - 1], LEA_VT_IP_ADDR,
                       inet_addr (argumentsinglevalue)) == OPSEC_SESSION_ERR)
                    {
                      fprintf (stderr,
                               "ERROR: failed to set rule value (%s)\n",
                               opsec_errno_str (opsec_errno));
                      lea_value_ex_destroy (val_arr[argumentcount - 1]);
                      lea_filter_rule_destroy (prule);
                      return NULL;
                    }
                }

              /*
               * create filter predicate
               */
              if ((ppred =
                   lea_filter_predicate_create ("dst", -1, negation,
                                                LEA_FILTER_PRED_BELONGS_TO,
                                                argumentcount,
                                                val_arr)) == NULL)
                {
                  fprintf (stderr, "ERROR: failed to create predicate\n");
                  lea_value_ex_destroy (val_arr[argumentcount - 1]);
                  lea_filter_rule_destroy (prule);
                  return NULL;
                }

              lea_value_ex_destroy (val_arr[argumentcount - 1]);
            }

          /*
           * add current predicate to current rule
           */
          if (lea_filter_rule_add_predicate (prule, ppred) == LEA_FILTER_ERR)
            {
              fprintf (stderr, "ERROR: failed to add predicate to rule\n");
              lea_filter_rule_destroy (prule);
              lea_filter_predicate_destroy (ppred);
              return NULL;
            }

          lea_filter_predicate_destroy (ppred);
        }

      /*
       * process arguments of type "proto"
       */
      else if (strcmp (argumentname, "proto") == 0)
        {
          argumentcount = 0;
          /*
           * get argument values separated by ","
           */
          while (argumentvalue)
            {
              argumentsinglevalue =
                string_trim (string_get_token (&argumentvalue, ','), ' ');
              argumentcount++;
              if (val_arr)
                {
                  val_arr =
                    (lea_value_ex_t **) realloc (val_arr,
                                                 argumentcount *
                                                 sizeof (lea_value_ex_t *));
                  if (val_arr == NULL)
                    {
                      fprintf (stderr, "ERROR: Out of memory\n");
                      exit_loggrabber (1);
                    }
                }
              else
                {
                  val_arr =
                    (lea_value_ex_t **) malloc (argumentcount *
                                                sizeof (lea_value_ex_t *));
                  if (val_arr == NULL)
                    {
                      fprintf (stderr, "ERROR: Out of memory\n");
                      exit_loggrabber (1);
                    }
                }

              /*
               * transform values (icmp, tcp, udp) into corresponding values
               */
              if (strcmp (argumentsinglevalue, "icmp") == 0)
                {
                  tempint = 1;
                }
              else if (strcmp (argumentsinglevalue, "tcp") == 0)
                {
                  tempint = 6;
                }
              else if (strcmp (argumentsinglevalue, "udp") == 0)
                {
                  tempint = 17;
                }
              else
                {
                  fprintf (stderr, "ERROR: invalid value for action: '%s'\n",
                           argumentsinglevalue);
                  return NULL;
                }

              /*
               * create extended opsec value
               */
              val_arr[argumentcount - 1] = lea_value_ex_create ();
              if (lea_value_ex_set
                  (val_arr[argumentcount - 1], LEA_VT_IP_PROTO,
                   tempint) == OPSEC_SESSION_ERR)
                {
                  fprintf (stderr, "ERROR: failed to set rule value (%s)\n",
                           opsec_errno_str (opsec_errno));
                  lea_value_ex_destroy (val_arr[argumentcount - 1]);
                  lea_filter_rule_destroy (prule);
                  return NULL;
                }
            }

          /*
           * create filter predicate
           */
          if ((ppred =
               lea_filter_predicate_create ("proto", -1, negation,
                                            LEA_FILTER_PRED_BELONGS_TO,
                                            argumentcount, val_arr)) == NULL)
            {
              fprintf (stderr, "ERROR: failed to create predicate\n");
              lea_value_ex_destroy (val_arr[argumentcount - 1]);
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          lea_value_ex_destroy (val_arr[argumentcount - 1]);

          /*
           * add current predicate to current rule
           */
          if (lea_filter_rule_add_predicate (prule, ppred) == LEA_FILTER_ERR)
            {
              fprintf (stderr, "ERROR: failed to add predicate to rule\n");
              lea_filter_rule_destroy (prule);
              lea_filter_predicate_destroy (ppred);
              return NULL;
            }

          lea_filter_predicate_destroy (ppred);
        }

      /*
       * process arguments of type "starttime"
       */
      else if (strcmp (argumentname, "starttime") == 0)
        {
          argumentsinglevalue = string_trim (argumentvalue, ' ');
          if (strlen (argumentsinglevalue) != 14)
            {
              fprintf (stderr,
                       "ERROR: syntax error in rule value of argument rule: '%s'.\n"
                       "       Required syntax: 'starttime=YYYYMMDDhhmmss'\n",
                       argumentsinglevalue);
              return NULL;
            }

          /*
           * convert starttime parameter to proper form (unixtime)
           */
          strncpy (tempchararray, argumentsinglevalue, 4);
          tempchararray[4] = '\0';
          timestruct.tm_year =
            strtol (tempchararray, (char **) NULL, 10) - 1900;
          argumentsinglevalue += 4 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_mon = strtol (tempchararray, (char **) NULL, 10) - 1;
          argumentsinglevalue += 2 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_mday = strtol (tempchararray, (char **) NULL, 10);
          argumentsinglevalue += 2 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_hour = strtol (tempchararray, (char **) NULL, 10);
          argumentsinglevalue += 2 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_min = strtol (tempchararray, (char **) NULL, 10);
          argumentsinglevalue += 2 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_sec = strtol (tempchararray, (char **) NULL, 10);

          /*
           * convert starttime parameter to long int
           */
          if ((timestruct.tm_mon > 11) || (timestruct.tm_mday > 31)
              || (timestruct.tm_hour > 23) || (timestruct.tm_min > 59)
              || (timestruct.tm_sec > 59))
            {
              fprintf (stderr,
                       "ERROR: illegal date format in argumentvalue\n");
              return NULL;
            }
          templong = (unsigned long) mktime (&timestruct);
          if (templong == -1)
            {
              fprintf (stderr,
                       "ERROR: illegal date format in argumentvalue\n");
              return NULL;
            }

          /*
           * create extended opsec value
           */
          lea_value = lea_value_ex_create ();
          if (lea_value_ex_set (lea_value, LEA_VT_TIME, templong) ==
              OPSEC_SESSION_ERR)
            {
              fprintf (stderr, "ERROR: failed to set starttime value (%s)\n",
                       opsec_errno_str (opsec_errno));
              lea_value_ex_destroy (lea_value);
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          /*
           * create filter predicate
           */
          if ((ppred =
               lea_filter_predicate_create ("time", -1, negation,
                                            LEA_FILTER_PRED_GREATER_EQUAL,
                                            lea_value)) == NULL)
            {
              fprintf (stderr, "ERROR: failed to create predicate\n");
              lea_value_ex_destroy (val_arr[argumentcount - 1]);
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          lea_value_ex_destroy (lea_value);

          /*
           * add current predicate to current rule
           */
          if (lea_filter_rule_add_predicate (prule, ppred) == LEA_FILTER_ERR)
            {
              fprintf (stderr, "ERROR: failed to add predicate to rule\n");
              lea_filter_rule_destroy (prule);
              lea_filter_predicate_destroy (ppred);
              return NULL;
            }

          lea_filter_predicate_destroy (ppred);
        }

      /*
       * process arguments of type "endtime"
       */
      else if (strcmp (argumentname, "endtime") == 0)
        {
          argumentsinglevalue = string_trim (argumentvalue, ' ');
          if (strlen (argumentsinglevalue) != 14)
            {
              fprintf (stderr,
                       "ERROR: syntax error in rule value of argument rule: '%s'.\n"
                       "       Required syntax: 'endtime=YYYYMMDDhhmmss'\n",
                       argumentsinglevalue);
              return NULL;
            }

          /*
           * convert starttime parameter to proper form (unixtime)
           */
          strncpy (tempchararray, argumentsinglevalue, 4);
          tempchararray[4] = '\0';
          timestruct.tm_year =
            strtol (tempchararray, (char **) NULL, 10) - 1900;
          argumentsinglevalue += 4 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_mon = strtol (tempchararray, (char **) NULL, 10) - 1;
          argumentsinglevalue += 2 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_mday = strtol (tempchararray, (char **) NULL, 10);
          argumentsinglevalue += 2 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_hour = strtol (tempchararray, (char **) NULL, 10);
          argumentsinglevalue += 2 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_min = strtol (tempchararray, (char **) NULL, 10);
          argumentsinglevalue += 2 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_sec = strtol (tempchararray, (char **) NULL, 10);

          /*
           * convert starttime parameter to long int
           */
          if ((timestruct.tm_mon > 11) || (timestruct.tm_mday > 31)
              || (timestruct.tm_hour > 23) || (timestruct.tm_min > 59)
              || (timestruct.tm_sec > 59))
            {
              fprintf (stderr,
                       "ERROR: illegal date format in argumentvalue\n");
              return NULL;
            }
          templong = (unsigned long) mktime (&timestruct);
          if (templong == -1)
            {
              fprintf (stderr,
                       "ERROR: illegal date format in argumentvalue\n");
              return NULL;
            }

          /*
           * create extended opsec value
           */
          lea_value = lea_value_ex_create ();
          if (lea_value_ex_set (lea_value, LEA_VT_TIME, templong) ==
              OPSEC_SESSION_ERR)
            {
              fprintf (stderr, "ERROR: failed to set endtime value (%s)\n",
                       opsec_errno_str (opsec_errno));
              lea_value_ex_destroy (lea_value);
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          /*
           * create filter predicate
           */
          if ((ppred =
               lea_filter_predicate_create ("time", -1, negation,
                                            LEA_FILTER_PRED_SMALLER_EQUAL,
                                            lea_value)) == NULL)
            {
              fprintf (stderr, "ERROR: failed to create predicate\n");
              lea_value_ex_destroy (val_arr[argumentcount - 1]);
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          lea_value_ex_destroy (lea_value);

          /*
           * add current predicate to current rule
           */
          if (lea_filter_rule_add_predicate (prule, ppred) == LEA_FILTER_ERR)
            {
              fprintf (stderr, "ERROR: failed to add predicate to rule\n");
              lea_filter_rule_destroy (prule);
              lea_filter_predicate_destroy (ppred);
              return NULL;
            }

          lea_filter_predicate_destroy (ppred);
        }

      /*
       * process arguments of type "rule"
       */
      else if (strcmp (argumentname, "rule") == 0)
        {
          argumentcount = 0;
          /*
           * get argument values separated by ","
           */
          while (argumentvalue)
            {
              argumentsinglevalue =
                string_trim (string_get_token (&argumentvalue, ','), ' ');
              if (strlen (argumentsinglevalue) == 0)
                {
                  fprintf (stderr,
                           "ERROR: syntax error in rule value of argument rule: '%s'.\n"
                           "       Required syntax: 'rule=x'\n",
                           argumentsinglevalue);
                  return NULL;
                }

              /*
               * get ranges separated by "-", if there is no "-" start and end value of the
               * range is the same.
               */
              tmpstring1 =
                string_trim (string_get_token (&argumentsinglevalue, '-'),
                             ' ');
              tmpstring2 =
                (argumentsinglevalue ==
                 NULL) ? tmpstring1 :
                string_trim (string_get_token (&argumentsinglevalue, '-'),
                             ' ');
              tmpint1 = (int) strtol (tmpstring1, (char **) NULL, 10);
              tmpint2 = (int) strtol (tmpstring2, (char **) NULL, 10);

              for (tempint = tmpint1; tempint <= tmpint2; tempint++)
                {
                  argumentcount++;
                  if (val_arr)
                    {
                      val_arr =
                        (lea_value_ex_t **) realloc (val_arr,
                                                     argumentcount *
                                                     sizeof (lea_value_ex_t
                                                             *));
                      if (val_arr == NULL)
                        {
                          fprintf (stderr, "ERROR: Out of memory\n");
                          exit_loggrabber (1);
                        }
                    }
                  else
                    {
                      val_arr =
                        (lea_value_ex_t **) malloc (argumentcount *
                                                    sizeof (lea_value_ex_t
                                                            *));
                      if (val_arr == NULL)
                        {
                          fprintf (stderr, "ERROR: Out of memory\n");
                          exit_loggrabber (1);
                        }
                    }

                  /*
                   * create extended opsec value
                   */
                  val_arr[argumentcount - 1] = lea_value_ex_create ();
                  if (lea_value_ex_set
                      (val_arr[argumentcount - 1], LEA_VT_RULE,
                       tempint) == OPSEC_SESSION_ERR)
                    {
                      fprintf (stderr,
                               "ERROR: failed to set rule value (%s)\n",
                               opsec_errno_str (opsec_errno));
                      lea_value_ex_destroy (val_arr[argumentcount - 1]);
                      lea_filter_rule_destroy (prule);
                      return NULL;
                    }
                }
            }

          /*
           * create filter predicate
           */
          if ((ppred =
               lea_filter_predicate_create ("rule", -1, negation,
                                            LEA_FILTER_PRED_BELONGS_TO,
                                            argumentcount, val_arr)) == NULL)
            {
              fprintf (stderr, "ERROR: failed to create predicate\n");
              lea_value_ex_destroy (val_arr[argumentcount - 1]);
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          lea_value_ex_destroy (val_arr[argumentcount - 1]);

          /*
           * add current predicate to current rule
           */
          if (lea_filter_rule_add_predicate (prule, ppred) == LEA_FILTER_ERR)
            {
              fprintf (stderr, "ERROR: failed to add predicate to rule\n");
              lea_filter_rule_destroy (prule);
              lea_filter_predicate_destroy (ppred);
              return NULL;
            }

          lea_filter_predicate_destroy (ppred);
        }

      /*
       * process arguments of type "service"
       */
      else if (strcmp (argumentname, "service") == 0)
        {
          argumentcount = 0;
          /*
           * get argument values separated by ","
           */
          while (argumentvalue)
            {
              argumentsinglevalue =
                string_trim (string_get_token (&argumentvalue, ','), ' ');
              if (strlen (argumentsinglevalue) == 0)
                {
                  fprintf (stderr,
                           "ERROR: syntax error in rule value of argument service: '%s'.\n"
                           "       Required syntax: 'service=<Port-Number>'\n",
                           argumentsinglevalue);
                  return NULL;
                }

              /*
               * get ranges separated by "-", if there is no "-" start and end value of the
               * range is the same.
               */
              tmpstring1 =
                string_trim (string_get_token (&argumentsinglevalue, '-'),
                             ' ');
              tmpstring2 =
                (argumentsinglevalue ==
                 NULL) ? tmpstring1 :
                string_trim (string_get_token (&argumentsinglevalue, '-'),
                             ' ');
              tmpushort1 =
                (unsigned short) strtol (tmpstring1, (char **) NULL, 10);
              tmpushort2 =
                (unsigned short) strtol (tmpstring2, (char **) NULL, 10);

              for (tempushort = tmpushort1; tempushort <= tmpushort2;
                   tempushort++)
                {
                  argumentcount++;
                  if (val_arr)
                    {
                      val_arr =
                        (lea_value_ex_t **) realloc (val_arr,
                                                     argumentcount *
                                                     sizeof (lea_value_ex_t
                                                             *));
                      if (val_arr == NULL)
                        {
                          fprintf (stderr, "ERROR: Out of memory\n");
                          exit_loggrabber (1);
                        }
                    }
                  else
                    {
                      val_arr =
                        (lea_value_ex_t **) malloc (argumentcount *
                                                    sizeof (lea_value_ex_t
                                                            *));
                      if (val_arr == NULL)
                        {
                          fprintf (stderr, "ERROR: Out of memory\n");
                          exit_loggrabber (1);
                        }
                    }

                  /*
                   * create extended opsec value
                   */
                  val_arr[argumentcount - 1] = lea_value_ex_create ();
                  if (lea_value_ex_set
                      (val_arr[argumentcount - 1], LEA_VT_USHORT,
                       tempushort) == OPSEC_SESSION_ERR)
                    {
                      fprintf (stderr,
                               "ERROR: failed to set rule value (%s)\n",
                               opsec_errno_str (opsec_errno));
                      lea_value_ex_destroy (val_arr[argumentcount - 1]);
                      lea_filter_rule_destroy (prule);
                      return NULL;
                    }
                }
            }

          /*
           * create filter predicate
           */
          if ((ppred =
               lea_filter_predicate_create ("service", -1, negation,
                                            LEA_FILTER_PRED_BELONGS_TO,
                                            argumentcount, val_arr)) == NULL)
            {
              fprintf (stderr, "ERROR: failed to create predicate\n");
              lea_value_ex_destroy (val_arr[argumentcount - 1]);
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          lea_value_ex_destroy (val_arr[argumentcount - 1]);

          /*
           * add current predicate to current rule
           */
          if (lea_filter_rule_add_predicate (prule, ppred) == LEA_FILTER_ERR)
            {
              fprintf (stderr, "ERROR: failed to add predicate to rule\n");
              lea_filter_rule_destroy (prule);
              lea_filter_predicate_destroy (ppred);
              return NULL;
            }

          lea_filter_predicate_destroy (ppred);
        }

      /*
       * process arguments of type "src"
       */
      else if (strcmp (argumentname, "src") == 0)
        {
          /*
           * check whether values are valid
           */
          if ((strchr (argumentvalue, ',')) && (strchr (argumentvalue, '/')))
            {
              fprintf (stderr,
                       "ERROR: use either netmask OR multiple IP addresses");
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          /*
           * if the value specifies a network, create the filter predicate directly
           */
          if (strchr (argumentvalue, '/'))
            {
              tmpstring1 =
                string_trim (string_get_token (&argumentvalue, '/'), ' ');
              tmpstring2 =
                string_trim (string_get_token (&argumentvalue, '/'), ' ');
              if ((strlen (tmpstring1) == 0) || (strlen (tmpstring2) == 0))
                {
                  fprintf (stderr,
                           "ERROR: syntax error in rule value of argument src: '%s/%s'.\n"
                           "       Required syntax: 'src=aaa.bbb.ccc.ddd/eee.fff.ggg.hhh'\n",
                           tmpstring1, tmpstring2);
                  return NULL;
                }
              if ((ppred =
                   lea_filter_predicate_create ("src", -1, negation,
                                                LEA_FILTER_PRED_BELONGS_TO_MASK,
                                                inet_addr (tmpstring1),
                                                inet_addr (tmpstring2))) ==
                  NULL)
                {
                  fprintf (stderr, "ERROR: failed to create predicate\n");
                  lea_value_ex_destroy (val_arr[argumentcount - 1]);
                  lea_filter_rule_destroy (prule);
                  return NULL;
                }
            }
          else
            {
              argumentcount = 0;
              /*
               * get argument values separated by ","
               */
              while (argumentvalue)
                {
                  argumentsinglevalue =
                    string_trim (string_get_token (&argumentvalue, ','), ' ');
                  if (strlen (argumentsinglevalue) == 0)
                    {
                      fprintf (stderr,
                               "ERROR: syntax error in rule value of argument src: '%s'.\n"
                               "       Required syntax: 'src=aaa.bbb.ccc.ddd'\n",
                               argumentsinglevalue);
                      return NULL;
                    }
                  argumentcount++;
                  if (val_arr)
                    {
                      val_arr =
                        (lea_value_ex_t **) realloc (val_arr,
                                                     argumentcount *
                                                     sizeof (lea_value_ex_t
                                                             *));
                      if (val_arr == NULL)
                        {
                          fprintf (stderr, "ERROR: Out of memory\n");
                          exit_loggrabber (1);
                        }
                    }
                  else
                    {
                      val_arr =
                        (lea_value_ex_t **) malloc (argumentcount *
                                                    sizeof (lea_value_ex_t
                                                            *));
                      if (val_arr == NULL)
                        {
                          fprintf (stderr, "ERROR: Out of memory\n");
                          exit_loggrabber (1);
                        }
                    }

                  /*
                   * create extended opsec value
                   */
                  val_arr[argumentcount - 1] = lea_value_ex_create ();
                  if (lea_value_ex_set
                      (val_arr[argumentcount - 1], LEA_VT_IP_ADDR,
                       inet_addr (argumentsinglevalue)) == OPSEC_SESSION_ERR)
                    {
                      fprintf (stderr,
                               "ERROR: failed to set rule value (%s)\n",
                               opsec_errno_str (opsec_errno));
                      lea_value_ex_destroy (val_arr[argumentcount - 1]);
                      lea_filter_rule_destroy (prule);
                      return NULL;
                    }
                }

              /*
               * create filter predicate
               */
              if ((ppred =
                   lea_filter_predicate_create ("src", -1, negation,
                                                LEA_FILTER_PRED_BELONGS_TO,
                                                argumentcount,
                                                val_arr)) == NULL)
                {
                  fprintf (stderr, "ERROR: failed to create predicate\n");
                  lea_value_ex_destroy (val_arr[argumentcount - 1]);
                  lea_filter_rule_destroy (prule);
                  return NULL;
                }

              lea_value_ex_destroy (val_arr[argumentcount - 1]);
            }

          /*
           * add current predicate to current rule
           */
          if (lea_filter_rule_add_predicate (prule, ppred) == LEA_FILTER_ERR)
            {
              fprintf (stderr, "ERROR: failed to add predicate to rule\n");
              lea_filter_rule_destroy (prule);
              lea_filter_predicate_destroy (ppred);
              return NULL;
            }

          lea_filter_predicate_destroy (ppred);
        }

      /*
       * process unknown arguments
       */
      else
        {
          fprintf (stderr, "ERROR: Unknown filterargument: '%s'\n",
                   argumentname);
          return NULL;
        }
    }

  /*
   * add current rule to rulebase
   */
  if (lea_filter_rulebase_add_rule (prulebase, prule) != OPSEC_SESSION_OK)
    {
      fprintf (stderr, "failed to add rule to rulebase\n");
      lea_filter_rulebase_destroy (prulebase);
      lea_filter_rule_destroy (prule);
      return NULL;
    }

  lea_filter_rule_destroy (prule);

  return prulebase;
}

/*
 * function create_audit_filter_rule
 */
LeaFilterRulebase *
create_audit_filter_rule (LeaFilterRulebase * prulebase,
                          char filterstring[255])
{
  LeaFilterRule *prule;
  LeaFilterPredicate *ppred;
  char *filterargument;
  char *argumentvalue;
  char *argumentname;
  unsigned int tempint;
  unsigned long templong;
  lea_value_ex_t **val_arr;
  lea_value_ex_t *lea_value;
  char *argumentsinglevalue;
  int argumentcount;
  int negation;
  struct tm timestruct;
  char tempchararray[10];

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function create_audit_filter_rule\n");
    }

  /*
   * create an empty rule with action "pass"
   */
  if ((prule = lea_filter_rule_create (LEA_FILTER_ACTION_PASS)) == NULL)
    {
      fprintf (stderr, "ERROR: failed to create rule\n");
      lea_filter_rulebase_destroy (prulebase);
      return NULL;
    }

  /*
   * split filter string in arguments separated by ";"
   */
  filterargument = strtok (filterstring, ";");
  while (filterargument != NULL)
    {
      /*
       * split argument into name and value separated by "="
       */
      argumentvalue = strchr (filterargument, '=');
      if (argumentvalue == NULL)
        {
          fprintf (stderr, "ERROR: syntax error in rule argument '%s'.\n"
                   "       Required syntax: 'argument=value'\n",
                   filterargument);
          return NULL;
        }
      argumentvalue++;
      argumentname = filterargument;
      argumentname[argumentvalue - filterargument - 1] = '\0';
      argumentvalue = string_trim (argumentvalue, ' ');
      argumentname = string_trim (argumentname, ' ');
      filterargument = strtok (NULL, ";");
      val_arr = NULL;

      if (argumentname[strlen (argumentname) - 1] == '!')
        {
          negation = 1;
          argumentname = string_trim (argumentname, '!');
        }
      else
        {
          negation = 0;
        }

      /*
       * change argument name to lower case letters
       */
      for (tempint = 0; tempint < strlen (argumentname); tempint++)
        {
          argumentname[tempint] = tolower (argumentname[tempint]);
        }

      /*
       * process arguments of type "product"
       */
      if (strcmp (argumentname, "product") == 0)
        {
          argumentcount = 0;
          /*
           * get argument values separated by ","
           */
          while (argumentvalue)
            {
              argumentsinglevalue =
                string_trim (string_get_token (&argumentvalue, ','), ' ');
              argumentcount++;
              if (val_arr)
                {
                  val_arr =
                    (lea_value_ex_t **) realloc (val_arr,
                                                 argumentcount *
                                                 sizeof (lea_value_ex_t *));
                  if (val_arr == NULL)
                    {
                      fprintf (stderr, "ERROR: Out of memory\n");
                      exit_loggrabber (1);
                    }
                }
              else
                {
                  val_arr =
                    (lea_value_ex_t **) malloc (argumentcount *
                                                sizeof (lea_value_ex_t *));
                  if (val_arr == NULL)
                    {
                      fprintf (stderr, "ERROR: Out of memory\n");
                      exit_loggrabber (1);
                    }
                }

              /*
               * check validity of argument value
               */
              if (!((strcmp (argumentsinglevalue, "SmartDashboard") == 0) ||
                    (strcmp (argumentsinglevalue, "Policy Editor") == 0) ||
                    (strcmp (argumentsinglevalue, "SmartView Tracker") == 0)
                    || (strcmp (argumentsinglevalue, "SmartView Status") == 0)
                    || (strcmp (argumentsinglevalue, "SmartView Monitor") ==
                        0)
                    || (strcmp (argumentsinglevalue, "System Monitor") == 0)
                    || (strcmp (argumentsinglevalue, "cpstat_monitor") == 0)
                    || (strcmp (argumentsinglevalue, "SmartUpdate") == 0)
                    || (strcmp (argumentsinglevalue, "CPMI Client") == 0)))
                {
                  fprintf (stderr, "ERROR: invalid value for product: '%s'\n",
                           argumentsinglevalue);
                  return NULL;
                }

              /*
               * create extended opsec value
               */
              val_arr[argumentcount - 1] = lea_value_ex_create ();
              if (lea_value_ex_set
                  (val_arr[argumentcount - 1], LEA_VT_STRING,
                   argumentsinglevalue) == OPSEC_SESSION_ERR)
                {
                  fprintf (stderr, "ERROR: failed to set rule value (%s)\n",
                           opsec_errno_str (opsec_errno));
                  lea_value_ex_destroy (val_arr[argumentcount - 1]);
                  lea_filter_rule_destroy (prule);
                  return NULL;
                }
            }

          /*
           * create filter predicate
           */
          if ((ppred =
               lea_filter_predicate_create ("product", -1, negation,
                                            LEA_FILTER_PRED_BELONGS_TO,
                                            argumentcount, val_arr)) == NULL)
            {
              fprintf (stderr, "ERROR: failed to create predicate\n");
              lea_value_ex_destroy (val_arr[argumentcount - 1]);
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          lea_value_ex_destroy (val_arr[argumentcount - 1]);

          /*
           * add current predicate to current rule
           */
          if (lea_filter_rule_add_predicate (prule, ppred) == LEA_FILTER_ERR)
            {
              fprintf (stderr, "ERROR: failed to add predicate to rule\n");
              lea_filter_rule_destroy (prule);
              lea_filter_predicate_destroy (ppred);
              return NULL;
            }

          lea_filter_predicate_destroy (ppred);
        }

      /*
       * process arguments of type "Administrator"
       */
      else if (strcmp (argumentname, "administrator") == 0)
        {
          argumentcount = 0;
          /*
           * get argument values separated by ","
           */
          while (argumentvalue)
            {
              argumentsinglevalue =
                string_trim (string_get_token (&argumentvalue, ','), ' ');
              argumentcount++;
              if (val_arr)
                {
                  val_arr =
                    (lea_value_ex_t **) realloc (val_arr,
                                                 argumentcount *
                                                 sizeof (lea_value_ex_t *));
                  if (val_arr == NULL)
                    {
                      fprintf (stderr, "ERROR: Out of memory\n");
                      exit_loggrabber (1);
                    }
                }
              else
                {
                  val_arr =
                    (lea_value_ex_t **) malloc (argumentcount *
                                                sizeof (lea_value_ex_t *));
                  if (val_arr == NULL)
                    {
                      fprintf (stderr, "ERROR: Out of memory\n");
                      exit_loggrabber (1);
                    }
                }

              /*
               * create extended opsec value
               */
              val_arr[argumentcount - 1] = lea_value_ex_create ();
              if (lea_value_ex_set
                  (val_arr[argumentcount - 1], LEA_VT_STRING,
                   argumentsinglevalue) == OPSEC_SESSION_ERR)
                {
                  fprintf (stderr, "ERROR: failed to set rule value (%s)\n",
                           opsec_errno_str (opsec_errno));
                  lea_value_ex_destroy (val_arr[argumentcount - 1]);
                  lea_filter_rule_destroy (prule);
                  return NULL;
                }
            }

          /*
           * create filter predicate
           */
          if ((ppred =
               lea_filter_predicate_create ("Administrator", -1, negation,
                                            LEA_FILTER_PRED_BELONGS_TO,
                                            argumentcount, val_arr)) == NULL)
            {
              fprintf (stderr, "ERROR: failed to create predicate\n");
              lea_value_ex_destroy (val_arr[argumentcount - 1]);
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          lea_value_ex_destroy (val_arr[argumentcount - 1]);

          /*
           * add current predicate to current rule
           */
          if (lea_filter_rule_add_predicate (prule, ppred) == LEA_FILTER_ERR)
            {
              fprintf (stderr, "ERROR: failed to add predicate to rule\n");
              lea_filter_rule_destroy (prule);
              lea_filter_predicate_destroy (ppred);
              return NULL;
            }

          lea_filter_predicate_destroy (ppred);
        }

      /*
       * process arguments of type "orig"
       */
      else if (strcmp (argumentname, "orig") == 0)
        {
          argumentcount = 0;
          /*
           * get argument values separated by ","
           */
          while (argumentvalue)
            {
              argumentsinglevalue =
                string_trim (string_get_token (&argumentvalue, ','), ' ');
              if (strlen (argumentsinglevalue) == 0)
                {
                  fprintf (stderr,
                           "ERROR: syntax error in rule value of argument orig: '%s'.\n"
                           "       Required syntax: 'orig=aaa.bbb.ccc.ddd'\n",
                           argumentsinglevalue);
                  return NULL;
                }
              argumentcount++;
              if (val_arr)
                {
                  val_arr =
                    (lea_value_ex_t **) realloc (val_arr,
                                                 argumentcount *
                                                 sizeof (lea_value_ex_t *));
                  if (val_arr == NULL)
                    {
                      fprintf (stderr, "ERROR: Out of memory\n");
                      exit_loggrabber (1);
                    }
                }
              else
                {
                  val_arr =
                    (lea_value_ex_t **) malloc (argumentcount *
                                                sizeof (lea_value_ex_t *));
                  if (val_arr == NULL)
                    {
                      fprintf (stderr, "ERROR: Out of memory\n");
                      exit_loggrabber (1);
                    }
                }

              /*
               * create extended opsec value
               */
              val_arr[argumentcount - 1] = lea_value_ex_create ();
              if (lea_value_ex_set
                  (val_arr[argumentcount - 1], LEA_VT_IP_ADDR,
                   inet_addr (argumentsinglevalue)) == OPSEC_SESSION_ERR)
                {
                  fprintf (stderr,
                           "ERROR: failed to set rule value (%s)\n",
                           opsec_errno_str (opsec_errno));
                  lea_value_ex_destroy (val_arr[argumentcount - 1]);
                  lea_filter_rule_destroy (prule);
                  return NULL;
                }
            }

          /*
           * create filter predicate
           */
          if ((ppred =
               lea_filter_predicate_create ("orig", -1, negation,
                                            LEA_FILTER_PRED_BELONGS_TO,
                                            argumentcount, val_arr)) == NULL)
            {
              fprintf (stderr, "ERROR: failed to create predicate\n");
              lea_value_ex_destroy (val_arr[argumentcount - 1]);
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          lea_value_ex_destroy (val_arr[argumentcount - 1]);

          /*
           * add current predicate to current rule
           */
          if (lea_filter_rule_add_predicate (prule, ppred) == LEA_FILTER_ERR)
            {
              fprintf (stderr, "ERROR: failed to add predicate to rule\n");
              lea_filter_rule_destroy (prule);
              lea_filter_predicate_destroy (ppred);
              return NULL;
            }

          lea_filter_predicate_destroy (ppred);
        }

      /*
       * process arguments of type "action"
       */
      else if (strcmp (argumentname, "action") == 0)
        {
          argumentcount = 0;
          /*
           * get argument values separated by ","
           */
          while (argumentvalue)
            {
              argumentsinglevalue =
                string_trim (string_get_token (&argumentvalue, ','), ' ');
              argumentcount++;
              if (val_arr)
                {
                  val_arr =
                    (lea_value_ex_t **) realloc (val_arr,
                                                 argumentcount *
                                                 sizeof (lea_value_ex_t *));
                  if (val_arr == NULL)
                    {
                      fprintf (stderr, "ERROR: Out of memory\n");
                      exit_loggrabber (1);
                    }
                }
              else
                {
                  val_arr =
                    (lea_value_ex_t **) malloc (argumentcount *
                                                sizeof (lea_value_ex_t *));
                  if (val_arr == NULL)
                    {
                      fprintf (stderr, "ERROR: Out of memory\n");
                      exit_loggrabber (1);
                    }
                }

              /*
               * transform values (accept, drop, reject) into corresponding values
               */
              if (strcmp (argumentsinglevalue, "ctl") == 0)
                {
                  tempint = 0;
                }
              else if (strcmp (argumentsinglevalue, "drop") == 0)
                {
                  tempint = 2;
                }
              else if (strcmp (argumentsinglevalue, "reject") == 0)
                {
                  tempint = 3;
                }
              else if (strcmp (argumentsinglevalue, "accept") == 0)
                {
                  tempint = 4;
                }
              else if (strcmp (argumentsinglevalue, "encrypt") == 0)
                {
                  tempint = 5;
                }
              else if (strcmp (argumentsinglevalue, "decrypt") == 0)
                {
                  tempint = 6;
                }
              else if (strcmp (argumentsinglevalue, "keyinst") == 0)
                {
                  tempint = 7;
                }
              else
                {
                  fprintf (stderr, "ERROR: invalid value for action: '%s'\n",
                           argumentsinglevalue);
                  return NULL;
                }

              /*
               * create extended opsec value
               */
              val_arr[argumentcount - 1] = lea_value_ex_create ();
              if (lea_value_ex_set
                  (val_arr[argumentcount - 1], LEA_VT_ACTION,
                   tempint) == OPSEC_SESSION_ERR)
                {
                  fprintf (stderr, "ERROR: failed to set rule value (%s)\n",
                           opsec_errno_str (opsec_errno));
                  lea_value_ex_destroy (val_arr[argumentcount - 1]);
                  lea_filter_rule_destroy (prule);
                  return NULL;
                }
            }

          /*
           * create filter predicate
           */
          if ((ppred =
               lea_filter_predicate_create ("action", -1, negation,
                                            LEA_FILTER_PRED_BELONGS_TO,
                                            argumentcount, val_arr)) == NULL)
            {
              fprintf (stderr, "ERROR: failed to create predicate\n");
              lea_value_ex_destroy (val_arr[argumentcount - 1]);
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          lea_value_ex_destroy (val_arr[argumentcount - 1]);

          /*
           * add current predicate to current rule
           */
          if (lea_filter_rule_add_predicate (prule, ppred) == LEA_FILTER_ERR)
            {
              fprintf (stderr, "ERROR: failed to add predicate to rule\n");
              lea_filter_rule_destroy (prule);
              lea_filter_predicate_destroy (ppred);
              return NULL;
            }

          lea_filter_predicate_destroy (ppred);
        }

      /*
       * process arguments of type "starttime"
       */
      else if (strcmp (argumentname, "starttime") == 0)
        {
          argumentsinglevalue = string_trim (argumentvalue, ' ');
          if (strlen (argumentsinglevalue) != 14)
            {
              fprintf (stderr,
                       "ERROR: syntax error in rule value of argument rule: '%s'.\n"
                       "       Required syntax: 'starttime=YYYYMMDDhhmmss'\n",
                       argumentsinglevalue);
              return NULL;
            }

          /*
           * convert starttime parameter to proper form (unixtime)
           */
          strncpy (tempchararray, argumentsinglevalue, 4);
          tempchararray[4] = '\0';
          timestruct.tm_year =
            strtol (tempchararray, (char **) NULL, 10) - 1900;
          argumentsinglevalue += 4 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_mon = strtol (tempchararray, (char **) NULL, 10) - 1;
          argumentsinglevalue += 2 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_mday = strtol (tempchararray, (char **) NULL, 10);
          argumentsinglevalue += 2 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_hour = strtol (tempchararray, (char **) NULL, 10);
          argumentsinglevalue += 2 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_min = strtol (tempchararray, (char **) NULL, 10);
          argumentsinglevalue += 2 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_sec = strtol (tempchararray, (char **) NULL, 10);

          /*
           * convert starttime parameter to long int
           */
          if ((timestruct.tm_mon > 11) || (timestruct.tm_mday > 31)
              || (timestruct.tm_hour > 23) || (timestruct.tm_min > 59)
              || (timestruct.tm_sec > 59))
            {
              fprintf (stderr,
                       "ERROR: illegal date format in argumentvalue\n");
              return NULL;
            }
          templong = (unsigned long) mktime (&timestruct);
          if (templong == -1)
            {
              fprintf (stderr,
                       "ERROR: illegal date format in argumentvalue\n");
              return NULL;
            }

          /*
           * create extended opsec value
           */
          lea_value = lea_value_ex_create ();
          if (lea_value_ex_set (lea_value, LEA_VT_TIME, templong) ==
              OPSEC_SESSION_ERR)
            {
              fprintf (stderr, "ERROR: failed to set starttime value (%s)\n",
                       opsec_errno_str (opsec_errno));
              lea_value_ex_destroy (lea_value);
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          /*
           * create filter predicate
           */
          if ((ppred =
               lea_filter_predicate_create ("time", -1, negation,
                                            LEA_FILTER_PRED_GREATER_EQUAL,
                                            lea_value)) == NULL)
            {
              fprintf (stderr, "ERROR: failed to create predicate\n");
              lea_value_ex_destroy (val_arr[argumentcount - 1]);
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          lea_value_ex_destroy (lea_value);

          /*
           * add current predicate to current rule
           */
          if (lea_filter_rule_add_predicate (prule, ppred) == LEA_FILTER_ERR)
            {
              fprintf (stderr, "ERROR: failed to add predicate to rule\n");
              lea_filter_rule_destroy (prule);
              lea_filter_predicate_destroy (ppred);
              return NULL;
            }

          lea_filter_predicate_destroy (ppred);
        }

      /*
       * process arguments of type "endtime"
       */
      else if (strcmp (argumentname, "endtime") == 0)
        {
          argumentsinglevalue = string_trim (argumentvalue, ' ');
          if (strlen (argumentsinglevalue) != 14)
            {
              fprintf (stderr,
                       "ERROR: syntax error in rule value of argument rule: '%s'.\n"
                       "       Required syntax: 'endtime=YYYYMMDDhhmmss'\n",
                       argumentsinglevalue);
              return NULL;
            }

          /*
           * convert starttime parameter to proper form (unixtime)
           */
          strncpy (tempchararray, argumentsinglevalue, 4);
          tempchararray[4] = '\0';
          timestruct.tm_year =
            strtol (tempchararray, (char **) NULL, 10) - 1900;
          argumentsinglevalue += 4 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_mon = strtol (tempchararray, (char **) NULL, 10) - 1;
          argumentsinglevalue += 2 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_mday = strtol (tempchararray, (char **) NULL, 10);
          argumentsinglevalue += 2 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_hour = strtol (tempchararray, (char **) NULL, 10);
          argumentsinglevalue += 2 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_min = strtol (tempchararray, (char **) NULL, 10);
          argumentsinglevalue += 2 * sizeof (char);
          strncpy (tempchararray, argumentsinglevalue, 2);
          tempchararray[2] = '\0';
          timestruct.tm_sec = strtol (tempchararray, (char **) NULL, 10);

          /*
           * convert starttime parameter to long int
           */
          if ((timestruct.tm_mon > 11) || (timestruct.tm_mday > 31)
              || (timestruct.tm_hour > 23) || (timestruct.tm_min > 59)
              || (timestruct.tm_sec > 59))
            {
              fprintf (stderr,
                       "ERROR: illegal date format in argumentvalue\n");
              return NULL;
            }
          templong = (unsigned long) mktime (&timestruct);
          if (templong == -1)
            {
              fprintf (stderr,
                       "ERROR: illegal date format in argumentvalue\n");
              return NULL;
            }

          /*
           * create extended opsec value
           */
          lea_value = lea_value_ex_create ();
          if (lea_value_ex_set (lea_value, LEA_VT_TIME, templong) ==
              OPSEC_SESSION_ERR)
            {
              fprintf (stderr, "ERROR: failed to set endtime value (%s)\n",
                       opsec_errno_str (opsec_errno));
              lea_value_ex_destroy (lea_value);
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          /*
           * create filter predicate
           */
          if ((ppred =
               lea_filter_predicate_create ("time", -1, negation,
                                            LEA_FILTER_PRED_SMALLER_EQUAL,
                                            lea_value)) == NULL)
            {
              fprintf (stderr, "ERROR: failed to create predicate\n");
              lea_value_ex_destroy (val_arr[argumentcount - 1]);
              lea_filter_rule_destroy (prule);
              return NULL;
            }

          lea_value_ex_destroy (lea_value);

          /*
           * add current predicate to current rule
           */
          if (lea_filter_rule_add_predicate (prule, ppred) == LEA_FILTER_ERR)
            {
              fprintf (stderr, "ERROR: failed to add predicate to rule\n");
              lea_filter_rule_destroy (prule);
              lea_filter_predicate_destroy (ppred);
              return NULL;
            }

          lea_filter_predicate_destroy (ppred);
        }

      /*
       * process unknown arguments
       */
      else
        {
          fprintf (stderr, "ERROR: Unknown filterargument: '%s'\n",
                   argumentname);
          return NULL;
        }
    }

  /*
   * add current rule to rulebase
   */
  if (lea_filter_rulebase_add_rule (prulebase, prule) != OPSEC_SESSION_OK)
    {
      fprintf (stderr, "failed to add rule to rulebase\n");
      lea_filter_rulebase_destroy (prulebase);
      lea_filter_rule_destroy (prule);
      return NULL;
    }

  lea_filter_rule_destroy (prule);

  return prulebase;
}

/*
 * BEGIN: function string_get_token
 */
char *
string_get_token (char **tokstring, char separator)
{
  char *tempstring = NULL;
  char *returnstring;
  int strlength;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function string_get_token\n");
    }

  /*
   * return if tokstring is NULL
   */
  if (*tokstring == NULL)
    {
      return NULL;
    }

  /*
   * search for first separator
   */
  tempstring = strchr (*tokstring, separator);

  /*
   * calculate string length
   */
  if (tempstring)
    {
      tempstring = tempstring + 1;
      strlength = strlen (*tokstring) - strlen (tempstring);
    }
  else
    {
      strlength = strlen (*tokstring) + 1;
    }

  returnstring = (char *) malloc (strlength + 1);
  if (returnstring == NULL)
    {
      fprintf (stderr, "ERROR: Out of memory\n");
      exit_loggrabber (1);
    }
  strncpy (returnstring, *tokstring, strlength);
  returnstring[strlength - 1] = '\0';

  *tokstring = tempstring;
  return returnstring;
}

/*
 * BEGIN: function string_duplicate
 */
char *
string_duplicate (const char *src)
{
  size_t length;
  char *dst;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function string_duplicate\n");
    }

  if (src == NULL)
    {
      return NULL;
    }

  length = strlen (src) + 1;
  dst = malloc (length);
  if (!dst)
    {
      fprintf (stderr, "ERROR: out of memory\n");
      exit_loggrabber (1);
    }
  return memcpy (dst, src, length);
}

/*
 * BEGIN: function string_left_trim
 */
char *
string_left_trim (char *string, char character)
{
  char *tmp;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function string_left_trim\n");
    }

  if (string == NULL)
    {
      return NULL;
    }
  tmp = string + strlen (string);
  while ((string[0] == character) && (string < tmp))
    string++;
  return (string);
}

/*
 * BEGIN: function string_right_trim
 */
char *
string_right_trim (char *string, char character)
{
  int tmp;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function string_right_trim\n");
    }

  if (string == NULL)
    {
      return NULL;
    }
  tmp = strlen (string);
  while ((string[tmp - 1] == character) && (tmp != 0))
    tmp--;
  string[tmp] = '\0';
  return (string);
}

/*
 * BEGIN: function string_trim
 */
char *
string_trim (char *string, char character)
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function string_trim\n");
    }

  return (string_right_trim
          (string_left_trim (string, character), character));
}

/*
 * BEGIN: function string_mask_newlines
 */
char *
string_mask_newlines (char *string)
{
  int i = 0;
  int z1, z2;
  int length = strlen (string);
  char *sptr = string;
  char *s;

  sptr = strchr (sptr, '\n');
  while (sptr != NULL)
    {
      i++;
      sptr = strchr (++sptr, '\n');
    }

  s = (char *) malloc (length + (i * 2) + 1);

  if (!s)
    {
      fprintf (stderr, "ERROR: out of memory\n");
      exit_loggrabber (1);
    }

  for (z1 = 0, z2 = 0; z1 < length; z1++)
    {
      if (string[z1] == '\n')
        {
          s[z2++] = '(';
          s[z2++] = '+';
          s[z2++] = ')';
        }
      else
        {
          s[z2++] = string[z1];
        }
    }

  s[z2] = '\0';

  return (s);
}

/*
 * BEGIN: function string_escape
 */
char *
string_escape (char *string, char character)
{
  int i = strlen (string);
  int z1, z2;
  char *s = (char *) malloc (i * 2 + 1);

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function string_escape\n");
    }

  /*
   * return if string is NULL
   */
  if (string == NULL)
    {
      return NULL;
    }

  if (!s)
    {
      fprintf (stderr, "ERROR: out of memory\n");
      exit_loggrabber (1);
    }

  for (z1 = 0, z2 = 0; z1 < i; z1++)
    {
      if ((string[z1] == character) || (string[z1] == '\\'))
        {
          s[z2++] = '\\';
        }
      s[z2++] = string[z1];
    }

  s[z2] = '\0';

  return (s);
}

/*
 * BEGIN: function string_rmchar
 */
char *
string_rmchar (char *string, char character)
{
  int i = strlen (string);
  int z1, z2;
  char *s = (char *) malloc (i + 1);

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function string_rmchar\n");
    }

  /*
   * return if string is NULL
   */
  if (string == NULL)
    {
      return NULL;
    }

  if (!s)
    {
      fprintf (stderr, "ERROR: out of memory\n");
      exit_loggrabber (1);
    }

  for (z1 = 0, z2 = 0; z1 < i; z1++)
    {
      if (string[z1] != character)
        {
          s[z2++] = string[z1];
        }
    }

  s[z2] = '\0';

  return (s);
}

/*
 * BEGIN: function string_touppper
 */
char *
string_toupper (const char *str1)
{
  char *tempstr1;
  unsigned int i;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function string_toupper\n");
    }

  /*
   * return if string is NULL
   */
  if (str1 == NULL)
    {
      return NULL;
    }

  tempstr1 = string_duplicate (str1);

  for (i = 0; i < strlen (tempstr1); i++)
    {
      tempstr1[i] = toupper (tempstr1[i]);
    }

  return (tempstr1);
}

/*
 * BEGIN: function string_icmp
 */
int
string_icmp (const char *str1, const char *str2)
{
  char *tempstr1;
  char *tempstr2;
  int cmpresult;
  unsigned int i;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function string_icmp\n");
    }

  tempstr1 = string_duplicate (str1);
  tempstr2 = string_duplicate (str2);

  for (i = 0; i < strlen (tempstr1); i++)
    {
      tempstr1[i] = tolower (tempstr1[i]);
    }

  for (i = 0; i < strlen (tempstr2); i++)
    {
      tempstr2[i] = tolower (tempstr2[i]);
    }

  cmpresult = strcmp (tempstr1, tempstr2);

  free (tempstr1);
  free (tempstr2);

  return (cmpresult);
}

/*
 * BEGIN: function string_incmp
 */
int
string_incmp (const char *str1, const char *str2, size_t count)
{
  char *tempstr1;
  char *tempstr2;
  int cmpresult;
  unsigned int i;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function string_incmp\n");
    }

  tempstr1 = string_duplicate (str1);
  tempstr2 = string_duplicate (str2);

  for (i = 0; i < strlen (tempstr1); i++)
    {
      tempstr1[i] = tolower (tempstr1[i]);
    }

  for (i = 0; i < strlen (tempstr2); i++)
    {
      tempstr2[i] = tolower (tempstr2[i]);
    }

  cmpresult = strncmp (tempstr1, tempstr2, count);

  free (tempstr1);
  free (tempstr2);

  return (cmpresult);
}

/*
 * BEGIN: function to read configuration file
 */
void
read_config_file (char *filename, configvalues * cfgvalues)
{
  FILE *configfile;
  char line[256];
  char *position;
  char *configparameter;
  char *configvalue;
  char *tmpstr;

  if ((configfile = fopen (filename, "r")) == NULL)
    {
      fprintf (stderr, "ERROR: Cannot open configfile (%s)\n", filename);
      exit_loggrabber (1);
    }

  while (fgets (line, sizeof line, configfile))
    {
      position = strchr (line, '\n');
      if (position)
        {
          *position = 0;
        }

      position = strchr (line, '#');
      if (position)
        {
          *position = 0;
        }

      configparameter = string_trim (strtok (line, "="), ' ');
      if (configparameter)
        {
          configvalue = string_trim (strtok (NULL, ""), ' ');
        }

      if (configparameter && configvalue)
        {
          if (debug_mode == 1)
            {
              fprintf (stderr, "DEBUG: %s=%s\n", configparameter,
                       configvalue);
            }
          if (strcmp (configparameter, "RECORD_SEPARATOR") == 0)
            {
              tmpstr = string_trim (configvalue, '"');
              if (tmpstr)
                {
                  cfgvalues->record_separator = tmpstr[0];
                }
            }
          else if (strcmp (configparameter, "DEBUG_LEVEL") == 0)
            {
              cfgvalues->debug_mode = atoi (string_trim (configvalue, '"'));
            }
          else if (strcmp (configparameter, "ONLINE_MODE") == 0)
            {
              configvalue = string_duplicate (string_trim (configvalue, '"'));
              if (string_icmp (configvalue, "no") == 0)
                {
                  cfgvalues->online_mode = 0;
                }
              else if (string_icmp (configvalue, "yes") == 0)
                {
                  cfgvalues->online_mode = 1;
                }
              else
                {
                  fprintf (stderr,
                           "WARNING: Illegal entry in configuration file: %s=%s\n",
                           configparameter, configvalue);
                }
              free (configvalue);
            }
          else if (strcmp (configparameter, "RESOLVE_MODE") == 0)
            {
              configvalue = string_duplicate (string_trim (configvalue, '"'));
              if (string_icmp (configvalue, "no") == 0)
                {
                  cfgvalues->resolve_mode = 0;
                }
              else if (string_icmp (configvalue, "yes") == 0)
                {
                  cfgvalues->resolve_mode = 1;
                }
              else
                {
                  fprintf (stderr,
                           "WARNING: Illegal entry in configuration file: %s=%s\n",
                           configparameter, configvalue);
                }
              free (configvalue);
            }
          else if (strcmp (configparameter, "FW1_TYPE") == 0)
            {
              configvalue = string_duplicate (string_trim (configvalue, '"'));
              if (string_icmp (configvalue, "ng") == 0)
                {
                  cfgvalues->fw1_2000 = 0;
                }
              else if (string_icmp (configvalue, "2000") == 0)
                {
                  cfgvalues->fw1_2000 = 1;
                }
              else
                {
                  fprintf (stderr,
                           "WARNING: Illegal entry in configuration file: %s=%s\n",
                           configparameter, configvalue);
                }
              free (configvalue);
            }
          else if (strcmp (configparameter, "FW1_MODE") == 0)
            {
              configvalue = string_duplicate (string_trim (configvalue, '"'));
              if (string_icmp (configvalue, "normal") == 0)
                {
                  cfgvalues->audit_mode = 0;
                }
              else if (string_icmp (configvalue, "audit") == 0)
                {
                  cfgvalues->audit_mode = 1;
                }
              else
                {
                  fprintf (stderr,
                           "WARNING: Illegal entry in configuration file: %s=%s\n",
                           configparameter, configvalue);
                }
              free (configvalue);
            }
          else if (strcmp (configparameter, "LOGGING_CONFIGURATION") == 0)
            {
              configvalue = string_duplicate (string_trim (configvalue, '"'));
              if (string_icmp (configvalue, "screen") == 0)
                {
                  cfgvalues->log_mode = SCREEN;
                }
              else if (string_icmp (configvalue, "file") == 0)
                {
                  cfgvalues->log_mode = LOGFILE;
                }
              else if (string_icmp (configvalue, "syslog") == 0)
                {
                  cfgvalues->log_mode = SYSLOG;
                }
              else
                {
                  fprintf (stderr,
                           "WARNING: Illegal entry in configuration file: %s=%s\n",
                           configparameter, configvalue);
                }
              free (configvalue);
            }
          else if (strcmp (configparameter, "OUTPUT_FILE_PREFIX") == 0)
            {
              cfgvalues->output_file_prefix =
                string_duplicate (string_trim (configvalue, '"'));
            }
          else if (strcmp (configparameter, "OUTPUT_FILE_ROTATESIZE") == 0)
            {
              cfgvalues->output_file_rotatesize =
                atol (string_trim (configvalue, '"'));
            }
          else if (strcmp (configparameter, "SYSLOG_FACILITY") == 0)
            {
              configvalue = string_duplicate (string_trim (configvalue, '"'));
              if (string_icmp (configvalue, "user") == 0)
                {
                  cfgvalues->syslog_facility = LOG_USER;
                }
              else if (string_icmp (configvalue, "local0") == 0)
                {
                  cfgvalues->syslog_facility = LOG_LOCAL0;
                }
              else if (string_icmp (configvalue, "local1") == 0)
                {
                  cfgvalues->syslog_facility = LOG_LOCAL1;
                }
              else if (string_icmp (configvalue, "local2") == 0)
                {
                  cfgvalues->syslog_facility = LOG_LOCAL2;
                }
              else if (string_icmp (configvalue, "local3") == 0)
                {
                  cfgvalues->syslog_facility = LOG_LOCAL3;
                }
              else if (string_icmp (configvalue, "local4") == 0)
                {
                  cfgvalues->syslog_facility = LOG_LOCAL4;
                }
              else if (string_icmp (configvalue, "local5") == 0)
                {
                  cfgvalues->syslog_facility = LOG_LOCAL5;
                }
              else if (string_icmp (configvalue, "local6") == 0)
                {
                  cfgvalues->syslog_facility = LOG_LOCAL6;
                }
              else if (string_icmp (configvalue, "local7") == 0)
                {
                  cfgvalues->syslog_facility = LOG_LOCAL7;
                }
              else
                {
                  fprintf (stderr,
                           "WARNING: Illegal entry in configuration file: %s=%s\n",
                           configparameter, configvalue);
                }
              free (configvalue);
            }
          else if (strcmp (configparameter, "FW1_OUTPUT") == 0)
            {
              configvalue = string_duplicate (string_trim (configvalue, '"'));
              if (string_icmp (configvalue, "files") == 0)
                {
                  cfgvalues->showfiles_mode = 1;
                }
              else if (string_icmp (configvalue, "logs") == 0)
                {
                  cfgvalues->showfiles_mode = 0;
                }
              else
                {
                  fprintf (stderr,
                           "WARNING: Illegal entry in configuration file: %s=%s\n",
                           configparameter, configvalue);
                }
              free (configvalue);
            }
          else if (strcmp (configparameter, "FW1_LOGFILE") == 0)
            {
              cfgvalues->fw1_logfile =
                string_duplicate (string_trim (configvalue, '"'));
            }
          else if (strcmp (configparameter, "FW1_FILTER_RULE") == 0)
            {
              cfgvalues->fw1_filter_count++;
              cfgvalues->fw1_filter_array =
                (char **) realloc (cfgvalues->fw1_filter_array,
                                   cfgvalues->fw1_filter_count *
                                   sizeof (char *));
              if (cfgvalues->fw1_filter_array == NULL)
                {
                  fprintf (stderr, "ERROR: Out of memory\n");
                  exit_loggrabber (1);
                }
              cfgvalues->fw1_filter_array[cfgvalues->fw1_filter_count - 1] =
                string_duplicate (string_trim (configvalue, '"'));
            }
          else if (strcmp (configparameter, "AUDIT_FILTER_RULE") == 0)
            {
              cfgvalues->audit_filter_count++;
              cfgvalues->audit_filter_array =
                (char **) realloc (cfgvalues->audit_filter_array,
                                   cfgvalues->audit_filter_count *
                                   sizeof (char *));
              if (cfgvalues->audit_filter_array == NULL)
                {
                  fprintf (stderr, "ERROR: Out of memory\n");
                  exit_loggrabber (1);
                }
              cfgvalues->audit_filter_array[cfgvalues->audit_filter_count -
                                            1] =
                string_duplicate (string_trim (configvalue, '"'));
            }
          else if (strcmp (configparameter, "IGNORE_FIELDS") == 0)
            {
              cfgvalues->ignore_fields =
                string_duplicate (string_trim (configvalue, '"'));
            }
          else if (strcmp (configparameter, "DATEFORMAT") == 0)
            {
              configvalue = string_duplicate (string_trim (configvalue, '"'));
              if (string_icmp (configvalue, "cp") == 0)
                {
                  cfgvalues->dateformat = DATETIME_CP;
                }
              else if (string_icmp (configvalue, "unix") == 0)
                {
                  cfgvalues->dateformat = DATETIME_UNIX;
                }
              else if (string_icmp (configvalue, "std") == 0)
                {
                  cfgvalues->dateformat = DATETIME_STD;
                }
              else
                {
                  fprintf (stderr,
                       "WARNING: Illegal entry in configuration file: %s=%s\n",
                       configparameter, configvalue);
                }
              free (configvalue);
            }
          else
            {
              fprintf (stderr,
                       "WARNING: Illegal entry in configuration file: %s=%s\n",
                       configparameter, configvalue);
            }
        }
    }

  fclose (configfile);
}

/*
 * BEGIN: function to initialize fields headers
 */
void
init_field_headers (char **headers[NUMBER_FIELDS])
{
  int i;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function init_field_headers\n");
    }

  for (i = 0; i < NUMBER_FIELDS; i++)
    {
      headers[i] = malloc (sizeof (char *));
      *headers[i] = NULL;
    }
}

/*
 * BEGIN: function to initialize fields values
 */
void
init_field_values (char **values[NUMBER_FIELDS])
{
  int i;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function init_field_values\n");
    }

  for (i = 0; i < NUMBER_FIELDS; i++)
    {
      values[i] = malloc (sizeof (char *));
      *values[i] = NULL;
    }
}

/*
 * BEGIN: function to free field pointers
 */
void
free_field_arrays (char **array[NUMBER_FIELDS])
{
  int i;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function free_field_arrays\n");
    }

  for (i = 0; i < NUMBER_FIELDS; i++)
    {
      if (array[i] != NULL)
        {
          if (*array[i] != NULL)
            {
              free (*array[i]);
              *array[i] = NULL;
            }
        }
      free (array[i]);
    }
}

/*
 * BEGIN: function to cleanup environment and exit fw1-loggrabber
 */
void
exit_loggrabber (int errorcode)
{

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function exit_loggrabber\n");
    }

  free_field_arrays (field_headers);
  free_field_arrays (field_values);

  if (LogfileName != NULL)
    {
      free (LogfileName);
    }
//      if (cfgvalues.fw1_logfile) {
//              free(cfgvalues.fw1_logfile);
//      }

//  for (i = 0; i < filtercount; i++)
//    {
//      if (filterarray[i])
//      {
//        free (filterarray[i]);
//      }
//    }

  while (sl)
    {
      sl = stringlist_delete (&sl);
    }

//  if (cfgvalues.config_filename != NULL) {
//    free (cfgvalues.config_filename);
//  }

//  if (cfgvalues.leaconfig_filename != NULL) {
//    free (cfgvalues.leaconfig_filename);
//  }

  exit (errorcode);
}

/*
 * initialization function to define open, submit and close handler
 */
void
logging_init_env (int logging)
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function logging_init_env\n");
    }

  // Specifies which logging operation shall be executed.
  switch (logging)
    {
    case SCREEN:
      open_log = &open_screen;
      submit_log = &submit_screen;
      close_log = &close_screen;
      break;
    case LOGFILE:
      open_log = &open_logfile;
      submit_log = &submit_logfile;
      close_log = &close_logfile;
      break;
    case SYSLOG:
      open_log = &open_syslog;
      submit_log = &submit_syslog;
      close_log = &close_syslog;
      break;
    default:
      open_log = &open_screen;
      submit_log = &submit_screen;
      close_log = &close_screen;
      break;
    }
  return;
}

/*
 * syslog initializations
 */
void
open_syslog ()
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function open_syslog\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr, "DEBUG: Open connection to Syslog.\n");
    }
  openlog ("fw1-loggrabber", LOG_CONS | LOG_PID | LOG_NDELAY,
           cfgvalues.syslog_facility);
  return;
}

void
submit_syslog (char *message)
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function submit_syslog\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr, "DEBUG: Submit message to Syslog.\n");
    }
  syslog (LOG_NOTICE, "%s", message);
  return;
}

void
close_syslog ()
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function close_syslog\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr, "DEBUG: Close connection to Syslog.\n");
    }
  closelog ();
  return;
}

/*
 * screen initializations
 */
void
open_screen ()
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function open_screen\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr, "DEBUG: Open connection to screen.\n");
    }
  //We don't need to do anything here
  return;
}

void
submit_screen (char *message)
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function submit_screen\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr, "DEBUG: Submit message to screen.\n");
    }
  fprintf (stdout, "%s\n", message);
  fflush (NULL);
  return;
}

void
close_screen ()
{
  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function close_screen\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr, "DEBUG: Close connection to screen.\n");
    }
  //We don't need to do anything here
  return;
}

/*
 * log file initializations
 */
void
open_logfile ()
{

  char *output_file_name;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function open_logfile\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr, "DEBUG: Initialize log file and open log file.\n");
    }

  //create current output filename
  output_file_name =
    (char *) malloc (strlen (cfgvalues.output_file_prefix) + 5);
  if (output_file_name == NULL)
    {
      fprintf (stderr, "ERROR: Out of memory\n");
      exit_loggrabber (1);
    }
  strcpy (output_file_name, cfgvalues.output_file_prefix);
  strcat (output_file_name, ".log");

  if ((logstream = fopen (output_file_name, "a+")) == NULL)
    {
      fprintf (stderr, "ERROR: Fail to open the log file.\n");
      exit_loggrabber (1);
    }

  return;
}

void
submit_logfile (char *message)
{

  int i;
  long fsize;
  char sn[100];
  char *output_file_name;

  time_t time_date;
  struct tm *current_date;
  int month;                      // 1 through 12
  int day;                        // 1 through max_days
  int year;                       // 1500 through 2200
  int hour;                       // 0 through 23
  int minute;                     // 0 through 59
  int second;                     // 0 through 59

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function submit_logfile\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr, "DEBUG: Submit message to log file.\n");
    }

  fprintf (logstream, "%s\n", message);

  //Check and see if it reaches the log file limitation
  fseek (logstream, 0, SEEK_CUR);
  fsize = ftell (logstream);
  /* File size check and see whether or not it reaches maximum */
  if (cfgvalues.output_file_rotatesize > 0 && fsize > cfgvalues.output_file_rotatesize)
    {
      //The log file will be refreshed.
      fclose (logstream);
      time_date = time (NULL);
      current_date = localtime (&time_date);
      month = current_date->tm_mon + 1;
      day = current_date->tm_mday;
      year = current_date->tm_year + 1900;
      hour = current_date->tm_hour;
      minute = current_date->tm_min;
      second = current_date->tm_sec;
      //create current output filename
      output_file_name =
        (char *) malloc (strlen (cfgvalues.output_file_prefix) + 5);
      strcpy (output_file_name, cfgvalues.output_file_prefix);
      strcat (output_file_name, ".log");
      //Copy log file
      sprintf (sn, "%s-%4.4d-%2.2d-%2.2d_%2.2d%2.2d%2.2d.log",
               cfgvalues.output_file_prefix, year, month, day, hour, minute,
               second);
      if (fileExist (sn))
        {
          //Unfortunately, events come in too fast
          i = 1;
          sprintf (sn, "%s-%4.4d-%2.2d-%2.2d_%2.2d%2.2d%2.2d_%d.log",
                   cfgvalues.output_file_prefix, year, month, day, hour,
                   minute, second, i);

          while (fileExist (sn))
            {
              i++;
              sprintf (sn, "%s-%4.4d-%2.2d-%2.2d_%2.2d%2.2d%2.2d_%d.log",
                       cfgvalues.output_file_prefix, year, month, day, hour,
                       minute, second, i);
            }                        //end of while
        }                        //end of inner if
      fileCopy (output_file_name, sn);
      //Clean log file
      if ((logstream = fopen (output_file_name, "w")) == NULL)
        {;
          fprintf (stderr, "ERROR: Fail to open the log file.\n");
          exit_loggrabber (1);
        }                        //end of inner if
    }                                //end of if

  return;
}

void
close_logfile ()
{

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function close_logfile\n");
    }

  if (cfgvalues.debug_mode)
    {
      fprintf (stderr, "DEBUG: Close the log file.\n");
    }
  fclose (logstream);

  return;
}

void
fileCopy (const char *inputFile, const char *outputFile)
{

  // The most recent character from input file to output file
  char x;

  // fpi points to the input file, fpo points to the output file
  FILE *fpi, *fpo;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function fileCopy\n");
    }

  // Open input file, read-only
  fpi = fopen (inputFile, "r");
  // Open output file, write-only
  fpo = fopen (outputFile, "w");

  // Get next char from input file, store in x, until we reach EOF
  while ((x = getc (fpi)) != -1)
    {
      putc (x, fpo);
    }

  //After we have done, close both files
  fclose (fpi);
  fclose (fpo);

  return;
}

int
fileExist (const char *fileName)
{
  FILE *infile;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function fileExist\n");
    }

  infile = fopen (fileName, "r");
  if (infile == NULL)
    {
      return FALSE;
    }
  else
    {
      fclose (infile);
      return TRUE;
    }                                //end of if
}

char
getschar ()
{
  char c;
  char ch;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function getschar\n");
    }

  ch = getchar ();
  while ((c = getchar ()) != '\n' && c != EOF);
  return ch;
}

int
integer_cmp (const void * a, const void * b)
{
  return ( *(int*)a - *(int*)b );
}

int
find_in_int_array (int * a, int len, int val)
{
  int left = 0;
  int right = len - 1;

  // Fast return if the value is less than the min or greater than the max
  if (len == 0 || val < a[left] || val > a[right])
    {
      return FALSE;
    }

  while (right >= left)
    {
      int middle = (right+left) / 2;
      if (val == a[middle])
        {
          return TRUE;
        }
      else if (val > a[middle])
        {
          left = middle + 1;
        }
      else
        {
          right = middle - 1;
        }
    }

  return FALSE;
}

void
check_config_files (char *loggrabberconf, char *leaconf)
{
  char *configdir;
  char *tempdir;
  char *opsecfile = NULL;
  char *tmpleaconf = NULL;
  char *tmploggrabberconf = NULL;
  char filebuff[1024];
  char *tempbuffer;

  FILE *filetest;

  long size;

  if (cfgvalues.debug_mode >= 2)
    {
      fprintf (stderr, "DEBUG: function check_config_files\n");
    }

  configdir = getenv ("LOGGRABBER_CONFIG_PATH");
  tempdir = getenv ("LOGGRABBER_TEMP_PATH");

  size = pathconf (".", _PC_PATH_MAX);
  if ((tmploggrabberconf = (char *) malloc ((size_t) size)) == NULL)
    {
      fprintf (stderr, "ERROR: Out of memory\n");
      exit_loggrabber (1);
    }

  // no fw1-loggrabber.conf specified via function parameter, default to 'fw1-loggrabber.conf' in cwd
  if (loggrabberconf == NULL)
    {
      if (getcwd (tmploggrabberconf, (size_t) size) == NULL)
        {
          fprintf (stderr, "ERROR: Cannot get current working directory\n");
          exit_loggrabber (1);
        }
      strcat (tmploggrabberconf, "/fw1-loggrabber.conf");
    }
  // fw1-loggrabber.conf specified via function parameter
  else
    {
      // first character of fw1-loggrabber.conf filename is '/' -> absolute path
      if (loggrabberconf[0] == '/')
        {
          strcpy (tmploggrabberconf, loggrabberconf);
        }
      // otherwise append the relative path to cwd
      else
        {
          if (getcwd (tmploggrabberconf, (size_t) size) == NULL)
            {
              fprintf (stderr,
                       "ERROR: Cannot get current working directory\n");
              exit_loggrabber (1);
            }
          strcat (tmploggrabberconf, "/");
          strcat (tmploggrabberconf, loggrabberconf);
        }
    }

  // cannot read loggrabber.conf, so try to look into LOGGRABBER_CONFIG_PATH
  if ((filetest = fopen (tmploggrabberconf, "r")) == NULL)
    {
      if (configdir != NULL)
        {
          strcpy (tmploggrabberconf, configdir);
          strcat (tmploggrabberconf, "/");
          strcat (tmploggrabberconf, loggrabberconf);

          // also cannot read fw1-loggrabber.conf in LOGGRABBER_CONFIG_PATH
          if ((filetest = fopen (tmploggrabberconf, "r")) == NULL)
            {
              fprintf (stderr,
                       "ERROR: Cannot open FW1-Loggrabber configuration file (%s)\n",
                       loggrabberconf);
              fprintf (stderr,
                       "       Specify either a absolute fw1-loggrabber.conf path on commandline,\n");
              fprintf (stderr,
                       "       or place fw1-loggrabber.conf into current working directory\n");
              fprintf (stderr,
                       "       or $LOGGRABBER_CONFIG_PATH directory.\n");
              exit_loggrabber (1);
            }
          else
            {
              fclose (filetest);
            }
        }
      else
        {
          fprintf (stderr,
                   "ERROR: Cannot open FW1-Loggrabber configuration file (%s)\n",
                   loggrabberconf);
          fprintf (stderr,
                   "       Specify either a absolute fw1-loggrabber.conf path on commandline,\n");
          fprintf (stderr,
                   "       or place fw1-loggrabber.conf into current working directory\n");
          fprintf (stderr, "       or $LOGGRABBER_CONFIG_PATH directory.\n");
          exit_loggrabber (1);
        }
    }
  else
    {
      fclose (filetest);
    }

  size = pathconf (".", _PC_PATH_MAX);
  if ((tmpleaconf = (char *) malloc ((size_t) size)) == NULL)
    {
      fprintf (stderr, "ERROR: Out of memory\n");
      exit_loggrabber (1);
    }

  // no lea.conf specified via function parameter, default to 'lea.conf' in cwd
  if (leaconf == NULL)
    {
      if (getcwd (tmpleaconf, (size_t) size) == NULL)
        {
          fprintf (stderr, "ERROR: Cannot get current working directory\n");
          exit_loggrabber (1);
        }
      strcat (tmpleaconf, "/lea.conf");
    }
  // lea.conf specified via function parameter
  else
    {
      // first character of lea.conf filename is '/' -> absolute path
      if (leaconf[0] == '/')
        {
          strcpy (tmpleaconf, leaconf);
        }
      // otherwise append the relative path to cwd
      else
        {
          if (getcwd (tmpleaconf, (size_t) size) == NULL)
            {
              fprintf (stderr,
                       "ERROR: Cannot get current working directory\n");
              exit_loggrabber (1);
            }
          strcat (tmpleaconf, "/");
          strcat (tmpleaconf, leaconf);
        }
    }

  // cannot read lea.conf, so try to look into LOGGRABBER_CONFIG_PATH
  if ((filetest = fopen (tmpleaconf, "r")) == NULL)
    {
      if (configdir != NULL)
        {
          strcpy (tmpleaconf, configdir);
          strcat (tmpleaconf, "/");
          strcat (tmpleaconf, leaconf);

          // also cannot read lea.conf in LOGGRABBER_CONFIG_PATH
          if ((filetest = fopen (tmpleaconf, "r")) == NULL)
            {
              fprintf (stderr,
                       "ERROR: Cannot open LEA configuration file (%s)\n",
                       leaconf);
              fprintf (stderr,
                       "       Specify either a absolute lea.conf path on commandline,\n");
              fprintf (stderr,
                       "       or place lea.conf into current working directory\n");
              fprintf (stderr,
                       "       or $LOGGRABBER_CONFIG_PATH directory.\n");
              exit_loggrabber (1);
            }
          else
            {
              fclose (filetest);
            }
        }
      else
        {
          fprintf (stderr, "ERROR: Cannot open LEA configuration file (%s)\n",
                   leaconf);
          fprintf (stderr,
                   "       Specify either a absolute lea.conf path on commandline,\n");
          fprintf (stderr,
                   "       or place lea.conf into current working directory\n");
          fprintf (stderr, "       or $LOGGRABBER_CONFIG_PATH directory.\n");
          exit_loggrabber (1);
        }
    }
  else
    {
      fclose (filetest);
    }

  // open lea.conf in order to get opsec_sslca_file value
  if ((filetest = fopen (tmpleaconf, "r")) == NULL)
    {
      fprintf (stderr, "ERROR: Cannot open LEA configuration file (%s)\n",
               leaconf);
      fprintf (stderr,
               "       Specify either a absolute lea.conf path on commandline,\n");
      fprintf (stderr,
               "       or place lea.conf into current working directory\n");
      fprintf (stderr, "       or $LOGGRABBER_CONFIG_PATH directory.\n");
      exit_loggrabber (1);
    }
  else
    {
      while (fgets (filebuff, 1023, filetest))
        {
          if (string_incmp (filebuff, "opsec_sslca_file", 16) == 0)
            {
              opsecfile = string_trim (filebuff + (16 * sizeof (char)), ' ');
              break;
            }
        }
    }

  // no opsec_sslca_file specified in lea.conf, so we probably don't need one...
  if (opsecfile != NULL)
    {
      // first character of opsec_sslca_file filename is '/' -> absolute path
      if (!(opsecfile[0] == '/'))
        {
          fprintf (stderr,
                   "WARNING: You specified a relative path for opsec_sslca_file in\n");
          fprintf (stderr, "         %s. When not using an\n", tmpleaconf);
          fprintf (stderr,
                   "         absolute path, the certificate will be searched in\n");
          fprintf (stderr,
                   "         $LOGGRABBER_TEMP_PATH or in current working.\n");
          fprintf (stderr,
                   "         directory if $LOGGRABBER_TEMP_PATH is not set.\n");
        }
    }

  cfgvalues.leaconfig_filename = string_duplicate (tmpleaconf);
  cfgvalues.config_filename = string_duplicate (tmploggrabberconf);

  if (debug_mode > 0)
    {
      fprintf (stderr, "DEBUG: LEA configuration file is: %s\n",
               cfgvalues.leaconfig_filename);
      fprintf (stderr, "DEBUG: LOGGRABBER configuration file is: %s\n",
               cfgvalues.config_filename);
    }

  if (tempdir != NULL)
    {
      tempbuffer = malloc (strlen (tempdir) + 10);
      if (tempbuffer == NULL)
        {
          fprintf (stderr, "ERROR: Out of memory\n");
          exit_loggrabber (1);
        }
      else
        {
          sprintf (tempbuffer, "OPSECDIR=%s", tempdir);
          putenv (tempbuffer);
        }
    }

  if (tmploggrabberconf != NULL)
    {
      free (tmploggrabberconf);
    }

  if (tmpleaconf != NULL)
    {
      free (tmpleaconf);
    }
}

/* Function prototypes for thread routines */
ThreadFuncReturnType leaRecordProcessor( void *data ){

    LinkedList * records;
    char* message;

    alive = TRUE;

    while(alive)
        {

                pthread_mutex_lock(&mutex);

                //Enter critical section
                if(isEmpty()) {
                        // end critical section
                        pthread_mutex_unlock(&mutex);
                        if (!(cfgvalues.fw1_2000)) {
                                if(suspended) {
                                        /* trig resume event */
                                        if (pEnv != NULL) {
                                                opsec_raise_event (pEnv, resumeent, (void *) 0);
                                        }
                                        suspended=FALSE;
                                }
                        }
                        SLEEPMIL(8);
                } else {
                        records = getFirst();
                        // end critical section
                        pthread_mutex_unlock(&mutex);
                        if(records != NULL) {
                                message = records->listElement;

                                //submit received lea record
                                submit_log (message);

                                //clean used memory
                                free(message);
                                free(records);
                        }

                }//end of if
        }//end while

        return 0;
}

