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

#ifndef THREAD_H
#define THREAD_H

#ifdef WIN32
#	include <stdio.h>
#	include <stdlib.h>
#	include <sys/types.h>   /* system types */
#	include <pthread.h>     /* trying with pthreads-w32-2-9-1-release */
#	include <windows.h>
#	define SLEEPMIL(millisec) Sleep(millisec*1000)
#else
#	include <stdio.h>
#	include <stdlib.h>
#	include <sys/types.h>   /* system types */
#	include <unistd.h>      /* standard UNIX stuff */
#	include <pthread.h>
#	define SLEEPMIL(millisec) usleep(millisec*1000)
#endif

#define ThreadFuncReturnType void *
typedef void * (*ThreadFuncType) (void *);
#define ThreadIDType pthread_t

void createThread(ThreadIDType * threadID, ThreadFuncType thread_func, void * data);

#endif
