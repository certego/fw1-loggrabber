/******************************************************************************/
/* fw1-loggrabber - (C)2004 Torsten Fellhauer, Xiaodong Lin                   */
/******************************************************************************/
/* Version: 1.11                                                              */
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
/* This is a  cross-platform thread implementation,  which is used to achieve */
/* the producer/consumer (sometimes called pipelining) model. In our applica- */
/* tion, the  program main thread running  opsec_mainloop()  is our producer, */
/* which produces data that is received from Check LEA server. Another thread,*/
/* which processing these datas, such as store into database, store into log  */
/* file, etc., is our consumer.                                               */
/* Note that for any *Nix, POSIX threads, or Pthreads has been used.Therefore,*/
/* it should link with -lpthread.                                             */
/*                                                                            */
/******************************************************************************/
#ifndef THREAD_H
#define THREAD_H

#include <stdio.h>
#ifdef WIN32
	#include <winbase.h>
	#define ThreadFuncType LPTHREAD_START_ROUTINE
	#define ThreadFuncReturnType DWORD WINAPI
	#define SLEEPMIL(millisec) Sleep(millisec)
	#define ThreadIDType DWORD
#else
	#include <sys/types.h>   /* system types */
	#include <unistd.h>      /* standard UNIX stuff */
	#include <pthread.h>
	#define ThreadFuncReturnType void *
	typedef void * (*ThreadFuncType) (void *);
	#define SLEEPMIL(millisec) usleep(millisec*1000)
	#define ThreadIDType pthread_t
#endif

void createThread(ThreadIDType * threadID, ThreadFuncType thread_func, void * data);

#endif
