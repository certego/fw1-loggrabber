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

#include <stdio.h>
#ifdef WIN32
	#include <winbase.h>
	#define ThreadFuncType LPTHREAD_START_ROUTINE
	#define ThreadFuncReturnType DWORD WINAPI
	#define SLEEP(sec) Sleep(1000*sec)
	#define ThreadIDType DWORD
#else
	#include <sys/types.h>   /* system types */
	#include <unistd.h>      /* standard UNIX stuff */
	#include <pthread.h>
	#define ThreadFuncReturnType void *
	typedef void * (*ThreadFuncType) (void *);
	#define SLEEP(sec) sleep(sec)
	#define ThreadIDType pthread_t
#endif

void createThread(ThreadIDType * threadID, ThreadFuncType thread_func, void * data);

/* The following method is used solely for purpose of the unit test */
/* Function prototypes for thread routines */
ThreadFuncReturnType printMessageFunction( void *data ){
	char *message;
	message = (char *) data;
	while(1) {
		printf("%s\n", message);
		SLEEP(1);
	}
	printf("The thread that prints \"%s\" exited ...\n", message);
	return 0;
}

/*
int main() {
	testThread();
}
*/

int testThread() {

	char * env;
	ThreadIDType thread_id;
	char *message1 = "Thread 1.";
	char *message2 = "Thread 2.";
	int count=0;

	createThread(&thread_id, printMessageFunction, (void *)message1);
	SLEEP(1);
	createThread(&thread_id, printMessageFunction, (void *)message2);
	SLEEP(1);
	while(count<=100) {
		printf("The main thread.\n");
		SLEEP(1);
		count++;
	}
	printf("The main thread exits...\n");
	return 0;
}

/*
* A cover for thread creation function
*/
void createThread (ThreadIDType *threadID, ThreadFuncType thread_func, void * data) {
	#ifdef WIN32
		CreateThread(NULL, 0, thread_func, data, 0, threadID);
	#else
		if (pthread_create(threadID, NULL, thread_func, data) != 0) {
			fprintf(stderr, "failed to create thread ...\n");
			exit(2);
		}
	#endif
}
