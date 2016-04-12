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

#include "thread.h"

/* The following method is used solely for purpose of the unit test */
/* Function prototypes for thread routines */
ThreadFuncReturnType printMessageFunction( void *data ){
        char *message;
        message = (char *) data;
        while(1) {
                printf("%s\n", message);
                SLEEPMIL(1);
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

        ThreadIDType thread_id;
        char *message1 = "Thread 1.";
        char *message2 = "Thread 2.";
        int count=0;

        createThread(&thread_id, printMessageFunction, (void *)message1);
        SLEEPMIL(1);
        createThread(&thread_id, printMessageFunction, (void *)message2);
        SLEEPMIL(1);
        while(count<=100) {
                printf("The main thread.\n");
                SLEEPMIL(1);
                count++;
        }
        printf("The main thread exits...\n");
        return 0;
}

/*
* A cover for thread creation function
*/
void createThread (ThreadIDType *threadID, ThreadFuncType thread_func, void * data) {
        if (pthread_create(threadID, NULL, thread_func, data) != 0) {
                fprintf(stderr, "failed to create thread ...\n");
                exit(2);
        }
}
