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

#include "queue.h"

// The queue length limitation
int threadhold = 1000;

// The count of elements in the list
int countOfList=0;

/*
int main() {
        testLinkedList();
}
*/

/* The following method is used solely for purpose of the unit test */
int testLinkedList() {

        char* message;
        char* x;
        char* y;
        char stringbuffer[1024];
        int capacity = 100;
        LinkedList * xyz;

        initialize();

        if(isEmpty()) {
                printf ("The list is empty.\n");
        } else        {
                printf ("The list should be empty but isn't.\n");
        }

        sprintf(stringbuffer, "78");
        message = (char *) malloc(capacity+1);
        strcpy(message,stringbuffer);
        add(message);

        sprintf(stringbuffer, "90");
        message = (char *) malloc(capacity+1);
        strcpy(message,stringbuffer);
        add(message);

        sprintf(stringbuffer, "56");
        message = (char *) malloc(capacity+1);
        strcpy(message,stringbuffer);
        addFirst(message);

        sprintf(stringbuffer, "34");
        message = (char *) malloc(capacity+1);
        strcpy(message,stringbuffer);
        addFirst(message);

        sprintf(stringbuffer, "12");
        message = (char *) malloc(capacity+1);
        strcpy(message,stringbuffer);
        addFirst(message);

        printf ("display begins\n");
        printf ("The elements of list are shown as follows:\n");
        printList();
        printf ("display ends\n");

        xyz = getFirst();
        if(xyz != NULL) {
                x = xyz->listElement;
                printf ("x is %s\n",x);
                printf ("display begins\n");
                printf ("The elements of list are shown as follows:\n");
                printList();
                printf ("display ends\n");
                free(x);
                free(xyz);
        }

        xyz = getFirst();
        if(xyz != NULL) {
                y = xyz->listElement;
                printf ("y is %s\n",y);
                printf ("display begins\n");
                printf ("The elements of list are shown as follows:\n");
                printList();
                printf ("display ends\n");
                free(y);
                free(xyz);
        }

        sprintf(stringbuffer, "88");
        message = (char *) malloc(capacity+1);
        strcpy(message,stringbuffer);
        add(message);

        printf ("display begins\n");
        printf ("The elements of list are shown as follows:\n");
        printList();
        printf ("display ends\n");

        xyz = getFirst();
        if(xyz != NULL) {
                y = xyz->listElement;
                printf ("y is %s\n",y);
                free(y);
                free(xyz);
        }

        xyz = getFirst();
        if(xyz != NULL) {
                y = xyz->listElement;
                printf ("y is %s\n",y);
                free(y);
                free(xyz);
        }

        xyz = getFirst();
        if(xyz != NULL) {
                y = xyz->listElement;
                printf ("y is %s\n",y);
                free(y);
                free(xyz);
        }

        xyz = getFirst();
        if(xyz != NULL) {
                y = xyz->listElement;
                printf ("y is %s\n",y);
                free(y);
                free(xyz);
        }

        sprintf(stringbuffer, "12");
        message = (char *) malloc(capacity+1);
        strcpy(message,stringbuffer);
        add(message);

        sprintf(stringbuffer, "34");
        message = (char *) malloc(capacity+1);
        strcpy(message,stringbuffer);
        add(message);

    clearList();

        return 0;

}/* main */

//Initialization of a linked list
void initialize(){
    head = tail = NULL;
    countOfList=0;
}

//Set the queue length limitation
void setThreshold(int thresh) {
        threadhold = thresh;
}

//Return the queue length limitation
int getThreshold(){
        return threadhold;
}

//Append the specified element to the end of this list.
Bool add(char* data) {

        if(head == NULL) {
                head = (LinkedList *) malloc (sizeof (struct LinkedListElement));
                head -> listElement = data;
                head -> next = NULL;
                tail = head;
        } else {
                tail -> next = (LinkedList *) malloc (sizeof (struct LinkedListElement));
                tail = tail -> next;
                tail -> next = NULL;
                tail -> listElement = data;
        }
        countOfList++;
        return TRUE;
}

//Insert the given element at the beginning of this list.
Bool addFirst(char* data){
        LinkedList * listPointer;

        if(head == NULL) {
                head = (LinkedList *) malloc (sizeof (struct LinkedListElement));
                head -> listElement = data;
                head -> next = NULL;
                tail = head;
        } else {
                listPointer = (LinkedList *) malloc (sizeof (struct LinkedListElement));
                listPointer -> next = head;
                head = listPointer;
                head -> listElement = data;
        }
        countOfList++;
        return TRUE;
}

//Remove all of the elements from this list.
void clearList(){

        LinkedList * listPointer;
    if (head == NULL) {
                //printf ("The queue is empty!\n");
    } else {
                listPointer = head;
                while (listPointer != NULL) {
                        head = head -> next;
                        free(listPointer->listElement);
                    free(listPointer);
                    listPointer = head;
                }//end of while
                countOfList=0;
        }//end of if

}

//Dsiplay all of the elements from this list.
void printList(){

        LinkedList * listPointer;

    if (head == NULL) {
                //printf ("The queue is empty!\n");
    } else {
                listPointer = head;
                while (listPointer != NULL) {
                    printf ("Element = %s\n\r", listPointer -> listElement);
                    listPointer = listPointer -> next;
                }//end of while
        }//end of if
    printf ("\n\r");

}

//Return count of elements in queue
int sizeofList(){
        return countOfList;
}

//Are there any elements on this list? true if nobody's home
Bool isEmpty(){
    if (head == NULL) {
                //The list is empty.
                return TRUE;
    } else {
                return FALSE;
        }
}

//Does this list reach its limitation? true if so
Bool isFull() {
        if(countOfList >= threadhold) {
                return TRUE;
        } else {
                return FALSE;
        }
}

//Return the first element in this list.
LinkedList *getFirst(){

        LinkedList * tp;
        if(head==NULL) {
                //The list is empty, and no element will be returned
                return NULL;
        }
    tp = head;
    head = head -> next;
    if(head==NULL) {
                tail = NULL;
        }
    countOfList--;
    return tp;

}
