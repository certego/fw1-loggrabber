/*
 * Copyright 2004 by Xiaodong Lin, All rights reserved.
 *
 * queue.c
 * A dynamic data structure, which is used to store incoming Check Point LEA
 * records.
 */
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
/* LinkedList is an implementation of a dynamic data structure, which is used */
/* to store incoming Check Point LEA, i.e Linked List. It consists of records */
/* (called nodes)  that hold data and  are linked to each other.The following */
/* is an implementation of a singly linked list in c.                         */
/* Note that  this implementation  is not synchronized.  If  multiple threads */
/* access a list  concurrently,  and at least one of the threads modifies the */
/* list structurally,  it  must  be  synchronized externally.   (A structural */
/* modification is any operation  that adds  or deletes one or more elements; */
/* merely setting the value of an element is not a structural  modification.) */
/* This is typically accomplished by synchronizing synchronize threads through*/
/* mutex.                                                                     */
/*                                                                            */
/******************************************************************************/

#include <stdio.h>

typedef int Bool;

#define FALSE 0
#define TRUE 1

// The queue length limitation
int THRESHOLD = 1000;

typedef struct LinkedListElement {
	char *listElement; 				// content of any specified element in this list
	struct LinkedListElement *next; //The point to the next elementin this list
} LinkedList;

// The first node in the list, called the head
LinkedList * head;
// The last node in the list, called the tail, which is not necessary for a singly linked list
LinkedList * tail;
// The count of elements in the list
int countOfList=0;

void initialize();				//Initialization of a linked list
void setThreshold(int thresh);	//Set the queue length limitation
int getThreshold();				//Return the queue length limitation
Bool addFirst(char* data);		//Insert the given element at the beginning of this list.
Bool add(char* data);			//Append the given element to the end of this list.
void clearList();				//Remove all of the elements from this list.
void printList();				//Dsiplay all of the elements from this list.
int sizeofList();				//Return count of elements in queue
Bool isEmpty();					//Are there any elements on this list? true if nobody's home
Bool isFull();					//Does this list reach its limitation? true if so
LinkedList *getFirst();			//Return the first element in this list.

int main() {
	testLinkedList();
}

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
	} else	{
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
	THRESHOLD = thresh;
}

//Return the queue length limitation
int getThreshold(){
	return THRESHOLD;
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
	if(countOfList >= THRESHOLD) {
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
