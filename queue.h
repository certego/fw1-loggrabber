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
#ifndef QUEUE_H
#define QUEUE_H

#include <stdio.h>
#include <stdlib.h>

typedef int Bool;

#define FALSE 0
#define TRUE 1

typedef struct LinkedListElement {
	char *listElement; 				// content of any specified element in this list
	struct LinkedListElement *next; //The point to the next elementin this list
} LinkedList;

// The first node in the list, called the head
LinkedList * head;
// The last node in the list, called the tail, which is not necessary for a singly linked list
LinkedList * tail;

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

#endif
