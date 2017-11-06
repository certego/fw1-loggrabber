#ifndef FW1CURSOR_H
#define FW1CURSOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define POSITION_MAX_SIZE 32

FILE *cursorstream;
char cursorline[POSITION_MAX_SIZE + 1];

int read_fw1_cursorfile (); // Return next log position from cursor file
int write_fw1_cursorfile (const char *message, const char separator); // Deduce next log position from current message
char* get_fw1_cursorname (const char *LogfileName); // Give cursor name associated with log file
void open_fw1_cursorfile (const char *LogfileName); // Initialize cursorstream file handler
void close_fw1_cursorfile (); // Close cursorstream file handler

#endif
