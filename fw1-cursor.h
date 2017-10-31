#ifndef FW1CURSOR_H
#define FW1CURSOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define POSITION_MAX_SIZE 20

int   read_fw1_cursorfile(const char *LogfileName); // Return next log position from cursor file
void  write_fw1_cursorfile(const char *LogfileName, const char *message, const char separator); // Deduce next log position from current message
char* get_fw1_cursorname(const char *LogfileName); // Give cursor name associated with log file

#endif
