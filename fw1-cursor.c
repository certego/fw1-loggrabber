#include "fw1-cursor.h"

int read_fw1_cursorfile (const char *LogfileName) {
  FILE *fd;
  char line[POSITION_MAX_SIZE];

  char *current_cursor = get_fw1_cursorname (LogfileName);
  fd = fopen (current_cursor,"r");

  if (fd == NULL)
   {
      fprintf (stderr, "Error while opening the file %s in read mode.\n", current_cursor);
      fprintf (stderr, "Maybe, it doesn't exist yet.\n");
      free(current_cursor);
      return 0;
   }
   free(current_cursor);

   fgets (line, POSITION_MAX_SIZE, fd);
   fclose (fd);

   return atoi (line);
}

void write_fw1_cursorfile (const char *LogfileName, const char *message, const char separator) {
  FILE *fd;

  char *current_cursor = get_fw1_cursorname (LogfileName);
  char position[POSITION_MAX_SIZE];
  int i, j = 0;

  fd = fopen (current_cursor,"r+");

  if (fd == NULL)
   {
      fprintf (stderr, "Error while opening the file %s in r+ mode.\n", current_cursor);
      fprintf (stderr, "Maybe, it doesn't exist yet. Trying to open it in w mode.\n");

      fd = fopen (current_cursor,"w");
      if (fd == NULL)
      {
          fprintf (stderr, "Error while opening the file %s in w mode also.\n", current_cursor);
          free(current_cursor);
          exit (EXIT_FAILURE);
      }
   }
   free(current_cursor);

   // Extract cuurent position from message
   for (i=4; i<strlen (message); i++)
   {
     if ((char)message[i] != separator)
     {
       position[j] = message[i];
       j++;
     }
     else
     {
       break;
     }
   }

   fprintf (fd, "%d", atoi (position)+1);
   fclose (fd);
}

char* get_fw1_cursorname(const char *LogfileName) {
  char *cursor_name =
    (char *) malloc (strlen (LogfileName) + 7);
  if (cursor_name == NULL)
    {
      fprintf (stderr, "ERROR: Out of memory\n");
      exit(EXIT_FAILURE);
    }
  strcpy (cursor_name, LogfileName);
  strcat (cursor_name, ".cursor");

  return cursor_name;
}
