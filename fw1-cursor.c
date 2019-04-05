#include "fw1-cursor.h"

#define CURSOR_FILE_EXT ".cursor"

int read_fw1_cursorfile () {
   rewind (cursorstream);
   fgets (cursorline, (POSITION_MAX_SIZE + 1), cursorstream);

   return atoi (cursorline);
}

/* Write next log position
 * return number of characters written
 */
int write_fw1_cursorfile (const char *message, const char separator) {
  char position[POSITION_MAX_SIZE];
  unsigned int i, j = 0;

  rewind (cursorstream);

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

   return fprintf (cursorstream, "%0" TOSTRING(POSITION_MAX_SIZE) "d\n", atoi (position)+1);
}

char* get_fw1_cursorname(const char *LogfileName) {
  char *cursorname =
    (char *) malloc (sizeof(char) * (strlen (LogfileName) + strlen (CURSOR_FILE_EXT) + 1));
  if (cursorname == NULL)
    {
      fprintf (stderr, "ERROR: Out of memory\n");
      exit(EXIT_FAILURE);
    }
  strcpy (cursorname, LogfileName);
  strcat (cursorname, CURSOR_FILE_EXT);

  return cursorname;
}

void open_fw1_cursorfile (const char *LogfileName) {
  char *cursorname = get_fw1_cursorname (LogfileName);

  // Open the file in "a" mode first to create it if it doesn't exist yet
  cursorstream = fopen (cursorname,"a");
  if (cursorstream == NULL)
   {
      fprintf (stderr, "Error while opening the file %s in a mode.\n", cursorname);
      free (cursorname);
      exit(EXIT_FAILURE);
   }
   fclose (cursorstream);

  // Open the file in "a" mode first to create it if it doesn't exist yet
  cursorstream = fopen (cursorname,"r+");
   if (cursorstream == NULL)
    {
       fprintf (stderr, "Error while opening the file %s in r+ mode.\n", cursorname);
       free (cursorname);
       exit(EXIT_FAILURE);
    }

    free (cursorname);
}

void  close_fw1_cursorfile() {
  fclose (cursorstream);
}
