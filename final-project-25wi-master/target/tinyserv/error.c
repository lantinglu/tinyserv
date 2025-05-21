#include "error.h"
#include <stdio.h>
#include <stdlib.h>
/* tinyserv's error handler */
void tinyserv_error(char *msg)
{
  fprintf(stderr,msg);
  exit(1);
}

/* Same, but for when syscalls fail */
void tinyserv_perror(char *msg)
{
  perror(msg);
  exit(1);
}
