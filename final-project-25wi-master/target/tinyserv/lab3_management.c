#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include "strnstr.h"
/* All of this is ONLY related to the management of the group
   secret. It is not related to the assignment, and you don't need to
   read or understand it.  If you see something broken, do tell us :)*/

#include "lab3_management.h"
/*
 * Outermost "login" to the HTTP server.
 * (really just to prevent groups from messing
 * with other groups.)
 */
int auth_group(const char *hdr, size_t hdr_len)
{
  return NULL != strnstr(hdr, lab_group_secret_key, hdr_len);
}

/* Return a pointer to the full 403 response on the heap. Needs
   to be freed after send */
char *make_403_response()
{
  size_t max_resp_size = 2 * (sizeof(resp403) + sizeof(resp403body));
  char *resp = calloc(max_resp_size, sizeof(char));
  assert(resp && "Couldn't allocate buffer for 403 response hdr+body");
  snprintf(resp, max_resp_size - 1, resp403, sizeof(resp403body) - 1,
     resp403body);
  return resp;
}

char *make_400_improper_syntax_response()
{
  size_t max_resp_size =
      2 * (sizeof(resp400) + sizeof(resp400_improper_syntax_body));
  char *resp = calloc(max_resp_size, sizeof(char));
  assert(resp && "Couldn't allocate buffer for 400 response hdr+body");
  snprintf(resp, max_resp_size - 1,
     resp400, sizeof(resp400_improper_syntax_body) - 1,
     resp400_improper_syntax_body);
  return resp;
}

char *make_400_too_long_response()
{
  size_t max_resp_size =
      2 * (sizeof(resp400) + sizeof(resp400_too_long_body));
  char *resp = calloc(max_resp_size, sizeof(char));
  assert(resp && "Couldn't allocate buffer for 400 response hdr+body");
  snprintf(resp, max_resp_size - 1,
     resp400, sizeof(resp400_too_long_body) - 1,
     resp400_too_long_body);
  return resp;
}
