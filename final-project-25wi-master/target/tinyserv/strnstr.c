#include <string.h>
#include "strnstr.h"

/* This is just a basic strnstr implementation since umnak doesn't
   have libbsd. You can safely ignore what it does internally */
char *strnstr(const char *haystack, const char *needle, size_t len)
{
        int i;
        size_t needle_len;

        /* segfault here if needle is not NULL terminated */
        if (0 == (needle_len = strlen(needle)))
                return (char *)haystack;

        for (i=0; i<=(int)(len-needle_len); i++)
        {
                if ((haystack[0] == needle[0]) &&
                        (0 == strncmp(haystack, needle, needle_len)))
                        return (char *)haystack;

                haystack++;
        }
        return NULL;
}
