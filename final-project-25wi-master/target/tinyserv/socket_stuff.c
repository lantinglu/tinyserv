#include <string.h>
#include <stdio.h>
#include "error.h"
#include "socket_stuff.h"
#include "lab3_management.h"
/* create & bind socket */
static struct sockaddr_in serv_addr;
const char *default_addr = "0.0.0.0";

int prepare_socket()
{
  long addr = inet_addr(default_addr);
  /* create socket */
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  /* Options for reuseaddr and reuseport (if in this version) to
     allow quick restart and rebind of the server */
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int) { 1 }, sizeof(int)) < 0)
    tinyserv_perror("setsockopt(SO_REUSEADDR) failed");
#ifdef SO_REUSEPORT
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &(int) { 1 }, sizeof(int)) < 0)
    tinyserv_perror("setsockopt(SO_REUSEPORT) failed");
#endif
  if (sock < 0)
    tinyserv_perror("Couldn't create socket");

  /* prepare tools */
  bzero((char *)&serv_addr, sizeof(serv_addr));  // initialize to zero
  serv_addr.sin_family = AF_INET;  // set address family to 'internet'
  serv_addr.sin_port = htons(GROUP_PORT_NO);  // convert host port to network port
  serv_addr.sin_addr.s_addr = addr;

  /* bind socket */
  if (bind(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    tinyserv_perror
      ("Couldn't bind socket in prepare_socket. Make sure you've stopped any running tinyserv processes before rerunning (running `killall -u tinyserv` in terminal will do the trick). If this doesn't work, you can try again in 5 minutes. If this fails, contact course staff.");
  }

  /* go online */
  listen(sock, 5);    // 5 is the standard maximum for waiting socket clients
  printf
    ("------------------------------\n    Listening on port %d\n       EXIT WITH CTRL+C       \n------------------------------\r\n",
     GROUP_PORT_NO);
  return sock;
}
