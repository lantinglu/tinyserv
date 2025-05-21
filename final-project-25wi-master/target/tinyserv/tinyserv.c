/*
  *  A simple single-threaded HTTP server.
  *
  * Meta-note: Normally a lot of this stuff would be in various header files.
  *       We've put it all in one place because it simplifies the patching
  *       management. Please don't significantly reformat or reorg things.
  *       You can't (and don't need to) change anything in any other file.
  *       You also won't be able to add any non-standard libraries.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/random.h>
#include <assert.h>
#include <time.h>
#include <sys/select.h>
#include <stdbool.h>
#include <ctype.h>
#include "hmac.h"
#include "strnstr.h"
#include "sha1.h"
#include "socket_stuff.h"
#include "lab3_management.h"
#include "error.h"

/* _____ OPTIONS _____ */
#define BUFFER_SIZE 1024  // size of connection buffer in bytes, minimum 512
#define MAX_READ ((1<<16))

#define COOKIE_VALID_DURATION (60*60*48) // How long an authentication cookie stays valid, in seconds.

#define LOGIN_PAGE "login.html"  // route to the admin login interface
#define ADMIN_PAGE "admin.txt"  // route to the admin dashboard
#define PASSWORD_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define PASSWORD_LEN 20
#define MAX_BUFFER_SIZE 4000
// const uint8_t *admin_cookie_key = (char[]) {
//   0x4E, 0x2B, 0xE2, 0x5A, 0xCC, 0x99, 0xA9, 0xAA,
//   0xC6, 0x6F, 0xB6, 0xCE, 0x21, 0x7F, 0x07, 0x1A,
//   0x47, 0x0B, 0xCE, 0x95, 0xB5, 0x3D, 0x6E, 0xD5,
//   0xB4, 0x6D, 0xA7, 0xE9, 0xF4, 0xD6, 0x55, 0x5E
// };
#define COOKIE_KEY_FILE "cookie_key.txt"
#define KEY_LENGTH 32

static uint8_t admin_cookie_key[KEY_LENGTH + 1]; 

void generate_admin_cookie_key();
void save_cookie_key_to_file(const char *username);
void load_cookie_key_from_file(const char *username);

/* _____ GLOBALS _____ */
int sock; // Our socket handle
static char *webroot;    // webroot directory
static int client_addr_len, pkt_size;  // socket handle;
static int connection_fd;  // connection handles
static char *conn_buffer; // Buffer for holding various content to/from the client
static struct sockaddr_in client_addr; // server and client addresses
static int online;    // status of server
static int error_receiving_data = 0;
char password[PASSWORD_LEN + 1];  // admin password

/* Response caching management */
#define MAX_CACHE_ENTRIES 256
#define MAX_CACHE_ENTRY_SIZE 350*1024  // Maximum size allowed for a cached response
struct cache_entry {
  char *response;
  size_t len;
};
struct cache_entry cache[MAX_CACHE_ENTRIES];  // The actual cache entries

/* Admin authentication cookie struct */
typedef struct {
  uint32_t authenticated;  // must be exactly 1 to be authenticated
  time_t expiration;    // must be in the future to be authenticated
} cookie_data;

/* Right now, we only log the referer, is_admin, and is_get. later
   todo: date/etc at some point*/
struct header {
  char date[50];
  size_t referer_len;
  char referer[256];
  int is_admin;
  int is_get;
  int is_redirect;
};

/* _____ FUNCTIONS _____ */
void parse_args(int argc, const char *argv[]);  // parse command line arguments
uint32_t uniform_random(uint32_t upper_bound);  // generate a nonnegative integer less than upper_bound uniformly at random
void generate_password();  // create and print the admin password

void accept_connections();  // accept requests and process them
long int get_packet_from_client(); // Handles reading the message from the client into our buffer
void serve();  // serve client
char *get_header(char *packet, struct header *hdr);  // generate header for response
char *header_helper(int status_code, char *status_msg, char *content_type, int packet_length, int filename_length);  // prints header to packet buffer
char *cookie_header_helper(char *url);
char *tmp_redirect_helper(char *url);  // prints status 302 header to packet buffer
char *redirect_helper(char *url);  // prints status 301 header to packet buffer
int log_request(const char *m, size_t m_len);  // write a short summary of the request to admin.txt
void log_invalid(const char* message, const char *extra, size_t extra_len); // Log data about bad admin logins, admin_log.txt attempts, etc.
void send_header(const char *header);  // send header to client
void init_cache();    // Setup the cache to be all empty at start
bool maybe_send_cached_response( char *buf);  // Check if there is a cached response available for this page
int send_data(char *data, int data_len);  // send data to client
void send_file(char *file_path, char *dynamic_page);  // send template or not a file and send to client
int file_size(char *file);  // get file size in bytes
int file_exists(char *file);  // check if file exists
void file_build_path( char *packet);  // combine webroot directory w/ requested file's path in packet buffer
char *file_build_absolute_path( char *filename);  // write filename to beginning of buffer
char *url_build( char *packet);  // build url in packet buffer
int get_referer(const char *m, size_t m_len, const char **referer_p);  // pull host uri from request header
int packet_is_admin_page(char *packet);  // determine whether request is for the admin page
int packet_is_login_page(char *packet);  // determine whether request is for the login page
int is_logout_page(char *m, size_t m_len);
int file_is_admin_page(char *file);  // determine whether request is for the admin page
int file_is_login_page(char *file);  // determine whether request is for the login page
int auth(char *packet);    // check if username and password are valid admin credentials
int make_cookie(uint8_t * buffer);  // generates a new cookie, encodes it in base16, and writes it to buffer
char *logout_header();  // generate the header for logout
int check_cookie(char *packet, size_t p_len);  // check if cookie is valid for the admin page
void cleanup_and_exit(int);  // cleanup memory, and exit (called w/ CTRL+C)

int main(int argc, const char *argv[])
{
  /* parse args */
  parse_args(argc, argv);

  /* generate admin password */
  generate_password();
  load_cookie_key_from_file("admin");

  /* print admin password */
  printf("\n------------------------------\n"
         "Admin password follows, keep it secret:\n%s\n",
         password);

  /* init cache to be all empty entries */
  init_cache();

  /* register exit signal (CTRL+C) */
  signal(SIGINT, cleanup_and_exit);

  /* register auto-shutdown */
  signal(SIGALRM, cleanup_and_exit);
  alarm(3 * 60 * 60);

  /* prepare socket */
  sock = prepare_socket();

  /* accept connections (loop) */
  accept_connections();
}

/* parse CLI arguments */
void parse_args(int argc, const char *argv[])
{
  // check number of args
  if (argc != 2)
    tinyserv_error("Usage: ./tinyserv <webroot directory>\n\tExample: ./tinyserv ./files/\n");

  // Ensure the webroot ends in slash
  // And save it.
  size_t webrootlen = strlen(argv[1]);
  if(argv[1][webrootlen-1] == '/'){
    webroot = malloc(webrootlen + 1);
    strcpy(webroot, argv[1]);
  }
  else{
    webroot = malloc(webrootlen + 2);
    strcpy(webroot, argv[1]);
    webroot[webrootlen] = '/';
    webroot[webrootlen+1] = '\0';
  }

  // verify dir exists
  if (0 != access(webroot, F_OK)) {
    if (ENOENT == errno) {
      // does not exist
      tinyserv_error("Webroot directory does not exist. "
            "This should probably be the files directory in the repo.\n");
    }
    if (ENOTDIR == errno) {
      // not a directory
      tinyserv_error("Path given is not directory. "
            "This should probably be the files directory in the repo.\n");
    }
  }

  printf("\nWebroot is %s, serving files from there.\n",webroot);
}

/* generate an integer in the range [0,upper_bound) uniformly at random */
uint32_t uniform_random(uint32_t upper_bound)
{
  if (upper_bound == 0)
    exit(EXIT_FAILURE);
  if (upper_bound == 1)
    return 1;
  uint32_t mask = 1;
  while (mask < upper_bound) {
    mask = 2 * (mask + 1) - 1;  // mask is always of the form 2^n-1
  }
  uint32_t bytes[4];
  while (1) {
    size_t expected_bytes = 4 * sizeof(uint32_t);
    int result = getrandom(bytes, expected_bytes, 0);
    assert(result == expected_bytes &&
           "Couldn't read enough random bytes in uniform_random");
    assert(result >= 0 && "Couldn't read random bytes using getrandom");

    for (int i = 0; i < 4; i++) {
      uint32_t candidate = bytes[i] & mask;
      if (candidate < upper_bound) {
        return candidate;
      }
    }
  };
}

/* create the admin password */
void generate_password()
{
  for (int i = 0; i < PASSWORD_LEN; i++) {
    uint32_t random = uniform_random(strlen(PASSWORD_CHARS));
    password[i] = PASSWORD_CHARS[random];
  }
  password[PASSWORD_LEN] = '\0';
}


/* accept socket connections and serve content */
void accept_connections()
{
  client_addr_len = sizeof(client_addr);
  while (1) {
    bzero(&client_addr, sizeof(struct sockaddr_in));
    connection_fd = accept(sock, (struct sockaddr *)
                           &client_addr, (unsigned int *)&client_addr_len);
    if (connection_fd < 0) {
      tinyserv_perror("Error accepting client.\n");
    }
    serve();
  }
}

long int get_packet_from_client()
{
  conn_buffer = calloc(BUFFER_SIZE, sizeof(char));
  assert(conn_buffer &&
         "Couldn't allocate initial buffer for reading client data");

  int total_buffer_size = BUFFER_SIZE;
  int packet_size = 0;

  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = 0;

  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(connection_fd, &readfds);
  char temp_buf[BUFFER_SIZE] = { 0 };

  while (1) {
    int temp_size = (int)read(connection_fd, temp_buf, BUFFER_SIZE);

    if (temp_size < 0) {
      tinyserv_perror("Couldn't read from socket in get_packet_from_client");
    }

    if (packet_size + temp_size >= MAX_READ) {
      error_receiving_data = 1;
      return -1;
    }

    if (packet_size + temp_size > total_buffer_size - 1) {
      total_buffer_size *= 2;
      conn_buffer = (char *)realloc(conn_buffer, total_buffer_size);
      assert(conn_buffer
             && "Couldn't reallocate more space for reading client data");
    }

    strncpy(conn_buffer + packet_size, temp_buf, temp_size);
    packet_size += temp_size;
    conn_buffer[packet_size] = '\0'; // We treat this as a string later

    int sel_rv = select(connection_fd + 1, &readfds, NULL, NULL, &timeout);

    if (sel_rv == 0) {
      break;
    }

    if (temp_size == 0) {
      break;
    }
  }

  return packet_size;
}

/* respond to client requests */
void serve()
{
  /* allocate resources */
  int timeout = 0;    // timeout counter; 3 1-second empty reads until session ends
  struct header hdr = { 0 };

  /* serving client */
  while (timeout < 3) {
    pkt_size = get_packet_from_client();

    if (error_receiving_data || pkt_size < 0) {
      char *too_long_resp_400 = make_400_too_long_response();
      /* send_header is more like send_string; it'll
         send the whole response */
      send_header(too_long_resp_400);
      free(too_long_resp_400);
      break;
    }

    if (log_request(conn_buffer, pkt_size)) {
      char *bad_syntax_resp_400 = make_400_improper_syntax_response();
      send_header(bad_syntax_resp_400);
      free(bad_syntax_resp_400);
      break;
    }

    /* Auth the group using the cookie. Your patches
       should not alter this code through the next comment
       that starts "End group auth...". */
    char *hdr_start = conn_buffer;
    const char *dbl_crlf = "\r\n\r\n";
    char *eor = strnstr(hdr_start, dbl_crlf, pkt_size);
    if (NULL == eor) {
      char *bad_syntax_resp_400 = make_400_improper_syntax_response();
      send_header(bad_syntax_resp_400);
      free(bad_syntax_resp_400);
      break;
    }

    size_t hdr_len = (size_t)(eor - hdr_start) + strlen(dbl_crlf);
    if (!auth_group(hdr_start, hdr_len)) {
      char *unauth_resp_403 = make_403_response();
      send_header(unauth_resp_403);
      free(unauth_resp_403);
      break;
    }
    /* End group auth. admin auth happens further down. */

    // if there's nothing to read
    if (pkt_size <= 0) {
      timeout++;    /*increment timeout counter */
    } else {
      char *header = get_header(conn_buffer, &hdr);
      send_header(header);  // parse what was read & send response header
      if (MAX_BUFFER_SIZE < (short int)pkt_size) {  // check input is good size
        send_file("400.html", NULL);
        break;
      }
      size_t temp_buf_len = pkt_size + 1;
      char *temp_buf = calloc(temp_buf_len, sizeof(char));
      strncpy(temp_buf, conn_buffer, pkt_size);

      if (strnstr(temp_buf, "http://", 7) == NULL) {  // if not a redirect
        if (file_is_login_page(temp_buf)) {
          send_file(LOGIN_PAGE, NULL);
        } else if (hdr.is_admin && file_is_admin_page(temp_buf)) {  // already authenticated via get_header
          send_file(temp_buf, NULL);
        } else if (!maybe_send_cached_response(temp_buf)) {
          // There wasn't a cached response, so go find and send the correct response
          if (file_exists(temp_buf)) {
            send_file(temp_buf, NULL);  // send HTTP payload
          } else {    // if file doesn't exist
            char url[100];  // url used in templated 404 page
            snprintf(url, 100, "http://%s",
                     temp_buf + strlen(webroot));
            send_file("404.html", url);
          }
        }
      }
      free(temp_buf);
      /* NO CONNECTIONS ARE PERSISTANT--if response was sent, close connection */
      break;
    }
  }

  /* ending session */
  shutdown(connection_fd, SHUT_RDWR);  // close connection
  free(conn_buffer);    // deallocate buffer
}

/* build response header based on request packet */
char *get_header( char *packet, struct header *hdr)
{
  char *request = strnstr(packet, "GET", 32);  // search for GET

  if (request != NULL) {
    hdr->is_get = 1;

    /* if /go/ redirect specified */
    if (strnstr(packet, " /go/", 16) != NULL) {
      return redirect_helper(url_build(packet));
    }

    /* if user is authenticating via login page */
    if (packet_is_login_page(packet)) {
      if (check_cookie(packet, pkt_size) || auth(packet)) {
        char url[32] = { 0 };
        url[0] = '/';
        strcat(url, ADMIN_PAGE);
        return cookie_header_helper(url);
      } else {
        file_build_absolute_path(LOGIN_PAGE);
        return header_helper(200, "OK", "text/html",
                             file_size(LOGIN_PAGE), (int)strlen(LOGIN_PAGE));
      }
    }

    /* if request is for admin page */
    else if (packet_is_admin_page(packet)) {
      hdr->is_admin = check_cookie(packet, pkt_size);

      /* get the referer to see where this user came from (if
         specified) to log that a non-admin has made an admin page
         request */
      if (!hdr->is_admin) {
        /* +2 to account for the last \r\n actually being part of a
           header. Otherwise our header_len is cutting off early.*/
        size_t header_len = strstr(packet, "\r\n\r\n") - packet + 2;
        const char *referer_uri;
        hdr->referer_len = get_referer(packet, header_len, &referer_uri);

        if (hdr->referer_len) {
          strncpy(hdr->referer, referer_uri, hdr->referer_len);
          hdr->referer[hdr->referer_len + 1] = '\0';
        }

        /* log the admin page request */
        log_invalid("Unauthorized log read with Referer:",hdr->referer, hdr->referer_len);
      }

      /* if they were authd, then serve the admin page */
      if (hdr->is_admin) {
        file_build_absolute_path(ADMIN_PAGE);
        return header_helper(200, "OK",
                             "text/plain",
                             file_size(ADMIN_PAGE), (int)strlen(ADMIN_PAGE));
      } else {
        /* otherwise, redirect to login page */
        return tmp_redirect_helper(
                                   file_build_absolute_path(LOGIN_PAGE));
      }
    }

    else if (is_logout_page(packet, pkt_size)) {
      return logout_header();
    }

    /* if no page specified */
    else if (strnstr(packet, " / ", 16) != NULL) {  // default "/" to "/index.html"
      file_build_path("/index.html ");
    }

    /* if page is specified */
    else if (strnstr(packet, " /", 16) != NULL) {
      file_build_path(packet);
    }

    /* verify file exists, then generate header */
    if (file_exists(conn_buffer)) {
      if (strnstr(conn_buffer, ".jpg", 50) != NULL) {
        return header_helper(200, "OK",
                             "image/jpeg",
                             file_size(conn_buffer), (int)strlen(conn_buffer));
      }
      if (strnstr(conn_buffer, ".png", 50) != NULL) {
        return header_helper(200, "OK", "image/png",
                             file_size(conn_buffer), (int)strlen(conn_buffer));
      }
      if (strnstr(conn_buffer, ".html", 50) != NULL) {
        return header_helper(200, "OK", "text/html",
                             file_size(conn_buffer), (int)strlen(conn_buffer));
      }
      if (strnstr(conn_buffer, ".css", 50) != NULL) {
        return header_helper(200, "OK", "text/css",
                             file_size(conn_buffer), (int)strlen(conn_buffer));
      }
      if (strnstr(conn_buffer, ".js", 50) != NULL) {
        return header_helper(200, "OK",
                             "Application/javascript",
                             file_size(conn_buffer), (int)strlen(conn_buffer));
      }
      return header_helper(200, "OK",
                           "text",
                           file_size(conn_buffer), (int)strlen(conn_buffer));  // default text content
    }

    /* if file doesn't exist, generate 404 from template */
    else {
      int filename_len = (int)(strlen(conn_buffer) - strlen(webroot));  // length of filename without full dir path
      int url_len = 7;    // length of "http://"
      // <HTML> + "http://" + <host:port> + <file>
      int content_len = file_size("404.html") - 1 + url_len + hdr->referer_len + filename_len;
      return header_helper(404, "Not Found", "text/html",
                           content_len, (int)strlen(conn_buffer));
    }
  }
  return NULL;      // shouldn't happen, useful for error detection.
}

/* print generic response header to buffer */
char *header_helper( int status_code, char *status_msg,
                     char *content_type, int content_length, int filename_length)
{
  char *header = conn_buffer + filename_length + 1;  // write header after file path in the buffer
  snprintf(header, 120,    // limit on header length to avoid overflow in small buffers
           "HTTP/1.1 %d %s\r\n"
           "Content-Type: %s\r\n"
           "Content-Length: %d\r\n"
           "Connection: close\r\n"
           "\r\n", status_code, status_msg, content_type, content_length);
  return header;
}

char *logout_header()
{
  char *header = conn_buffer;

  /* blank session value for overwrite, expires date in the past
     means the useragent should wipe the cookie */
  const char *write = "HTTP/1.1 302 Found\r\n"
    "Location: /index.html\r\n"
    "Set-Cookie: session=; Expires=Tue, 1 Nov 2022 00:00:00 GMT\r\n\r\n";

  if (pkt_size < strlen(write)) {
    header = realloc(header, 2 * strlen(write));
    assert(header &&
           "Couldn't reallocate space to write logout header in buffer in logout_header");
    conn_buffer = header;
  }

  strcpy(header, write);

  return header;
}

char *cookie_header_helper( char *url)
{
  char cookie[120] = { 0 };
  int cookie_len = make_cookie((char *)cookie);

  char *header = conn_buffer;

  const char *template = "HTTP/1.1 302 Found\r\n"
    "Location: /index.html\r\n" "Set-Cookie: session=%s; Path=/\r\n\r\n";

  int write_size = cookie_len + strlen(template) + 1;
  if (pkt_size < write_size) {
    header = realloc(header, write_size);
    assert(header &&
           "Couldn't reallocate space to write 302 resp header in cookie_header_helper");
    conn_buffer = header;
    pkt_size = write_size;
  }

  snprintf(header, write_size, template, (char *)cookie);

  return header;
}

/* print status 301 header in buffer for redirect functionality */
char *redirect_helper( char *url)
{
  char *header = conn_buffer + strlen(url) + 1;  // write header after file path in the buffer
  snprintf(header, 120,    // limit on header length to avoid overflow in small buffers
           "HTTP/1.1 301 Moved Permanently\r\n" "Location: %s\r\n" "\r\n", url);
  return header;
}

/* print status 302 header in buffer for temporary redirect functionality */
char *tmp_redirect_helper( char *url)
{
  char *header = conn_buffer + strlen(url) + 1;  // write header after file path in the buffer
  snprintf(header, 120,    // limit on header length to avoid overflow in small buffers
           "HTTP/1.1 302 Found\r\n" "Location: %s\r\n" "\r\n", url);
  return header;
}

/* Note, the real HTTP spec misspells "Referrer" as "Referer", so we
   implement this correctly */
int get_referer(const char *m, size_t m_len, const char **referer_p)
{
  const char *referer = "Referer:";
  int referer_len = 0;
  char *field_start = strnstr(m, referer, m_len);

  if(field_start == NULL)
    goto no_referer;

  size_t max_field_len = (m + m_len) - field_start;

  char *field_end =
    strnstr(field_start, "\r\n", max_field_len);

  if (field_end == NULL)
    goto no_referer;

  char *uri = field_start + strlen(referer);

  if (uri == field_end)
    goto no_referer;

  for (; isspace(*uri); uri += 1) {
  }

  if (uri == field_end)
    goto no_referer;

  referer_len = (int)(field_end - uri);
  *referer_p = uri;
  goto done;

 no_referer:
  *referer_p = NULL;
 done:
  return referer_len;
}

/* write a short summary of the request to admin.txt */
int log_request(const char *m, size_t m_len)
{
  int err = 0;

  char *l = calloc(m_len, sizeof(char));
  assert(l && "Couldn't allocate buffer for logging message");

  char *req_line_end = strnstr(m, "\r\n", m_len);
  if (NULL == req_line_end) {
    err = -1;
    goto cleanup;
  }

  size_t req_line_len = (size_t)(req_line_end - m);

  strncpy(l, m, req_line_len);

  l[req_line_len] = '\n';
  l[req_line_len + 1] = '\0';

  FILE *pFile = fopen(ADMIN_PAGE, "a");
  fputs(l, pFile);
  fclose(pFile);

 cleanup:
  free(l);
  return err;
}


void log_invalid(const char* message, const char* extra, size_t extra_len){
  FILE *f = fopen(ADMIN_PAGE, "a");
  char ipaddr_buf[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &client_addr.sin_addr, ipaddr_buf, sizeof(ipaddr_buf));
  fprintf(f, "IP:%s ", ipaddr_buf);
  fprintf(f, "%s %.*s",message, extra_len, extra);
  fputc('\n',f);
  fclose(f);
}

/* send header to client */
void send_header(const char *header)
{
  if (header != NULL) {
    int n = (int)strlen(header);
    const void *pos = header;
    while (n > 0) {
      int bytes_written = (int)send(connection_fd, pos, n, 0);
      if (bytes_written <= 0) {
        tinyserv_perror("Couldn't send header.");
      }
      n -= bytes_written;
      pos += bytes_written;
    }
  }
}

uint8_t fnv1a_hash(const char *data, size_t len)
{
  const uint32_t FNV_prime = 16777619u;
  const uint32_t FNV_offset_basis = 2166136261u;

  uint32_t hash = FNV_offset_basis;
  for (size_t i = 0; i < len; i++) {
    hash ^= (uint32_t) data[i];
    hash *= FNV_prime;
  }
  return (uint8_t) (hash & 0xFFu);
}

void init_cache()
{
  int i = 0;
  for (i = 0; i < MAX_CACHE_ENTRIES; i++) {
    cache[i].response = NULL;
  }
}

bool maybe_send_cached_response( char *buf)
{
  uint8_t key = fnv1a_hash(buf, strlen(buf));
  struct cache_entry entry = cache[key];
  if (entry.response == NULL) {
    // Cache miss, no entry for this file
    return false;
  }

  // Cache hit, send the cached file
  send_data(entry.response, entry.len);
  return true;
}

// Note that update_cache expects to take ownership of response, it
// shouldn't be free'd elsewhere
void update_cache(char *key, char *response, size_t len)
{
  uint8_t cache_key = fnv1a_hash(key, strlen(key));
  struct cache_entry *entry = &cache[cache_key];
  if (entry->response != NULL) {
    free(entry->response);
  }
  entry->response = response;
  entry->len = len;
}

int send_data(char *data, int data_len)
{
  while (data_len > 0) {
    int bytes_written = (int)write(connection_fd, data, data_len);
    if (bytes_written <= 0) {
      tinyserv_perror("Couldn't send data to client.");
    }
    data_len -= bytes_written;
    data += bytes_written;
  }
  return data_len;
}

/* Send input_file to client, optionally filling dynamic template data */
void send_file( char *file_path, char *dynamic)
{
  int input_file = open(file_path, O_RDONLY);
  /* handle missing file cases */
  if (input_file == -1) {
    input_file = open("404.html", O_RDONLY);  // 404 if specified file missing
    if (input_file == -1) {
      tinyserv_error("Necessary files missing: 404.html");
    }        // error if 404 template missing
  }
  /* clear buffer */
  bzero(conn_buffer, BUFFER_SIZE);

  char *full_file = malloc(BUFFER_SIZE);
  int full_file_bytes = 0;

  /* send file to client */
  char *read_pos = conn_buffer;
  char *dyn_pos = dynamic;
  while (1) {
    int bytes_read;
    if (dynamic == NULL) {
      bytes_read = (int)read(input_file, conn_buffer, BUFFER_SIZE);  // Read data into buffer.
    } else {
      bytes_read = (int)read(input_file, read_pos, 1);  // Read data into buffer.
      read_pos++;
    }
    if (bytes_read == 0) {
      break;
    }        // Exit if nothing to read.
    if (bytes_read < 0) {
      tinyserv_perror("Couldn't read file into buffer");
    }        // Handle errors.
    if (dynamic != NULL) {
      /* render template */
      while (bytes_read <= BUFFER_SIZE) {  // while buffer has space
        int new_bytes = (int)read(input_file, read_pos, 1);  // read 1 byte at a time
        if (new_bytes == 0) {
          break;
        }      // Exit if nothing to read.
        if (new_bytes < 0) {
          tinyserv_perror("Couldn't read file into buffer");
        }      // Handle errors.
        bytes_read += new_bytes;  // increment bytes_read
        if (*read_pos == '*') {  // if current char is template marker '*'
          while ((*dyn_pos != '\0') && (bytes_read <= BUFFER_SIZE)) {  // insert dynamic data at marker
            *read_pos = *dyn_pos;
            read_pos++;
            dyn_pos++;
            bytes_read++;
          }
        } else {
          read_pos++;    // if current != '*', continue reading
        }
      }
    }

    if (full_file != NULL) {
      if (full_file_bytes + bytes_read < MAX_CACHE_ENTRY_SIZE) {
        full_file = realloc(full_file, full_file_bytes + bytes_read);
        memcpy(full_file + full_file_bytes, conn_buffer, bytes_read);
        full_file_bytes += bytes_read;
      } else {
        // cache entry too big :( don't cache it
        free(full_file);
        full_file = NULL;
      }
    }

    // Write data into socket.
    bytes_read = send_data(conn_buffer, bytes_read);
  }

  // Cache this file for future use, if it wasn't too big
  if (full_file != NULL) {
    // update cache is now in charge of this buffer, don't free it
    update_cache(file_path, full_file, full_file_bytes);
  }

  /* close file */
  close(input_file);
}

/* get file size in bytes */
int file_size(char *file)
{
  struct stat st;
  stat(file, &st);
  return (int)st.st_size;
}

/* check if file exists */
int file_exists(char *file)
{
  if (0 == access(file, 0)) {
    return 1;
  }
  return 0;
}

/* write filename to beginning of buffer */
char *file_build_absolute_path( char *filename)
{
  int len = strlen(filename);  // find length of filename
  bzero(conn_buffer, BUFFER_SIZE);  // clear buffer
  strncpy(conn_buffer, filename, len + 1);  // add filename to path with null byte
  return conn_buffer;
}

/* build webroot dir + filename path at beginning of buffer */
void file_build_path( char *packet)
{
  char *start = strnstr(packet, "/", 100);  // find beginning of filename
  char *end = strnstr(start, " ", strlen(packet));  // find end of filename
  int len = (int)(end - start);  // find length of filename
  char filename[len + 1];  // allocate storage
  strncpy(filename, start, len);  // copy filename, buffer about to be wiped
  filename[len] = '\0';    // add null (strncpy doesn't)
  bzero(conn_buffer, strlen(conn_buffer) + strlen(webroot));  // clear buffer
  strcpy(conn_buffer, webroot);
  strncpy(conn_buffer + strlen(webroot), filename, len + 1);  // add filename to path
}

/* builds URL of requested file based on packet's request line */
char *url_build( char *packet)
{
  char *start = strnstr(packet, "/go/", 100);  // find beginning of hostname
  start += 4;      // move past "/go/"
  char *end = strnstr(start, " ", 100);  // find end of hostname
  int len = (int)(end - start);  // find length of filename
  char hostname[len + 1];  // allocate storage
  strncpy(hostname, start, len);  // copy hostname, buffer about to be wiped
  hostname[len] = '\0';    // add null (strncpy doesn't)
  bzero(conn_buffer, BUFFER_SIZE);  // clear buffer
  int url_components = 7 + 4 + 4 + 1;  // "http://" + "www." + ".com\0"
  snprintf(conn_buffer, len + url_components, "http://www.%s.com", hostname);
  return conn_buffer;
}


/* returns the smallest non-NULL value from loc1 and loc2 */
char *earliest_occurrence(char *loc1, char *loc2)
{
  char *earliest;
  if (loc1 == NULL) {
    earliest = loc2;
  } else if (loc2 == NULL) {
    earliest = loc1;
  } else {
    earliest = loc1 < loc2 ? loc1 : loc2;
  }
  return earliest;
}

/* determine whether request is for the admin page */
int packet_is_admin_page(char *packet)
{
  char *start = strnstr(packet, "/", 100) + 1;  // find beginning of filename
  char *end = strnstr(start, " ", 100);  // find end of filename
  int len = (int)(end - start);  // find length of filename
  if (len != strlen(ADMIN_PAGE))
    return 0;
  return !strncmp(start, ADMIN_PAGE, len);
}

/* determine whether request is for the login page */
/* Requests to the login page may have URL query parameters, so ignore those */
int packet_is_login_page(char *packet)
{
  char *start = strnstr(packet, "/", 100) + 1;  // find beginning of filename
  char *end1 = strnstr(start, " ", 100);
  char *end2 = strnstr(start, "?", 100);
  char *end = earliest_occurrence(end1, end2);  // find end of filename, ignoring URL parameters
  int len = (int)(end - start);  // find length of filename
  if (len != strlen(LOGIN_PAGE))
    return 0;
  return !strncmp(start, LOGIN_PAGE, len);
}

int is_logout_page(char *m, size_t m_len)
{
  const char *logout_req_line_pref = "GET /logout";
  size_t max_search = strlen(logout_req_line_pref);
  return 0 == memcmp(m, logout_req_line_pref, max_search);
}

/* determine whether request is for the admin page */
int file_is_admin_page(char *file)
{
  return !strncmp(file, ADMIN_PAGE, 50);
}

/* determine whether request is for the login page */
int file_is_login_page(char *file)
{
  return !strncmp(file, LOGIN_PAGE, 50);
}

/* check if username and password are valid admin credentials */
int auth(char *packet)
{
  char *start = strnstr(packet, "?", 120);  // find beginning of querystring
  if (start == NULL)
    return 0;      // no login details included
  char *end = strnstr(start, " ", 120) + 1;  // find end of querystring
  int len = (int)(end - start);

  char *name_start = strnstr(start, "user=", len);
  if (name_start == NULL)
    return 0;      // no username
  name_start += strlen("user=");

  char *name_end1 = strnstr(name_start, "&", len);
  char *name_end2 = strnstr(name_start, " ", len);
  char *name_end = earliest_occurrence(name_end1, name_end2);
  int name_len = (int)(name_end - name_start);

  char *password_start = strnstr(start, "password=", len);
  if (password_start == NULL)
    return 0;      // no password
  password_start += strlen("password=");

  char *password_end1 = strnstr(password_start, "&", len);
  char *password_end2 = strnstr(password_start, " ", len);
  char *password_end = earliest_occurrence(password_end1, password_end2);
  int input_password_len = (int)(password_end - password_start);

  int name_cmp_len = name_len > strlen("admin") ? name_len : strlen("admin");
  int pass_cmp_len =
    input_password_len > PASSWORD_LEN ? input_password_len : PASSWORD_LEN;

  // TODO: Support more users in the future.
  if (strncmp(name_start, "admin", name_cmp_len) != 0) {  // Only user is "admin"
    log_invalid("Failed login with username:",name_start, name_cmp_len);
    return 0;
  } else if (strncmp(password_start, password, pass_cmp_len) != 0) {  // Password must match
    log_invalid("Failed login with username:",name_start, name_cmp_len);
    return 0;
  }
  return 1;      // Authenticated
}

/* generates a new cookie, encodes it in base16, and writes it to buffer */
/* returns number of bytes written */
int make_cookie(uint8_t * buffer)
{
  time_t rawtime;
  time(&rawtime);
  cookie_data *to_sign = (cookie_data *) malloc(sizeof(cookie_data));
  to_sign->authenticated = 1;
  to_sign->expiration = rawtime + COOKIE_VALID_DURATION;
  uint8_t signature[20];
  hmac_sha1(admin_cookie_key, KEY_LENGTH,
            (uint8_t *) to_sign, sizeof(cookie_data), (uint8_t *) signature);
  // write cookie data
  int data_size = sizeof(cookie_data);
  for (int i = 0; i < data_size; i++) {
    uint8_t byte = ((uint8_t *) to_sign)[i];
    snprintf(buffer + (2 * i), 3, "%02X", byte);  // Write byte as ASCII, e.g. "9A" for 0x9A
  };
  // write signature
  for (int i = 0; i < 20; i++) {
    uint8_t byte = signature[i];
    snprintf(buffer + (2 * data_size) + (2 * i), 3, "%02X", byte);
  };
  free(to_sign);
  return 2 * data_size + 2 * 20;
}

/* check if cookie is valid for the admin page */
int check_cookie(char *packet, size_t p_len)
{
  char *end = packet + p_len;
  // Parse the header
  const char *sess = "session=";
  char *start = strnstr(packet, sess, p_len);
  if (start == NULL)
    return 0;

  start += strlen(sess);

  char *maybe_field_end =
    earliest_occurrence(strnstr(start, "\r\n", end - start),
                        strnstr(start, ";", end - start));
  if (NULL == maybe_field_end)
    return 0;

  int len = (int)(maybe_field_end - start);

  if (len != 2 * sizeof(cookie_data) + 2 * 20)
    return 0;

  uint8_t *cookie = (uint8_t *) malloc(sizeof(cookie_data));
  char *pos = start;
  for (int i = 0; i < sizeof(cookie_data); i++) {  // Get cookie_data
    sscanf(pos, "%2hhx", cookie + i);
    pos += 2;
  }

  // Get the signature from the cookie
  uint8_t given_signature[20];
  for (int i = 0; i < 20; i++) {  // Get cookie_data
    sscanf(pos, "%2hhx", given_signature + i);
    pos += 2;
  }

  // Compare the cookie data
  time_t timenow;
  time(&timenow);
  if (((cookie_data *) cookie)->expiration < timenow ||
      ((cookie_data *) cookie)->authenticated != 1) {
    free(cookie);
    return 0;
  }

  // Compute the HMAC of cookie_data
  uint8_t computed_signature[20];
  hmac_sha1(admin_cookie_key, KEY_LENGTH,
            (uint8_t *) cookie, sizeof(cookie_data),
            (uint8_t *) computed_signature);
  free(cookie);

  // Compare the signatures
  for (int i = 0; i < 20; i++) {
    if (computed_signature[i] != given_signature[i])
      return 0;
  }
  return 1;
}

/* close sockets, free malloc's, & exit. */
void cleanup_and_exit(int sig)
{
  if (sig == SIGALRM) {
    printf("\n****Shutting down automatically due to running too long****\n");
  }
  printf("\nCleaning up...\n");

  shutdown(connection_fd, 2);
  shutdown(sock, 2);
  printf("\nsockets/connections closed...");
  free(webroot);
  printf("\ngoodbye!\n");
  exit(0);
}

void generate_admin_cookie_key() {
  for (int i = 0; i < KEY_LENGTH; i++) {
      admin_cookie_key[i] = (uint8_t)uniform_random(256);
  }
  admin_cookie_key[KEY_LENGTH] = '\0';
}

void save_cookie_key_to_file(const char *username) {
  FILE *file = fopen(COOKIE_KEY_FILE, "a");
  if (file == NULL) {
      tinyserv_perror("Could not open cookie key file for writing");
      return;
  }

  
  fprintf(file, "%s:", username);
  for (int i = 0; i < KEY_LENGTH; i++) {
      fprintf(file, "%02X", admin_cookie_key[i]);
  }
  fprintf(file, "\n");

  fclose(file);
}

void load_cookie_key_from_file(const char *username) {
  FILE *file = fopen(COOKIE_KEY_FILE, "r");
  if (file == NULL) {
      //if the file does not exist, create a new one
      generate_admin_cookie_key();
      save_cookie_key_to_file(username);
      return;
  }

  char line[256];
  while (fgets(line, sizeof(line), file)) {
      char *file_username = strtok(line, ":");
      if (file_username && strcmp(file_username, username) == 0) {
          // find the corresponding username and get its cookie key
          char *key_hex = strtok(NULL, "\n");
          for (int i = 0; i < KEY_LENGTH; i++) {
              sscanf(key_hex + 2 * i, "%02hhX", &admin_cookie_key[i]);
          }
          fclose(file);
          return;
      }
  }

  //if the username is not found, generate a new cookie key
  fclose(file);
  generate_admin_cookie_key();
  save_cookie_key_to_file(username);
}