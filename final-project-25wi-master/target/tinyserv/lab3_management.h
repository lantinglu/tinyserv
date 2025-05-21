#ifndef _LAB3_MANAGEMENT_H_
#define _LAB3_MANAGEMENT_H_
/* All of this is ONLY related to the management of the group
   secret. It is not related to the assignment, and you don't need to
   read or understand it.  If you see something broken, do tell us :)*/

static const char lab_group_secret_key[] = LAB_GROUP_SECRET_KEY;

static const char resp403body[] =
    "<div>Group secret not provided or incorrect</div>\n"
"<input type=\"text\" value=\"\" id=\"ckvalue\" name='usrname'>\n"
"<script>function setcookie() {document.cookie='LAB_GROUP_SECRET_KEY='+document.getElementById('ckvalue').value;console.log('set');}</script>\n"
"<input type=\"button\" value=\"Set Cookie\" onclick=\"setcookie();\">";

static const char resp403[] = "HTTP/1.1 403 Forbidden\r\n"
    "Connection: close\r\n"
    "Content-Type: text/html\r\n" "Content-Length: %lu\r\n" "\r\n%s";

static const char resp400_improper_syntax_body[] =
    "<div>Request was improperly formatted. tinyserv couldn't verify the group auth cookie.</div>\n";

static const char resp400_too_long_body[] =
    "<div>Request was too long.</div>\n";

static const char resp400[] = "HTTP/1.1 400 Bad Request\r\n"
    "Connection: close\r\n"
    "Content-Type: text/html\r\n" "Content-Length: %lu\r\n" "\r\n%s";


int auth_group(const char *hdr, size_t hdr_len);
char *make_403_response();
char *make_400_improper_syntax_response();
char *make_400_too_long_response();

#endif /* _LAB3_MANAGEMENT_H_ */
