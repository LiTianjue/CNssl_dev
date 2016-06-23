#ifndef SSL_DEBUG_H
#define SSL_DEBUG_H

#define SSL_SERVER_RSA_CERT "/home/andy/GitHub/Tmp/ssl_debug/ssl_debug/Cert/server.crt"
#define SSL_SERVER_RSA_KEY	 "/home/andy/GitHub/Tmp/ssl_debug/ssl_debug/Cert/server.key"
#define SSL_SERVER_RSA_CA_CERT	 "/home/andy/GitHub/Tmp/ssl_debug/ssl_debug/Cert/ca.crt"
#define SSL_SERVER_RSA_CA_PATH  "/home/andy/GitHub/Tmp/ssl_debug/ssl_debug/Cert/"


#define SSL_CLIENT_RSA_CERT "/home/andy/GitHub/Tmp/ssl_debug/ssl_debug/Cert/client.crt"
#define SSL_CLIENT_RSA_KEY	 "/home/andy/GitHub/Tmp/ssl_debug/ssl_debug/Cert/client.key"
#define SSL_CLIENT_RSA_CA_CERT	 "/home/andy/GitHub/Tmp/ssl_debug/ssl_debug/Cert/ca.crt"
#define SSL_CLIENT_RSA_CA_PATH  "/home/andy/GitHub/Tmp/ssl_debug/ssl_debug/Cert/"

#define OFF	0
#define ON	1
#include <openssl/ssl.h>
void apps_ssl_info_callback(const SSL *s, int where, int ret);


int ssl_server_libssl(void);
int ssl_client_libssl(void);

#endif // SSL_DEBUG_H
