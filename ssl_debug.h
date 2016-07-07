#ifndef SSL_DEBUG_H
#define SSL_DEBUG_H

#include <openssl/ssl.h>
/* -  RSA -*/
#define SSL_SERVER_RSA_CERT "/home/andy/GitHub/Tmp/ssl_debug/ssl_debug/Cert/server.crt"
#define SSL_SERVER_RSA_KEY	 "/home/andy/GitHub/Tmp/ssl_debug/ssl_debug/Cert/server.key"
#define SSL_SERVER_RSA_CA_CERT	 "/home/andy/GitHub/Tmp/ssl_debug/ssl_debug/Cert/ca.crt"
#define SSL_SERVER_RSA_CA_PATH  "/home/andy/GitHub/Tmp/ssl_debug/ssl_debug/Cert/"

#define SSL_CLIENT_RSA_CERT "/home/andy/GitHub/Tmp/ssl_debug/ssl_debug/Cert/client.crt"
#define SSL_CLIENT_RSA_KEY	 "/home/andy/GitHub/Tmp/ssl_debug/ssl_debug/Cert/client.key"
#define SSL_CLIENT_RSA_CA_CERT	 "/home/andy/GitHub/Tmp/ssl_debug/ssl_debug/Cert/ca.crt"
#define SSL_CLIENT_RSA_CA_PATH  "/home/andy/GitHub/Tmp/ssl_debug/ssl_debug/Cert/"

/* - ECC - */
#define SSL_SERVER_ECC_CERT		"/home/andy/GitHub/WORK/gmssl_dev/gmssl_dev/Cert/Ecc/server.crt"
#define SSL_SERVER_ECC_KEY		"/home/andy/GitHub/WORK/gmssl_dev/gmssl_dev/Cert/Ecc/server.key"
#define SSL_SERVER_ECC_CA_CERT	"/home/andy/GitHub/WORK/gmssl_dev/gmssl_dev/Cert/Ecc/ca.crt"
#define SSL_SERVER_ECC_CA_PATH  "/home/andy/GitHub/WORK/gmssl_dev/gmssl_dev/Cert/Ecc/"

#define SSL_CLIENT_ECC_CERT		"/home/andy/GitHub/WORK/gmssl_dev/gmssl_dev/Cert/Ecc/client.crt"
#define SSL_CLIENT_ECC_KEY		"/home/andy/GitHub/WORK/gmssl_dev/gmssl_dev/Cert/Ecc/client.key"
#define SSL_CLIENT_ECC_CA_CERT	"/home/andy/GitHub/WORK/gmssl_dev/gmssl_dev/Cert/Ecc/ca.crt"
#define SSL_CLIENT_ECC_CA_PATH  "/home/andy/GitHub/WORK/gmssl_dev/gmssl_dev/Cert/Ecc/"


/* - SM2 - */
#define SSL_SERVER_SM2_CERT	"/home/andy/GitHub/WORK/gmssl_dev/gmssl_dev/Cert/SM2_Cert/server/server.cer"
#define SSL_SERVER_SM2_KEY	"/home/andy/GitHub/WORK/gmssl_dev/gmssl_dev/Cert/SM2_Cert/server/server.pem"
#define SSL_SERVER_SM2_CA_CERT	"/home/andy/GitHub/WORK/gmssl_dev/gmssl_dev/Cert/SM2_Cert/ca.crt"
#define SSL_SERVER_SM2_CA_PATH	"/home/andy/GitHub/WORK/gmssl_dev/gmssl_dev/Cert/SM2_Cert/"

#define SSL_CLIENT_SM2_CERT	"/home/andy/GitHub/WORK/gmssl_dev/gmssl_dev/Cert/SM2_Cert/client/client.cer"
#define SSL_CLIENT_SM2_KEY	"/home/andy/GitHub/WORK/gmssl_dev/gmssl_dev/Cert/SM2_Cert/client/client.pem"
#define SSL_CLIENT_SM2_CA_CERT	"/home/andy/GitHub/WORK/gmssl_dev/gmssl_dev/Cert/SM2_Cert/ca.crt"
#define SSL_CLIENT_SM2_CA_PATH	"/home/andy/GitHub/WORK/gmssl_dev/gmssl_dev/Cert/SM2_Cert/"



#if 1
# define SERVER_CERT	SSL_SERVER_SM2_CERT
# define SERVER_KEY		SSL_SERVER_SM2_KEY
# define CLIENT_CERT	SSL_CLIENT_SM2_CERT
# define CLIENT_KEY		SSL_CLIENT_SM2_KEY
# define CA_CERT		SSL_CLIENT_SM2_CA_CERT
# define CA_PATH		SSL_CLIENT_SM2_CA_PATH
# define FILE_TYPE		SSL_FILETYPE_ASN1
# elif 0
# define SERVER_CERT	SSL_SERVER_RSA_CERT
# define SERVER_KEY		SSL_SERVER_RSA_KEY
# define CLIENT_CERT	SSL_CLIENT_RSA_CERT
# define CLIENT_KEY		SSL_CLIENT_RSA_KEY
# define CA_CERT		SSL_CLIENT_RSA_CA_CERT
# define CA_PATH		SSL_CLIENT_RSA_CA_PATH
# define FILE_TYPE		SSL_FILETYPE_PEM
# else
# define SERVER_CERT	SSL_SERVER_ECC_CERT
# define SERVER_KEY		SSL_SERVER_ECC_KEY
# define CLIENT_CERT	SSL_CLIENT_ECC_CERT
# define CLIENT_KEY		SSL_CLIENT_ECC_KEY
# define CA_CERT		SSL_CLIENT_ECC_CA_CERT
# define CA_PATH		SSL_CLIENT_ECC_CA_PATH
# define FILE_TYPE		SSL_FILETYPE_PEM
#endif

#define OFF	0
#define ON	1
#include <openssl/ssl.h>
void apps_ssl_info_callback(const SSL *s, int where, int ret);


int ssl_server_libssl(void);
int ssl_client_libssl(void);

#endif // SSL_DEBUG_H
