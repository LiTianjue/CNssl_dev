#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <openssl/ssl.h>


void apps_ssl_info_callback(SSL *s, int where, int ret)
{
	const char *str;
	int w;

	w=where& ~SSL_ST_MASK;

	if(w & SSL_ST_CONNECT)
		str="SSL_connect";
	else if (w & SSL_ST_ACCEPT) 
		str="SSL_accept";
	else 
		str="undefined";

	if (where & SSL_CB_LOOP)
	{
		//BIO_printf(bio_err,"%s:%s\n",str,SSL_state_string_long(s));
		printf("%s:%s\n",str,SSL_state_string_long(s));
	}
	else if (where & SSL_CB_ALERT)
	{
		str=(where & SSL_CB_READ)?"read":"write";
		/*
		BIO_printf(bio_err,"SSL3 alert %s:%s:%s\n",
				str,
				SSL_alert_type_string_long(ret),
				SSL_alert_desc_string_long(ret));
		*/
		printf("GMSSL1 alert %s:%s:%s\n",
				str,
				SSL_alert_type_string_long(ret),
				SSL_alert_desc_string_long(ret));
		
	}
	else if (where & SSL_CB_EXIT)
	{
		if (ret == 0)
			printf("%s:failed in %s\n",
					str,SSL_state_string_long(s));
		else if (ret < 0)
		{
			printf("%s:error in %s\n",
					str,SSL_state_string_long(s));
		}
	}
}
