TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    ssl/bio_ssl.c \
    ssl/d1_both.c \
    ssl/d1_clnt.c \
    ssl/d1_lib.c \
    ssl/d1_meth.c \
    ssl/d1_pkt.c \
    ssl/d1_srtp.c \
    ssl/d1_srvr.c \
    ssl/kssl.c \
    ssl/s23_clnt.c \
    ssl/s23_lib.c \
    ssl/s23_meth.c \
    ssl/s23_pkt.c \
    ssl/s23_srvr.c \
    ssl/s2_clnt.c \
    ssl/s2_enc.c \
    ssl/s2_lib.c \
    ssl/s2_meth.c \
    ssl/s2_pkt.c \
    ssl/s2_srvr.c \
    ssl/s3_both.c \
    ssl/s3_cbc.c \
    ssl/s3_clnt.c \
    ssl/s3_enc.c \
    ssl/s3_lib.c \
    ssl/s3_meth.c \
    ssl/s3_pkt.c \
    ssl/s3_srvr.c \
    ssl/ssl_algs.c \
    ssl/ssl_asn1.c \
    ssl/ssl_cert.c \
    ssl/ssl_ciph.c \
    ssl/ssl_conf.c \
    ssl/ssl_err.c \
    ssl/ssl_err2.c \
    ssl/ssl_lib.c \
    ssl/ssl_rsa.c \
    ssl/ssl_sess.c \
    ssl/ssl_stat.c \
    ssl/ssl_utst.c \
    ssl/t1_clnt.c \
    ssl/t1_enc.c \
    ssl/t1_ext.c \
    ssl/t1_lib.c \
    ssl/t1_meth.c \
    ssl/t1_reneg.c \
    ssl/t1_srvr.c \
    ssl/t1_trce.c \
    ssl/tls_srp.c \
    ssl/ssl_txt.c \
	ssl/gm_meth.c  \
	ssl/gm_srvr.c	\
	ssl/gm_clnt.c  \
	ssl/gm_lib.c  \
	ssl/gm_enc.c \
    ssl_server_libssl.c \
    ssl_debug.c \
    ssl_client_libssl.c \
    debug_message.c \
    api_test.c

HEADERS += \
    ssl/dtls1.h \
    ssl/kssl.h \
    ssl/kssl_lcl.h \
    ssl/srtp.h \
    ssl/ssl.h \
    ssl/ssl2.h \
    ssl/ssl23.h \
    ssl/ssl3.h \
    ssl/ssl_locl.h \
    ssl/tls1.h \
	ssl/gmssl1.h \
    ssl_debug.h \
    api_test.h

LIBS += -L /home/andy/GitHub/WORK/gmssl_dev/gmssl_dev/lib -lcrypto -ldl
INCLUDEPATH+= -I ./crypto/  -I ./ssl  -I ./  -I ./include/
