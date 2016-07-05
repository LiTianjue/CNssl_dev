#
# OpenSSL/ssl/Makefile
#

DIR=	ssl
TOP=	.
CC=	gcc
INCLUDES= -I./ -I./crypto -I$(TOP) -I./include $(KRB5_INCLUDES)
CFLAG= -g
#CFLAG= -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -Wa,--noexecstack -m64 -DL_ENDIAN -O3 -Wall -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM -DECP_NISTZ256_ASM

AR=		ar r

# KRB5 stuff
KRB5_INCLUDES=

CFLAGS= $(INCLUDES) $(CFLAG)


LIB=ssl/libssl.a
TESTAPP=andy_ssl

LIBSRC=	\
	ssl/s2_meth.c  ssl/s2_srvr.c 	ssl/s2_clnt.c  ssl/s2_lib.c  ssl/s2_enc.c ssl/s2_pkt.c \
	ssl/s3_meth.c  ssl/s3_srvr.c 	ssl/s3_clnt.c  ssl/s3_lib.c  ssl/s3_enc.c ssl/s3_pkt.c ssl/s3_both.c ssl/s3_cbc.c \
	ssl/s23_meth.c ssl/s23_srvr.c 	ssl/s23_clnt.c ssl/s23_lib.c ssl/s23_pkt.c \
	ssl/t1_meth.c  ssl/t1_srvr.c 	ssl/t1_clnt.c  ssl/t1_lib.c  ssl/t1_enc.c t1_ext.c \
	ssl/d1_meth.c  ssl/d1_srvr.c 	ssl/d1_clnt.c  ssl/d1_lib.c  ssl/d1_pkt.c \
	ssl/d1_both.c  ssl/d1_srtp.c \
	ssl/gm_meth.c  ssl/gm_srvr.c 	ssl/gm_clnt.c  ssl/gm_lib.c  ssl/gm_enc.c \
	ssl/ssl_lib.c  ssl/ssl_err2.c 	ssl/ssl_cert.c ssl/ssl_sess.c \
	ssl/ssl_ciph.c ssl/ssl_stat.c 	ssl/ssl_rsa.c \
	ssl/ssl_asn1.c ssl/ssl_txt.c 	ssl/ssl_algs.c ssl/ssl_conf.c \
	ssl/bio_ssl.c  ssl/ssl_err.c 	ssl/kssl.c t1_reneg.c ssl/tls_srp.c ssl/t1_trce.c ssl/ssl_utst.c
LIBOBJ= \
	ssl/s2_meth.o	ssl/s2_srvr.o  ssl/s2_clnt.o  ssl/s2_lib.o  ssl/s2_enc.o ssl/s2_pkt.o \
	ssl/s3_meth.o	ssl/s3_srvr.o  ssl/s3_clnt.o  ssl/s3_lib.o  ssl/s3_enc.o ssl/s3_pkt.o ssl/s3_both.o ssl/s3_cbc.o \
	ssl/s23_meth.o	ssl/s23_srvr.o ssl/s23_clnt.o ssl/s23_lib.o          ssl/s23_pkt.o \
	ssl/t1_meth.o 	ssl/t1_srvr.o  ssl/t1_clnt.o  ssl/t1_lib.o  ssl/t1_enc.o ssl/t1_ext.o \
	ssl/d1_meth.o   ssl/d1_srvr.o  ssl/d1_clnt.o  ssl/d1_lib.o  ssl/d1_pkt.o \
	ssl/d1_both.o 	ssl/d1_srtp.o\
	ssl/gm_meth.o	ssl/gm_srvr.o 	ssl/gm_clnt.o  ssl/gm_lib.o  ssl/gm_enc.o \
	ssl/ssl_lib.o	ssl/ssl_err2.o 	ssl/ssl_cert.o ssl/ssl_sess.o \
	ssl/ssl_ciph.o	ssl/ssl_stat.o 	ssl/ssl_rsa.o \
	ssl/ssl_asn1.o	ssl/ssl_txt.o 	ssl/ssl_algs.o 	ssl/ssl_conf.o \
	ssl/bio_ssl.o	ssl/ssl_err.o 	ssl/kssl.o 		ssl/t1_reneg.o ssl/tls_srp.o ssl/t1_trce.o ssl/ssl_utst.o

TESTSRC= ssl_server_libssl.c ssl_client_libssl.c ssl_debug.c debug_message.c api_test.c

SRC= $(LIBSRC) $(TESTSRC)
OBJ= $(LIBOBJ) ssl_server_libssl.o ssl_client_libssl.o ssl_debug.o debug_message.o api_test.o

EXHEADER= ssl.h ssl2.h ssl3.h ssl23.h tls1.h dtls1.h gmssl1.h  kssl.h srtp.h
HEADER=	$(EXHEADER) ssl_locl.h kssl_lcl.h

ALL=     $(SRC) $(HEADER)

#top:
#	(cd ..; $(MAKE) DIRS=$(DIR) all)

#all:	shared
all:	lib $(TESTAPP)


lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)

$(TESTAPP): $(OBJ)
	$(CC) -o $(TESTAPP) $(OBJ)  -L./lib -lcrypto -ldl 



clean:
	rm -f *.o *.obj  core .pure .nfs* *.old *.bak fluff $(TESTAPP)  $(OBJ) $(LIB)
