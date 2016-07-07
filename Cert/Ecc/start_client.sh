#!/bin/sh
#openssl s_client -tls1_1 -CAfile ca.crt -cert client.crt -key client.key -connect 127.0.0.1:4433 -debug

openssl s_client -tls1_1 -connect 127.0.0.1:4433 -debug
