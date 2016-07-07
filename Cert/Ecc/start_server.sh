#!/bin/sh
#openssl s_server -tls1_1 -CAfile ca.crt -cert server.crt -key server.key -debug
openssl s_server -tls1_1 -CAfile ca.crt -cert server.crt -key server.key -debug
