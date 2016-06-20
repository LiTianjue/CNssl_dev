#!/bin/sh
openssl s_server -CAfile ca.crt -cert server.crt -key server.key -debug
