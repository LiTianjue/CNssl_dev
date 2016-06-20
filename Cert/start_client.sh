#!/bin/sh
openssl s_client -CAfile ca.crt -cert client.crt -key client.key -connect 127.0.0.1:4433 -debug
