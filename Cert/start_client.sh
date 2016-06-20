#!/bin/sh
openssl s_client -CAfile ca.crt -cert client.crt -key client.key -connect 192.168.2.68:4433 -debug
