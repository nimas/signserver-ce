#!/usr/bin/env sh

# Create directory where the H2 database is be stored
mkdir -p /mnt/persistent/h2

# Assemble the SignServer EAR with the configuration in /opt/keyfactor/signserver-custom/conf
/opt/keyfactor/signserver/bin/ant deploy