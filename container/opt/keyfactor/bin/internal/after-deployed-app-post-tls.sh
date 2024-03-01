#!/usr/bin/env sh

# TODO: Only do this when the pod starts with an empty database?
sleep 200
/opt/keyfactor/signserver/bin/signserver wsadmins -allowany true

echo "🚀 SignServer is now running!"