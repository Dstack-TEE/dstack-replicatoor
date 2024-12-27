#!/bin/bash
set -x
set -e

# Configure to the IP address of the container
GUEST=172.16.238.10:4001
#GUEST=localhost:14001

# Configure the API keys
curl -X POST -H "Content-Type: text/plain" --data-binary @host.env http://$GUEST/configure
#curl http://$GUEST/status

# Write some secrets
cp private.env /tmp/tapp-ramdisk/private.env

# Request the key
curl -s -X POST http://$GUEST/requestKey > request.out
PUBK=$(cat request.out | jq -r .pubk)
QUOTE=$(cat request.out | jq -r .quote)

# Prepare the encrypted state file
curl -s -X POST -d "pubk=$PUBK" -d "quote=$QUOTE"  http://$GUEST/onboard > onboard.out

# Post the encrypted state file
curl -X POST -H "Content-Type: text/plain" --data-binary @onboard.out http://$GUEST/receiveKey
#curl http://$GUEST/status
