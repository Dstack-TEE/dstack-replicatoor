This is a self contained docker image for handling key migration in Dstack.
======

Remote attestation
===================
It makes use of the low level remote attestation provided by Dstack:
```
/var/run/tappd.sock
```

It does not make use of the KMS. This is important while the KMS is still in a "mock" state.

It also does not require special support from the base image, although this might be a source of future proposals to the base image.

UpgradeOperator Contract
========================
This contract has an owner. This can be a multisig wallet. It accepts proposals to change the "current docker compose" and "current base image hash".
A time limit is imposed, upgrades are pending for a minimum of 48 hours.

Interact with the Replicatoor from untrusted host
========
See `test.sh` for an example.
You will need to change the IP address to match the one

You can send GET/POST to the IP running this service:
- GET  /status/ gives an indication how it's going, can be used to retrieve quotes and public parameters
```bash
curl http://$GUEST/status
```

- POST /configure/  used to provide API keys
```bash
curl -X POST -H "Content-Type: text/plain" -d @private.env http://172.20.0.2:4001/configure
```

- POST /requestKey/  used to request a key 
```
curl -s -X POST http://$GUEST/requestKey > request.out
PUBK=$(cat request.out | jq -r .pubk)
QUOTE=$(cat request.out | jq -r .quote)
```
Returns a json containg $PUBK and $QUOTE

- POST /onboard/ {pubk} {quote} produces an encrypted state file
```
curl -s -X POST -d "pubk=$PUBK" -d "quote=$QUOTE"  http://$GUEST/onboard > onboard.out
```

- POST /receiveKey  {encrypted_message}
```bash
curl -X POST -H "Content-Type: text/plain" --data-binary @onboard.out http://$GUEST/receiveKey
```

Getting the reference value for the rtmr3
=======
Assuming we already have the hash of the base image, we just need to provide the docker-compose as input.

Providing private reference values
===============
The app can receive untrusted private inputs from, such as API keys, by listening.

How to interact with the replicatoor from guest application
========
- POST /getkey/
   Returns a unique derived key to your container

How to include in dstack:
===========
In your "docker-compose.yml" file, just drop this in there

```
services:
  replicatoor:
    image: amiller/dstack-replicatoor
    volumes:
      - /var/run/tappd.sock:/var/run/tappd.sock
      - untrustedhost:/var/run/untrustedhost
```
