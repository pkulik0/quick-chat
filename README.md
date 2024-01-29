# Quick Chat

## Description

Quick Chat is a simple SSL socket based chat application with both signed public and encrypted private messages. 

No registration is required. Identities are based on a certificate generated on first run, with the only requirement being a unique (per server) identifier.
The server and all peers associate the certificate with the identifier and are immune to impersonation attacks.

All messages are provably sent by the identity they claim to be sent by, and all private messages are encrypted for the recipient.

## Message types
- **Auth** - Sent by the client to the server to authenticate the client. Contains the client's certificate.
- **System** - Sent by the server to the client to notify the client of a system event. Contains a message.
- **Certificate Request** - Sent by the client to the server to request a specific user's certificate. Contains the requested user's identifier.
- **Certificate Response** - Sent to the requester to provide the requested user's certificate.
- **List Users** - Sent by the client to the server to request a list of all connected clients.
----
- **Public** - Sent by the client to the server to send a public message to all connected clients.
- **Private** - Sent by the client to the server to send a private message to a specific client. Contains a recipient and the same fields as a public message.
