# Cryo-Client-Node

#### Part of the Cryo Ecosystem

```
 █████ ██████  ██   ██  █████  
██     ██   ██  ██ ██  ██   ██ 
██     ██████    ███   ██   ██ 
██     ██ ██     ██    ██   ██ 
██     ██  ██    ██    ██   ██ 
 █████ ██   ██   ██     █████  
                Node.js client implementation
```

---

## Cryo / Overview

Cryo is a lightweight, efficient Websocket framework intended for building real-time systems

Client implementations are available for:

- **TypeScript / JavaScript** under **Node.Js**
- **TypeScript / JavaScript** under **modern Browsers**
- **C#** under **.NET 8.0**

A server implementation is available for **TypeScript / JavaScript** under **Node.Js**

## Cryo-Client-Node / Overview

The Cryo Node.js client takes care of the following:

- Authentication at the server
- Correct framing and structuring of received and sent data

The client provides a public API for creating and destroying an instance.
It provides access incoming communication via events

## Setup

To set up a Cryo Client, simply import the ``cryo`` function from the ``cryo-client-node`` package.

The ``cryo``-function takes two arguments:

- host
    - a required host string
- bearer
    - a required authentication token string
- use_cale
    - If the client should use ``CALE``, see [CALE](#cale---cryo-application-level-encryption)
- timeout
    - an optional timeout value, indicating how long the client should wait until a connection request to the server is
      aborted

## CryoClientWebsocketSession / Overview

### Public methods

| Name    | Parameter                       | Description                                | Returns |
|---------|---------------------------------|--------------------------------------------|---------|
| Close   |                                 | Closes the underlying Websocket connection |         |
| Destroy | code?: number, message?: string | Tears down the session                     |         |

### Data Events

These events are emitted when the server-side session receives data from a client-side session

| Name           | Parameter    | Description                                                    |
|----------------|--------------|----------------------------------------------------------------|
| message-utf8   | data: string | Emitted, when the session receives a utf8 text message         |
| message-binary | data: Buffer | Emitted, when the session receives an arbitrary binary message |

### Meta events

This category of events is emitted when the session state changes

| Name         | Parameter                    | Description                                     |
|--------------|------------------------------|-------------------------------------------------|
| connected    |                              | Emitted, when the session successfully connects |
| disconnected |                              | Emitted, when the session has been disconnected |
| reconnected  |                              | Emitted, when the session has reconnected       |
| closed       | code: number, reason: string | Emitted, when the session is closed             |

## Cryo-Client / Example

```typescript
import {cryo} from "cryo-client-node";

const HOST = "localhost:8080";
const TOKEN = process.env.CRYO_AUTH_TOKEN;

const client = await cryo(HOST, TOKEN, false, 10000);
client.on("connected", () => {
    console.info(`Successfully connected to ${HOST}`);
});
```

## CALE - Cryo application level encryption

Warning - This feature is unavailable in the C# client

**CALE** is an optional, end-to-end encryption layer for Cryo.

It adds a layer of cryptographic protection on top of WebSockets/TCP, mainly for environments without TLS or custom
setups

**How:**

- It uses **ECDH / P-256** for an ephemeral key exchange
- Derives symmetric session keys using **SHA-256**
- Encrypts frames using **AES-128-GCM**
- Performs a 3-step handshake ``server_hello -> client_hello -> handshake_done``
- Once completed, all frames are encrypted

```` 
+-------------+                                      +-------------+
|   Client    |                                      |   Server    |
+------+------+                                      +------+------+
       |                                                    |
       | 1) server_hello(pub_key_s, sid, ack)               |
       | <------------------------------------------------- |
       |                                                    |
       | 2) client_hello(pub_key_c, sid, ack)               |
       | -------------------------------------------------> |
       |                                                    |
       | 3) handshake_done                                  |
       | <------------------------------------------------- |
       |                                                    |
       | 4) handshake_done (ack)                            |
       | -------------------------------------------------> |
       |                                                    |
+------+------ +                                      +------+------+
| Secure Chan. | <---------- AES-128-GCM ------------>| Secure Chan.|
|  (tx/rx)     |                                      |  (tx/rx)    |
+--------------+                                      +-------------+

````

Session keys are derived as such

```
secret  = ECDH(pub_key_server, priv_key_client)
hash    = SHA256(secret)
rx_key  = hash[0..15]
tx_key  = hash[16..31]
```

After the ``handshake_done``-step, both peers switch into secure mode, meaning that all data frames (`utf8data`,
`binarydata`) will be encrypted using AES-GCM

**Why:**

CALE is not meant to replace TLS, I wouldn't dare.

It is a protocol-level experiment for extra application-layer encryption, primarily for private deployments or custom
setups.

If you are communicating via TLS, you do **not** need **CALE** at all and it is recommended to disable it for
performance reasons.
