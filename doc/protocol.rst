Client protocol
---

Common header
^^^

length: uint32
number: uint32
seq:    uint64

CONNECT
^^^

  * request (CONNECT)
    client_id: uint32 (might be 0 for new clients)

  * response (ACCEPT)
    client_id: uint32


PROBE
^^^

  * request (sent by server)
    token: uint64 (to be returned by the client)

  * response (returned through all paths by client)
    token: uint64


GETATTR
^^^

  * request

  * response
    result: int32
    size: uint64


READ
^^^

  * request
    offset: uint64
    size: uint64

  * response
    result: int32
    data


WRITE
^^^

  * request
    offset: uint64
    size: uint64
    data

  * response:
    result: int32
