# Stage 2 protocol

What the challenge server says and what it expects back. `client.py` already does the framing; this page is so that you know what you are sending and can tell a protocol mistake from a Diffie-Hellman mistake.

## Framing

One JSON object per line, in both directions, UTF-8, each line ended by `\n`. Nothing else is on the wire. The connection carries one challenge and then closes.

Rules the server enforces:

- Every line must be a JSON object, and `"msg"` names the message.
- Every Diffie-Hellman value is a string of decimal digits, not a JSON number. A 2048-bit value is 617 digits long, and JSON numbers are not safe at that size outside Python. Send `str(x)`; read `int(s)`.
- Every encrypted message is a string of lowercase hex, the bytes that `wire.encrypt` returned. Send `blob.hex()`; read `bytes.fromhex(s)`.
- A line longer than 8192 bytes is refused.
- The server waits 30 seconds for each line, then hangs up.
- A public value must be between 2 and p - 2.
- A team id is 1 to 32 characters of `a-z`, `0-9`, `-` or `_`. The server lowercases it and sends back what it recorded, which is the id your flag is derived from.

At any point the server may answer

```json
{"msg": "error", "detail": "what was wrong"}
```

and close. `client.py` turns that into a `ServerError` carrying the detail, so read what it says: most of them name the field.

## Challenge A: an honest handshake

You and the server run one Diffie-Hellman exchange, and it sends you a message encrypted under the secret. The group is g = 2 and the 2048-bit prime from RFC 3526, the same one `params.py` calls group 14. The server sends both, so nothing is hard-coded on your side.

| # | Direction | Line |
| :--- | :--- | :--- |
| 1 | you send | `{"msg": "hello", "challenge": "A", "team": "blue-3"}` |
| 2 | server sends | `{"msg": "params", "challenge": "A", "team": "blue-3", "g": "2", "p": "<617 digits>"}` |
| 3 | server sends | `{"msg": "public", "from": "server", "public": "<digits>"}` |
| 4 | you send | `{"msg": "public", "public": "<digits>"}` |
| 5 | server sends | `{"msg": "text", "from": "server", "blob": "<hex>"}` |

Then the server closes the connection. Step 5 is encrypted under the secret the two of you agreed, and the flag is inside it.

## Challenge B: Ava and Ben talk through you

The server plays both people. It sends you what Ava sends, and delivers to Ben whatever you send back. It then does the same for Ben. You are the whole path between them, so every message arrives at its reader only if you deliver one.

Copy the `"from"` and `"to"` fields through unchanged. They say who sent the message and who is waiting for it. The server refuses a line that has moved them, because a real network would not reroute a packet for you.

| # | Direction | Line |
| :--- | :--- | :--- |
| 1 | you send | `{"msg": "hello", "challenge": "B", "team": "blue-3"}` |
| 2 | server sends | `{"msg": "params", "challenge": "B", "team": "blue-3", "g": "2", "p": "<617 digits>"}` |
| 3 | server sends | `{"msg": "public", "from": "Ava", "to": "Ben", "public": "<Ava's value>"}` |
| 4 | you send | `{"msg": "public", "from": "Ava", "to": "Ben", "public": "<what Ben receives>"}` |
| 5 | server sends | `{"msg": "public", "from": "Ben", "to": "Ava", "public": "<Ben's value>"}` |
| 6 | you send | `{"msg": "public", "from": "Ben", "to": "Ava", "public": "<what Ava receives>"}` |
| 7 | server sends | `{"msg": "text", "from": "Ava", "to": "Ben", "blob": "<hex>"}` |
| 8 | you send | `{"msg": "text", "from": "Ava", "to": "Ben", "blob": "<what Ben receives>"}` |
| 9 | server sends | `{"msg": "result", "ok": true, "detail": "..."}` |

Ava encrypts step 7 under the secret she holds, which she computed from the value she received in step 6. Ben decrypts step 8 with the secret he computed from the value he received in step 4.

Before step 9 the server checks that Ben recovered exactly the text Ava wrote. If he did not, you get an `error` instead, saying so. That check is the part of the attack students usually skip. Reading a message is easy if the reader is allowed to notice; the point of Step 3 was that neither side notices.

Delivering both values untouched is legal and works. Ava and Ben agree a secret with each other, Ben reads her message, and the server says so. Read `blob` from step 7 in that case and see how far it gets you.

## The flag

Each team recovers a different one:

```
CS4930-DH-<challenge>-<16 hex digits>
```

The hex digits are HMAC-SHA256 over the text `<challenge>|<team id>`, keyed with a secret only the server holds. So it is fixed for your team, different for every other team, and not something you can compute from the format. Paste both flags into your answers with the team id you used.

## References

- Python `socket`: <https://docs.python.org/3/library/socket.html>
- Socket Programming HOWTO: <https://docs.python.org/3/howto/sockets.html>
- RFC 3526, section 3, the 2048-bit group: <https://www.rfc-editor.org/rfc/rfc3526#section-3>
