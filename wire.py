"""A pretend network between Alice and Bob, all inside one Python process. Given; do not change it.

Nothing here opens a socket. A "message" is a Python object that Alice hands
to the wire and the wire hands to Bob. That keeps the man in the middle about
the protocol, not about networking:

    wire = Wire()                       # an honest wire
    wire.middle = mallory               # now every message passes through her

Every message that crosses the wire is appended to wire.transcript. That list
is exactly what a passive eavesdropper sees.

Messages carry either a Diffie-Hellman public value ("public") or encrypted
text ("text"). Party runs one side of the exchange using your dh.py, then
encrypts with the shared secret.

The cipher here is a toy built from SHA-256 so that the lab needs only the
standard library. It is enough to show who can read what. Do not use it to
protect anything real.
"""

import hashlib
import os
from dataclasses import dataclass

import dh


@dataclass
class Message:
    kind: str          # "public" or "text"
    sender: str
    receiver: str
    value: object      # an int for "public", bytes for "text"


def _keystream(secret, nonce, n):
    key = hashlib.sha256(str(secret).encode()).digest()
    out = b""
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        counter += 1
    return out[:n]


def encrypt(secret, text):
    """Encrypt a string under a shared secret (an int). Returns bytes."""
    data = text.encode()
    nonce = os.urandom(8)
    return nonce + bytes(a ^ b for a, b in zip(data, _keystream(secret, nonce, len(data))))


def decrypt(secret, blob):
    """Decrypt bytes from encrypt(). With the wrong secret you get gibberish, not an error."""
    nonce, body = blob[:8], blob[8:]
    data = bytes(a ^ b for a, b in zip(body, _keystream(secret, nonce, len(body))))
    return data.decode(errors="replace")


class Wire:
    def __init__(self):
        self.transcript = []    # every Message sent, as sent
        self.middle = None      # an object with intercept(message) -> message, or None

    def carry(self, message):
        """Record the message and return what arrives at the other end."""
        self.transcript.append(message)
        if self.middle is not None:
            return self.middle.intercept(message)
        return message


class Party:
    """One side of the exchange: Alice or Bob."""

    def __init__(self, name, g, p, wire):
        self.name, self.g, self.p, self.wire = name, g, p, wire
        self.private = dh.generate_private(p)
        self.public = dh.public_from(g, p, self.private)
        self.secret = None      # set once the other side's public value arrives
        self.inbox = []         # the plaintext of every message received

    def send_public(self, other):
        other.receive(self.wire.carry(Message("public", self.name, other.name, self.public)))

    def send_text(self, other, text):
        other.receive(self.wire.carry(Message("text", self.name, other.name, encrypt(self.secret, text))))

    def receive(self, message):
        if message.kind == "public":
            self.secret = dh.shared_secret(message.value, self.p, self.private)
        else:
            self.inbox.append(decrypt(self.secret, message.value))


def exchange(g, p, middle=None):
    """Alice and Bob swap public values over a wire, optionally through `middle`. Returns (alice, bob, wire)."""
    wire = Wire()
    wire.middle = middle
    alice, bob = Party("Alice", g, p, wire), Party("Bob", g, p, wire)
    alice.send_public(bob)
    bob.send_public(alice)
    return alice, bob, wire
