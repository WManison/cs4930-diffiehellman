"""The active attacker: Mallory sits on the wire and can change what passes. You write the two methods marked YOUR TASK.

An eavesdropper only reads the wire. Mallory can also replace a message
before it arrives. wire.py hands her every Message through intercept(), and
whatever she returns is what the receiver gets.

Her goal: Alice and Bob each finish the exchange believing they share a
secret with the other, every message they send is readable by her, and
neither of them sees anything wrong.

Message fields (see wire.py): kind ("public" or "text"), sender, receiver,
value. wire.encrypt(secret, text) and wire.decrypt(secret, blob) are the
cipher Alice and Bob use.

Read first: why an unauthenticated key exchange lets someone in the middle,
    https://en.wikipedia.org/wiki/Man-in-the-middle_attack
"""

from dataclasses import replace

import dh
import wire


class Mallory:
    def __init__(self, g, p):
        self.g, self.p = g, p
        self.private = dh.generate_private(p)
        self.public = dh.public_from(g, p, self.private)
        self.secrets = {}     # party name -> the shared secret Mallory holds with that party
        self.read = []        # (sender, receiver, plaintext) for every text message she relays
        self.rewrite = None   # optional: a function text -> text applied to every message she relays

    def intercept(self, message):
        """Called by the wire for every message. Returns the message to deliver."""
        if message.kind == "public":
            return self.swap_public(message)
        return self.relay_text(message)

    def swap_public(self, message):
        """A public value is travelling from message.sender to message.receiver.

        Finish an exchange of your own with the sender, remember the secret
        you now share with them in self.secrets, and return the message the
        receiver should get instead. `replace(message, value=...)` makes a
        copy of a Message with one field changed.

        YOUR TASK.
        """
        raise NotImplementedError("swap_public")

    def relay_text(self, message):
        """An encrypted message is travelling from message.sender to message.receiver.

        Read it, record (sender, receiver, plaintext) in self.read, apply
        self.rewrite if it is set, and return a message the receiver can
        decrypt with the secret they think they share with the sender.

        YOUR TASK.
        """
        raise NotImplementedError("relay_text")


def attack(g, p, texts, rewrite=None):
    """Run the exchange with Mallory in the middle, then send `texts`: a list of (sender name, text)."""
    mallory = Mallory(g, p)
    mallory.rewrite = rewrite
    alice, bob, line = wire.exchange(g, p, middle=mallory)
    people = {"Alice": (alice, bob), "Bob": (bob, alice)}
    for sender, text in texts:
        me, them = people[sender]
        me.send_text(them, text)
    return alice, bob, mallory, line
