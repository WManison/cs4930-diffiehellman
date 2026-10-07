"""Diffie-Hellman key exchange. You write the three functions marked YOUR TASK.

Each side picks a private key, sends a public value, and combines the other
side's public value with its own private key. Both end up with the same
number, the shared secret. g and p come from params.py.

Every number is a Python int, which has no size limit, so the same code has to
work for p = 23 and for the 2048-bit prime.

Read first: the worked example with p = 23 and g = 5, the class numbers,
    https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange#Cryptographic_explanation


CS 4930-002 -- Group 8
2026/10/12
"""

import secrets

def generate_private(p):
    """A new private key: a random whole number from 2 to p - 2, inclusive.

    In plain steps:
        pick a random x with 2 <= x <= p - 2
        return x

    Use the secrets module, not random: its numbers are meant to be
    unguessable. secrets.randbelow(n) gives 0 to n - 1, so shift it into range.
        https://docs.python.org/3/library/secrets.html#secrets.randbelow

    YOUR TASK.
    """
    x = secrets.randbelow(p-3) + 2
    return x

    raise NotImplementedError("generate_private")


def public_from(g, p, private):
    """The public value to send: g to the power private, modulo p.

    In plain steps:
        raise g to the power private
        keep only the remainder after dividing by p

    Do both at once. With the 2048-bit group, g ** private on its own would
    need more memory than exists; pow with a third argument never builds it.
        https://docs.python.org/3/library/functions.html#pow

    YOUR TASK.
    """

    return pow(g, private, p)

    raise NotImplementedError("public_from")


def shared_secret(their_public, p, my_private):
    """The shared secret, from the other side's public value and your private key.

    In plain steps:
        raise their public value to the power of your private key, modulo p

    Alice and Bob each call this with their own arguments and get the same
    answer, because (g^a)^b and (g^b)^a are both g^(ab). Check it on paper
    with the class numbers before you write it.

    YOUR TASK.
    """

    return pow(their_public, my_private, p)

    raise NotImplementedError("shared_secret")
