"""The eavesdropper. You write the three functions marked YOUR TASK.

The eavesdropper has everything that crossed the wire: g, p, and both public
values, but neither private key. Against a small p, its only move is to guess
private keys until one fits.

You write the search two ways and time both. How you search changes the cost
by a constant factor; the size of p changes it exponentially. The timing table
shows which of the two matters.

Read first: why finding x from g^x mod p is hard, and the plain search,
    https://en.wikipedia.org/wiki/Discrete_logarithm#Algorithms

CS 4930-002 -- Group 8
Due: 2026-10-12
"""


def brute_force_pow(g, p, public):
    """The private key behind `public`, found by trying every exponent with pow.

    In plain steps:
        for each x from 0 up to p - 1:
            if g to the power x, modulo p, equals public: return x
        return None

    YOUR TASK.
    """
    raise NotImplementedError("brute_force_pow")


def brute_force_running(g, p, public):
    """The same answer as brute_force_pow, without calling pow at all.

    In plain steps:
        value = 1, which is g to the power 0
        for each x from 0 up to p - 1:
            if value equals public: return x
            value = value times g, modulo p, which is now g to the power x + 1
        return None

    Each step costs one multiplication and one remainder.

    YOUR TASK.
    """
    raise NotImplementedError("brute_force_running")


def recover_secret(g, p, alice_public, bob_public, search=brute_force_running):
    """The shared secret Alice and Bob agreed, from public values only.

    In plain steps:
        a = search for Alice's private key, using her public value
        compute the secret the way Alice would, from Bob's public value and a

    `search` is one of the two functions above. Your dh.py already has the
    second step.

    YOUR TASK.
    """
    raise NotImplementedError("recover_secret")
