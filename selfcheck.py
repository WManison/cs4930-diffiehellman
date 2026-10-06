"""Check dh.py, eavesdrop.py, and mitm.py before you run the experiments. Given; do not change it.

    python3 selfcheck.py

Each check prints PASS, FAIL (with what it expected), or SKIP when a function
it needs still raises NotImplementedError. The small cases use g = 5, p = 23,
the numbers from class, so you can check every expected value by hand.
Passing every check means your functions do what the docstrings ask. It does
not grade your written answers.
"""

import signal
import time

import dh
import eavesdrop
import mitm
import params

G, P = params.TOY_G, params.TOY_P
results = []


class TooSlow(Exception):
    pass


def _alarm(signum, frame):
    raise TooSlow()


def check(name, fn, seconds=20):
    # On macOS and Linux a check that runs too long is stopped; Windows has no alarm, so it just waits.
    has_alarm = hasattr(signal, "SIGALRM")
    if has_alarm:
        signal.signal(signal.SIGALRM, _alarm)
        signal.alarm(seconds)
    try:
        fn()
        results.append("PASS")
        print(f"PASS  {name}")
    except NotImplementedError as e:
        results.append("SKIP")
        print(f"SKIP  {name} ({e} not written yet)")
    except AssertionError as e:
        results.append("FAIL")
        print(f"FAIL  {name}: {e}")
    except TooSlow:
        results.append("FAIL")
        print(f"FAIL  {name}: still running after {seconds} s. Is a huge number being built before the remainder is taken?")
    finally:
        if has_alarm:
            signal.alarm(0)


# dh.py

def t_generate_private():
    keys = [dh.generate_private(P) for _ in range(500)]
    assert all(isinstance(k, int) for k in keys), "private keys should be ints"
    assert min(keys) >= 2 and max(keys) <= P - 2, f"with p = 23 every key must be from 2 to 21; saw {min(keys)} to {max(keys)}"
    assert len(set(keys)) >= 15, f"500 keys with p = 23 should cover most of 2..21; saw only {sorted(set(keys))}"
    big = dh.generate_private(params.GROUP14_P)
    assert 2 <= big <= params.GROUP14_P - 2 and big.bit_length() > 2000, (
        "a key for the 2048-bit group should be about 2048 bits long, not a small number")


def t_public_from():
    got = dh.public_from(G, P, 6)
    assert got == 8, f"g = 5, p = 23, private 6: 5^6 = 15625, and 15625 mod 23 = 8; got {got}"
    got = dh.public_from(G, P, 15)
    assert got == 19, f"g = 5, p = 23, private 15: expected 19, got {got}"
    print("      (public_from: now the 2048-bit group. It should take well under a second;\n"
          "       if it hangs, press Ctrl+C and reread the public_from docstring)")
    start = time.perf_counter()
    big = dh.public_from(params.GROUP14_G, params.GROUP14_P, params.GROUP14_P - 2)
    assert 1 < big < params.GROUP14_P, "a public value must be between 1 and p"
    assert time.perf_counter() - start < 5, "one 2048-bit public value took more than 5 seconds"


def t_shared_secret():
    assert dh.shared_secret(19, P, 6) == 2, "Alice (private 6) receives Bob's 19: the secret is 2"
    assert dh.shared_secret(8, P, 15) == 2, "Bob (private 15) receives Alice's 8: the secret is also 2"
    a, b = dh.generate_private(params.GROUP14_P), dh.generate_private(params.GROUP14_P)
    A = dh.public_from(params.GROUP14_G, params.GROUP14_P, a)
    B = dh.public_from(params.GROUP14_G, params.GROUP14_P, b)
    assert dh.shared_secret(B, params.GROUP14_P, a) == dh.shared_secret(A, params.GROUP14_P, b), (
        "with the 2048-bit group, Alice and Bob computed different secrets")


# eavesdrop.py

def t_brute_force_pow():
    got = eavesdrop.brute_force_pow(G, P, 8)
    assert got == 6, f"which exponent turns 5 into 8 mod 23? expected 6, got {got}"
    got = eavesdrop.brute_force_pow(G, P, 1)
    assert got == 0, f"5^0 = 1, so the first match for 1 is x = 0; got {got}"
    got = eavesdrop.brute_force_pow(G, P, 0)
    assert got is None, f"no power of 5 is 0 mod 23, so expected None; got {got}"


def t_brute_force_running():
    for public, want in ((8, 6), (19, 15), (1, 0), (0, None)):
        got = eavesdrop.brute_force_running(G, P, public)
        assert got == want, f"public {public} with g = 5, p = 23: expected {want}, got {got}"
    g, p = params.SIZES[16]
    public = pow(g, 40000, p)
    got = eavesdrop.brute_force_running(g, p, public)
    assert got == 40000, f"16-bit group, private 40000: expected 40000, got {got}"


def t_recover_secret():
    got = eavesdrop.recover_secret(G, P, 8, 19)
    assert got == 2, f"from 8 and 19 alone the eavesdropper should reach the secret 2; got {got}"
    got = eavesdrop.recover_secret(G, P, 8, 19, search=eavesdrop.brute_force_pow)
    assert got == 2, f"the same, searching with brute_force_pow: expected 2, got {got}"


# mitm.py

def t_swap_public():
    alice, bob, mallory, line = mitm.attack(G, P, [])
    assert [m.value for m in line.transcript] == [alice.public, bob.public], (
        "the wire should carry Alice's and Bob's real public values; Mallory changes what arrives, not what was sent")
    assert set(mallory.secrets) == {"Alice", "Bob"}, f"Mallory should hold a secret for Alice and one for Bob; has {sorted(mallory.secrets)}"
    assert mallory.secrets["Alice"] == alice.secret, "Mallory's secret for Alice should equal the secret Alice computed"
    assert mallory.secrets["Bob"] == bob.secret, "Mallory's secret for Bob should equal the secret Bob computed"


def t_relay_text():
    texts = [("Alice", "meet at noon"), ("Bob", "see you there")]
    alice, bob, mallory, _ = mitm.attack(params.SIZES[16][0], params.SIZES[16][1], texts)
    assert bob.inbox == ["meet at noon"], f"Bob should read Alice's message unchanged; got {bob.inbox}"
    assert alice.inbox == ["see you there"], f"Alice should read Bob's reply unchanged; got {alice.inbox}"
    assert mallory.read == [("Alice", "Bob", "meet at noon"), ("Bob", "Alice", "see you there")], (
        f"Mallory should have recorded both messages as (sender, receiver, text); got {mallory.read}")
    _, bob, _, _ = mitm.attack(params.SIZES[16][0], params.SIZES[16][1], [("Alice", "meet at noon")],
                               rewrite=lambda t: t.replace("noon", "midnight"))
    assert bob.inbox == ["meet at midnight"], f"with a rewrite set, Bob should get the changed text; got {bob.inbox}"


for name, fn in [("generate_private", t_generate_private), ("public_from", t_public_from),
                 ("shared_secret", t_shared_secret), ("brute_force_pow", t_brute_force_pow),
                 ("brute_force_running", t_brute_force_running), ("recover_secret", t_recover_secret),
                 ("swap_public", t_swap_public), ("relay_text", t_relay_text)]:
    check(name, fn)
print(f"\n{results.count('PASS')} passed, {results.count('FAIL')} failed, {results.count('SKIP')} not written yet")
raise SystemExit(1 if "FAIL" in results else 0)
