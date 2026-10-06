"""Run the exchange, time the eavesdropper, and run the man in the middle. Given; do not change it.

    python3 experiments.py              all three parts
    python3 experiments.py exchange     Step 1: the exchange, by hand and at 2048 bits
    python3 experiments.py timing       Step 2: brute force at 16, 20, 24, and 28 bits
    python3 experiments.py timing --bits 16 20     only some sizes (28 bits takes a while)
    python3 experiments.py mitm         Step 3: Mallory in the middle

The Canvas questions ask for what it prints. It also writes results.json,
which keeps the latest run of each part.

The timing part is the harness for your brute-force table. For each prime
size it picks private keys from a seeded random generator (change them with
--seed), times recover_secret() with each search style, and checks the answer
against the real secret. Because the search tries exponents in order, the
number of guesses is the private key plus one. The last column scales your
measured speed up to every possible key, which is the number to extrapolate
from.
"""

import argparse
import json
import random
import time

import dh
import eavesdrop
import mitm
import params
import wire


def short(n, digits=12):
    """A big number shown as its first hex digits and its size, so a table stays readable."""
    h = format(n, "x")
    return h if len(h) <= digits else f"{h[:digits]}... ({n.bit_length()} bits)"


def part_exchange():
    print("## Step 1. The exchange\n")
    g, p = params.TOY_G, params.TOY_P
    a, b = 6, 15
    A, B = dh.public_from(g, p, a), dh.public_from(g, p, b)
    sa, sb = dh.shared_secret(B, p, a), dh.shared_secret(A, p, b)
    print(f"Public: g = {g}, p = {p}")
    print(f"Alice picks private a = {a} and sends A = g^a mod p = {A}")
    print(f"Bob picks private b = {b} and sends B = g^b mod p = {B}")
    print(f"Alice computes B^a mod p = {sa}")
    print(f"Bob computes A^b mod p = {sb}")
    print(f"The wire carried only {g}, {p}, {A}, and {B}.\n")

    a2, b2 = dh.generate_private(p), dh.generate_private(p)
    A2, B2 = dh.public_from(g, p, a2), dh.public_from(g, p, b2)
    print(f"Again with random keys: a = {a2}, b = {b2}, A = {A2}, B = {B2}, "
          f"secrets {dh.shared_secret(B2, p, a2)} and {dh.shared_secret(A2, p, b2)}\n")

    g, p = params.GROUP14_G, params.GROUP14_P
    start = time.perf_counter()
    a3, b3 = dh.generate_private(p), dh.generate_private(p)
    A3, B3 = dh.public_from(g, p, a3), dh.public_from(g, p, b3)
    sa3, sb3 = dh.shared_secret(B3, p, a3), dh.shared_secret(A3, p, b3)
    took = time.perf_counter() - start
    print(f"RFC 3526 group 14: g = {g}, p = {short(p)}")
    print(f"Alice sends A = {short(A3)}")
    print(f"Bob sends   B = {short(B3)}")
    print(f"Alice's secret = {short(sa3)}")
    print(f"Bob's secret   = {short(sb3)}")
    print(f"Both sides agree: {sa3 == sb3}  (whole exchange: {took:.3f} s)\n")
    return {"toy": {"g": 5, "p": 23, "a": a, "b": b, "A": A, "B": B, "alice_secret": sa, "bob_secret": sb},
            "group14": {"agree": sa3 == sb3, "secret_bits": sa3.bit_length(), "seconds": round(took, 4)}}


def time_search(g, p, A, B, secret, search):
    """Seconds for one recover_secret() call, and whether its answer was right.

    A search that finishes in under 0.2 s is repeated and averaged, because a
    single run that short is mostly timer noise.
    """
    runs, total = 0, 0.0
    while True:
        start = time.perf_counter()
        got = eavesdrop.recover_secret(g, p, A, B, search=search)
        total += time.perf_counter() - start
        runs += 1
        if total >= 0.2 or runs >= 1000 or got != secret:
            return total / runs, got == secret


def part_timing(bits_list, seed, pow_bits):
    print("## Step 2. The eavesdropper, timed\n")
    print("Running product (brute_force_running):\n")
    print("| bits | p | private key | guesses | seconds | guesses per second | seconds to try every key |")
    print("| --: | --: | --: | --: | --: | --: | --: |")
    rows, keys = [], {}
    for bits in bits_list:
        g, p = params.SIZES[bits]
        rng = random.Random(seed * 1000 + bits)
        a, b = rng.randint(2, p - 2), rng.randint(2, p - 2)
        A, B = pow(g, a, p), pow(g, b, p)
        keys[bits] = (g, p, a, A, B, pow(B, a, p))
        took, right = time_search(g, p, A, B, pow(B, a, p), eavesdrop.brute_force_running)
        rate = (a + 1) / took
        rows.append({"bits": bits, "p": p, "private": a, "seconds": took, "per_second": round(rate),
                     "all_keys_seconds": round((p - 1) / rate, 2), "correct": right})
        flag = "" if right else "  WRONG SECRET"
        print(f"| {bits} | {p} | {a} | {a + 1} | {took:.4f} | {rate:,.0f} | {(p - 1) / rate:,.2f} |{flag}")

    print("\nOne pow() per guess (brute_force_pow), same keys:\n")
    print("| bits | seconds | guesses per second | slower than the running product by |")
    print("| --: | --: | --: | --: |")
    slow = []
    for bits in pow_bits:
        if bits not in keys:
            continue
        g, p, a, A, B, secret = keys[bits]
        took, right = time_search(g, p, A, B, secret, eavesdrop.brute_force_pow)
        fast = next(r["seconds"] for r in rows if r["bits"] == bits)
        ratio = took / fast
        slow.append({"bits": bits, "seconds": took, "ratio": round(ratio, 1), "correct": right})
        flag = "" if right else "  WRONG SECRET"
        print(f"| {bits} | {took:.4f} | {(a + 1) / took:,.0f} | {ratio:.1f}x |{flag}")
    print("\nThe extrapolation to 2048 bits is yours: use the last column of the first table.\n")
    return {"seed": seed, "running": rows, "pow": slow}


def part_mitm():
    print("## Step 3. The man in the middle\n")
    g, p = params.GROUP14_G, params.GROUP14_P
    texts = [("Alice", "the key to the office is under the mat"), ("Bob", "thanks, I will be there at 9")]

    alice, bob, line = wire.exchange(g, p)
    for sender, text in texts:
        (alice if sender == "Alice" else bob).send_text(bob if sender == "Alice" else alice, text)
    print("Without Mallory, 2048-bit group. A passive eavesdropper sees only this:")
    for m in line.transcript:
        shown = short(m.value) if m.kind == "public" else m.value[:12].hex() + "..."
        print(f"  {m.sender} -> {m.receiver}  {m.kind:6}  {shown}")
    print(f"Alice and Bob share one secret: {alice.secret == bob.secret}\n")

    alice, bob, mallory, line = mitm.attack(g, p, texts)
    print("With Mallory in the middle, same group, same messages:")
    print(f"  Alice's secret: {short(alice.secret)}")
    print(f"  Bob's secret:   {short(bob.secret)}")
    print(f"  Alice and Bob share one secret: {alice.secret == bob.secret}")
    print(f"  Mallory holds Alice's secret: {mallory.secrets.get('Alice') == alice.secret}, "
          f"Bob's secret: {mallory.secrets.get('Bob') == bob.secret}")
    print("  What Mallory read:")
    for sender, receiver, text in mallory.read:
        print(f"    {sender} -> {receiver}: {text!r}")
    print(f"  What Bob received: {bob.inbox}")
    print(f"  What Alice received: {alice.inbox}\n")

    _, bob2, _, _ = mitm.attack(g, p, texts[:1], rewrite=lambda t: t.replace("under the mat", "with the front desk"))
    print("Mallory rewrites Alice's message on the way:")
    print(f"  Alice sent:    {texts[0][1]!r}")
    print(f"  Bob received:  {bob2.inbox[0]!r}\n")
    return {"share_one_secret": alice.secret == bob.secret, "mallory_read": mallory.read,
            "bob_received": bob.inbox, "rewritten": bob2.inbox}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("part", nargs="?", choices=["exchange", "timing", "mitm"], help="run one part (default: all)")
    ap.add_argument("--bits", type=int, nargs="+", choices=sorted(params.SIZES), default=sorted(params.SIZES),
                    help="prime sizes for the timing table")
    ap.add_argument("--pow-bits", type=int, nargs="+", default=[16, 20],
                    help="sizes to also time with brute_force_pow (default 16 20)")
    ap.add_argument("--seed", type=int, default=7, help="seed for the timing table's private keys")
    args = ap.parse_args()

    try:
        with open("results.json") as f:
            out = json.load(f)
    except (OSError, ValueError):
        out = {}
    parts = [("exchange", part_exchange), ("timing", lambda: part_timing(args.bits, args.seed, args.pow_bits)),
             ("mitm", part_mitm)]
    for name, run in parts:
        if args.part not in (None, name):
            continue
        try:
            out[name] = run()
        except NotImplementedError as e:
            print(f"\n## {name}: skipped, {e} is not written yet (python3 selfcheck.py shows what is left)\n")
    with open("results.json", "w") as f:
        json.dump(out, f, indent=1)
    print("wrote results.json")


if __name__ == "__main__":
    main()
