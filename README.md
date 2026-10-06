# Diffie-Hellman: build it, break it, argue it

The instructions and questions are on the Canvas page. This file lists what is here and how to run it.

## What is what

| File | Who writes it | What it is |
| :--- | :--- | :--- |
| `dh.py` | you, Step 1 | the exchange: `generate_private`, `public_from`, `shared_secret` |
| `eavesdrop.py` | you, Step 2 | the two brute-force searches and `recover_secret` |
| `mitm.py` | you, Step 3 | Mallory's `swap_public` and `relay_text` |
| `client.py` | you, Stage 2 | `solve_a` and `solve_b`, against the class server |
| `params.py` | given | g = 5 and p = 23, the 2048-bit group from RFC 3526, and small primes for timing |
| `wire.py` | given | a pretend network inside one Python program, with Alice, Bob, and a toy cipher |
| `selfcheck.py` | given | PASS, FAIL (with what it expected), or SKIP for each of your functions |
| `experiments.py` | given | the exchange, the timing tables, and Mallory; writes `results.json` |
| `PROTOCOL.md` | given | every message the class server sends and expects |

## Build and run

Python 3, no packages.

```
python3 selfcheck.py
python3 experiments.py
python3 experiments.py exchange
python3 experiments.py timing --bits 16 20 24
python3 experiments.py mitm
python3 client.py OURTEAM
python3 client.py OURTEAM A
```

A SKIP means a function is not written yet. A FAIL says what it expected, so start reading there.
