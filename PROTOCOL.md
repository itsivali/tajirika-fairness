# The Tajirika fairness protocol

Two things are random in Tajirika: the slot a spin lands on, and the winners of a draw. Both are decided by inputs
that are fixed, and partly published, before the outcome can be known, so that anyone can recompute the result
afterwards. This document is the specification; `cmd/verifier` implements it independently of the platform.

## 1. Spins

A player has a **seed chain**:

- a **server seed**: 32 random bytes, kept secret until the chain is rotated, and shown up front only as its
  **commitment**, the lower-case hex SHA-256 of the seed bytes;
- a **client seed**: 1 to 64 letters, digits, `-` or `_`, chosen by the player (the app gives a default);
- a **nonce**: starts at 0 and increases by one with every spin on the chain.

Each spin also records its **odds version**: the slot count *n* (2 to 65536) and the number of **lucky slots** *k*
(1 to *n*−1); slots `0 … k−1` are lucky.

The slot of a spin is derived from the chain:

```
for round = 0, 1, 2, …:
    mac = HMAC-SHA256(key = server seed bytes,
                      message = client seed + ":" + nonce + ":" + round)     # decimal numbers, ASCII
    for each of the 8 big-endian 32-bit words w of mac, in order:
        if w < 2^32 − (2^32 mod n):  the slot is w mod n          # done
```

Words at or above the limit are rejected and the next word (or the next round) is tried, so every slot is exactly
equally likely: there is no modulo bias.

When the chain is **rotated** the server seed is revealed. Anyone can then check that its SHA-256 is the commitment
that was shown before the spins, and recompute every slot. A commitment cannot be changed after the fact, and the
server cannot pick a seed that favours it without knowing the client seed and nonces in advance of committing.

## 2. Draws

A draw covers a period (daily, and the player's own weekly, monthly and quarterly periods) and runs in stages that
each fix something the next stage depends on.

### 2.1 Freeze

At the end of the period the draw is **frozen**:

- the **entry list** is fixed: every paid play in the period becomes one numbered entry, `1 … N`, in order;
- the **entry list hash** is published: the SHA-256 of the list written as one line per entry,
  `entry_no|user_id|play_date|ticket_id` followed by a newline (`\n`), in entry order;
- a **draw seed** (32 random bytes) is generated and only its commitment, the SHA-256 of the seed, is published;
- the **beacon round** is fixed: the drand *quicknet* round that will be published at 09:00 Nairobi time the next
  morning (`drand_round_at`).

Two different officials must sign the frozen draw before that round is published. A draw not signed in time is
voided and re-run against the next 09:00 round.

### 2.2 The beacon

The randomness comes from [drand](https://drand.love)'s quicknet chain (chain hash
`52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971`), a public, unbiased, unpredictable beacon
produced by a network of independent operators. For round *r*:

- the **signature** is a BLS signature on BLS12-381 G1 of `SHA-256(r as 8 big-endian bytes)`, verifiable against the
  chain's public key on G2, which the verifier pins and never takes from the certificate;
- the **randomness** is `SHA-256(signature)`.

Nobody, the platform included, knows the beacon before the round is published, and nobody can alter it afterwards.

### 2.3 The picks

Once the beacon exists, the draw is **conducted**. The pick key is

```
key = SHA-256(randomness bytes || draw seed bytes || entry list hash bytes || draw id as ASCII)
```

and pick number *i* (from 0) over *N* entries is

```
for round = 0, 1, 2, …:
    mac = HMAC-SHA256(key, "pick:" + i + ":" + round)                       # decimal numbers, ASCII
    for each of the 4 big-endian 64-bit words w of mac, in order:
        if w ≤ 2^64 − 1 − (2^64 mod N):  the pick is entry (w mod N) + 1   # done
```

Prizes are awarded in rank order: rank 1 goes to pick 0's entry, and each following rank to the next pick whose
entry belongs to a player who has **not already won** in this draw; picks landing on a player who already won are
skipped.

### 2.4 Money

The **pool** is the period's stakes multiplied by the published `pool_share` (a decimal with at most five places),
rounded as the certificate's `rounding` says (`down`, `up` or `half_up`), in whole shillings. Each prize is the pool
multiplied by its rank's `share`, rounded the same way. The prizes never exceed the pool.

### 2.5 The certificate

The conducted draw is written as a **certificate**, a JSON document holding the draw id, the number of entries and
the entry list hash, the seed commitment and the revealed seed, the beacon (round, signature, randomness) and chain
hash, the stakes, pool share, pool, rounding, and the prizes (rank, share, amount, winning entry number). Its SHA-256
is the draw's `certificate_hash`, published with the results. Two officials review the certificate and approve the
draw before any prize is paid; a certificate cannot be changed afterwards without changing its hash.

Certificates name winning **entries**, not players. The entry list itself is not public, so players stay private; it
is given to the regulator, who can check with it that no player won twice and that every skipped pick landed on a
player who had already won. Players see their own entries and prizes in the app.

### 2.6 What the verifier checks

Given a certificate and its hash (and optionally the entry list), `verifier draw` checks every statement above:
the hash, the chain and the beacon signature, the seed against its commitment, the pool and prizes, and that each
winner is the algorithm's pick in rank order. Any discrepancy is reported as `MISMATCH`.

## 3. Reporting a problem

If the verifier reports a mismatch on a real spin or draw, keep the inputs (the certificate, the hash, the seeds)
and raise it with Tajirika and, if you wish, the regulator. The inputs are enough for anyone to reproduce the check.
