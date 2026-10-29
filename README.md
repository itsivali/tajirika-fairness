# Tajirika fairness

[Tajirika](https://tajirika.co.ke) is an M-Pesa lottery for Kenya. This repository is the public half of its fairness
story: the **protocol** every spin and draw follows ([PROTOCOL.md](PROTOCOL.md)) and a **verifier** that checks real
spins and draws against it, using only what the platform publishes. The verifier shares no code with the platform; it
re-implements the protocol from the document, which is the point.

## Install

```sh
go install github.com/itsivali/tajirika-fairness/cmd/verifier@latest
```

or clone and `go run ./cmd/verifier …`.

## Check your own spins

Each player has a *seed chain*: a secret server seed the platform commits to up front (you see its SHA-256 before you
spin), your client seed, and a nonce that counts your spins. When the chain is rotated (the app's **Fairness** page,
*Rotate seed*), the server seed is revealed. Then:

```sh
verifier -server-seed <revealed seed> -commitment <commitment shown before the spins> \
         -client-seed <your client seed> -nonce 0-3 -slots 12 -lucky 1
```

It confirms the revealed seed is the committed one and prints the slot of every spin, which must be what the wheel
showed. `-slots` and `-lucky` are the odds version recorded on each spin (the app shows them).

## Check a draw

Every conducted draw publishes a certificate and its hash:

```sh
curl -s https://api.tajirika.co.ke/v1/draws/<id> | python3 -m json.tool       # certificate_hash, drand round, results
curl -s https://api.tajirika.co.ke/v1/draws/<id>/certificate -o cert.json    # the exact bytes that were hashed
verifier draw -certificate cert.json -hash <certificate_hash>
```

The verifier checks, in order: that the certificate hashes to the published hash; that the randomness is a genuine
[drand quicknet](https://drand.love) beacon (a BLS signature verified against the chain's pinned public key, not
anything the certificate claims); that the revealed seed matches the commitment made when the draw was frozen, before
the beacon existed; that the pool and every prize follow from the stakes and the published shares; and that every
winner is exactly the pick the algorithm produces, in rank order.

Certificates name winning **entries**, never players. Without the full entry list (which is not public, to keep
players private) the verifier cannot confirm that no player won twice; it says so. The regulator receives the entry
list and runs the same command with `-entries entries.jsonl`.

You can fetch the beacon yourself and compare: `https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/<round>`.

## What is where

- `PROTOCOL.md`: the specification, in full, for spins and draws.
- `cmd/verifier`: the tool, with the test vectors (`testdata/`) the platform's own tests use.

Licensed under the MIT License. The platform itself is not open source.
