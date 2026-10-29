package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	bls12381 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign/bdn"
)

// The drand quicknet chain, pinned here (never taken from the certificate): https://api.drand.sh/<hash>/info.
const (
	quicknetHash = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
	quicknetKey  = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
)

type certificate struct {
	DrawID        string `json:"draw_id"`
	Entries       int    `json:"entries"`
	EntryListHash string `json:"entry_list_hash"`
	SeedCommit    string `json:"seed_commit"`
	RevealedSeed  string `json:"revealed_seed"`
	Beacon        struct {
		Round      uint64 `json:"round"`
		Randomness string `json:"randomness"`
		Signature  string `json:"signature"`
	} `json:"beacon"`
	ChainHash string `json:"drand_chain_hash"`
	StakesKES int64  `json:"stakes_kes"`
	PoolShare string `json:"pool_share"`
	PoolKES   int64  `json:"pool_kes"`
	Rounding  string `json:"rounding"`
	Prizes    []struct {
		Rank      int    `json:"rank"`
		Share     string `json:"share"`
		AmountKES int64  `json:"amount_kes"`
		EntryNo   int    `json:"entry_no"`
		UserID    string `json:"user_id"` // only in certificates issued before winners' ids were left out
	} `json:"prizes"`
}

type entry struct {
	EntryNo  int    `json:"entry_no"`
	UserID   string `json:"user_id"`
	PlayDate string `json:"play_date"`
	TicketID string `json:"ticket_id"`
}

func mismatch(format string, a ...any) error { return fmt.Errorf("MISMATCH: "+format, a...) }

// runDraw checks a draw certificate: go run ./tools/verifier draw -certificate cert.json [-hash HEX] [-entries entries.jsonl]
func runDraw(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("verifier draw", flag.ContinueOnError)
	certPath := fs.String("certificate", "", "the certificate as downloaded from GET /v1/draws/{id}/certificate")
	wantHash := fs.String("hash", "", "the draw's certificate_hash (optional)")
	entriesPath := fs.String("entries", "", "the full entry list, one JSON object per line (optional; lotteryctl draws entries)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := os.ReadFile(*certPath)
	if err != nil {
		return err
	}
	say := func(format string, a ...any) { _, _ = fmt.Fprintf(out, format+"\n", a...) }
	if *wantHash != "" {
		if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != strings.ToLower(*wantHash) {
			return mismatch("the certificate does not hash to %s", *wantHash)
		}
		say("certificate hash ok")
	}
	var c certificate
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	var entries []entry
	if *entriesPath != "" {
		if entries, err = readEntries(*entriesPath, c); err != nil {
			return err
		}
		say("entry list ok: %d entries hash to %s", len(entries), c.EntryListHash)
	}

	if c.ChainHash != quicknetHash {
		return mismatch("the beacon is from chain %s, not quicknet", c.ChainHash)
	}
	if err := verifyBeacon(c.Beacon.Round, c.Beacon.Signature, c.Beacon.Randomness); err != nil {
		return err
	}
	say("beacon ok: quicknet round %d", c.Beacon.Round)
	seed, err := hex.DecodeString(c.RevealedSeed)
	if sum := sha256.Sum256(seed); err != nil || hex.EncodeToString(sum[:]) != c.SeedCommit {
		return mismatch("the revealed seed is not the one committed to at freeze")
	}
	say("seed commitment ok")

	pool, err := apply(c.StakesKES, c.PoolShare, c.Rounding)
	if err != nil {
		return err
	}
	if pool != c.PoolKES {
		return mismatch("pool %d, but %s of stakes %d rounded %s is %d", c.PoolKES, c.PoolShare, c.StakesKES, c.Rounding, pool)
	}
	var total int64
	for _, p := range c.Prizes {
		amount, err := apply(pool, p.Share, c.Rounding)
		if err != nil {
			return err
		}
		if amount != p.AmountKES || amount <= 0 {
			return mismatch("rank %d pays %d, but %s of the pool is %d", p.Rank, p.AmountKES, p.Share, amount)
		}
		total += amount
	}
	if total > pool {
		return mismatch("prizes %d exceed the pool %d", total, pool)
	}
	say("pool and prizes ok: pool %d of stakes %d", pool, c.StakesKES)

	confirmed, unconfirmed, err := checkPicks(c, seed, entries)
	if err != nil {
		return err
	}
	say("winners ok: %d prizes are the algorithm's picks in rank order; skipped picks: %d confirmed, %d unconfirmed", len(c.Prizes), confirmed, unconfirmed)
	if entries == nil {
		say("certificates name winning entries, not players: pass -entries to check no player won twice and each skipped pick landed on a player who had already won")
	}
	return nil
}

// readEntries reads the entry list and checks it is the one the certificate's hash fixes.
func readEntries(path string, c certificate) ([]entry, error) {
	f, err := os.Open(path) //nolint:gosec // the user names the file to check
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var entries []entry
	h := sha256.New()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("entries line %d: %w", len(entries)+1, err)
		}
		if e.EntryNo != len(entries)+1 {
			return nil, mismatch("entry %d is numbered %d", len(entries)+1, e.EntryNo)
		}
		entries = append(entries, e)
		_, _ = fmt.Fprintf(h, "%d|%s|%s|%s\n", e.EntryNo, e.UserID, e.PlayDate, e.TicketID)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(entries) != c.Entries {
		return nil, mismatch("%d entries, the certificate says %d", len(entries), c.Entries)
	}
	if hex.EncodeToString(h.Sum(nil)) != c.EntryListHash {
		return nil, mismatch("the entry list does not hash to the certificate's entry_list_hash")
	}
	return entries, nil
}

// verifyBeacon: a BLS signature on G1 of SHA-256(round as 8 big-endian bytes) under the pinned G2 key, and
// randomness = SHA-256(signature).
func verifyBeacon(round uint64, sigHex, randomness string) error {
	suite := bls12381.NewBLS12381Suite()
	pub := suite.G2().Point()
	key, _ := hex.DecodeString(quicknetKey)
	if err := pub.UnmarshalBinary(key); err != nil {
		return err
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || round == 0 {
		return mismatch("the beacon's signature is not hex")
	}
	var r [8]byte
	binary.BigEndian.PutUint64(r[:], round)
	msg := sha256.Sum256(r[:])
	if err := bdn.NewSchemeOnG1(suite).Verify(pub, msg[:], sig); err != nil {
		return mismatch("the beacon's signature does not verify for round %d", round)
	}
	if sum := sha256.Sum256(sig); hex.EncodeToString(sum[:]) != strings.ToLower(randomness) {
		return mismatch("the beacon's randomness is not the SHA-256 of its signature")
	}
	return nil
}

// checkPicks replays the pick sequence: each prize must be the next pick that lands on a player who has not won.
// Without the entry list a skipped pick is confirmed only when it lands on an earlier winner's own entry.
func checkPicks(c certificate, seed []byte, entries []entry) (int, int, error) {
	randomness, err := hex.DecodeString(c.Beacon.Randomness)
	if err != nil || c.Entries < 1 {
		return 0, 0, mismatch("no randomness or no entries")
	}
	elh, err := hex.DecodeString(c.EntryListHash)
	if err != nil {
		return 0, 0, mismatch("entry_list_hash is not hex")
	}
	h := sha256.New()
	h.Write(randomness)
	h.Write(seed)
	h.Write(elh)
	h.Write([]byte(c.DrawID))
	key := h.Sum(nil)

	later := map[int]int{} // entry number → its rank, for prizes not reached yet
	for _, p := range c.Prizes {
		later[p.EntryNo] = p.Rank
	}
	// who holds an entry: the entry list says; without it, the player an older certificate names, or else the entry
	// stands for its holder
	who := func(no int, certified string) string {
		switch {
		case entries != nil:
			return entries[no-1].UserID
		case certified != "":
			return certified
		}
		return "entry:" + strconv.Itoa(no)
	}
	won := map[string]bool{}
	wonEntry := map[int]bool{}
	confirmed, unconfirmed := 0, 0
	r := 0
	for i := 0; r < len(c.Prizes); i++ {
		if i > 10*c.Entries+1000 {
			return 0, 0, mismatch("rank %d's entry %d is not among the picks", c.Prizes[r].Rank, c.Prizes[r].EntryNo)
		}
		p := pick(key, i, uint64(c.Entries)) //nolint:gosec // a positive entry count
		prize := c.Prizes[r]
		switch {
		case p == prize.EntryNo:
			u := who(p, prize.UserID)
			if won[u] || (entries != nil && prize.UserID != "" && prize.UserID != u) {
				return 0, 0, mismatch("pick %d (entry %d) is certified for a player who already won or does not hold it", i, p)
			}
			won[u], wonEntry[p] = true, true
			delete(later, p)
			r++
		case later[p] != 0:
			// that player had not won yet, so this pick would have given them the current rank
			return 0, 0, mismatch("pick %d landed on entry %d before rank %d went to entry %d", i, p, prize.Rank, prize.EntryNo)
		case entries != nil:
			if !won[entries[p-1].UserID] {
				return 0, 0, mismatch("pick %d landed on entry %d of a player who had not won, but rank %d went to entry %d", i, p, prize.Rank, prize.EntryNo)
			}
			confirmed++
		case wonEntry[p]:
			confirmed++
		default:
			unconfirmed++
		}
	}
	return confirmed, unconfirmed, nil
}

// pick: the first 64-bit big-endian word w of HMAC-SHA256(key, "pick:i:round") with w < 2^64 - (2^64 mod n), as
// entry w mod n + 1.
func pick(key []byte, i int, n uint64) int {
	rem := (^uint64(0)%n + 1) % n // 2^64 mod n
	for round := 0; ; round++ {
		m := hmac.New(sha256.New, key)
		_, _ = fmt.Fprintf(m, "pick:%d:%d", i, round)
		sum := m.Sum(nil)
		for j := 0; j < len(sum); j += 8 {
			if w := binary.BigEndian.Uint64(sum[j:]); rem == 0 || w <= ^uint64(0)-rem {
				return int(w%n) + 1 //nolint:gosec // below n
			}
		}
	}
}

// apply is amount × rate (a decimal with at most 5 places, 0 to 1) rounded as the certificate says, in integers.
func apply(amount int64, rate, rounding string) (int64, error) {
	whole, frac, _ := strings.Cut(rate, ".")
	if (whole != "0" && whole != "1") || len(frac) > 5 {
		return 0, fmt.Errorf("bad rate %q", rate)
	}
	frac += strings.Repeat("0", 5-len(frac))
	f, err := strconv.ParseInt(frac, 10, 64)
	if err != nil || strings.Trim(frac, "0123456789") != "" || (whole == "1" && f != 0) {
		return 0, fmt.Errorf("bad rate %q", rate)
	}
	if whole == "1" {
		f = 100_000
	}
	if amount < 0 || amount > 1<<40 {
		return 0, errors.New("amount out of range")
	}
	q, rem := amount*f/100_000, amount*f%100_000
	switch rounding {
	case "down":
	case "up":
		if rem > 0 {
			q++
		}
	case "half_up":
		if rem*2 >= 100_000 {
			q++
		}
	default:
		return 0, fmt.Errorf("unknown rounding %q", rounding)
	}
	return q, nil
}
