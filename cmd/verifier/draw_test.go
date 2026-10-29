package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The golden certificate the server's package builds from a real quicknet beacon (internal/draws/golden_test.go).
const (
	goldenCert    = "testdata/certificate.json"
	goldenEntries = "testdata/entries.jsonl"
)

func goldenHash(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(goldenCert)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func TestDraw_VerifiesTheGoldenCertificateWithItsEntryList(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"draw", "-certificate", goldenCert, "-hash", goldenHash(t), "-entries", goldenEntries}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	for _, want := range []string{"certificate hash ok", "entry list ok: 14 entries", "beacon ok: quicknet round 1000000", "seed commitment ok",
		"pool and prizes ok: pool 420", "winners ok: 3 prizes", "0 unconfirmed"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "skipped picks: 0 confirmed") {
		t.Errorf("the golden draw skips a repeat winner, none confirmed:\n%s", out.String())
	}
}

func TestDraw_WithoutTheEntryListSaysWhatItCouldNotCheck(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"draw", "-certificate", goldenCert}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "winners ok") || strings.Contains(out.String(), "certificate hash ok") {
		t.Fatalf("%s", out.String())
	}
}

// tampered writes the golden certificate with one change.
func tampered(t *testing.T, change func(map[string]any)) string {
	t.Helper()
	raw, err := os.ReadFile(goldenCert)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	change(c)
	out, _ := json.Marshal(c)
	path := filepath.Join(t.TempDir(), "cert.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func prize(c map[string]any, i int) map[string]any { return c["prizes"].([]any)[i].(map[string]any) }

// named adds each winning entry's holder to the prizes, as certificates issued before winners' ids were left out did.
func named(c map[string]any) {
	raw, err := os.ReadFile(goldenEntries)
	if err != nil {
		panic(err)
	}
	holder := map[float64]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var e struct {
			EntryNo float64 `json:"entry_no"`
			UserID  string  `json:"user_id"`
		}
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			panic(err)
		}
		holder[e.EntryNo] = e.UserID
	}
	for i := range c["prizes"].([]any) {
		p := prize(c, i)
		p["user_id"] = holder[p["entry_no"].(float64)]
	}
}

func TestDraw_CertificatesNameNoPlayersAndOlderOnesThatDoStillVerify(t *testing.T) {
	raw, err := os.ReadFile(goldenCert)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("user_id")) {
		t.Fatal("the certificate names its winners")
	}
	var out bytes.Buffer
	if err := run([]string{"draw", "-certificate", tampered(t, named), "-entries", goldenEntries}, &out); err != nil {
		t.Fatalf("an older certificate naming its winners: %v\n%s", err, out.String())
	}
	out.Reset()
	if err := run([]string{"draw", "-certificate", tampered(t, named)}, &out); err != nil || !strings.Contains(out.String(), "winners ok") {
		t.Fatalf("without the entry list: %v\n%s", err, out.String())
	}
}

func TestDraw_RefusesEveryKindOfTampering(t *testing.T) {
	for name, change := range map[string]func(map[string]any){
		"winner swapped":         func(c map[string]any) { p := prize(c, 0); p["entry_no"] = float64(int(p["entry_no"].(float64))%14 + 1) },
		"ranks reordered":        func(c map[string]any) { ps := c["prizes"].([]any); ps[0], ps[1] = ps[1], ps[0] },
		"prize inflated":         func(c map[string]any) { prize(c, 0)["amount_kes"] = float64(211) },
		"pool inflated":          func(c map[string]any) { c["pool_kes"] = float64(421) },
		"stakes changed":         func(c map[string]any) { c["stakes_kes"] = float64(1500) },
		"other seed":             func(c map[string]any) { c["revealed_seed"] = strings.Repeat("ab", 32) },
		"other randomness":       func(c map[string]any) { c["beacon"].(map[string]any)["randomness"] = strings.Repeat("0", 64) },
		"relabelled round":       func(c map[string]any) { c["beacon"].(map[string]any)["round"] = float64(1000001) },
		"other chain":            func(c map[string]any) { c["drand_chain_hash"] = strings.Repeat("0", 64) },
		"other entry list":       func(c map[string]any) { c["entry_list_hash"] = strings.Repeat("1", 64) },
		"rank to another player": func(c map[string]any) { prize(c, 2)["entry_no"] = float64(14) },
		// certificates issued before winners' ids were left out name them; a wrong name is caught
		"named repeat winner": func(c map[string]any) {
			named(c)
			prize(c, 1)["user_id"] = prize(c, 0)["user_id"]
		},
		"named wrong holder": func(c map[string]any) {
			named(c)
			prize(c, 2)["user_id"] = "0192f3a0-0000-7000-8000-00000000000d"
		},
		"fewer ranks awarded": func(c map[string]any) { c["prizes"] = c["prizes"].([]any)[:1] }, // a structure with one rank: still the right pick
	} {
		path := tampered(t, change)
		err := run([]string{"draw", "-certificate", path, "-entries", goldenEntries}, &bytes.Buffer{})
		if name == "fewer ranks awarded" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "MISMATCH") {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	// without the entry list a pick on a later winner's entry still gives the reordering away
	swapped := tampered(t, func(c map[string]any) { ps := c["prizes"].([]any); ps[0], ps[1] = ps[1], ps[0] })
	if err := run([]string{"draw", "-certificate", swapped}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "MISMATCH") {
		t.Errorf("reordered ranks accepted without the entry list: %v", err)
	}
	// the downloaded bytes must be exactly the hashed ones
	if err := run([]string{"draw", "-certificate", tampered(t, func(map[string]any) {}), "-hash", goldenHash(t)}, &bytes.Buffer{}); err == nil {
		t.Error("re-encoded certificate matched the hash")
	}
}

func TestDraw_RefusesAnEntryListThatIsNotTheFrozenOne(t *testing.T) {
	raw, err := os.ReadFile(goldenEntries)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"an entry moved to another player": strings.Replace(string(raw), "00000000000a", "00000000000d", 1),
		"an entry missing":                 string(raw[bytes.IndexByte(raw, '\n')+1:]),
		"not json":                         "nope\n",
	} {
		path := filepath.Join(dir, "entries.jsonl")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"draw", "-certificate", goldenCert, "-entries", path}, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestApply_RoundsLikeTheLedger(t *testing.T) {
	for _, tc := range []struct {
		amount   int64
		rate, rd string
		want     int64
	}{
		{1400, "0.30000", "down", 420}, {105, "0.5", "down", 52}, {105, "0.5", "half_up", 53}, {101, "0.33", "up", 34},
		{700, "1", "down", 700}, {700, "0", "up", 0},
	} {
		if got, err := apply(tc.amount, tc.rate, tc.rd); err != nil || got != tc.want {
			t.Errorf("%d × %s %s = %d %v, want %d", tc.amount, tc.rate, tc.rd, got, err, tc.want)
		}
	}
	for _, bad := range []string{"1.5", "0.123456", "2", "0.+1234", "x"} {
		if _, err := apply(100, bad, "down"); err == nil {
			t.Errorf("rate %q accepted", bad)
		}
	}
	if _, err := apply(100, "0.5", "sideways"); err == nil {
		t.Error("unknown rounding accepted")
	}
}
