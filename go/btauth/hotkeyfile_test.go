package btauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadHotkeyFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(content), 0o600)
		_ = os.Chmod(p, mode)
		return p
	}
	seed := "0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a" // //Alice, public
	good := write("good", `{"secretSeed":"`+seed+`","ss58Address":"5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"}`, 0o600)
	k, err := LoadHotkeyFile(good, Sr25519)
	if err != nil || k.SS58() != "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY" {
		t.Fatal(k, err)
	}
	ed, err := LoadHotkeyFile(write("ed", `{"secretSeed":"`+seed+`"}`, 0o600), Ed25519)
	if err != nil || ed.Scheme() != Ed25519 {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		content string
		mode    os.FileMode
		want    string
	}{
		"open":     {`{"secretSeed":"` + seed + `"}`, 0o644, "group or others"},
		"notjson":  {`x`, 0o600, "not JSON"},
		"noseed":   {`{}`, 0o600, "no secretSeed"},
		"phrase":   {`{"secretPhrase":"bottom drive obey lake curtain smoke basket hold race lonely fit walk"}`, 0o600, "secretSeed only"},
		"short":    {`{"secretSeed":"0x1234"}`, 0o600, "no secretSeed"},
		"noprefix": {`{"secretSeed":"` + seed[2:] + `"}`, 0o600, "no secretSeed"},
		"mismatch": {`{"secretSeed":"` + seed + `","ss58Address":"5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"}`, 0o600, "does not match"},
	} {
		_, err := LoadHotkeyFile(write(name, tc.content, tc.mode), Sr25519)
		if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), seed[2:]) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := LoadHotkeyFile(filepath.Join(dir, "missing"), Sr25519); err == nil {
		t.Fatal("missing file")
	}
	if _, err := LoadHotkeyFile(dir, Sr25519); err == nil {
		t.Fatal("directory")
	}
}
