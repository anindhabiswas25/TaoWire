package btauth

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// LoadHotkeyFile reads a Bittensor hotkey file (the JSON btcli writes in
// <wallet>/hotkeys/<name>) and returns its key under scheme. The file must
// not be readable by group or others (one descriptor is used for the mode
// check and the read); its secretSeed (0x + 64 hex) is the key's seed, and
// its ss58Address, when present, must match. A file with only a
// secretPhrase is refused (derive the seed with btcli or the TypeScript
// package). Errors name the file, never its contents.
func LoadHotkeyFile(path string, scheme Scheme) (*Keypair, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("btauth: cannot open hotkey file %s", path)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("btauth: hotkey file %s is not a regular file", path)
	}
	if st.Mode().Perm()&0o044 != 0 {
		return nil, fmt.Errorf("btauth: hotkey file %s is readable by group or others; run: chmod 600 %s", path, path)
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("btauth: cannot read hotkey file %s", path)
	}
	var fields struct {
		SecretSeed   string  `json:"secretSeed"`
		SecretPhrase string  `json:"secretPhrase"`
		SS58Address  *string `json:"ss58Address"`
	}
	if json.Unmarshal(data, &fields) != nil {
		return nil, fmt.Errorf("btauth: hotkey file %s is not JSON", path)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(fields.SecretSeed, "0x"))
	if err != nil || len(raw) != 32 || !strings.HasPrefix(fields.SecretSeed, "0x") {
		if fields.SecretPhrase != "" {
			return nil, fmt.Errorf("btauth: hotkey file %s has a secretPhrase but no secretSeed (0x + 64 hex); this package reads secretSeed only", path)
		}
		return nil, fmt.Errorf("btauth: hotkey file %s has no secretSeed (0x + 64 hex)", path)
	}
	var seed [32]byte
	copy(seed[:], raw)
	var key *Keypair
	if scheme == Ed25519 {
		key = NewEd25519FromSeed(seed)
	} else if key, err = NewSr25519FromSeed(seed); err != nil {
		return nil, fmt.Errorf("btauth: hotkey file %s: %v", path, err)
	}
	if fields.SS58Address != nil && *fields.SS58Address != key.SS58() {
		return nil, fmt.Errorf("btauth: hotkey file %s: the seed does not match its ss58Address under %s", path, scheme)
	}
	return key, nil
}
