package btauth

import (
	"bytes"
	"errors"

	"github.com/mr-tron/base58"
	"golang.org/x/crypto/blake2b"
)

// SS58Prefix is Bittensor's SS58 network prefix.
const SS58Prefix = 42

// ss58Len is the length of every prefix-42 address (35 bytes in base58).
// Longer input is refused before decoding: base58 decoding is quadratic, and
// the sender header is read before any signature check.
const ss58Len = 48

var errSS58 = errors.New("not a Bittensor SS58 address (prefix 42)")

func ss58Checksum(raw []byte) []byte {
	h, _ := blake2b.New512(nil) // nil key never fails
	h.Write([]byte("SS58PRE"))
	h.Write(raw)
	return h.Sum(nil)[:2]
}

// DecodeSS58 returns the 32-byte public key of a prefix-42 SS58 address
// (spec Appendix D). Other prefixes, lengths and bad checksums are errors.
func DecodeSS58(address string) ([32]byte, error) {
	var key [32]byte
	if len(address) != ss58Len {
		return key, errSS58
	}
	raw, err := base58.Decode(address)
	if err != nil || len(raw) != 35 || raw[0] != SS58Prefix {
		return key, errSS58
	}
	if !bytes.Equal(ss58Checksum(raw[:33]), raw[33:]) {
		return key, errSS58
	}
	copy(key[:], raw[1:33])
	return key, nil
}

// EncodeSS58 returns the prefix-42 SS58 address of a public key.
func EncodeSS58(publicKey [32]byte) string {
	raw := append([]byte{SS58Prefix}, publicKey[:]...)
	return base58.Encode(append(raw, ss58Checksum(raw)...))
}
