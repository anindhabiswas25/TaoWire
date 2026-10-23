package btauth

// The only file that touches go-schnorrkel (pinned in go.mod): its API names
// change between versions, so a bump changes this file alone (spec 11.4).

import (
	schnorrkel "github.com/ChainSafe/go-schnorrkel"
)

// signingContext is the substrate signing context for sr25519 (spec 4.2).
var signingContext = []byte("substrate")

// sr25519Verify verifies sig over exactly msg. It never tries a wrapped form.
// Undecodable keys or signatures (including a missing schnorrkel marker bit)
// and the identity key are simply invalid.
func sr25519Verify(publicKey [32]byte, msg []byte, sig [64]byte) bool {
	if publicKey == ([32]byte{}) {
		return false // the ristretto identity: a universal signature exists
	}
	pk, err := schnorrkel.NewPublicKey(publicKey)
	if err != nil {
		return false
	}
	var s schnorrkel.Signature
	if err := s.Decode(sig); err != nil {
		return false
	}
	ok, err := pk.Verify(&s, schnorrkel.NewSigningContext(signingContext, msg))
	return err == nil && ok
}

type sr25519Key struct {
	secret *schnorrkel.SecretKey
	public [32]byte
}

// newSr25519Key expands a 32-byte mini secret the substrate way (Ed25519 mode).
func newSr25519Key(seed [32]byte) (*sr25519Key, error) {
	mini, err := schnorrkel.NewMiniSecretKeyFromRaw(seed)
	if err != nil {
		return nil, err
	}
	return &sr25519Key{secret: mini.ExpandEd25519(), public: mini.Public().Encode()}, nil
}

// sign returns a schnorrkel signature over msg (randomized: go-schnorrkel
// draws witness randomness from crypto/rand).
func (k *sr25519Key) sign(msg []byte) ([64]byte, error) {
	sig, err := k.secret.Sign(schnorrkel.NewSigningContext(signingContext, msg))
	if err != nil {
		return [64]byte{}, err
	}
	return sig.Encode(), nil
}
