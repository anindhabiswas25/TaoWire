package btauth

import (
	"crypto/ed25519"

	"filippo.io/edwards25519"
)

// Keypair is a hotkey that can sign: sr25519 or ed25519.
type Keypair struct {
	scheme Scheme
	public [32]byte
	ss58   string
	sr     *sr25519Key
	ed     ed25519.PrivateKey
}

// NewSr25519FromSeed builds an sr25519 hotkey from its 32-byte mini secret
// ("secretSeed" in a Bittensor hotkey file; spec 11.3 notes).
func NewSr25519FromSeed(seed [32]byte) (*Keypair, error) {
	k, err := newSr25519Key(seed)
	if err != nil {
		return nil, err
	}
	return &Keypair{scheme: Sr25519, public: k.public, ss58: EncodeSS58(k.public), sr: k}, nil
}

// NewEd25519FromSeed builds an ed25519 hotkey from its 32-byte RFC 8032 seed.
func NewEd25519FromSeed(seed [32]byte) *Keypair {
	priv := ed25519.NewKeyFromSeed(seed[:])
	var pub [32]byte
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	return &Keypair{scheme: Ed25519, public: pub, ss58: EncodeSS58(pub), ed: priv}
}

// Scheme is the key's signature scheme.
func (k *Keypair) Scheme() Scheme { return k.scheme }

// PublicKey is the raw 32-byte public key.
func (k *Keypair) PublicKey() [32]byte { return k.public }

// SS58 is the key's prefix-42 address.
func (k *Keypair) SS58() string { return k.ss58 }

// Sign signs exactly msg, never a wrapped form. ed25519 signatures are
// deterministic; sr25519 signatures are randomized.
func (k *Keypair) Sign(msg []byte) ([64]byte, error) {
	if k.scheme == Ed25519 {
		var out [64]byte
		copy(out[:], ed25519.Sign(k.ed, msg))
		return out, nil
	}
	return k.sr.sign(msg)
}

// String never shows key material.
func (k *Keypair) String() string { return "Keypair(" + k.ss58 + ", " + string(k.scheme) + ")" }

// IsWeakPublicKey reports whether a public key has a signature that verifies
// for every message: the sr25519 (ristretto) identity, or an ed25519 point
// of order 1, 2, 4 or 8. Verifiers refuse such keys (negative.json N63, N64).
func IsWeakPublicKey(scheme Scheme, publicKey [32]byte) bool {
	if scheme == Sr25519 {
		return publicKey == [32]byte{}
	}
	p, err := new(edwards25519.Point).SetBytes(publicKey[:])
	if err != nil {
		return false // not a point: it never verifies anyway
	}
	return new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1
}

// verifySignature verifies sig over exactly msg under scheme only.
func verifySignature(scheme Scheme, publicKey [32]byte, msg []byte, sig [64]byte) bool {
	if IsWeakPublicKey(scheme, publicKey) {
		return false
	}
	if scheme == Ed25519 {
		return ed25519.Verify(publicKey[:], msg, sig[:])
	}
	return sr25519Verify(publicKey, msg, sig)
}
