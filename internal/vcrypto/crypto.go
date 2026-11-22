// Package vcrypto wraps the signing primitives used across the system.
//
// Every signature is domain-separated: the signer signs
// domain || 0x00 || canonical-payload. Without this, a signature produced for
// one purpose (say, a station check-in) could be replayed as a signature for
// another (say, an owner consent), which is exactly the kind of
// cross-protocol confusion an attacker with a stolen device would look for.
package vcrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrBadSignature is returned when verification fails.
var ErrBadSignature = errors.New("vcrypto: signature verification failed")

// GenerateKey returns a fresh Ed25519 keypair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("vcrypto: generate key: %w", err)
	}
	return pub, priv, nil
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("vcrypto: random: %w", err)
	}
	return b, nil
}

// RandomID returns a 128-bit random identifier encoded as lowercase hex.
func RandomID() string {
	b, err := RandomBytes(16)
	if err != nil {
		// crypto/rand failing is unrecoverable for an authorization service.
		panic(err)
	}
	return hex.EncodeToString(b)
}

func message(domain string, payload []byte) []byte {
	msg := make([]byte, 0, len(domain)+1+len(payload))
	msg = append(msg, domain...)
	msg = append(msg, 0x00)
	msg = append(msg, payload...)
	return msg
}

// Sign signs domain || 0x00 || payload with priv.
func Sign(priv ed25519.PrivateKey, domain string, payload []byte) []byte {
	return ed25519.Sign(priv, message(domain, payload))
}

// Verify checks a signature produced by Sign.
func Verify(pub ed25519.PublicKey, domain string, payload, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad public key length %d", ErrBadSignature, len(pub))
	}
	if !ed25519.Verify(pub, message(domain, payload), sig) {
		return ErrBadSignature
	}
	return nil
}

// Hash returns SHA-256 over the concatenation of its arguments.
func Hash(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		// Length-prefix each part so that Hash("ab","c") != Hash("a","bc").
		var l [8]byte
		n := uint64(len(p))
		for i := 0; i < 8; i++ {
			l[i] = byte(n >> (8 * (7 - i)))
		}
		h.Write(l[:])
		h.Write(p)
	}
	return h.Sum(nil)
}

// Equal reports constant-time equality of two byte slices.
func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
