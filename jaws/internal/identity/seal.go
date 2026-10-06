package identity

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"crypto/sha256"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"io"
)

// Sealing hides the payload from everything between this agent and the
// Oddjob it enrolled with.
//
// The signature already proves who sent a request and that it arrived
// whole. It does not hide it, and what goes over this channel is the
// client's own vulnerability inventory, from inside the client's own
// network — where a TLS-terminating proxy is ordinary corporate
// furniture. TLS alone means that box reads everything.
//
// So the body is sealed under a key derived from the X25519 halves
// swapped at enrollment, and TLS stays underneath for what it is good
// for. Standard primitives throughout: X25519, HKDF-SHA256,
// ChaCha20-Poly1305. The construction must match the server's exactly
// — see backend/app/agentcrypto.py, and the pinned vectors in the
// tests, because a mismatch here does not fail loudly, it fails as
// "the sealed body did not open" on an agent nobody can reach.

// SealVersion is sent as a header so a mismatch is a clear refusal
// rather than a decryption failure.
const SealVersion = "v1"

const SealedHeader = "X-Jaws-Sealed"

// GenerateKex makes the key-agreement pair, as (private, public).
func GenerateKex() (string, string, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", err
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv[:]),
		base64.StdEncoding.EncodeToString(pub), nil
}

// SharedKey derives the symmetric key for this agent and its server.
//
// HKDF rather than the raw X25519 output: that output is not uniformly
// random and is not safe to use as a key directly. The info string
// pins the construction, so changing it produces a different key
// instead of two versions silently half-working.
func SharedKey(privateB64, peerPublicB64 string) ([]byte, error) {
	priv, err := base64.StdEncoding.DecodeString(privateB64)
	if err != nil || len(priv) != 32 {
		return nil, fmt.Errorf("bad key-agreement private key")
	}
	peer, err := base64.StdEncoding.DecodeString(peerPublicB64)
	if err != nil || len(peer) != 32 {
		return nil, fmt.Errorf("bad key-agreement public key")
	}
	secret, err := curve25519.X25519(priv, peer)
	if err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	r := hkdf.New(sha256.New, secret, nil,
		[]byte("oddjob/jaws seal "+SealVersion))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// ChannelBinding is what the seal is tied to: direction, agent, method,
// path, timestamp, nonce. Authenticated but not encrypted, so an
// envelope lifted onto another route, replayed back the other way, or
// aimed at a different agent will not open.
func ChannelBinding(direction string, agentID int, method, path, ts,
	nonce string) []byte {
	return []byte(strings.Join([]string{
		SealVersion, direction, fmt.Sprint(agentID),
		strings.ToUpper(method), path, ts, nonce,
	}, "\n"))
}

// Seal returns base64(nonce || ciphertext).
func Seal(key, plaintext, aad []byte) (string, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(
		append(nonce, a.Seal(nil, nonce, plaintext, aad)...)), nil
}

// Unseal reverses it. Any failure is a refusal, never a partial trust.
func Unseal(key []byte, blob string, aad []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(blob))
	if err != nil {
		return nil, fmt.Errorf("sealed body is not base64")
	}
	if len(raw) < chacha20poly1305.NonceSize+16 {
		return nil, fmt.Errorf("sealed body is too short to be one")
	}
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	out, err := a.Open(nil, raw[:chacha20poly1305.NonceSize],
		raw[chacha20poly1305.NonceSize:], aad)
	if err != nil {
		return nil, fmt.Errorf("the sealed body did not open")
	}
	return out, nil
}

// CanSeal reports whether this identity has both halves it needs.
func (i *Identity) CanSeal() bool {
	return i != nil && i.KexPrivateKey != "" && i.ServerKexPublicKey != ""
}

// SealKey is the derived symmetric key, computed once and kept.
func (i *Identity) SealKey() ([]byte, error) {
	if !i.CanSeal() {
		return nil, fmt.Errorf("this agent enrolled without a key-agreement key")
	}
	if i.sealKey == nil {
		k, err := SharedKey(i.KexPrivateKey, i.ServerKexPublicKey)
		if err != nil {
			return nil, err
		}
		i.sealKey = k
	}
	return i.sealKey, nil
}
