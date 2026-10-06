// Package identity is this agent's half of the mutual Ed25519 trust
// with Oddjob.
//
// The private key is generated here, on the host the agent runs on, and
// never leaves it: the server is sent only the public half and stores
// only that, so a dump of Oddjob's database cannot impersonate any
// agent. In the other direction the agent pins the server's public key
// at enrolment and checks it on every inbound call, which is what makes
// this agent belong to one Oddjob rather than to whoever finds the
// port.
//
// Enrolment is a one-time token traded for that pair of facts. After it
// has been traded the token is useless, and the file written here is
// the only thing that lets the agent keep working — so it is written
// 0600 and, on a host where that cannot be guaranteed, is the thing
// worth protecting rather than the token.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// File is what persists between runs.
type File struct {
	AgentID         int    `json:"agent_id"`
	Project         string `json:"project"`
	Server          string `json:"server"`
	PrivateKey      string `json:"private_key"`
	PublicKey       string `json:"public_key"`
	ServerPublicKey string `json:"server_public_key"`
	ConnectionMode  string `json:"connection_mode"`
	EnrolledAt      string `json:"enrolled_at"`
}

type Identity struct {
	File
	priv ed25519.PrivateKey
	srv  ed25519.PublicKey
	path string
}

// Generate makes a new keypair. The private half exists only here until
// Save writes it.
func Generate() (priv string, pub string, err error) {
	p, s, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(s),
		base64.StdEncoding.EncodeToString(p), nil
}

// Load reads a saved identity. A missing file is not an error: it means
// this agent has not enrolled yet, which is an ordinary first run.
func Load(path string) (*Identity, error) {
	raw, err := os.ReadFile(path) // #nosec G304 — operator-supplied path
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s is not a readable identity: %w", path, err)
	}
	return fromFile(f, path)
}

func fromFile(f File, path string) (*Identity, error) {
	pk, err := base64.StdEncoding.DecodeString(f.PrivateKey)
	if err != nil || len(pk) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("stored private key is not an Ed25519 key")
	}
	sp, err := base64.StdEncoding.DecodeString(f.ServerPublicKey)
	if err != nil || len(sp) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("stored server key is not an Ed25519 key")
	}
	return &Identity{File: f, priv: ed25519.PrivateKey(pk),
		srv: ed25519.PublicKey(sp), path: path}, nil
}

// FromParts builds an in-memory identity from the two keys that
// matter, with nothing on disk. For tests and for callers that have
// already loaded the material themselves.
func FromParts(privateKey, serverPublicKey string) (*Identity, error) {
	return fromFile(File{PrivateKey: privateKey,
		ServerPublicKey: serverPublicKey}, "")
}

// New builds an identity from a completed enrolment and writes it.
func New(path string, f File) (*Identity, error) {
	id, err := fromFile(f, path)
	if err != nil {
		return nil, err
	}
	return id, id.Save()
}

func (i *Identity) Save() error {
	if err := os.MkdirAll(filepath.Dir(i.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(i.File, "", "  ")
	if err != nil {
		return err
	}
	// Written to a temporary file and renamed so a crash midway cannot
	// leave a half-written identity, which would look like corruption
	// and cost an operator a re-enrolment.
	tmp := i.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, i.path)
}

// Sign returns the headers that authenticate one request.
func (i *Identity) Sign(method, path string, body []byte) map[string]string {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := newNonce()
	sig := ed25519.Sign(i.priv, Canonical(method, path, body, ts, nonce))
	return map[string]string{
		"X-Jaws-Agent":     strconv.Itoa(i.AgentID),
		"X-Jaws-Timestamp": ts,
		"X-Jaws-Nonce":     nonce,
		"X-Jaws-Signature": base64.StdEncoding.EncodeToString(sig),
	}
}

// VerifyServer checks a signature made by the Oddjob this agent pinned.
// Anything that fails here is not our server, whatever it claims.
func (i *Identity) VerifyServer(method, path string, body []byte,
	ts, nonce, sig string) bool {
	// An agent with no identity cannot have pinned anything, so there
	// is nothing a signature could be checked against. Answered rather
	// than panicked: this is reachable from the network.
	if i == nil || i.srv == nil {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	if !Fresh(ts) {
		return false
	}
	return ed25519.Verify(i.srv, Canonical(method, path, body, ts, nonce), raw)
}

// Canonical is what both sides sign. It must match the server's
// construction byte for byte -- see backend/app/agentcrypto.py. The
// body is hashed rather than included so a large scan result is not
// held twice, and the path is in there so a signature captured from
// one route cannot be replayed against another.
func Canonical(method, path string, body []byte, ts, nonce string) []byte {
	sum := sha256.Sum256(body)
	return []byte(strings.Join([]string{
		strings.ToUpper(method), path, hex.EncodeToString(sum[:]), ts, nonce,
	}, "\n"))
}

// SkewSeconds is how far apart the two clocks may be, matching the
// server. Generous enough for a host whose clock drifts, tight enough
// that a captured request is not useful for long.
const SkewSeconds = 300

func Fresh(ts string) bool {
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	d := time.Now().Unix() - n
	if d < 0 {
		d = -d
	}
	return d <= SkewSeconds
}

func newNonce() string {
	b := make([]byte, 16)
	// crypto/rand.Read does not fail in practice, and a nonce that is
	// merely unique would still be sound here -- the signature is what
	// authenticates. Falling back to the clock keeps the agent working
	// rather than wedging it on an impossible error.
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
