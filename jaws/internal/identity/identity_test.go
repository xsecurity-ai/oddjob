package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The signature scheme spans two languages, and a mismatch between them
// does not fail loudly -- it fails as "401, signature does not verify"
// on an agent in the field, which looks like a key problem and is not.
// These vectors come from the Python side (backend/app/agentcrypto.py)
// and are pinned here so a change to either construction breaks a test
// rather than an engagement.
const (
	vecCanonical = "POST\n/api/agents/heartbeat\n" +
		"93a23971a914e5eacbf0a8d25154cda309c3c1c72fbb9914d47c60f3cb681588\n" +
		"1760000000\nabc123"
	vecPub = "+ytAfMeASRay/z3eYzVtpQfebKIQ6u6+qJAaW/vX430="
	vecSig = "HOwjw3CUvNdPUnRPhBNmp5Ho+M5dTMdShdYSZOKc3skmyLiGerqZ4mjM13prLW9h" +
		"DqizjiPyFZi74Y1dULNrBg=="
	vecBody = `{"hello":"world"}`
)

func TestCanonicalMatchesTheServer(t *testing.T) {
	got := string(Canonical("post", "/api/agents/heartbeat",
		[]byte(vecBody), "1760000000", "abc123"))
	if got != vecCanonical {
		t.Errorf("canonical string differs from the server's:\n got %q\nwant %q",
			got, vecCanonical)
	}
}

func TestVerifiesASignatureMadeByTheServer(t *testing.T) {
	pub, err := base64.StdEncoding.DecodeString(vecPub)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(vecSig)
	if err != nil {
		t.Fatal(err)
	}
	msg := Canonical("POST", "/api/agents/heartbeat", []byte(vecBody),
		"1760000000", "abc123")
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("a signature the server made does not verify here")
	}
	// And the inverse: a body the server did not sign must not pass.
	bad := Canonical("POST", "/api/agents/heartbeat", []byte(`{"hello":"there"}`),
		"1760000000", "abc123")
	if ed25519.Verify(pub, bad, sig) {
		t.Fatal("signature verified against a different body")
	}
}

func TestSignRoundTrips(t *testing.T) {
	priv, pub, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	spub, _ := base64.StdEncoding.DecodeString(pub)
	id, err := fromFile(File{AgentID: 7, PrivateKey: priv,
		ServerPublicKey: pub}, "")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"a":1}`)
	h := id.Sign("POST", "/api/agents/heartbeat", body)
	if h["X-Jaws-Agent"] != "7" {
		t.Errorf("agent id header = %q", h["X-Jaws-Agent"])
	}
	sig, err := base64.StdEncoding.DecodeString(h["X-Jaws-Signature"])
	if err != nil {
		t.Fatal(err)
	}
	msg := Canonical("POST", "/api/agents/heartbeat", body,
		h["X-Jaws-Timestamp"], h["X-Jaws-Nonce"])
	if !ed25519.Verify(ed25519.PublicKey(spub), msg, sig) {
		t.Fatal("our own signature does not verify")
	}
}

func TestNoncesDoNotRepeat(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		n := newNonce()
		if seen[n] {
			t.Fatalf("nonce repeated after %d draws: %q", i, n)
		}
		seen[n] = true
	}
}

func TestFreshWindow(t *testing.T) {
	now := strconv.FormatInt(time.Now().Unix(), 10)
	if !Fresh(now) {
		t.Error("a current timestamp is not fresh")
	}
	old := strconv.FormatInt(time.Now().Unix()-SkewSeconds-10, 10)
	if Fresh(old) {
		t.Error("a stale timestamp passed")
	}
	// Ahead of us as well as behind: a clock that runs fast is just as
	// much of a problem, and accepting it would widen the replay window
	// in the direction nobody checks.
	ahead := strconv.FormatInt(time.Now().Unix()+SkewSeconds+10, 10)
	if Fresh(ahead) {
		t.Error("a timestamp from the future passed")
	}
	if Fresh("not-a-number") {
		t.Error("a malformed timestamp passed")
	}
}

func TestVerifyServerRejectsAnotherServer(t *testing.T) {
	_, realPub, _ := Generate()
	impostorPriv, _, _ := Generate()

	myPriv, _, _ := Generate()
	id, err := fromFile(File{AgentID: 1, PrivateKey: myPriv,
		ServerPublicKey: realPub}, "")
	if err != nil {
		t.Fatal(err)
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	raw, _ := base64.StdEncoding.DecodeString(impostorPriv)
	msg := Canonical("POST", "/poll", nil, ts, "n1")
	sig := base64.StdEncoding.EncodeToString(
		ed25519.Sign(ed25519.PrivateKey(raw), msg))

	// This is the property that makes an agent belong to one Oddjob: a
	// perfectly valid signature from a different server is still not
	// our server.
	if id.VerifyServer("POST", "/poll", nil, ts, "n1", sig) {
		t.Fatal("accepted a signature from a server we never enrolled with")
	}
}

func TestIdentityFileIsPrivateAndSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "identity.json")
	priv, pub, _ := Generate()
	_, srvPub, _ := Generate()

	id, err := New(path, File{AgentID: 42, Project: "ACME", Server: "https://x",
		PrivateKey: priv, PublicKey: pub, ServerPublicKey: srvPub,
		ConnectionMode: "callback"})
	if err != nil {
		t.Fatal(err)
	}
	_ = id

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// The private key is the whole credential. World-readable here
	// means any local user becomes the agent.
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("identity file mode = %o, want 600", perm)
	}

	back, err := Load(path)
	if err != nil || back == nil {
		t.Fatalf("reload: %v", err)
	}
	if back.AgentID != 42 || back.Project != "ACME" ||
		back.ServerPublicKey != srvPub {
		t.Errorf("reloaded identity differs: %+v", back.File)
	}
}

func TestLoadingNothingIsNotAnError(t *testing.T) {
	// A first run has no identity. That is ordinary, not a failure, and
	// treating it as one would make the agent refuse to enroll.
	id, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil || id != nil {
		t.Errorf("missing identity: got (%v, %v), want (nil, nil)", id, err)
	}
}

func TestCorruptIdentityIsReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("a corrupt identity file loaded without complaint")
	}
}
