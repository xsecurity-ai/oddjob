package callin

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xsecurity-ai/oddjob/jaws/internal/identity"
)

type fakeWaker struct{ woken int }

func (f *fakeWaker) Wake()                  { f.woken++ }
func (f *fakeWaker) Status() map[string]any { return map[string]any{"ok": true} }

// nilVerifier stands in for an agent that has not enrolled yet. It is
// a non-nil interface value whose underlying identity is absent, which
// is exactly the shape that crashed: a typed nil passes `== nil` only
// when the interface itself is nil, and this one is not.
type nilVerifier struct{}

func (nilVerifier) VerifyServer(string, string, []byte, string, string, string) bool {
	return false
}

func srv(key string, v Verifier) *Server {
	return New("127.0.0.1:0", key, &fakeWaker{}, v)
}

func req(method, path string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(""))
	for k, val := range headers {
		r.Header.Set(k, val)
	}
	return r
}

// The regression: an inbound signed request against an agent with no
// pinned server used to dereference a nil pointer and panic, inside an
// HTTP handler, reachable by anyone who could open the port.
func TestSignedCallWithNoIdentityIsRefusedNotFatal(t *testing.T) {
	for _, v := range []Verifier{nil, nilVerifier{}} {
		s := srv("the-key", v)
		w := httptest.NewRecorder()
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("panicked on an inbound signed request: %v", p)
			}
		}()
		s.auth(s.status)(w, req("POST", "/status", map[string]string{
			"X-Jaws-Signature": "AAAA",
			"X-Jaws-Timestamp": strconv.FormatInt(time.Now().Unix(), 10),
			"X-Jaws-Nonce":     "n",
		}))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", w.Code)
		}
	}
}

// A caller who offers a signature is held to it. Otherwise anyone
// holding the weaker shared key could present a junk signature,
// have it ignored, and fall through to the key — which would make
// signing pointless.
func TestABadSignatureDoesNotFallBackToTheKey(t *testing.T) {
	s := srv("the-key", nilVerifier{})
	w := httptest.NewRecorder()
	s.auth(s.status)(w, req("POST", "/status", map[string]string{
		"X-Jaws-Signature":   "not-a-signature",
		"X-Jaws-Timestamp":   strconv.FormatInt(time.Now().Unix(), 10),
		"X-Jaws-Nonce":       "n",
		"X-Jaws-Call-In-Key": "the-key",
	}))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("a bad signature fell through to the key: status %d", w.Code)
	}
}

func TestTheRightSignatureIsAccepted(t *testing.T) {
	serverPriv, serverPub, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	agentPriv, _, _ := identity.Generate()
	id, err := identityFor(agentPriv, serverPub)
	if err != nil {
		t.Fatal(err)
	}

	s := srv("the-key", id)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	raw, _ := base64.StdEncoding.DecodeString(serverPriv)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(
		ed25519.PrivateKey(raw), identity.Canonical("POST", "/poll", nil, ts, "n1")))

	w := httptest.NewRecorder()
	s.auth(s.poll)(w, req("POST", "/poll", map[string]string{
		"X-Jaws-Signature": sig,
		"X-Jaws-Timestamp": ts,
		"X-Jaws-Nonce":     "n1",
	}))
	// 202, not 200: /poll accepts the nudge and returns before the
	// loop has actually polled.
	if w.Code < 200 || w.Code > 299 {
		t.Fatalf("a correctly signed call was refused: %d %s", w.Code, w.Body)
	}
}

func TestAKeyStillWorksWhenNoSignatureIsOffered(t *testing.T) {
	s := srv("the-key", nilVerifier{})
	w := httptest.NewRecorder()
	s.auth(s.status)(w, req("POST", "/status",
		map[string]string{"X-Jaws-Call-In-Key": "the-key"}))
	if w.Code != http.StatusOK {
		t.Errorf("the call-in key was refused: %d", w.Code)
	}

	w2 := httptest.NewRecorder()
	s.auth(s.status)(w2, req("POST", "/status",
		map[string]string{"X-Jaws-Call-In-Key": "wrong"}))
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("a wrong key was accepted: %d", w2.Code)
	}
}

func TestHealthNeedsNothing(t *testing.T) {
	// Deliberately open so systemd or a load balancer can see the
	// process is alive without being handed a credential.
	s := srv("the-key", nilVerifier{})
	w := httptest.NewRecorder()
	s.health(w, req("GET", "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Errorf("healthz = %d, want 200", w.Code)
	}
}

// identityFor builds an Identity the way enrollment does, without
// touching the filesystem.
func identityFor(agentPriv, serverPub string) (Verifier, error) {
	return identity.FromParts(agentPriv, serverPub)
}
