package identity

import (
	"encoding/base64"
	"testing"
)

// Vectors from the Python side (backend/app/agentcrypto.py). The two
// constructions must agree byte for byte; a mismatch does not fail
// loudly, it fails as "the sealed body did not open" on an agent
// inside someone else's network.
const (
	vecAgentPriv = "WMb2SbYrJSbkM+8495RvOGSEQLl80lwuNyKdsIHz5FM="
	vecServerPub = "AyTj6rGrob59V+nCqIbE9Vfsp/d809p5mdkzP7Rclm8="
	vecSealed    = "xFXSrTC7TXSJhzo9XDaLsNe9uA6CBn5A9/vaXAr/pRnSnHzyG5NmY2WJHF9idg=="
	vecKey       = "tr5iEzdvtG9Y1KEKw21qXJjrjvh8HuknpGXcsVZAeMQ="
)

func TestSealKeyMatchesTheServer(t *testing.T) {
	got, err := SharedKey(vecAgentPriv, vecServerPub)
	if err != nil {
		t.Fatal(err)
	}
	if base64.StdEncoding.EncodeToString(got) != vecKey {
		t.Fatalf("derived a different key from the same halves:\n got %s\nwant %s",
			base64.StdEncoding.EncodeToString(got), vecKey)
	}
}

func TestOpensWhatTheServerSealed(t *testing.T) {
	key, _ := SharedKey(vecAgentPriv, vecServerPub)
	aad := ChannelBinding("req", 42, "POST", "/api/agents/heartbeat",
		"1760000000", "abc123")
	out, err := Unseal(key, vecSealed, aad)
	if err != nil {
		t.Fatalf("could not open a body the server sealed: %v", err)
	}
	if string(out) != `{"scan":"results"}` {
		t.Errorf("opened to %q", out)
	}
	// And the binding is load-bearing: the same envelope on another
	// route must not open.
	if _, err := Unseal(key, vecSealed, ChannelBinding(
		"req", 42, "POST", "/api/agents/register", "1760000000", "abc123")); err == nil {
		t.Error("a sealed body opened on a route it was not sealed for")
	}
	if _, err := Unseal(key, vecSealed, ChannelBinding(
		"res", 42, "POST", "/api/agents/heartbeat", "1760000000", "abc123")); err == nil {
		t.Error("a request envelope opened as a response")
	}
	if _, err := Unseal(key, vecSealed, ChannelBinding(
		"req", 43, "POST", "/api/agents/heartbeat", "1760000000", "abc123")); err == nil {
		t.Error("a sealed body opened for a different agent")
	}
}
