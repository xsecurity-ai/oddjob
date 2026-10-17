package socksrelay

import (
	"encoding/hex"
	"strings"
	"testing"
)

// These rows are copied VERBATIM from backend/app/proxytunnel.py's
// VECTORS. That is the point of them: the two halves of this codec
// are written in different languages from the same paragraph of
// prose, and a disagreement about endianness or header width is a
// hung stream in production and a failing test here.
//
// If a row changes on one side, change it on the other.
var vectors = []struct {
	label   string
	kind    byte
	stream  uint32
	payload []byte
	want    string
}{
	{"open stream 1", OPEN, 1, append([]byte{0x01, 0xbb}, []byte("a.example")...),
		"0100000001" + "01bb" + "612e6578616d706c65"},
	{"opened", OPENED, 1, nil, "0200000001"},
	{"failed with a reason", FAILED, 2, []byte("no route"),
		"0300000002" + "6e6f20726f757465"},
	{"data", DATA, 3, []byte{0x00, 0xff}, "040000000300ff"},
	{"close", CLOSE, 4, nil, "0500000004"},
	// The boundary that catches a signed/unsigned mistake: a stream
	// id with the top bit set. Go's uint32 and Python's struct "!I"
	// must agree here or every long-lived tunnel breaks once the
	// counter climbs.
	{"high stream id", DATA, 0xFFFFFFFF, []byte("x"), "04ffffffff78"},
}

func TestVectorsMatchThePythonHalf(t *testing.T) {
	for _, v := range vectors {
		t.Run(v.label, func(t *testing.T) {
			got, err := Encode(v.kind, v.stream, v.payload)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if hex.EncodeToString(got) != v.want {
				t.Errorf("encoded %s, wanted %s",
					hex.EncodeToString(got), v.want)
			}
			raw, _ := hex.DecodeString(v.want)
			f, err := Decode(raw)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if f.Kind != v.kind || f.Stream != v.stream {
				t.Errorf("decoded kind=%d stream=%d, wanted %d/%d",
					f.Kind, f.Stream, v.kind, v.stream)
			}
			if string(f.Payload) != string(v.payload) {
				t.Errorf("payload %q, wanted %q", f.Payload, v.payload)
			}
		})
	}
}

func TestDecodeRefusesJunk(t *testing.T) {
	// Losing framing means dropping the tunnel, so each of these has
	// to be an error rather than a best guess.
	cases := []struct {
		label string
		raw   []byte
	}{
		{"empty", nil},
		{"shorter than the header", []byte{DATA, 0, 0, 0}},
		{"unknown type", []byte{0x7f, 0, 0, 0, 1}},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			if _, err := Decode(c.raw); err == nil {
				t.Error("decoded when it should have refused")
			}
		})
	}
}

func TestDecodeCopiesThePayload(t *testing.T) {
	// The caller's buffer is a read buffer that gets reused for the
	// next frame, and a DATA payload outlives this call by going onto
	// a channel. Aliasing it means one stream reading another's bytes
	// -- which looks like corruption, not like a bug in the codec.
	buf := []byte{DATA, 0, 0, 0, 1, 'a', 'b'}
	f, err := Decode(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	buf[5], buf[6] = 'z', 'z'
	if string(f.Payload) != "ab" {
		t.Errorf("payload aliased the caller's buffer: got %q", f.Payload)
	}
}

func TestOpenRoundTrip(t *testing.T) {
	raw, err := EncodeOpen(7, "shop.acme.example", 8443)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	f, err := Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	host, port, err := DecodeOpen(f)
	if err != nil {
		t.Fatalf("decode open: %v", err)
	}
	if host != "shop.acme.example" || port != 8443 {
		t.Errorf("got %s:%d", host, port)
	}
	// A name stays a name: this agent resolves it, where the estate
	// is. Encoding it as an address here would pick the destination
	// from the server's view of DNS.
	if strings.Count(host, ".") != 2 {
		t.Errorf("host was rewritten: %q", host)
	}
}

func TestOpenRefusesBadPorts(t *testing.T) {
	for _, p := range []int{0, -1, 65536, 1 << 20} {
		if _, err := EncodeOpen(1, "h", p); err == nil {
			t.Errorf("port %d was accepted", p)
		}
	}
}

func TestDecodeOpenRefusesTruncated(t *testing.T) {
	if _, _, err := DecodeOpen(Frame{Kind: OPEN, Stream: 1,
		Payload: []byte{0x01}}); err == nil {
		t.Error("a truncated OPEN was accepted")
	}
	if _, _, err := DecodeOpen(Frame{Kind: DATA, Stream: 1,
		Payload: []byte("x")}); err == nil {
		t.Error("a DATA frame was read as an OPEN")
	}
}
