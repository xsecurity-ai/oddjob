// Package socksrelay carries proxied TCP streams for Oddjob.
//
// The server hands this agent a destination over a WebSocket it is
// already holding open; the agent dials it and relays bytes. One
// socket, many streams, because a browser opens six connections to
// load one page and a socket each would be six dials through NAT.
//
// The Ghost dials OUT to hold the tunnel open. That is the only
// direction that works -- an agent sits behind NAT with nothing
// exposed, which is why the whole agent model is poll-and-callback
// rather than the server reaching in. See internal/callin, which is
// deliberately unable to do anything like this.
//
// # The frame
//
//	byte 0      type
//	bytes 1..4  stream id, uint32 big-endian
//	bytes 5..   payload
//
// Fixed five-byte header, so a reader never has to parse to know how
// much to skip. Big-endian to match every other length on this wire.
//
// This file is the codec and nothing else: no sockets, no dialling.
// The Python half is backend/app/proxytunnel.py and the vectors in
// frame_test.go are ITS vectors, copied verbatim. A codec two
// languages implement from one paragraph of prose is a codec that
// disagrees in production.
package socksrelay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

// Header is the fixed prefix on every frame.
const Header = 5

// Frame types. OPEN travels server->agent; OPENED and FAILED come
// back; DATA and CLOSE go either way.
//
// ARRIVED is the one that goes only agent->server, and it is what
// makes a shell tunnel different from a proxy one. A proxy stream
// starts because the server asked for a destination; a shell stream
// starts because something connected to a port the agent is
// listening on, which the server could not have asked for and does
// not learn any other way. Payload is the peer address as the agent
// saw it -- provenance, and the only thing distinguishing two
// callbacks on one port.
const (
	OPEN    = 0x01
	OPENED  = 0x02
	FAILED  = 0x03
	DATA    = 0x04
	CLOSE   = 0x05
	ARRIVED = 0x06
)

// MaxPayload caps one frame's payload. Not a protocol limit -- it
// bounds how much a single misbehaving stream can make this agent
// allocate before anything has been read.
const MaxPayload = 1 << 20

// ErrFrame means the bytes are not a frame this understands. The
// caller drops the whole TUNNEL, not the frame: a multiplexer that
// has lost framing cannot know where the next frame starts, and
// carrying on would feed one stream's bytes to another.
var ErrFrame = errors.New("malformed tunnel frame")

// Frame is one decoded message.
type Frame struct {
	Kind    byte
	Stream  uint32
	Payload []byte
}

func known(kind byte) bool {
	switch kind {
	case OPEN, OPENED, FAILED, DATA, CLOSE, ARRIVED:
		return true
	}
	return false
}

// Encode builds a frame.
func Encode(kind byte, stream uint32, payload []byte) ([]byte, error) {
	if !known(kind) {
		return nil, fmt.Errorf("%w: unknown type %d", ErrFrame, kind)
	}
	if len(payload) > MaxPayload {
		return nil, fmt.Errorf("%w: payload over the cap", ErrFrame)
	}
	out := make([]byte, Header+len(payload))
	out[0] = kind
	binary.BigEndian.PutUint32(out[1:5], stream)
	copy(out[Header:], payload)
	return out, nil
}

// Decode reads one frame.
func Decode(raw []byte) (Frame, error) {
	if len(raw) < Header {
		return Frame{}, fmt.Errorf("%w: shorter than its header", ErrFrame)
	}
	kind := raw[0]
	if !known(kind) {
		return Frame{}, fmt.Errorf("%w: unknown type %d", ErrFrame, kind)
	}
	if len(raw)-Header > MaxPayload {
		return Frame{}, fmt.Errorf("%w: payload over the cap", ErrFrame)
	}
	// Copied, not aliased. The caller's buffer is a read buffer that
	// will be reused for the next frame, and a DATA payload outlives
	// this call by going onto a channel.
	payload := make([]byte, len(raw)-Header)
	copy(payload, raw[Header:])
	return Frame{Kind: kind, Stream: binary.BigEndian.Uint32(raw[1:5]),
		Payload: payload}, nil
}

// EncodeOpen builds an OPEN, carrying the destination as a NAME where
// it is one. This agent resolves it, because it is where the estate
// is and split-horizon DNS inside one is the normal case.
func EncodeOpen(stream uint32, host string, port int) ([]byte, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("%w: port out of range", ErrFrame)
	}
	if len(host) > 253 {
		return nil, fmt.Errorf("%w: host too long", ErrFrame)
	}
	payload := make([]byte, 2+len(host))
	binary.BigEndian.PutUint16(payload[:2], uint16(port))
	copy(payload[2:], host)
	return Encode(OPEN, stream, payload)
}

// DecodeOpen reads the destination out of an OPEN.
func DecodeOpen(f Frame) (string, int, error) {
	if f.Kind != OPEN {
		return "", 0, fmt.Errorf("%w: not an OPEN", ErrFrame)
	}
	if len(f.Payload) < 3 {
		return "", 0, fmt.Errorf("%w: OPEN truncated", ErrFrame)
	}
	port := int(binary.BigEndian.Uint16(f.Payload[:2]))
	host := string(f.Payload[2:])
	if !utf8.ValidString(host) {
		return "", 0, fmt.Errorf("%w: OPEN host is not utf-8", ErrFrame)
	}
	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("%w: port out of range", ErrFrame)
	}
	return host, port, nil
}
