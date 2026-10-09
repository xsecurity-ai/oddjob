//go:build linux

package portscan

import (
	"encoding/binary"
	"testing"
)

// The checksum is the function whose failure is invisible.
//
// Get it wrong and the kernel still sends the packet, the far end
// silently discards it, nothing answers, and the scan reports a quiet
// estate. There is no error anywhere — a broken scanner and a
// correct scan of a firewalled range produce identical output. So it
// is verified against a vector computed independently rather than
// against itself.
func TestTCPChecksum(t *testing.T) {
	// A SYN from 192.0.2.1:40000 to 198.51.100.1:80, sequence
	// 0x11223344, window 1024. The expected value is the ones-
	// complement sum worked out separately, below, so this is not the
	// implementation marking its own homework.
	src := [4]byte{192, 0, 2, 1}
	dst := [4]byte{198, 51, 100, 1}
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], 40000)
	binary.BigEndian.PutUint16(h[2:4], 80)
	binary.BigEndian.PutUint32(h[4:8], 0x11223344)
	h[12] = 5 << 4
	h[13] = 0x02
	binary.BigEndian.PutUint16(h[14:16], 1024)

	got := tcpChecksum(h, src, dst)
	want := referenceChecksum(h, src, dst)
	if got != want {
		t.Fatalf("checksum = %#04x, independently computed %#04x", got, want)
	}

	// The defining property: a receiver sums the whole segment WITH
	// the checksum in place and must get 0xffff. If that does not
	// hold, every packet is discarded and the scan silently finds
	// nothing.
	binary.BigEndian.PutUint16(h[16:18], got)
	if v := verifySum(h, src, dst); v != 0xffff {
		t.Errorf("a receiver verifying this segment gets %#04x, not 0xffff "+
			"— every packet would be dropped and the scan would report "+
			"an empty network", v)
	}

	// And it must actually depend on its inputs. A constant passes
	// every test above.
	h2 := make([]byte, len(h))
	copy(h2, h)
	binary.BigEndian.PutUint16(h2[16:18], 0)
	binary.BigEndian.PutUint16(h2[2:4], 443) // different port
	if tcpChecksum(h2, src, dst) == got {
		t.Error("changing the destination port did not change the checksum")
	}
	if tcpChecksum(h, [4]byte{10, 0, 0, 1}, dst) == got {
		t.Error("changing the source address did not change the checksum")
	}
}

// referenceChecksum is a second, deliberately naive implementation.
// Slower and clearer; its only job is to disagree if the real one
// drifts.
func referenceChecksum(tcp []byte, src, dst [4]byte) uint16 {
	buf := make([]byte, 0, 12+len(tcp))
	buf = append(buf, src[:]...)
	buf = append(buf, dst[:]...)
	buf = append(buf, 0, 6)
	// #nosec G115 -- test input is a 20-byte header
	buf = append(buf, byte(len(tcp)>>8), byte(len(tcp)))
	body := make([]byte, len(tcp))
	copy(body, tcp)
	body[16], body[17] = 0, 0 // checksum field zeroed
	buf = append(buf, body...)

	var sum uint32
	for i := 0; i+1 < len(buf); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(buf[i : i+2]))
	}
	if len(buf)%2 == 1 {
		sum += uint32(buf[len(buf)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// verifySum is what a receiver does: sum everything including the
// checksum field and expect 0xffff.
func verifySum(tcp []byte, src, dst [4]byte) uint16 {
	buf := make([]byte, 0, 12+len(tcp))
	buf = append(buf, src[:]...)
	buf = append(buf, dst[:]...)
	buf = append(buf, 0, 6)
	// #nosec G115 -- test input is a 20-byte header
	buf = append(buf, byte(len(tcp)>>8), byte(len(tcp)))
	buf = append(buf, tcp...)
	var sum uint32
	for i := 0; i+1 < len(buf); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(buf[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}

func TestSynPacketShape(t *testing.T) {
	p := synPacket([4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 1}, 40000, 443)
	if len(p) != 20 {
		t.Fatalf("packet is %d bytes, want a 20-byte header", len(p))
	}
	if got := binary.BigEndian.Uint16(p[0:2]); got != 40000 {
		t.Errorf("source port %d", got)
	}
	if got := binary.BigEndian.Uint16(p[2:4]); got != 443 {
		t.Errorf("destination port %d", got)
	}
	if p[12]>>4 != 5 {
		t.Errorf("data offset %d words, want 5", p[12]>>4)
	}
	// SYN and nothing else. An ACK here would be a different packet
	// with different meaning to anything watching.
	if p[13] != 0x02 {
		t.Errorf("flags %#02x, want SYN only (0x02)", p[13])
	}
	// A zero window and a zero sequence are both signatures. Neither
	// is wrong on the wire; both say "written by a script".
	if binary.BigEndian.Uint16(p[14:16]) == 0 {
		t.Error("zero window")
	}
	if binary.BigEndian.Uint32(p[4:8]) == 0 {
		t.Error("zero sequence number")
	}
}

func TestParseSynAck(t *testing.T) {
	// A 20-byte IPv4 header followed by TCP, which is what a raw read
	// hands back.
	mk := func(flags byte, dport uint16, ihlWords byte) []byte {
		ihl := int(ihlWords) * 4
		b := make([]byte, ihl+20)
		b[0] = 0x40 | ihlWords
		t := b[ihl:]
		binary.BigEndian.PutUint16(t[0:2], 8080) // source: the scanned port
		binary.BigEndian.PutUint16(t[2:4], dport)
		t[13] = flags
		return b
	}

	if p, ok := parseSynAck(mk(0x12, 40000, 5), 40000); !ok || p != 8080 {
		t.Errorf("a SYN-ACK to our port gave (%d, %v)", p, ok)
	}
	// Only SYN+ACK means something is listening. A lone SYN is a
	// simultaneous open; a lone ACK is not an offer of service.
	if _, ok := parseSynAck(mk(0x02, 40000, 5), 40000); ok {
		t.Error("a bare SYN was read as a listening port")
	}
	if _, ok := parseSynAck(mk(0x10, 40000, 5), 40000); ok {
		t.Error("a bare ACK was read as a listening port")
	}
	// A RST is a closed port and must never count as open.
	if _, ok := parseSynAck(mk(0x14, 40000, 5), 40000); ok {
		t.Error("a RST-ACK was read as a listening port")
	}
	// Not addressed to us: somebody else's conversation on a shared
	// raw socket.
	if _, ok := parseSynAck(mk(0x12, 12345, 5), 40000); ok {
		t.Error("a reply to another port was accepted")
	}
	// IP options make the header longer than 20 bytes; reading TCP at
	// a fixed offset would parse the options as a TCP header.
	if p, ok := parseSynAck(mk(0x12, 40000, 6), 40000); !ok || p != 8080 {
		t.Errorf("a header with IP options gave (%d, %v)", p, ok)
	}
	// Short and malformed input must be refused, not indexed into.
	if _, ok := parseSynAck([]byte{0x45, 0, 0}, 40000); ok {
		t.Error("a truncated packet was accepted")
	}
	if _, ok := parseSynAck(nil, 40000); ok {
		t.Error("nil was accepted")
	}
}
