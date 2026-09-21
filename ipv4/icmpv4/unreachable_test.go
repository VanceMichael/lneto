package icmpv4

import (
	"encoding/binary"
	"testing"

	"github.com/soypat/lneto"
)

// buildQuote builds a minimal quoted IPv4+UDP reference (20-byte IP header with
// no options followed by an 8-byte UDP header).
func buildQuote(srcIP, dstIP [4]byte, srcPort, dstPort uint16) []byte {
	quote := make([]byte, 28)
	quote[0] = 0x45 // version 4, IHL 5.
	binary.BigEndian.PutUint16(quote[2:4], 28)
	quote[8] = 64 // TTL.
	quote[9] = uint8(lneto.IPProtoUDP)
	copy(quote[12:16], srcIP[:])
	copy(quote[16:20], dstIP[:])
	binary.BigEndian.PutUint16(quote[20:22], srcPort)
	binary.BigEndian.PutUint16(quote[22:24], dstPort)
	binary.BigEndian.PutUint16(quote[24:26], 8)
	return quote
}

func TestPortUnreachableQueue_QueueAndDrain(t *testing.T) {
	var q PortUnreachableQueue
	src := [4]byte{192, 168, 1, 10}
	dst := [4]byte{192, 168, 1, 1}
	q.Queue(src[:], buildQuote(src, dst, 4000, 9))
	if q.Pending() != 1 {
		t.Fatalf("Pending = %d, want 1", q.Pending())
	}

	carrier := make([]byte, 256)
	for i := range carrier {
		carrier[i] = 0xff // stale bytes must not corrupt checksum/unused fields.
	}
	const ipOff, icmpOff = 0, 20
	carrier[ipOff] = 0x45 // required by SetIPAddrs version detection.
	n, err := q.Drain(carrier, ipOff, icmpOff)
	if err != nil {
		t.Fatal(err)
	}
	const wantN = 8 + 28
	if n != wantN {
		t.Fatalf("Drain n = %d, want %d", n, wantN)
	}
	if q.Pending() != 0 {
		t.Fatal("queue not emptied")
	}
	b := carrier[icmpOff : icmpOff+n]
	if b[0] != uint8(TypeDestinationUnreachable) || b[1] != uint8(CodePortUnreachable) {
		t.Fatalf("type/code = %d/%d, want 3/4", b[0], b[1])
	}
	if binary.BigEndian.Uint32(b[4:8]) != 0 {
		t.Fatal("unused field must be zero")
	}
	var crc lneto.CRC791
	if crc.PayloadSum16(b) != 0 {
		t.Fatal("ICMP checksum invalid")
	}
	quote := b[8:]
	if quote[0] != 0x45 || quote[9] != uint8(lneto.IPProtoUDP) {
		t.Fatal("quoted IP header corrupted")
	}
	if got := binary.BigEndian.Uint16(quote[12:14]); got != binary.BigEndian.Uint16(src[:2]) {
		t.Fatal("quoted src IP mismatch")
	}
	if binary.BigEndian.Uint16(quote[20:22]) != 4000 || binary.BigEndian.Uint16(quote[22:24]) != 9 {
		t.Fatal("quoted UDP ports mismatch")
	}
	// Outer IP destination must be the original sender.
	if string(carrier[16:20]) != string(src[:]) {
		t.Fatal("outer destination must be the original source address")
	}
}

func TestPortUnreachableQueue_DrainEmpty(t *testing.T) {
	var q PortUnreachableQueue
	n, err := q.Drain(make([]byte, 256), 0, 20)
	if err != nil || n != 0 {
		t.Fatalf("empty drain = (%d,%v), want (0,nil)", n, err)
	}
}

func TestPortUnreachableQueue_Overflow(t *testing.T) {
	var q PortUnreachableQueue
	addr := []byte{10, 0, 0, 1}
	for range 4 {
		q.Queue(addr, buildQuote([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1, 2))
	}
	if q.Pending() != 4 {
		t.Fatalf("Pending = %d, want 4", q.Pending())
	}
	q.Queue(addr, buildQuote([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1, 2))
	if q.Pending() != 4 {
		t.Fatalf("overflow must be dropped, Pending = %d", q.Pending())
	}
}

func TestPortUnreachableQueue_RejectsInvalid(t *testing.T) {
	good := buildQuote([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1, 2)
	wrongVersion := append([]byte(nil), good...)
	wrongVersion[0] = 0x65
	tests := []struct {
		name       string
		remoteAddr []byte
		quote      []byte
	}{
		{"non-ipv4 remote", make([]byte, 16), good},
		{"short quote", []byte{10, 0, 0, 1}, good[:20]},
		{"truncated UDP header", []byte{10, 0, 0, 1}, good[:26]},
		{"wrong version", []byte{10, 0, 0, 1}, wrongVersion},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var q PortUnreachableQueue
			q.Queue(tt.remoteAddr, tt.quote)
			if q.Pending() != 0 {
				t.Fatalf("Pending = %d, want 0", q.Pending())
			}
		})
	}
}

func TestPortUnreachableQueue_DrainShortCarrier(t *testing.T) {
	var q PortUnreachableQueue
	q.Queue([]byte{10, 0, 0, 1}, buildQuote([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1, 2))
	// Carrier too small to hold IP+ICMP+quote: drain yields nothing but keeps
	// behavior bounded (entry consumed, no panic).
	n, err := q.Drain(make([]byte, 30), 0, 20)
	if err != nil || n != 0 {
		t.Fatalf("got (%d,%v), want (0,nil)", n, err)
	}
}
