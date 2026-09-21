package icmpv4

import (
	"encoding/binary"
	"testing"

	"github.com/soypat/lneto"
)

// fragNeededBuilder assures an RFC 1191 Fragmentation Needed message with a
// 20-byte quoted IPv4 header and the first 8 bytes of a quoted TCP header.
type fragNeededBuilder struct {
	mtu      uint16
	src, dst [4]byte
	sport    uint16
	dport    uint16
	df       bool
	proto    lneto.IPProto
	code     CodeDestinationUnreachable
	ihl      int
	totalLen uint16
	corrupt  bool
	truncate int  // final message length override (<0 disables).
	omitL4   bool // quote only the IP header (20 bytes).
}

func (b fragNeededBuilder) build() []byte {
	ihl := b.ihl
	if ihl == 0 {
		ihl = 20
	}
	totalLen := b.totalLen
	if totalLen == 0 {
		totalLen = uint16(ihl + 20) // claims a full 20-byte TCP header.
	}
	quoteLen := ihl + 8
	if b.omitL4 {
		quoteLen = ihl
	}
	msg := make([]byte, sizeHeader+quoteLen)
	msg[0] = byte(TypeDestinationUnreachable)
	msg[1] = byte(b.code)
	binary.BigEndian.PutUint16(msg[6:8], b.mtu)
	q := msg[sizeHeader:]
	q[0] = 0x40 | byte(ihl/4)
	binary.BigEndian.PutUint16(q[2:4], totalLen)
	var flags uint16
	if b.df {
		flags |= 0x4000
	}
	binary.BigEndian.PutUint16(q[6:8], flags)
	q[9] = byte(b.proto)
	copy(q[12:16], b.src[:])
	copy(q[16:20], b.dst[:])
	if !b.omitL4 {
		l4 := q[ihl:]
		binary.BigEndian.PutUint16(l4[0:2], b.sport)
		binary.BigEndian.PutUint16(l4[2:4], b.dport)
	}
	var crc lneto.CRC791
	csum := crc.PayloadSum16(msg)
	if b.corrupt {
		csum ^= 0xffff
	}
	binary.BigEndian.PutUint16(msg[2:4], csum)
	if b.truncate > 0 {
		msg = msg[:b.truncate]
	}
	return msg
}

func validFragBuilder() fragNeededBuilder {
	return fragNeededBuilder{
		mtu:   576,
		src:   [4]byte{10, 0, 0, 1},
		dst:   [4]byte{10, 0, 0, 2},
		sport: 12345,
		dport: 80,
		df:    true,
		proto: lneto.IPProtoTCP,
		code:  CodeFragNeededAndDFSet,
	}
}

func TestParseFragNeeded4_Valid(t *testing.T) {
	b := validFragBuilder()
	ev, ok, err := ParseFragNeeded4(b.build())
	if err != nil || !ok {
		t.Fatalf("ParseFragNeeded4 ok=%v err=%v, want accepted", ok, err)
	}
	if ev.LocalAddr != b.src || ev.RemoteAddr != b.dst ||
		ev.LocalPort != b.sport || ev.RemotePort != b.dport || ev.NextHopMTU != b.mtu {
		t.Fatalf("event mismatch: %+v", ev)
	}
}

func TestParseFragNeeded4_ZeroMTULegacy(t *testing.T) {
	b := validFragBuilder()
	b.mtu = 0 // Pre-RFC 1191 router: the receiver must plateau-search itself.
	ev, ok, err := ParseFragNeeded4(b.build())
	if err != nil || !ok {
		t.Fatalf("zero MTU quote ok=%v err=%v, want accepted with zero field", ok, err)
	}
	if ev.NextHopMTU != 0 {
		t.Fatalf("next-hop mtu=%d, want 0 passthrough", ev.NextHopMTU)
	}
}

func TestParseFragNeeded4_Rejects(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*fragNeededBuilder)
		want   error // nil means ok=false, ErrBadCRC means hard error.
	}{
		{"bad checksum", func(b *fragNeededBuilder) { b.corrupt = true }, lneto.ErrBadCRC},
		{"wrong code (host unreachable)", func(b *fragNeededBuilder) { b.code = CodeHostUnreachable }, nil},
		{"truncated message", func(b *fragNeededBuilder) { b.truncate = 30 }, nil},
		{"quoted protocol UDP", func(b *fragNeededBuilder) { b.proto = lneto.IPProtoUDP }, nil},
		{"DF not set", func(b *fragNeededBuilder) { b.df = false }, nil},
		{"multicast destination", func(b *fragNeededBuilder) { b.dst = [4]byte{224, 0, 0, 1} }, nil},
		{"limited broadcast destination", func(b *fragNeededBuilder) { b.dst = [4]byte{255, 255, 255, 255} }, nil},
		{"multicast source", func(b *fragNeededBuilder) { b.src = [4]byte{239, 1, 2, 3} }, nil},
		{"zero source", func(b *fragNeededBuilder) { b.src = [4]byte{} }, nil},
		{"zero source port", func(b *fragNeededBuilder) { b.sport = 0 }, nil},
		{"zero destination port", func(b *fragNeededBuilder) { b.dport = 0 }, nil},
		{"incomplete quote (no L4)", func(b *fragNeededBuilder) { b.omitL4 = true }, nil},
		{"total length too short", func(b *fragNeededBuilder) { b.totalLen = 20 }, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := validFragBuilder()
			tt.modify(&b)
			ev, ok, err := ParseFragNeeded4(b.build())
			if tt.want != nil {
				if err != tt.want {
					t.Fatalf("err=%v, want %v", err, tt.want)
				}
				return
			}
			if err != nil || ok {
				t.Fatalf("ok=%v err=%v ev=%+v, want rejection", ok, err, ev)
			}
		})
	}
}

func TestParseFragNeeded4_RejectsFragmentOffset(t *testing.T) {
	msg := validFragBuilder().build()
	// Clear DF and set fragment offset 1 (8 octets into the datagram): ports
	// quoted would not belong to a first fragment.
	flags := binary.BigEndian.Uint16(msg[sizeHeader+6:])&^0x4000 | 0x0001
	binary.BigEndian.PutUint16(msg[sizeHeader+6:], flags)
	binary.BigEndian.PutUint16(msg[2:4], 0)
	var crc lneto.CRC791
	binary.BigEndian.PutUint16(msg[2:4], crc.PayloadSum16(msg))
	if ev, ok, err := ParseFragNeeded4(msg); err != nil || ok {
		t.Fatalf("fragment-offset quote: ok=%v err=%v ev=%+v", ok, err, ev)
	}
}

func TestClient_DemuxFragNeededDispatches(t *testing.T) {
	var got []FragNeeded4
	var client Client
	client.SetFragNeeded4Sink(func(ev FragNeeded4) { got = append(got, ev) })

	msg := validFragBuilder().build()
	// Unconfigured client must still deliver PMTU feedback (echo disabled).
	if err := client.Demux(msg, 0); err != nil {
		t.Fatalf("Demux frag-needed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("sink invoked %d times, want 1", len(got))
	}
	if got[0].RemotePort != 80 || got[0].NextHopMTU != 576 {
		t.Fatalf("event mismatch: %+v", got[0])
	}

	// Malformed quote is dropped and never reaches the sink.
	bad := validFragBuilder()
	bad.proto = lneto.IPProtoUDP
	before := len(got)
	if err := client.Demux(bad.build(), 0); err != lneto.ErrPacketDrop {
		t.Fatalf("bad quote err=%v, want ErrPacketDrop", err)
	}
	if len(got) != before {
		t.Fatal("sink invoked for invalid quote")
	}

	// Bad checksum is reported as such.
	corrupt := validFragBuilder()
	corrupt.corrupt = true
	if err := client.Demux(corrupt.build(), 0); err != lneto.ErrBadCRC {
		t.Fatalf("corrupt err=%v, want ErrBadCRC", err)
	}

	// Echo traffic on an unconfigured client is dropped without error noise.
	echo := make([]byte, sizeHeader+4)
	echo[0] = byte(TypeEcho)
	if err := client.Demux(echo, 0); err != lneto.ErrPacketDrop {
		t.Fatalf("unconfigured echo err=%v, want ErrPacketDrop", err)
	}
}

// wrapIPv4 prepends a 20-byte IPv4 header (proto ICMP) to an ICMP message.
func wrapIPv4(dst [4]byte, icmp []byte) []byte {
	pkt := make([]byte, 20+len(icmp))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = byte(lneto.IPProtoICMP)
	copy(pkt[16:20], dst[:])
	var crc lneto.CRC791
	crc.WriteEven(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], crc.Sum16())
	copy(pkt[20:], icmp)
	return pkt
}

func TestClient_DemuxFragNeededOuterContext(t *testing.T) {
	var got []FragNeeded4
	var client Client
	client.SetFragNeeded4Sink(func(ev FragNeeded4) { got = append(got, ev) })
	msg := validFragBuilder().build()

	// Unicast outer destination: dispatched.
	unicast := wrapIPv4([4]byte{10, 0, 0, 1}, msg)
	if err := client.Demux(unicast, 20); err != nil {
		t.Fatalf("unicast context: %v", err)
	}
	if len(got) != 1 {
		t.Fatal("valid event not delivered in unicast context")
	}

	// Multicast outer destination: ignored.
	mcast := wrapIPv4([4]byte{224, 0, 0, 1}, msg)
	if err := client.Demux(mcast, 20); err != lneto.ErrPacketDrop {
		t.Fatalf("multicast context err=%v, want drop", err)
	}
	// Limited broadcast outer destination: ignored.
	bcast := wrapIPv4([4]byte{255, 255, 255, 255}, msg)
	if err := client.Demux(bcast, 20); err != lneto.ErrPacketDrop {
		t.Fatalf("broadcast context err=%v, want drop", err)
	}
	if len(got) != 1 {
		t.Fatal("sink invoked for broadcast/multicast context")
	}
}
