package xnet

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/udp"
)

// newUDPICMPPair creates a UDP test pair with ICMPv4 enabled capacity so both
// stacks can receive Echo and Destination Unreachable messages.
func newUDPICMPPair(t testing.TB, seed int64, acceptBcastMcast bool) (s1, s2 *StackAsync) {
	t.Helper()
	s1, s2 = new(StackAsync), new(StackAsync)
	cfg := func(name string, ip [4]byte, mac [6]byte, s int64) StackConfig {
		return StackConfig{
			Hostname:            name,
			RandSeed:            s,
			StaticAddress4:      ip,
			HardwareAddress:     mac,
			MTU:                 ethernet.MaxMTU,
			MaxActiveUDPPorts:   6,
			ICMPQueueLimit:      4,
			AcceptMulticast:     acceptBcastMcast,
			AcceptIPv4Broadcast: acceptBcastMcast,
		}
	}
	if err := s1.Reset(cfg("UDPICMP-1", [4]byte{10, 2, 0, 1}, [6]byte{0xaa, 0xbb, 0, 0, 1, 1}, seed)); err != nil {
		t.Fatal("s1 Reset:", err)
	}
	if err := s2.Reset(cfg("UDPICMP-2", [4]byte{10, 2, 0, 2}, [6]byte{0xaa, 0xbb, 0, 0, 1, 2}, ^seed)); err != nil {
		t.Fatal("s2 Reset:", err)
	}
	s1.SetGatewayHardwareAddr(s2.HardwareAddr())
	s2.SetGatewayHardwareAddr(s1.HardwareAddr())
	return s1, s2
}

func dialUDPConn(t *testing.T, s *StackAsync, localPort uint16, remote netip.AddrPort) *udp.Conn {
	t.Helper()
	var conn udp.Conn
	err := conn.Configure(udp.ConnConfig{
		RxBuf:       make([]byte, testUDPBufSize),
		TxBuf:       make([]byte, testUDPBufSize),
		RxQueueSize: testUDPQueueSize,
		TxQueueSize: testUDPQueueSize,
		RWBackoff:   backoffYield,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DialUDP4(&conn, localPort, remote.Addr().As4(), remote.Port()); err != nil {
		t.Fatal("DialUDP4:", err)
	}
	return &conn
}

// exchangeAllowDrop exchanges one frame, accepting lneto.ErrPacketDrop from
// ingress (expected when the destination port has no listener).
func exchangeAllowDrop(t *testing.T, src, dst *StackAsync, buf []byte) int {
	t.Helper()
	n, err := src.EgressEthernet(buf)
	if err != nil {
		t.Error(err)
	}
	if n == 0 {
		return 0
	}
	if err := dst.IngressEthernet(buf[:n]); err != nil && !errors.Is(err, lneto.ErrPacketDrop) {
		t.Error("ingress:", err)
	}
	return n
}

// buildIPv4UDP constructs a complete IPv4/UDP datagram with valid header and
// transport checksums.
func buildIPv4UDP(src, dst [4]byte, sport, dport uint16, payload []byte) []byte {
	frame := make([]byte, 20+8+len(payload))
	ifrm, _ := ipv4.NewFrame(frame)
	ifrm.SetVersionAndIHL(4, 5)
	ifrm.SetTotalLength(uint16(len(frame)))
	ifrm.SetTTL(64)
	ifrm.SetProtocol(lneto.IPProtoUDP)
	*ifrm.SourceAddr() = src
	*ifrm.DestinationAddr() = dst
	ufrm, _ := udp.NewFrame(ifrm.Payload())
	ufrm.SetSourcePort(sport)
	ufrm.SetDestinationPort(dport)
	ufrm.SetLength(uint16(8 + len(payload)))
	copy(ufrm.Payload(), payload)
	var crc lneto.CRC791
	ifrm.CRCWriteUDPPseudo(&crc, ufrm.Length())
	ufrm.SetCRC(lneto.NeverZeroSum(crc.PayloadSum16(ufrm.RawData())))
	ifrm.SetCRC(ifrm.CalculateHeaderCRC())
	return frame
}

// buildICMPPortUnreachable builds an IPv4 ICMP message carrying the given quote.
func buildICMPPortUnreachable(src, dst [4]byte, quote []byte) []byte {
	frame := make([]byte, 20+8+len(quote))
	ifrm, _ := ipv4.NewFrame(frame)
	ifrm.SetVersionAndIHL(4, 5)
	ifrm.SetTotalLength(uint16(len(frame)))
	ifrm.SetTTL(64)
	ifrm.SetProtocol(lneto.IPProtoICMP)
	*ifrm.SourceAddr() = src
	*ifrm.DestinationAddr() = dst
	b := ifrm.Payload()
	b[0] = 3 // destination unreachable
	b[1] = 4 // port unreachable
	copy(b[8:], quote)
	var crc lneto.CRC791
	binary.BigEndian.PutUint16(b[2:4], crc.PayloadSum16(b))
	ifrm.SetCRC(ifrm.CalculateHeaderCRC())
	return frame
}

// TestUDPConn_PortUnreachable_EndToEnd drives a UDP datagram from a connected
// udp.Conn to a port with no listener, expects an ICMPv4 Port Unreachable back,
// and verifies the failure surfaces on Read exactly once and the socket can be
// reconfigured on the same port once the destination comes up.
func TestUDPConn_PortUnreachable_EndToEnd(t *testing.T) {
	const (
		svPort = 9100
		clPort = 9101
	)
	cl, sv := newUDPICMPPair(t, 2468, false)
	if err := cl.EnableICMP(true); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, ethernet.MaxMTU+ethernet.MaxOverheadSize)
	svTarget := netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort)
	conn := dialUDPConn(t, cl, clPort, svTarget)

	if _, err := conn.Write([]byte("knock")); err != nil {
		t.Fatal(err)
	}
	if exchangeAllowDrop(t, cl, sv, buf) == 0 {
		t.Fatal("client did not send")
	}
	// Receiver must answer with a single ICMPv4 frame.
	n, err := sv.EgressEthernet(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("expected ICMP Port Unreachable from receiver")
	}
	if err := cl.IngressEthernet(buf[:n]); err != nil {
		t.Fatal("client ingress ICMP:", err)
	}
	// No second frame queued.
	if n, _ := sv.EgressEthernet(buf); n != 0 {
		t.Fatalf("receiver sent %d excess bytes", n)
	}

	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 64)); !errors.Is(err, udp.ErrPortUnreachable) {
		t.Fatalf("Read = %v, want udp.ErrPortUnreachable", err)
	}
	// Exactly once: the error is gone; a follow-up read times out.
	conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, err := conn.Read(make([]byte, 64)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("second Read = %v, want deadline exceeded", err)
	}

	// Bring the service up and re-use the same local port: a fresh connection
	// generation sends and delivers normally, with no ICMP response.
	var pc udp.PacketConn
	if err := pc.Configure(udp.PacketConnConfig{
		RxBuf: make([]byte, testUDPBufSize), TxBuf: make([]byte, testUDPBufSize),
		RxQueueSize: testUDPQueueSize, TxQueueSize: testUDPQueueSize,
		RWBackoff: backoffYield,
	}); err != nil {
		t.Fatal(err)
	}
	if err := pc.Open(netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort)); err != nil {
		t.Fatal(err)
	}
	if err := sv.RegisterListenerUDP(&pc); err != nil {
		t.Fatal(err)
	}
	conn.Abort()
	conn = dialUDPConn(t, cl, clPort, svTarget)
	if _, err := conn.Write([]byte("again")); err != nil {
		t.Fatal(err)
	}
	if exchangeEthernetOnce(t, cl, sv, buf) == 0 {
		t.Fatal("client did not re-send")
	}
	if n, _ := sv.EgressEthernet(buf); n != 0 {
		t.Fatalf("bound port must not trigger ICMP, got %d bytes", n)
	}
	pc.SetReadDeadline(time.Now().Add(time.Second))
	var rbuf [64]byte
	n, sender, err := pc.ReadFrom(rbuf[:])
	if err != nil {
		t.Fatal("listener ReadFrom:", err)
	}
	if string(rbuf[:n]) != "again" {
		t.Fatalf("got %q, want %q", rbuf[:n], "again")
	}
	wantSender := netip.AddrPortFrom(netip.AddrFrom4(cl.Addr4()), clPort)
	if sender != wantSender {
		t.Fatalf("sender = %v, want %v", sender, wantSender)
	}
}

// TestUDPPacketConn_PortUnreachable_EndToEnd exercises the connectionless
// PacketConn sender path.
func TestUDPPacketConn_PortUnreachable_EndToEnd(t *testing.T) {
	const (
		svPort = 9400
		clPort = 9401
	)
	cl, sv := newUDPICMPPair(t, 1357, false)
	if err := cl.EnableICMP(true); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, ethernet.MaxMTU+ethernet.MaxOverheadSize)

	var pc udp.PacketConn
	if err := pc.Configure(udp.PacketConnConfig{
		RxBuf: make([]byte, testUDPBufSize), TxBuf: make([]byte, testUDPBufSize),
		RxQueueSize: testUDPQueueSize, TxQueueSize: testUDPQueueSize,
		RWBackoff: backoffYield,
	}); err != nil {
		t.Fatal(err)
	}
	if err := pc.Open(netip.AddrPortFrom(netip.AddrFrom4(cl.Addr4()), clPort)); err != nil {
		t.Fatal(err)
	}
	if err := cl.RegisterListenerUDP(&pc); err != nil {
		t.Fatal(err)
	}
	dst := netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort)
	if _, err := pc.WriteTo([]byte("x"), dst); err != nil {
		t.Fatal(err)
	}
	if exchangeAllowDrop(t, cl, sv, buf) == 0 {
		t.Fatal("client did not send")
	}
	n, err := sv.EgressEthernet(buf)
	if err != nil || n == 0 {
		t.Fatalf("expected ICMP, n=%d err=%v", n, err)
	}
	if err := cl.IngressEthernet(buf[:n]); err != nil {
		t.Fatal(err)
	}
	pc.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := pc.ReadFrom(make([]byte, 64)); !errors.Is(err, udp.ErrPortUnreachable) {
		t.Fatalf("ReadFrom = %v, want ErrPortUnreachable", err)
	}
}

// TestUDPPortUnreachable_OtherSocketUnaffected verifies an ICMP error for one
// socket is never delivered to another bound socket.
func TestUDPPortUnreachable_OtherSocketUnaffected(t *testing.T) {
	const (
		openPort   = 9150
		closedPort = 9151
		clPort     = 9152
	)
	cl, sv := newUDPICMPPair(t, 8642, false)
	if err := cl.EnableICMP(true); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, ethernet.MaxMTU+ethernet.MaxOverheadSize)

	var listener udp.PacketConn
	if err := listener.Configure(udp.PacketConnConfig{
		RxBuf: make([]byte, testUDPBufSize), TxBuf: make([]byte, testUDPBufSize),
		RxQueueSize: testUDPQueueSize, TxQueueSize: testUDPQueueSize,
		RWBackoff: backoffYield,
	}); err != nil {
		t.Fatal(err)
	}
	if err := listener.Open(netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), openPort)); err != nil {
		t.Fatal(err)
	}
	if err := sv.RegisterListenerUDP(&listener); err != nil {
		t.Fatal(err)
	}

	good := dialUDPConn(t, cl, clPort, netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), openPort))
	bad := dialUDPConn(t, cl, clPort+1, netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), closedPort))

	if _, err := good.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	exchangeEthernetOnce(t, cl, sv, buf)
	listener.SetReadDeadline(time.Now().Add(time.Second))
	if n, _, err := listener.ReadFrom(make([]byte, 64)); err != nil || n != 2 {
		t.Fatalf("listener read n=%d err=%v", n, err)
	}

	// Provoke an ICMP for the second socket.
	if _, err := bad.Write([]byte("boom")); err != nil {
		t.Fatal(err)
	}
	exchangeAllowDrop(t, cl, sv, buf)
	if n, _ := sv.EgressEthernet(buf); n == 0 {
		t.Fatal("expected ICMP")
	} else if err := cl.IngressEthernet(buf[:n]); err != nil {
		t.Fatal(err)
	}
	bad.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := bad.Read(make([]byte, 64)); !errors.Is(err, udp.ErrPortUnreachable) {
		t.Fatalf("bad conn Read = %v, want ErrPortUnreachable", err)
	}

	// The healthy socket must not see the error: its read just times out.
	good.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	if _, err := good.Read(make([]byte, 64)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("unrelated socket Read = %v, want deadline", err)
	}
}

// TestUDPPortUnreachable_ResponderGuards verifies the responder side never
// answers for multicast, broadcast, bad checksums, truncated references or
// already-bound ports.
func TestUDPPortUnreachable_ResponderGuards(t *testing.T) {
	cl, sv := newUDPICMPPair(t, 9753, true)
	if err := cl.EnableICMP(true); err != nil {
		t.Fatal(err)
	}
	tx := make([]byte, ethernet.MaxMTU)

	svIP, clIP := sv.Addr4(), cl.Addr4()

	// Multicast to a closed port.
	f := buildIPv4UDP(clIP, [4]byte{224, 0, 0, 1}, 5000, 6000, []byte("m"))
	if err := sv.IngressIP(f); err != nil && !errors.Is(err, lneto.ErrPacketDrop) {
		t.Fatal("multicast ingress:", err)
	}
	if n, _ := sv.EgressIP(tx); n != 0 {
		t.Fatalf("multicast produced ICMP: %d bytes", n)
	}

	// Limited broadcast to a closed port.
	f = buildIPv4UDP(clIP, [4]byte{255, 255, 255, 255}, 5000, 6000, []byte("b"))
	if err := sv.IngressIP(f); err != nil && !errors.Is(err, lneto.ErrPacketDrop) {
		t.Fatal("broadcast ingress:", err)
	}
	if n, _ := sv.EgressIP(tx); n != 0 {
		t.Fatalf("broadcast produced ICMP: %d bytes", n)
	}

	// Bad UDP checksum to a closed local-unicast port.
	f = buildIPv4UDP(clIP, svIP, 5000, 6000, []byte("crc"))
	f[20+7] ^= 0xff // corrupt UDP checksum byte.
	err := sv.IngressIP(f)
	if !errors.Is(err, lneto.ErrBadCRC) {
		t.Fatalf("bad crc ingress = %v, want ErrBadCRC", err)
	}
	if n, _ := sv.EgressIP(tx); n != 0 {
		t.Fatalf("bad checksum produced ICMP: %d bytes", n)
	}

	// Bound port: datagram is delivered, no ICMP is generated.
	const boundPort = 9300
	var listener udp.PacketConn
	if err := listener.Configure(udp.PacketConnConfig{
		RxBuf: make([]byte, testUDPBufSize), TxBuf: make([]byte, testUDPBufSize),
		RxQueueSize: testUDPQueueSize, TxQueueSize: testUDPQueueSize,
		RWBackoff: backoffYield,
	}); err != nil {
		t.Fatal(err)
	}
	if err := listener.Open(netip.AddrPortFrom(netip.AddrFrom4(svIP), boundPort)); err != nil {
		t.Fatal(err)
	}
	if err := sv.RegisterListenerUDP(&listener); err != nil {
		t.Fatal(err)
	}
	f = buildIPv4UDP(clIP, svIP, 5001, boundPort, []byte("data"))
	if err := sv.IngressIP(f); err != nil {
		t.Fatal("bound port ingress:", err)
	}
	if n, _ := sv.EgressIP(tx); n != 0 {
		t.Fatalf("bound port produced ICMP: %d bytes", n)
	}
	listener.SetReadDeadline(time.Now().Add(time.Second))
	if n, _, err := listener.ReadFrom(make([]byte, 64)); err != nil || n != 4 {
		t.Fatalf("listener n=%d err=%v", n, err)
	}

	// Truncated ICMP quote arriving at the sender must not arm the socket.
	closed := dialUDPConn(t, cl, 9301, netip.AddrPortFrom(netip.AddrFrom4(svIP), 6000))
	badQuote := buildIPv4UDP(clIP, svIP, 9301, 6000, nil)[:24] // IP header + 4 bytes only.
	icmp := buildICMPPortUnreachable(svIP, clIP, badQuote)
	if err := cl.IngressIP(icmp); !errors.Is(err, lneto.ErrPacketDrop) {
		t.Fatalf("truncated quote ingress = %v, want ErrPacketDrop", err)
	}
	closed.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	if _, err := closed.Read(make([]byte, 64)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("truncated quote delivered error: %v", err)
	}
}
