package udp

import (
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"
)

func tupleForConn(conn *Conn) PortUnreachable {
	return PortUnreachable{
		SrcIP:   [4]byte{10, 0, 0, 2},
		DstIP:   [4]byte{10, 0, 0, 1},
		SrcPort: conn.LocalPort(),
		DstPort: conn.RemotePort(),
	}
}

func TestConn_PortUnreachable_DeliveredOnce(t *testing.T) {
	conn := newTestConn(t) // local 1234 -> 10.0.0.1:8080
	tup := tupleForConn(conn)

	// Unrelated four-tuples are rejected by the socket.
	bad := tup
	bad.DstPort = 9999
	if conn.RecvPortUnreachable(bad) {
		t.Fatal("mismatched remote port must not be delivered")
	}
	bad = tup
	bad.DstIP = [4]byte{10, 9, 9, 9}
	if conn.RecvPortUnreachable(bad) {
		t.Fatal("mismatched remote address must not be delivered")
	}

	if !conn.RecvPortUnreachable(tup) {
		t.Fatal("matching four-tuple must arm the error")
	}
	// Duplicate while pending coalesces: still a single delivery.
	if !conn.RecvPortUnreachable(tup) {
		t.Fatal("duplicate ICMP while pending should be claimed")
	}

	conn.SetReadDeadline(time.Now().Add(time.Second))
	var buf [64]byte
	if _, err := conn.Read(buf[:]); !errors.Is(err, ErrPortUnreachable) {
		t.Fatalf("Read error = %v, want ErrPortUnreachable", err)
	}

	// Exactly once: the next read blocks until its deadline.
	conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := conn.Read(buf[:]); !errors.Is(err, osDeadline()) {
		t.Fatalf("second Read error = %v, want deadline exceeded", err)
	}
}

func TestConn_PortUnreachable_ReconfigureClearsGeneration(t *testing.T) {
	conn := newTestConn(t)
	if !conn.RecvPortUnreachable(tupleForConn(conn)) {
		t.Fatal("arm")
	}
	// Reconfigure (new connection generation) drops the stale error.
	if err := conn.Configure(ConnConfig{
		RxBuf:       make([]byte, 256),
		TxBuf:       make([]byte, 256),
		RxQueueSize: 4,
		TxQueueSize: 4,
		RWBackoff:   backoffYield,
	}); err != nil {
		t.Fatal(err)
	}
	if err := conn.Open(1234, netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), 8080)); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	var buf [64]byte
	if _, err := conn.Read(buf[:]); !errors.Is(err, osDeadline()) {
		t.Fatalf("Read after reconfigure = %v, want deadline (stale error cleared)", err)
	}
	// Sending on the same port still works.
	if _, err := conn.Write([]byte("after")); err != nil {
		t.Fatalf("Write after reconfigure: %v", err)
	}
}

func TestConn_PortUnreachable_ClosedRejects(t *testing.T) {
	conn := newTestConn(t)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if conn.RecvPortUnreachable(tupleForConn(conn)) {
		t.Fatal("closed socket must not receive ICMP errors")
	}
}

func newTestPacketConn(t *testing.T, localPort uint16) *PacketConn {
	t.Helper()
	var pc PacketConn
	err := pc.Configure(PacketConnConfig{
		RxBuf:       make([]byte, 512),
		TxBuf:       make([]byte, 512),
		RxQueueSize: 4,
		TxQueueSize: 4,
		RWBackoff:   backoffYield,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = pc.Open(netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), localPort))
	if err != nil {
		t.Fatal(err)
	}
	return &pc
}

func TestPacketConn_PortUnreachable_MatchSendGeneration(t *testing.T) {
	const lport = 3333
	pc := newTestPacketConn(t, lport)
	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), 9000)
	if _, err := pc.WriteTo([]byte("hi"), dst); err != nil {
		t.Fatal(err)
	}
	tup := PortUnreachable{
		SrcIP:   [4]byte{10, 0, 0, 2},
		DstIP:   [4]byte{10, 0, 0, 1},
		SrcPort: lport,
		DstPort: 9000,
	}
	// Error for a flow this socket never sent to must not be delivered.
	unknown := tup
	unknown.DstPort = 4444
	if pc.RecvPortUnreachable(unknown) {
		t.Fatal("ICMP error without matching send generation must be rejected")
	}
	unknown = tup
	unknown.SrcPort = lport + 1
	if pc.RecvPortUnreachable(unknown) {
		t.Fatal("ICMP error for unbound local port must be rejected")
	}
	if !pc.RecvPortUnreachable(tup) {
		t.Fatal("matching send generation must arm the error")
	}

	pc.SetReadDeadline(time.Now().Add(time.Second))
	var buf [64]byte
	if _, _, err := pc.ReadFrom(buf[:]); !errors.Is(err, ErrPortUnreachable) {
		t.Fatalf("ReadFrom = %v, want ErrPortUnreachable", err)
	}

	// Once: subsequent read hits the deadline; further sends on same port work.
	pc.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, _, err := pc.ReadFrom(buf[:]); !errors.Is(err, osDeadline()) {
		t.Fatalf("second ReadFrom = %v, want deadline", err)
	}
	if _, err := pc.WriteTo([]byte("again"), dst); err != nil {
		t.Fatalf("WriteTo after consumed error: %v", err)
	}
}
