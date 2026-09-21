package xnet

import (
	"encoding/binary"
	"io"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/tcp"
)

// buildFragNeeded crafts an Ethernet frame carrying an ICMPv4 Fragmentation
// Needed message (type 3, code 4) that quotes quoteIP (the original IPv4
// datagram, at least IP header + 8 transport octets).
func buildFragNeeded(dstMAC, srcMAC [6]byte, dstIP, srcIP [4]byte, quoteIP []byte, nextHopMTU uint16, corruptICMP bool) []byte {
	icmpLen := 8 + len(quoteIP)
	ipTotal := 20 + icmpLen
	frame := make([]byte, 14+ipTotal)
	// Ethernet.
	copy(frame[0:6], dstMAC[:])
	copy(frame[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], uint16(ethernet.TypeIPv4))
	// Outer IPv4 header.
	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipTotal))
	ip[8] = 64
	ip[9] = byte(lneto.IPProtoICMP)
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	var crc lneto.CRC791
	crc.WriteEven(ip[:20])
	binary.BigEndian.PutUint16(ip[10:12], crc.Sum16())
	// ICMP.
	ic := ip[20:]
	ic[0] = 3 // destination unreachable
	ic[1] = 4 // fragmentation needed and DF set
	binary.BigEndian.PutUint16(ic[6:8], nextHopMTU)
	copy(ic[8:], quoteIP)
	if corruptICMP {
		ic[8+20+2] ^= 0xFF // flip a quoted TCP byte without touching the checksum field.
	}
	var icmpCRC lneto.CRC791
	csum := icmpCRC.PayloadSum16(ic)
	if corruptICMP {
		csum ^= 0xFFFF
	}
	binary.BigEndian.PutUint16(ic[2:4], csum)
	return frame
}

// egressIngress pumps one frame src->dst, returning the frame length.
func egressIngress(t *testing.T, src, dst *StackAsync, buf []byte) int {
	t.Helper()
	n, err := src.EgressEthernet(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n > 0 {
		if err := dst.IngressEthernet(buf[:n]); err != nil {
			t.Fatal(err)
		}
	}
	return n
}

// TestStackAsync_PMTUFeedback closes the IPv4 PMTU loop end to end: a full-size
// TCP segment dropped by a smaller path triggers an ICMP Frag Needed quote; the
// client must re-segment unacked data to the learned budget, deliver every byte
// once, and finish with a clean FIN close. Malformed, bad-checksum and
// foreign-tuple feedback is ignored.
func TestStackAsync_PMTUFeedback(t *testing.T) {
	const mtu = ethernet.MaxMTU
	s1, s2, c1, c2 := newTCPStacks(t, 99, mtu)
	tst := testerFrom(t, mtu)
	const svPort, clPort = uint16(80), uint16(1337)
	tst.TestTCPSetupAndEstablish(s2, s1, c2, c1, svPort, clPort)

	stream := make([]byte, 1460)
	for i := range stream {
		stream[i] = byte(i*3 + 7)
	}
	if _, err := c1.Write(stream); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, mtu+ethernet.MaxOverheadSize)
	// Egress the full-size segment; the "router" drops it.
	n, err := s1.EgressEthernet(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no data segment emitted")
	}
	dropped := append([]byte(nil), buf[:n]...)
	ifrm, err := ipv4.NewFrame(dropped[14:])
	if err != nil {
		t.Fatal(err)
	}
	if ipLen := ifrm.TotalLength(); ipLen != 1500 {
		t.Fatalf("original IP total length=%d, want 1500", ipLen)
	}
	if !ifrm.Flags().DontFragment() {
		t.Fatal("egress must set DF")
	}
	quote := dropped[14 : 14+28] // IP header + first 8 TCP octets.

	routerMAC := [6]byte{0xde, 0xad, 0, 0, 0, 254}
	routerIP := [4]byte{10, 0, 0, 254}
	s1addr := s1.Addr4()
	h := c1.InternalHandler()

	// Bad ICMP checksum: ignored.
	bad := buildFragNeeded(s1.HardwareAddr(), routerMAC, s1addr, routerIP, quote, 576, true)
	if err := s1.IngressEthernet(bad); err != lneto.ErrBadCRC {
		t.Fatalf("corrupt ICMP err=%v, want ErrBadCRC", err)
	}
	if h.PMTU4() != 0 {
		t.Fatal("budget changed on corrupt ICMP")
	}

	// Valid ICMP but quoting a foreign local address: ignored.
	foreignLocal := buildFragNeeded(s1.HardwareAddr(), routerMAC, s1addr, routerIP, func() []byte {
		q := append([]byte(nil), quote...)
		copy(q[12:16], []byte{10, 9, 9, 9})
		return q
	}(), 576, false)
	if err := s1.IngressEthernet(foreignLocal); err != nil {
		t.Fatalf("foreign-local ingress: %v", err)
	}
	if h.PMTU4() != 0 {
		t.Fatal("budget changed on foreign local address")
	}

	// Valid ICMP quoting a connection on different ports: ignored.
	foreignPorts := buildFragNeeded(s1.HardwareAddr(), routerMAC, s1addr, routerIP, func() []byte {
		q := append([]byte(nil), quote...)
		binary.BigEndian.PutUint16(q[20:22], 4242) // quoted TCP source port.
		return q
	}(), 576, false)
	if err := s1.IngressEthernet(foreignPorts); err != nil {
		t.Fatalf("foreign-ports ingress: %v", err)
	}
	if h.PMTU4() != 0 {
		t.Fatal("budget changed for a foreign 4-tuple")
	}

	// Valid feedback quoting the dropped segment: budget shrinks to 576.
	good := buildFragNeeded(s1.HardwareAddr(), routerMAC, s1addr, routerIP, quote, 576, false)
	if err := s1.IngressEthernet(good); err != nil {
		t.Fatalf("valid frag-needed ingress: %v", err)
	}
	if h.PMTU4() != 576 {
		t.Fatalf("PMTU4=%d, want 576", gotPMTU(h))
	}

	// Drain data: every client TCP/IP datagram must fit 576 bytes and carry no
	// FIN; the server receives all 1460 bytes in order after ACKs flow.
	buf2 := make([]byte, mtu+ethernet.MaxOverheadSize)
	for i := 0; i < 32 && c2.BufferedInput() < len(stream); i++ {
		n1 := egressIngress(t, s1, s2, buf)
		if n1 > 0 {
			ipf, err := ipv4.NewFrame(buf[14:n1])
			if err != nil {
				t.Fatal(err)
			}
			if tlen := ipf.TotalLength(); tlen > 576 {
				t.Fatalf("post-PMTU IP datagram %d > 576", tlen)
			}
			if ipf.Protocol() != lneto.IPProtoTCP {
				t.Fatalf("proto=%s", ipf.Protocol())
			}
			tf, _ := tcp.NewFrame(ipf.Payload())
			seg := tf.Segment(int(ipf.TotalLength()) - int(ipf.HeaderLength()) - tf.HeaderLength())
			if seg.Flags.HasAny(tcp.FlagFIN) {
				t.Fatal("FIN crossed re-segmented data")
			}
		}
		n2 := egressIngress(t, s2, s1, buf2) // ACKs back.
		if n1 == 0 && n2 == 0 {
			t.Fatalf("stalled with %d/%d bytes delivered", c2.BufferedInput(), len(stream))
		}
	}
	if c2.BufferedInput() != len(stream) {
		t.Fatalf("delivered %d bytes, want %d", c2.BufferedInput(), len(stream))
	}
	rx := make([]byte, len(stream))
	if n, _ := c2.Read(rx); n != len(stream) {
		t.Fatalf("read %d bytes", n)
	}
	for i := range stream {
		if rx[i] != stream[i] {
			t.Fatalf("byte %d mismatch: %d != %d", i, rx[i], stream[i])
		}
	}
	_ = rx

	// Trusted larger feedback restores the default budget.
	raise := buildFragNeeded(s1.HardwareAddr(), routerMAC, s1addr, routerIP, quote, mtu, false)
	if err := s1.IngressEthernet(raise); err != nil {
		t.Fatal(err)
	}
	if h.PMTU4() != 0 {
		t.Fatalf("trusted raise did not restore default: %d", h.PMTU4())
	}

	// Clean FIN close proves FIN still follows all data.
	if err := c1.Close(); err != nil {
		t.Fatal(err)
	}
	if n := egressIngress(t, s1, s2, buf); n == 0 {
		t.Fatal("FIN not emitted")
	}
	if n := egressIngress(t, s2, s1, buf2); n == 0 {
		t.Fatal("FIN ACK not emitted")
	}
	// c2 reads EOF once FIN is processed.
	for i := 0; i < 8; i++ {
		if _, err := c2.Read(make([]byte, 1)); err == io.EOF {
			return
		}
		egressIngress(t, s2, s1, buf2)
	}
	t.Fatal("peer did not reach EOF after FIN")
}

func gotPMTU(h *tcp.Handler) uint16 { return h.PMTU4() }
