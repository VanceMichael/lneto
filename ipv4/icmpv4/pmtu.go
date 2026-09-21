package icmpv4

import (
	"encoding/binary"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ipv4"
)

// sizeFragNeeded is the shortest acceptable Fragmentation Needed message:
// 8-byte ICMP header + quoted IPv4 header (20) + 8 octets (64 bits) of the
// quoted transport header per RFC 792.
const sizeFragNeeded = sizeHeader + 20 + 8

// FragNeeded4 is a validated ICMPv4 Destination Unreachable /
// "fragmentation needed and DF set" message (type 3, code 4, RFC 792/RFC 1191)
// that quotes a datagram the local host sent.
type FragNeeded4 struct {
	// LocalAddr is the source address of the quoted datagram, i.e. one of the
	// local host's own IPv4 addresses.
	LocalAddr [4]byte
	// RemoteAddr is the destination address of the quoted datagram.
	RemoteAddr [4]byte
	// LocalPort is the TCP source port of the quoted datagram.
	LocalPort uint16
	// RemotePort is the TCP destination port of the quoted datagram.
	RemotePort uint16
	// NextHopMTU is the RFC 1191 next-hop MTU carried by the message. A zero
	// value means the sender of the message predates RFC 1191 and did not
	// include a usable MTU; the receiver must fall back to a lower plateau.
	NextHopMTU uint16
}

// FragNeeded4Sink receives validated Fragmentation Needed events. It is invoked
// from [Client.Demux], so implementations run in the same ingress context.
type FragNeeded4Sink func(FragNeeded4)

// NextHopMTU returns the MTU field of a Destination Unreachable message as
// defined by RFC 1191 (the 16 bits at offset 6, unused/zero in the original
// RFC 792 layout).
func (frm FrameDestinationUnreachable) NextHopMTU() uint16 {
	return binary.BigEndian.Uint16(frm.buf[6:8])
}

// ParseFragNeeded4 validates an ICMPv4 Fragmentation Needed message
// (type 3, code 4) and extracts the quoted IPv4/TCP reference.
//
// It enforces every acceptance rule that can be checked without connection
// state: ICMP checksum, message length, code, quoted header completeness
// (IPv4 header plus the RFC 792 eight transport octets), quoted protocol
// (TCP only), DF set on the quote, no fragment offset on the quote, and that
// neither quoted address is unspecified, multicast or limited broadcast and
// that both quoted TCP ports are non-zero. Matching the tuple against a live
// connection is left to the caller.
//
// ok is false (with nil error) for every structurally unacceptable message;
// err is non-nil only when the ICMP checksum fails.
func ParseFragNeeded4(packet []byte) (ev FragNeeded4, ok bool, err error) {
	if len(packet) < sizeFragNeeded {
		return ev, false, nil
	}
	var crc lneto.CRC791
	if crc.PayloadSum16(packet) != 0 {
		return ev, false, lneto.ErrBadCRC
	}
	if Type(packet[0]) != TypeDestinationUnreachable ||
		CodeDestinationUnreachable(packet[1]) != CodeFragNeededAndDFSet {
		return ev, false, nil
	}

	quote := packet[sizeHeader:]
	if quote[0]>>4 != 4 {
		return ev, false, nil // Only IPv4 quotes are supported.
	}
	ihl := int(quote[0]&0x0f) * 4
	if ihl < 20 || ihl+8 > len(quote) {
		return ev, false, nil // Truncated IP header or fewer than 8 transport octets quoted.
	}
	totalLen := binary.BigEndian.Uint16(quote[2:4])
	if int(totalLen) < ihl+20 {
		return ev, false, nil // Quote cannot contain the full TCP header it claims.
	}
	frag := ipv4.Flags(binary.BigEndian.Uint16(quote[6:8]))
	if !frag.DontFragment() || frag.FragmentOffset() != 0 {
		// PMTU feedback only applies to unfragmented DF datagrams; transport
		// ports are only present in the first fragment.
		return ev, false, nil
	}
	if lneto.IPProto(quote[9]) != lneto.IPProtoTCP {
		return ev, false, nil // Only TCP feedback is acted upon.
	}

	copy(ev.LocalAddr[:], quote[12:16])
	copy(ev.RemoteAddr[:], quote[16:20])
	for _, addr := range [2][4]byte{ev.LocalAddr, ev.RemoteAddr} {
		if addr == [4]byte{} || ipv4.IsMulticast(addr) || ipv4.IsBroadcast(addr) {
			return ev, false, nil
		}
	}
	l4 := quote[ihl:]
	ev.LocalPort = binary.BigEndian.Uint16(l4[0:2])
	ev.RemotePort = binary.BigEndian.Uint16(l4[2:4])
	if ev.LocalPort == 0 || ev.RemotePort == 0 {
		return ev, false, nil
	}
	ev.NextHopMTU = binary.BigEndian.Uint16(packet[6:8])
	return ev, true, nil
}
