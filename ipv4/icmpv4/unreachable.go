package icmpv4

import (
	"encoding/binary"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

const (
	// ipv4MinHeader is the minimum IPv4 header size (IHL=5), used when
	// validating the quoted datagram without importing the ipv4 package.
	ipv4MinHeader = 20
	// maxIPv4Header is the largest possible IPv4 header (IHL=15).
	maxIPv4Header = 60
	// maxPortUnreachQuote bounds the quoted portion of a Destination Unreachable
	// message: at most the full IPv4 header (60 bytes, RFC 791) plus the first
	// 64 bits (8 bytes) of the original datagram's payload, as mandated by RFC 792.
	maxPortUnreachQuote = maxIPv4Header + 8
)

// PortUnreachableQueue is a small fixed-size queue of pending stateless ICMPv4
// Destination Unreachable / Port Unreachable responses (Type 3, Code 4).
// Entries quote the offending IPv4 header together with the original UDP
// header so the sender can attribute the error to the failing four-tuple.
// It is not safe for concurrent use; callers must synchronize access.
type PortUnreachableQueue struct {
	buf [4]portUnreachableEntry
	len uint8
}

type portUnreachableEntry struct {
	// remoteAddr is the original datagram's source address and becomes the
	// outer IP destination of the ICMP response.
	remoteAddr [4]byte
	// quote holds the original IPv4 header followed by 8 bytes (UDP header).
	quote    [maxPortUnreachQuote]byte
	quoteLen uint8
}

// Pending returns the number of queued Port Unreachable responses.
func (q *PortUnreachableQueue) Pending() int { return int(q.len) }

// Queue enqueues a Port Unreachable response. remoteAddr is the original
// datagram source address (4 bytes). quote must start with the offending IPv4
// header and contain at least the complete IP header plus the first 8 bytes
// following it (the UDP header). Silently drops the entry on any invalid or
// truncated argument and when the queue is full.
func (q *PortUnreachableQueue) Queue(remoteAddr, quote []byte) {
	if len(remoteAddr) != 4 || q.len >= uint8(len(q.buf)) {
		return
	}
	if len(quote) < ipv4MinHeader+sizeHeader || len(quote) > maxPortUnreachQuote {
		return
	}
	if quote[0]>>4 != 4 {
		return
	}
	ihl := int(quote[0]&0x0f) * 4
	if ihl < ipv4MinHeader || len(quote) < ihl+sizeHeader {
		return // Truncated reference: never queue an undeliverable quote.
	}
	entry := &q.buf[q.len]
	copy(entry.remoteAddr[:], remoteAddr)
	entry.quoteLen = uint8(copy(entry.quote[:], quote[:ihl+sizeHeader]))
	q.len++
}

// Drain writes one pending ICMPv4 Port Unreachable message at offsetToICMP and
// sets the outer IPv4 destination address (the original sender). It returns
// the number of ICMP bytes written. Returns (0, nil) when the queue is empty,
// offsets are invalid, or the carrier cannot hold the message.
func (q *PortUnreachableQueue) Drain(carrierData []byte, offsetToIP, offsetToICMP int) (int, error) {
	if q.len == 0 || offsetToIP < 0 || offsetToICMP < offsetToIP {
		return 0, nil
	}
	q.len--
	entry := &q.buf[q.len]
	n := sizeHeader + int(entry.quoteLen)
	if offsetToICMP+n > len(carrierData) {
		return 0, nil
	}
	b := carrierData[offsetToICMP : offsetToICMP+n]
	b[0] = uint8(TypeDestinationUnreachable)
	b[1] = uint8(CodePortUnreachable)
	// Checksum and unused field must be zero while summing; the carrier is
	// reused and may contain stale bytes from a previous frame.
	binary.BigEndian.PutUint16(b[2:4], 0)
	binary.BigEndian.PutUint32(b[4:8], 0)
	copy(b[sizeHeader:], entry.quote[:entry.quoteLen])
	var crc lneto.CRC791
	binary.BigEndian.PutUint16(b[2:4], crc.PayloadSum16(b))
	err := internal.SetIPAddrs(carrierData[offsetToIP:offsetToICMP], 0, nil, entry.remoteAddr[:])
	if err != nil {
		return 0, nil
	}
	return n, nil
}
