package udp

import "errors"

// ErrPortUnreachable is delivered once to a UDP socket when an ICMPv4
// Destination Unreachable / Port Unreachable response quotes a datagram
// previously sent by that socket. It lets callers tell a closed or unbound
// destination port apart from congestion or silent drops.
var ErrPortUnreachable = errors.New("udp: ICMPv4 destination port unreachable")

// PortUnreachable describes the original UDP datagram quoted by an ICMPv4
// Port Unreachable message (RFC 792). All fields refer to the quoted packet,
// i.e. the packet this host sent: SrcIP/SrcPort are the local endpoint and
// DstIP/DstPort the destination that had no UDP listener.
type PortUnreachable struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
}

// PortUnreachableReceiver is implemented by UDP sockets that can consume
// ICMPv4 Port Unreachable errors attributed to their traffic. Implementations
// must validate the quoted four-tuple and report whether the error was
// delivered to this socket.
type PortUnreachableReceiver interface {
	// RecvPortUnreachable delivers a validated ICMPv4 Port Unreachable.
	// It returns true when the quoted four-tuple belongs to the socket and the
	// error was armed for exactly-once delivery; false means the socket does
	// not own the quoted flow and the error must not be delivered.
	RecvPortUnreachable(PortUnreachable) bool
}
