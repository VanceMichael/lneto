//go:build !tinygo

package internet

import (
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/udp"
)

func makecbnode(s lneto.StackNode) cbnode {
	cb := cbnode{
		_s: s,
	}
	if r, ok := s.(udp.PortUnreachableReceiver); ok {
		cb._recvPortUnreachable = r.RecvPortUnreachable
	}
	return cb
}

type cbnode struct {
	// Do not access outside of handlers/node logic.
	_s lneto.StackNode
	// _recvPortUnreachable is non-nil only for UDP sockets implementing
	// [udp.PortUnreachableReceiver]. Do not access outside of node logic.
	_recvPortUnreachable func(udp.PortUnreachable) bool
}

func (s cbnode) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	return s._s.Encapsulate(carrierData, offsetToIP, offsetToFrame)
}

func (s cbnode) Demux(carrierData []byte, frameOffset int) error {
	return s._s.Demux(carrierData, frameOffset)
}

// RecvPortUnreachable forwards an ICMPv4 Port Unreachable to a UDP socket that
// implements [udp.PortUnreachableReceiver]; nodes that do not implement it
// never receive ICMP errors.
func (s cbnode) RecvPortUnreachable(t udp.PortUnreachable) bool {
	if s._recvPortUnreachable == nil {
		return false
	}
	return s._recvPortUnreachable(t)
}

func (s cbnode) IsZeroed() bool {
	return s._s == nil
}
