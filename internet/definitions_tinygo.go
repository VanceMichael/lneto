//go:build tinygo

package internet

import (
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/udp"
)

func makecbnode(s lneto.StackNode) cbnode {
	cb := cbnode{
		_demux:       s.Demux,
		_encapsulate: s.Encapsulate,
	}
	if r, ok := s.(udp.PortUnreachableReceiver); ok {
		cb._recvPortUnreachable = r.RecvPortUnreachable
	}
	return cb
}

type cbnode struct {
	// Do not access outside of handlers/node logic.
	_demux func([]byte, int) error
	// Do not access outside of handlers/node logic.
	_encapsulate func([]byte, int, int) (int, error)
	// _recvPortUnreachable is non-nil only for UDP sockets implementing
	// [udp.PortUnreachableReceiver]. Do not access outside of node logic.
	_recvPortUnreachable func(udp.PortUnreachable) bool
}

func (s *cbnode) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	return s._encapsulate(carrierData, offsetToIP, offsetToFrame)
}

func (s *cbnode) Demux(carrierData []byte, frameOffset int) error {
	debugLog("cbnode:pre-demux")
	return s._demux(carrierData, frameOffset)
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
	return s._demux == nil || s._encapsulate == nil
}
