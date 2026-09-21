//go:build tinygo

package internet

import "github.com/soypat/lneto"

func makecbnode(s lneto.StackNode) cbnode {
	cb := cbnode{
		_demux:       s.Demux,
		_encapsulate: s.Encapsulate,
	}
	if n, ok := s.(pmtu4Notifier); ok {
		cb._pmtu4 = n.HandlePMTU4
	}
	return cb
}

type cbnode struct {
	// Do not access outside of handlers/node logic.
	_demux func([]byte, int) error
	// Do not access outside of handlers/node logic.
	_encapsulate func([]byte, int, int) (int, error)
	// _pmtu4 is non-nil when the node implements pmtu4Notifier.
	// Do not access outside of handlers/node logic.
	_pmtu4 PMTU4Func
}

func (s *cbnode) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	return s._encapsulate(carrierData, offsetToIP, offsetToFrame)
}

func (s *cbnode) Demux(carrierData []byte, frameOffset int) error {
	debugLog("cbnode:pre-demux")
	return s._demux(carrierData, frameOffset)
}

func (s *cbnode) handlePMTU4(localAddr, remoteAddr [4]byte, localPort, remotePort uint16, nextHopMTU uint16, nowUnixNano int64) bool {
	if s._pmtu4 == nil {
		return false
	}
	return s._pmtu4(localAddr, remoteAddr, localPort, remotePort, nextHopMTU, nowUnixNano)
}

func (s cbnode) IsZeroed() bool {
	return s._demux == nil || s._encapsulate == nil
}
