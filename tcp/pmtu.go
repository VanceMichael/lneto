package tcp

import (
	"time"

	"github.com/soypat/lneto/internal"
)

const (
	// ipv4MinimumMTU is the smallest legal IPv4 path MTU (RFC 791): a 68-byte
	// IP datagram carrying 28 bytes of fixed IPv4+TCP headers and 28 of data.
	// Learned send budgets are never stored below it.
	ipv4MinimumMTU = 68
	ipv4HeaderSize = 20

	// pmtu4TTL bounds how long a reduced IPv4 path-MTU budget is honored
	// before the explicit clock restores the default budget. Mirrors the
	// common 10-minute route-MTU expiry (Linux ip_rt_mtu_expires).
	pmtu4TTL = int64(10 * time.Minute)
)

// rfc1191Plateaus are the PMTU plateaus from RFC 1191 §7, descending. A
// pre-RFC1191 router that sends a zero next-hop MTU is handled by dropping to
// the highest plateau below the current estimate.
var rfc1191Plateaus = [...]uint16{
	65535, 32000, 17914, 8166, 4352,
	2002, 1492, 1006, 508, 296, ipv4MinimumMTU,
}

// nextLowerPMTU4Plateau returns the RFC 1191 plateau immediately below cur,
// never below [ipv4MinimumMTU].
func nextLowerPMTU4Plateau(cur uint16) uint16 {
	for i := 0; i < len(rfc1191Plateaus)-1; i++ {
		if rfc1191Plateaus[i] < cur {
			return rfc1191Plateaus[i]
		}
	}
	return ipv4MinimumMTU
}

// HandlePMTU4 applies an already-validated ICMPv4 Fragmentation Needed
// notification to this Handler. Validation of the ICMP checksum and of the
// quoted addresses/ports is the caller's responsibility; this method applies
// the deterministic path-budget rules:
//
//   - Budgets smaller than the IPv4 minimum are raised to the minimum and a
//     zero next-hop MTU (pre-RFC1191 router) selects the next RFC 1191 plateau
//     below the current budget.
//   - A smaller trusted budget is adopted immediately and all sent-but-
//     unacknowledged data is rewound so it is re-segmented at the new budget on
//     the next Send. Data bytes are neither lost nor duplicated and the FIN
//     control flag stays above the data.
//   - A larger trusted budget is raised; reaching the first-hop default clears
//     the override.
//   - A reduced budget expires [pmtu4TTL] after it was learned; the override
//     can also be cleared with [Handler.ResetPMTU4].
//
// nowUnixNano is the explicit monotonic clock (nanoseconds). It reports false
// when the connection cannot consume the feedback (not synchronized) and true
// when it was accepted, including when the budget is unchanged.
func (h *Handler) HandlePMTU4(nextHopMTU uint16, nowUnixNano int64) bool {
	if !h.scb.State().IsSynchronized() {
		return false
	}
	h.pmtu4ExpireCheck(nowUnixNano)

	mtu := nextHopMTU
	if mtu == 0 {
		cur := h.pmtu4
		if cur == 0 {
			cur = h.pmtu4Link
		}
		if cur == 0 {
			return false // No current budget to step down from.
		}
		mtu = nextLowerPMTU4Plateau(cur)
	} else if mtu < ipv4MinimumMTU {
		mtu = ipv4MinimumMTU
	}

	shrink := false
	switch {
	case h.pmtu4 == 0:
		// Default budget in effect: anything below the known first-hop budget
		// is a reduction; an unknown default trusts the validated message.
		if h.pmtu4Link != 0 && mtu >= h.pmtu4Link {
			return true
		}
		h.pmtu4 = mtu
		h.pmtu4Expire = nowUnixNano + pmtu4TTL
		shrink = h.pmtu4Link == 0 || mtu < h.pmtu4Link
	case mtu < h.pmtu4:
		h.pmtu4 = mtu
		h.pmtu4Expire = nowUnixNano + pmtu4TTL
		shrink = true
	case mtu > h.pmtu4:
		// Larger trusted feedback: raise, restoring the default once the
		// first-hop budget is reached.
		if h.pmtu4Link != 0 && mtu >= h.pmtu4Link {
			h.pmtu4 = 0
			h.pmtu4Expire = 0
		} else {
			h.pmtu4 = mtu
			h.pmtu4Expire = nowUnixNano + pmtu4TTL
		}
	default:
		// Same budget: refresh nothing, event matches a live connection.
		return true
	}

	// Rewind queued data only: when nothing is in flight (e.g. a lone FIN),
	// rewinding NXT could not be recovered by data segments. The new budget
	// still applies to everything sent afterwards.
	if shrink && h.bufTx.BufferedSent() > 0 && h.scb.State().txQueuedDataOpen() {
		// Rewind the whole retransmission queue: ControlBlock and ring move
		// together so every unacked byte re-enters the unsent region and gets
		// re-segmented at the new budget by the normal Send path.
		una := h.scb.SendUNA()
		if h.scb.RetransmitFrom(una) {
			h.bufTx.RetransmitFromUNA()
		}
	}
	return true
}

// PMTU4Tick advances the explicit path-MTU clock: if a reduced budget has aged
// past [pmtu4TTL] the default budget is restored. Restoring the default does
// not rewind in-flight data; larger segments are used for new data and for
// whatever loss recovery later retransmits.
func (h *Handler) PMTU4Tick(nowUnixNano int64) {
	h.pmtu4ExpireCheck(nowUnixNano)
}

// ResetPMTU4 clears any learned IPv4 path-MTU override, restoring the default
// (peer-MSS/link-MTU) send budget.
func (h *Handler) ResetPMTU4() {
	h.pmtu4 = 0
	h.pmtu4Expire = 0
}

// PMTU4 reports the effective IPv4 path MTU budget in use: the learned reduced
// value, or zero when the default budget applies.
func (h *Handler) PMTU4() uint16 { return h.pmtu4 }

func (h *Handler) pmtu4ExpireCheck(nowUnixNano int64) {
	if h.pmtu4 != 0 && h.pmtu4Expire != 0 && nowUnixNano >= h.pmtu4Expire {
		h.pmtu4 = 0
		h.pmtu4Expire = 0
	}
}

// pmtu4PayloadBudget returns the maximum TCP payload octets that fit the
// learned path MTU given the on-wire TCP header length, or -1 when no override
// is active (the caller then uses peer MSS and buffer limits).
func (h *Handler) pmtu4PayloadBudget(tcpHeaderLen int) int {
	if h.pmtu4 == 0 {
		return -1
	}
	budget := int(h.pmtu4) - ipv4HeaderSize - tcpHeaderLen
	if budget < 0 {
		budget = 0
	}
	return budget
}

// learnDefaultPMTU4 records the first-hop (default) budget implied by the
// egress frame capacity: TCP frame slice length plus the fixed IPv4 header.
// The stack clips egress buffers to the link MTU before handing them down, so
// this value only ever tracks that MTU.
func (h *Handler) learnDefaultPMTU4(frameLen int) {
	if frameLen < sizeHeaderTCP {
		return
	}
	if v := uint32(frameLen) + ipv4HeaderSize; v <= 65535 && uint16(v) > h.pmtu4Link {
		h.pmtu4Link = uint16(v)
	}
}

// HandlePMTU4 is the internet-layer hook for a validated ICMPv4 Fragmentation
// Needed message that quotes this connection. The notification is ignored
// unless it references the connection's current remote IPv4 address and both
// ports (the local address is matched by the owning IP stack). Time uses the
// same nanosecond convention as [time.Time.UnixNano].
func (conn *Conn) HandlePMTU4(localAddr, remoteAddr [4]byte, localPort, remotePort uint16, nextHopMTU uint16, nowUnixNano int64) bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if !internal.BytesEqual(conn.remoteAddr, remoteAddr[:]) {
		return false
	}
	if conn.h.localPort != localPort || conn.h.remotePort != remotePort {
		return false
	}
	return conn.h.HandlePMTU4(nextHopMTU, nowUnixNano)
}

// HandlePMTU4 is the Listener hook: it forwards the validated notification to
// the accepted or handshaking child connection whose remote address and port
// match the quote.
func (listener *Listener) HandlePMTU4(localAddr, remoteAddr [4]byte, localPort, remotePort uint16, nextHopMTU uint16, nowUnixNano int64) bool {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if listener.isClosed() || listener.port != localPort {
		return false
	}
	ra := remoteAddr[:]
	if idx := getConn(listener.accepted, remotePort, ra); idx >= 0 {
		return listener.accepted[idx].conn.HandlePMTU4(localAddr, remoteAddr, localPort, remotePort, nextHopMTU, nowUnixNano)
	}
	if idx := getConn(listener.incoming, remotePort, ra); idx >= 0 {
		return listener.incoming[idx].conn.HandlePMTU4(localAddr, remoteAddr, localPort, remotePort, nextHopMTU, nowUnixNano)
	}
	return false
}
