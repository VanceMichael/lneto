package xnet

import (
	"errors"
	"net/netip"
	"time"

	"github.com/soypat/lneto/dns"
)

// This file wires bounded DNS resolution snapshots into the blocking/retrying
// lookup call chain (StackRetrying -> StackBlocking -> StackAsync) on top of
// the existing dns.Client and UDP demux/result API:
//
//   - A cache hit completes without arming the dns.Client, so no UDP query
//     port is occupied and no query packet is sent.
//   - A cache miss registers an in-flight generation in the cache, performs
//     the ordinary StartResolve -> UDP -> Demux -> ResponseAnswerLookup query,
//     and stores the result by answer TTL (positive) or RFC 2308 negative TTL.
//   - Concurrent callers for the same key join the leader's generation and all
//     receive the same result.
//   - Expiry, response validation failure, timeout or UDP-node reset release
//     every waiter; the next call starts a new generation and a new query.
//   - DNS server, local address and configuration changes invalidate all
//     snapshots.
//
// Direct dns.Client use and the uncached StartLookupIPType/ResultLookupIP API
// keep their existing behavior; the cache is only used when enabled through
// StackConfig.DNSCache.

var (
	errDNSQueryReset   = errors.New("cywnet: DNS query node reset before response")
	errDNSResponseLame = errors.New("cywnet: invalid DNS response")
)

// dnsLookupState is the per-call state of a cache-mediated lookup.
type dnsLookupState uint8

const (
	dnsLookupHit dnsLookupState = iota
	// dnsLookupLeader: this call armed the dns.Client and owns the generation.
	dnsLookupLeader
	// dnsLookupFollower: this call waits on the leader's generation.
	dnsLookupFollower
	// dnsLookupAwaitTurn: the single hardware client is busy; the call either
	// holds an unled generation (gen != 0) or a bypass reservation (gen == 0)
	// and arms once the current owner finishes.
	dnsLookupAwaitTurn
	// dnsLookupBypass: cache at capacity; query runs uncached.
	dnsLookupBypass
)

// dnsQueryNode wraps dns.Client to observe demux validation failures without
// changing dns.Client's own behavior. All other StackNode methods are promoted.
type dnsQueryNode struct {
	*dns.Client
	// demuxErr is the first error returned by a response Demux for the armed
	// query; it is cleared on every (re)arm.
	demuxErr error
}

func (n *dnsQueryNode) Demux(carrierData []byte, frameOffset int) error {
	err := n.Client.Demux(carrierData, frameOffset)
	if err != nil {
		n.demuxErr = err
	}
	return err
}

// dnsInflightQuery records the single hardware query currently armed on the
// stack's dns.Client, if any.
type dnsInflightQuery struct {
	key    dns.SnapshotKey
	host   string
	qtype  dns.Type
	gen    uint64 // cache generation; zero for an uncached bypass query.
	connID uint64 // dns.Client.ConnectionID captured at arm time.
}

func (s *StackAsync) dnsSnapKey(host string, qtype dns.Type) dns.SnapshotKey {
	return dns.SnapshotKey{Host: host, Qtype: qtype, Server: s.dnssv}
}

// dnsLookupBegin classifies a lookup before any blocking wait. It returns the
// initial state; for dnsLookupHit the result is already delivered in
// addrs/err and no UDP packet will be sent.
func (s *StackAsync) dnsLookupBegin(host string, qtype dns.Type) (st dnsLookupState, gen uint64, addrs []netip.Addr, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dnsBeginLocked(host, qtype)
}

func (s *StackAsync) dnsBeginLocked(host string, qtype dns.Type) (st dnsLookupState, gen uint64, addrs []netip.Addr, err error) {
	if !s.dnssv.IsValid() {
		return 0, 0, nil, errNoDNSServer
	} else if !s.dnssv.Is4() {
		return 0, 0, nil, errDNSv6Transport
	}
	name, err := dns.NewName(host)
	if err != nil {
		return 0, 0, nil, err
	}
	key := s.dnsSnapKey(host, qtype)
	snap, gen, kind := s.dnscache.Acquire(key)
	switch kind {
	case dns.SnapshotHit:
		return dnsLookupHit, gen, snap.Addrs, negativeSnapshotErr(snap)
	case dns.SnapshotJoin:
		return dnsLookupFollower, gen, nil, nil
	case dns.SnapshotNew, dns.SnapshotBypass:
		if s.dnsInflight != nil {
			// The single hardware client is busy with another query. A New
			// reservation keeps gen so same-key joiners coalesce behind this
			// future leader; a Bypass reservation carries gen == 0.
			return dnsLookupAwaitTurn, gen, nil, nil
		}
		if err = s.armDNSQueryLocked(name, qtype); err != nil {
			if kind == dns.SnapshotNew {
				s.dnscache.Fail(key, gen, err)
			}
			return 0, 0, nil, err
		}
		s.dnsInflight = &dnsInflightQuery{
			key:    key,
			host:   host,
			qtype:  qtype,
			gen:    gen, // 0 for SnapshotBypass.
			connID: *s.dns.ConnectionID(),
		}
		if kind == dns.SnapshotNew {
			return dnsLookupLeader, gen, nil, nil
		}
		return dnsLookupBypass, 0, nil, nil
	}
	return 0, 0, nil, errDNSResponseLame
}

// dnsLookupPoll advances the lookup. When done is false the caller backs off
// and polls again; st/gen are updated when an awaiter acquires the hardware
// client.
func (s *StackAsync) dnsLookupPoll(host string, qtype dns.Type, st dnsLookupState, gen uint64) (addrs []netip.Addr, st2 dnsLookupState, gen2 uint64, done bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.dnsSnapKey(host, qtype)
	switch st {
	case dnsLookupFollower:
		snap, terminal := s.dnscache.Result(key, gen)
		if !terminal {
			return nil, st, gen, false, nil
		}
		return snap.Addrs, st, gen, true, negativeSnapshotErr(snap)

	case dnsLookupAwaitTurn:
		if s.dnsInflight != nil {
			return nil, st, gen, false, nil
		}
		return s.dnsTakeTurnLocked(host, qtype, gen)

	case dnsLookupLeader, dnsLookupBypass:
		in := s.dnsInflight
		if in == nil || (gen != 0 && in.gen != gen) {
			// The hardware query was taken over or released out from under us.
			if gen != 0 {
				s.dnscache.Fail(key, gen, errDNSQueryReset)
			}
			return nil, st, gen, true, errDNSQueryReset
		}
		if cur := *s.dns.ConnectionID(); cur != in.connID || s.dns.IsClosed() {
			// A new StartResolve/Abort/reset replaced our UDP node.
			s.releaseInflightLocked(in, errDNSQueryReset)
			return nil, st, gen, true, errDNSQueryReset
		}
		if s.dnsqnode.demuxErr != nil {
			// Response failed decoding/validation: release everyone, cache
			// nothing, let the next call query again.
			s.releaseInflightLocked(in, s.dnsqnode.demuxErr)
			return nil, st, gen, true, s.dnsqnode.demuxErr
		}
		flags, isResp := s.dns.ResponseFlags()
		if !isResp {
			return nil, st, gen, false, nil
		} else if flags.IsTruncated() {
			s.releaseInflightLocked(in, errDNSResponseLame)
			return nil, st, gen, true, errDNSResponseLame
		}
		rcode := flags.ResponseCode()
		if rcode != 0 {
			// Explicit failure response (NXDOMAIN, SERVFAIL, ...).
			ttl := s.negativeTTLForRCodeLocked(rcode)
			s.finishNegativeLocked(in, rcode, ttl)
			return nil, st, gen, true, error(rcode)
		}
		n, perr := s.dns.ResponseAnswerLookup(s.addrbufnip[:], host)
		if perr != nil {
			s.releaseInflightLocked(in, perr)
			return nil, st, gen, true, perr
		}
		if n == 0 {
			// NOERROR with no usable address: NODATA negative answer.
			ttl := s.negativeTTLForRCodeLocked(dns.RCodeSuccess)
			s.finishNegativeLocked(in, dns.RCodeSuccess, ttl)
			return nil, st, gen, true, errDNSNoAns
		}
		answerTTL, ok := s.dns.ResponseMinAnswerTTL()
		if !ok {
			s.releaseInflightLocked(in, errDNSResponseLame)
			return nil, st, gen, true, errDNSResponseLame
		}
		addrs = append(addrs, s.addrbufnip[:n]...)
		ttl := s.dnscache.ClampPositiveTTL(answerTTL)
		s.finishPositiveLocked(in, addrs, ttl)
		return addrs, st, gen, true, nil
	}
	return nil, st, gen, true, errDNSResponseLame
}

// dnsTakeTurnLocked arms the hardware client for an awaiter once it is free.
func (s *StackAsync) dnsTakeTurnLocked(host string, qtype dns.Type, gen uint64) (addrs []netip.Addr, st dnsLookupState, gen2 uint64, done bool, err error) {
	key := s.dnsSnapKey(host, qtype)
	if gen == 0 {
		// Bypass reservation held nothing: reclassify against the cache.
		nst, ngen, naddrs, nerr := s.dnsBeginLocked(host, qtype)
		done := nst == dnsLookupHit || nerr != nil
		return naddrs, nst, ngen, done, nerr
	}
	// A New generation was reserved before the wait: confirm it is still
	// pending, then become its leader.
	snap, terminal := s.dnscache.Result(key, gen)
	if terminal {
		return snap.Addrs, dnsLookupFollower, gen, true, negativeSnapshotErr(snap)
	}
	name, err := dns.NewName(host)
	if err != nil {
		s.dnscache.Fail(key, gen, err)
		return nil, dnsLookupLeader, gen, true, err
	}
	if err = s.armDNSQueryLocked(name, qtype); err != nil {
		s.dnscache.Fail(key, gen, err)
		return nil, dnsLookupLeader, gen, true, err
	}
	s.dnsInflight = &dnsInflightQuery{
		key:    key,
		host:   host,
		qtype:  qtype,
		gen:    gen,
		connID: *s.dns.ConnectionID(),
	}
	return nil, dnsLookupLeader, gen, false, nil
}

// dnsLookupTimedOut releases resources after the caller's deadline elapsed.
// Only the generation owner aborts the hardware query and fails the
// generation; departing followers leave it intact for the remaining waiters.
func (s *StackAsync) dnsLookupTimedOut(host string, qtype dns.Type, st dnsLookupState, gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch st {
	case dnsLookupLeader, dnsLookupBypass:
		in := s.dnsInflight
		if in == nil || (gen != 0 && in.gen != gen) {
			return
		}
		s.dns.Abort()
		s.releaseInflightLocked(in, errDeadlineExceed)
	case dnsLookupAwaitTurn:
		if gen != 0 {
			s.dnscache.Fail(s.dnsSnapKey(host, qtype), gen, errDeadlineExceed)
		}
	}
}

func (s *StackAsync) finishPositiveLocked(in *dnsInflightQuery, addrs []netip.Addr, ttl time.Duration) {
	if in.gen != 0 {
		s.dnscache.StorePositive(in.key, in.gen, addrs, ttl)
	}
	s.dnsInflight = nil
	s.dns.Abort() // Release the UDP query node now that the snapshot is stored.
}

func (s *StackAsync) finishNegativeLocked(in *dnsInflightQuery, rcode dns.RCode, ttl time.Duration) {
	if in.gen != 0 {
		// StoreNegative with a zero TTL releases waiters without caching.
		s.dnscache.StoreNegative(in.key, in.gen, rcode, ttl)
	}
	s.dnsInflight = nil
	s.dns.Abort()
}

func (s *StackAsync) releaseInflightLocked(in *dnsInflightQuery, cause error) {
	if in.gen != 0 {
		s.dnscache.Fail(in.key, in.gen, cause)
	}
	s.dnsInflight = nil
	// The node may already have been replaced (connID mismatch); only abort
	// when the client still belongs to this generation.
	if cur := *s.dns.ConnectionID(); cur == in.connID {
		s.dns.Abort()
	}
}

// negativeTTLForRCodeLocked returns the cache TTL for a terminal response
// code. NXDOMAIN and NODATA honor an SOA-derived RFC 2308 TTL; other failure
// codes are cached only for the configured fallback duration.
func (s *StackAsync) negativeTTLForRCodeLocked(rcode dns.RCode) time.Duration {
	fallback := s.dnscache.NegativeFallback()
	maxTTL := s.dnscache.MaxNegativeTTL()
	if rcode == dns.RCodeNameError || rcode == dns.RCodeSuccess {
		return s.dns.ResponseNegativeTTL(fallback, maxTTL)
	}
	return clampNegTTL(fallback, maxTTL)
}

func clampNegTTL(v, maxTTL time.Duration) time.Duration {
	if maxTTL <= 0 {
		return 0
	}
	if v > maxTTL {
		return maxTTL
	}
	return v
}

// negativeSnapshotErr maps a cached negative snapshot to the same error the
// leader returned: a response code for explicit failures, errDNSNoAns for a
// cached NODATA answer.
func negativeSnapshotErr(snap dns.Snapshot) error {
	if snap.Err == dns.ErrNoAnswer {
		return errDNSNoAns
	}
	return snap.Err
}

// invalidateDNSSnapshotsLocked aborts any in-flight query and drops all
// snapshots. It must be called with s.mu held whenever the DNS server, local
// address or other identity-bearing configuration changes.
func (s *StackAsync) invalidateDNSSnapshotsLocked() {
	if s.dnsInflight != nil {
		in := s.dnsInflight
		s.dns.Abort()
		s.releaseInflightLocked(in, dns.ErrSnapshotInvalidated)
	}
	if s.dnscache != nil {
		s.dnscache.Invalidate()
	}
}
