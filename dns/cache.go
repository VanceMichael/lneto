package dns

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"
)

// SnapshotKey identifies a resolution. It scopes a cached answer to the
// hostname, the record type and the DNS server that produced it, so changing
// the configured server can never leave an old-server answer as a hit.
type SnapshotKey struct {
	// Host is the queried name. Comparison is ASCII case-insensitive per
	// RFC 1035 section 2.3.3.
	Host string
	// Qtype is the question record type (TypeA or TypeAAAA).
	Qtype Type
	// Server is the DNS server the query was sent to.
	Server netip.Addr
}

// SnapshotKind classifies the result of [SnapshotCache.Acquire].
type SnapshotKind uint8

const (
	// SnapshotNew means no valid snapshot existed: the caller is the leader
	// and must perform the query, then report it with StorePositive,
	// StoreNegative or Fail.
	SnapshotNew SnapshotKind = iota
	// SnapshotHit means a still-valid positive or negative snapshot is
	// returned directly. No UDP query is required.
	SnapshotHit
	// SnapshotJoin means a query for the same key is already in flight: the
	// caller waits and polls [SnapshotCache.Result] with the returned
	// generation, eventually receiving the same generation's result.
	SnapshotJoin
	// SnapshotBypass means the cache was full of non-evictable entries.
	// The caller performs an uncached query and reports nothing back.
	SnapshotBypass
)

// Snapshot is a point-in-time view of a resolution.
type Snapshot struct {
	// Kind is meaningful for Acquire results.
	Kind SnapshotKind
	// Addrs holds the resolved addresses for positive snapshots.
	Addrs []netip.Addr
	// RCode is the response code for negative snapshots.
	RCode RCode
	// Err carries a terminal failure (failed generation or staleness).
	Err error
	// TTL is the remaining lifetime of a SnapshotHit.
	TTL time.Duration
}

// SnapshotConfig configures a [SnapshotCache].
type SnapshotConfig struct {
	// MaxEntries bounds the number of stored entries, including in-flight
	// generations. Zero defaults to 64. When all entries are occupied by
	// in-flight generations new lookups bypass the cache instead of waiting.
	MaxEntries int
	// MinTTL and MaxTTL clamp the positive TTL taken from answer records.
	// MaxTTL zero defaults to one hour.
	MinTTL time.Duration
	MaxTTL time.Duration
	// NegativeTTL is the fallback negative-caching TTL used when the response
	// has no usable SOA (RFC 2308 section 5). It is also the TTL applied to
	// explicit failure responses that carry no SOA. Zero means such responses
	// are not cached; waiters are still released.
	NegativeTTL time.Duration
	// MaxNegativeTTL caps the SOA-derived negative TTL (min(SOA TTL, SOA
	// MINIMUM)). Zero defaults to five minutes.
	MaxNegativeTTL time.Duration
	// Now is the clock used for expiry; nil uses time.Now. An explicit clock
	// keeps TTL behavior deterministically testable.
	Now func() time.Time
}

const (
	defaultSnapshotMaxEntries     = 64
	defaultSnapshotMaxTTL         = time.Hour
	defaultSnapshotMaxNegativeTTL = 5 * time.Minute
)

var (
	// ErrSnapshotStale is returned by Result for a generation that was
	// superseded by another one for the same key.
	ErrSnapshotStale = errors.New("dns snapshot generation superseded")
	// ErrSnapshotInvalidated is returned by Result for a generation dropped
	// because the cache was invalidated (server/address/config change).
	ErrSnapshotInvalidated = errors.New("dns snapshot cache invalidated")

	errSnapshotEmpty = errors.New("dns positive snapshot had no addresses or TTL")
)

// ErrNoAnswer is delivered by a cached NODATA snapshot: a NOERROR response
// that contained no usable A/AAAA address.
var ErrNoAnswer = errors.New("dns response contained no address answer")

// SnapshotCache is a bounded cache of DNS resolution snapshots with in-flight
// request coalescing ("single flight"): callers joining an in-flight key wait
// for the leader's generation and all receive the same result. It is safe for
// concurrent use and does no I/O of its own.
type SnapshotCache struct {
	mu       sync.Mutex
	now      func() time.Time
	max      int
	minTTL   time.Duration
	maxTTL   time.Duration
	negTTL   time.Duration
	maxNeg   time.Duration
	genSeq   uint64
	evictSeq uint64
	entries  map[SnapshotKey]*snapshotEntry
}

type snapshotState uint8

const (
	stateInflight snapshotState = iota
	statePositive
	stateNegative
	stateFailed
)

type snapshotEntry struct {
	gen       uint64
	state     snapshotState
	addrs     []netip.Addr
	rcode     RCode
	err       error
	expiresAt time.Time
	created   uint64
}

// NewSnapshotCache validates cfg and returns a ready cache.
func NewSnapshotCache(cfg SnapshotConfig) (*SnapshotCache, error) {
	if cfg.MinTTL < 0 || cfg.MaxTTL < 0 || cfg.NegativeTTL < 0 || cfg.MaxNegativeTTL < 0 {
		return nil, errors.New("dns: negative TTL in SnapshotConfig")
	}
	if cfg.MinTTL > cfg.MaxTTL && cfg.MaxTTL > 0 {
		return nil, errors.New("dns: MinTTL greater than MaxTTL")
	}
	max := cfg.MaxEntries
	if max == 0 {
		max = defaultSnapshotMaxEntries
	}
	maxTTL := cfg.MaxTTL
	if maxTTL == 0 {
		maxTTL = defaultSnapshotMaxTTL
	}
	maxNeg := cfg.MaxNegativeTTL
	if maxNeg == 0 {
		maxNeg = defaultSnapshotMaxNegativeTTL
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &SnapshotCache{
		now:     now,
		max:     max,
		minTTL:  cfg.MinTTL,
		maxTTL:  maxTTL,
		negTTL:  cfg.NegativeTTL,
		maxNeg:  maxNeg,
		entries: make(map[SnapshotKey]*snapshotEntry, max),
	}, nil
}

// Acquire classifies a lookup. On SnapshotNew the caller owns generation gen
// and MUST eventually report its outcome. On SnapshotJoin the caller polls
// Result with gen. SnapshotHit and SnapshotBypass need no further calls.
func (c *SnapshotCache) Acquire(key SnapshotKey) (snap Snapshot, gen uint64, kind SnapshotKind) {
	key = foldKey(key)
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok {
		switch e.state {
		case stateInflight:
			return Snapshot{Kind: SnapshotJoin}, e.gen, SnapshotJoin
		case statePositive:
			if now.Before(e.expiresAt) {
				return Snapshot{Kind: SnapshotHit, Addrs: e.addrs, TTL: e.expiresAt.Sub(now)}, e.gen, SnapshotHit
			}
		case stateNegative:
			if now.Before(e.expiresAt) {
				return negativeSnapshot(e, e.expiresAt.Sub(now)), e.gen, SnapshotHit
			}
		}
		// Expired or previously failed: replace with a fresh generation.
		delete(c.entries, key)
	}
	if len(c.entries) >= c.max && !c.evictOneLocked(now) {
		return Snapshot{Kind: SnapshotBypass}, 0, SnapshotBypass
	}
	gen = c.genSeq + 1
	c.genSeq = gen
	c.evictSeq++
	c.entries[key] = &snapshotEntry{
		gen:     gen,
		state:   stateInflight,
		created: c.evictSeq,
	}
	return Snapshot{Kind: SnapshotNew}, gen, SnapshotNew
}

// Result polls the generation. The second return is false while the leader's
// query is still in flight.
func (c *SnapshotCache) Result(key SnapshotKey, gen uint64) (Snapshot, bool) {
	key = foldKey(key)
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return Snapshot{Err: ErrSnapshotInvalidated}, true
	}
	if e.gen != gen {
		return Snapshot{Err: ErrSnapshotStale}, true
	}
	switch e.state {
	case stateInflight:
		return Snapshot{}, false
	case statePositive:
		return Snapshot{Kind: SnapshotHit, Addrs: e.addrs}, true
	case stateNegative:
		return negativeSnapshot(e, 0), true
	default:
		return Snapshot{Err: e.err}, true
	}
}

// negativeSnapshot builds the Snapshot for a negative entry. RCodeSuccess
// encodes a cached NODATA answer (NOERROR with no addresses), delivered with
// ErrNoAnswer.
func negativeSnapshot(e *snapshotEntry, ttl time.Duration) Snapshot {
	snap := Snapshot{Kind: SnapshotHit, RCode: e.rcode, TTL: ttl}
	if e.rcode != RCodeSuccess {
		snap.Err = error(e.rcode)
	} else {
		snap.Err = ErrNoAnswer
	}
	return snap
}

// StorePositive completes gen with addresses valid for ttl (clamped to the
// configured bounds). A zero TTL stores nothing and releases waiters as
// failed so the next call re-queries.
func (c *SnapshotCache) StorePositive(key SnapshotKey, gen uint64, addrs []netip.Addr, ttl time.Duration) {
	ttl = c.ClampPositiveTTL(ttl)
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[foldKey(key)]
	if !ok || e.gen != gen || e.state != stateInflight {
		return
	}
	if ttl <= 0 || len(addrs) == 0 {
		c.failLocked(e, errSnapshotEmpty)
		return
	}
	cp := append([]netip.Addr(nil), addrs...)
	e.addrs = cp
	e.state = statePositive
	e.expiresAt = c.now().Add(ttl)
}

// StoreNegative completes gen with an explicit response code. ttl is the
// negative-caching lifetime; zero (or a response that must not be cached)
// releases waiters without leaving a cached entry.
func (c *SnapshotCache) StoreNegative(key SnapshotKey, gen uint64, rcode RCode, ttl time.Duration) {
	ttl = clampDuration(ttl, 0, c.maxNeg)
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[foldKey(key)]
	if !ok || e.gen != gen || e.state != stateInflight {
		return
	}
	if ttl <= 0 {
		cause := error(rcode)
		if rcode == RCodeSuccess {
			cause = ErrNoAnswer
		}
		c.failLocked(e, cause)
		return
	}
	e.rcode = rcode
	e.state = stateNegative
	e.expiresAt = c.now().Add(ttl)
}

// Fail abandons gen (validation failure, timeout, node reset): waiters are
// released with cause and no snapshot is cached. The next Acquire starts a new
// generation and a new query.
func (c *SnapshotCache) Fail(key SnapshotKey, gen uint64, cause error) {
	if cause == nil {
		cause = errors.New("dns resolution failed")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[foldKey(key)]
	if !ok || e.gen != gen {
		return
	}
	c.failLocked(e, cause)
}

// failLocked marks an in-flight entry failed. Failed entries are retained
// only until the next Acquire for the key (or eviction), so pollers observe
// the terminal error exactly once per generation.
func (c *SnapshotCache) failLocked(e *snapshotEntry, cause error) {
	if cause == nil {
		cause = errors.New("dns resolution failed")
	}
	e.state = stateFailed
	e.err = cause
	e.addrs = nil
	e.expiresAt = time.Time{}
}

// Invalidate drops every snapshot and generation. Used when the DNS server,
// local address or stack configuration changes.
func (c *SnapshotCache) Invalidate() {
	c.mu.Lock()
	clear(c.entries)
	c.mu.Unlock()
}

// Len is the number of entries, including in-flight generations.
func (c *SnapshotCache) Len() int {
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	return n
}

// ClampPositiveTTL clamps ttl to the configured positive bounds.
func (c *SnapshotCache) ClampPositiveTTL(ttl time.Duration) time.Duration {
	return clampDuration(ttl, c.minTTL, c.maxTTL)
}

// NegativeFallback is the TTL used for negative responses without an SOA.
func (c *SnapshotCache) NegativeFallback() time.Duration { return c.negTTL }

// MaxNegativeTTL is the cap for SOA-derived negative TTLs.
func (c *SnapshotCache) MaxNegativeTTL() time.Duration { return c.maxNeg }

// evictOneLocked removes an expired entry, else the oldest completed one.
// In-flight generations are never evicted. It reports whether room was made.
func (c *SnapshotCache) evictOneLocked(now time.Time) bool {
	var oldestDone, oldestExpired SnapshotKey
	var haveDone, haveExpired bool
	var doneSeq uint64
	for k, e := range c.entries {
		switch e.state {
		case statePositive, stateNegative:
			if !now.Before(e.expiresAt) {
				if !haveExpired {
					oldestExpired, haveExpired = k, true
				}
			}
			fallthrough
		case stateFailed:
			if !haveDone || e.created < doneSeq {
				oldestDone, haveDone, doneSeq = k, true, e.created
			}
		}
	}
	if haveExpired {
		delete(c.entries, oldestExpired)
		return true
	}
	if haveDone {
		delete(c.entries, oldestDone)
		return true
	}
	return false
}

func foldKey(k SnapshotKey) SnapshotKey {
	k.Host = asciiFold(k.Host)
	return k
}

func asciiFold(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for ; i < len(b); i++ {
				if b[i] >= 'A' && b[i] <= 'Z' {
					b[i] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

func clampDuration(v, lo, hi time.Duration) time.Duration {
	if lo > 0 && v < lo {
		return lo
	}
	if hi > 0 && v > hi {
		return hi
	}
	return v
}

// MinAnswerTTL returns the smallest TTL among the A/AAAA and CNAME records of
// the answer section. A CNAME-chain resolution must not outlive any of its
// records, so the conservative minimum (RFC 2181 section 5.2) is used as the
// snapshot lifetime.
func (m *Message) MinAnswerTTL() (time.Duration, bool) {
	var ttl uint32
	found := false
	for i := range m.Answers {
		h := m.Answers[i].Header()
		if h.Type != TypeA && h.Type != TypeAAAA && h.Type != TypeCNAME {
			continue
		}
		if !found || h.TTL < ttl {
			ttl, found = h.TTL, true
		}
	}
	return time.Duration(ttl) * time.Second, found
}

// NegativeTTL derives the negative-caching TTL per RFC 2308 section 5 from
// the first SOA record in authorities: min(SOA record TTL, SOA MINIMUM field).
// With no usable SOA the fallback is used. A non-positive maxTTL means
// negative answers must not be cached at all and returns zero; otherwise the
// result is clamped to [0, maxTTL].
func NegativeTTL(authorities []Resource, fallback, maxTTL time.Duration) time.Duration {
	if maxTTL <= 0 {
		return 0
	}
	ttl := fallback
	for i := range authorities {
		r := &authorities[i]
		if r.Header().Type != TypeSOA {
			continue
		}
		minimum, ok := SOAMinimum(r.RawData())
		if !ok {
			continue
		}
		ttl = time.Duration(minimum) * time.Second
		if soaTTL := time.Duration(r.Header().TTL) * time.Second; soaTTL < ttl {
			ttl = soaTTL
		}
		break
	}
	return clampDuration(ttl, 0, maxTTL)
}

// SOAMinimum parses the MINIMUM (negative-caching TTL) field from a decoded
// SOA RDATA: two wire-format names followed by five 32-bit fields, the last
// of which is MINIMUM.
func SOAMinimum(rdata []byte) (uint32, bool) {
	off, err := visitAllLabels(rdata, 0, func([]byte) {}, false)
	if err != nil {
		return 0, false
	}
	off, err = visitAllLabels(rdata, off, func([]byte) {}, false)
	if err != nil {
		return 0, false
	}
	// serial, refresh, retry, expire, minimum.
	if int(off)+20 > len(rdata) {
		return 0, false
	}
	return binary.BigEndian.Uint32(rdata[int(off)+16:]), true
}
