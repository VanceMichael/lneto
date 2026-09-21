package dns

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func newTestCache(t *testing.T, now func() time.Time, max int) *SnapshotCache {
	t.Helper()
	c, err := NewSnapshotCache(SnapshotConfig{
		MaxEntries:     max,
		MinTTL:         time.Second,
		MaxTTL:         time.Hour,
		NegativeTTL:    30 * time.Second,
		MaxNegativeTTL: time.Minute,
		Now:            now,
	})
	if err != nil {
		t.Fatalf("NewSnapshotCache: %v", err)
	}
	return c
}

func TestSnapshotCache_PositiveCoalesceAndTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	c := newTestCache(t, clock, 4)
	key := SnapshotKey{Host: "Example.COM", Qtype: TypeA, Server: netip.MustParseAddr("8.8.8.8")}

	_, gen, kind := c.Acquire(key)
	if kind != SnapshotNew {
		t.Fatalf("first Acquire = %v, want SnapshotNew", kind)
	}
	// Case-insensitive key: a same-name different-case caller joins.
	snap2, gen2, kind2 := c.Acquire(SnapshotKey{Host: "example.com", Qtype: TypeA, Server: netip.MustParseAddr("8.8.8.8")})
	if kind2 != SnapshotJoin || gen2 != gen {
		t.Fatalf("second Acquire = %v gen %d, want join gen %d (%+v)", kind2, gen2, gen, snap2)
	}
	if _, done := c.Result(key, gen); done {
		t.Fatal("in-flight generation must not report done")
	}

	want := []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8")}
	c.StorePositive(key, gen, want, 10*time.Second)

	got, done := c.Result(key, gen)
	if !done || !slicesEqual(got.Addrs, want) {
		t.Fatalf("leader result = %+v done=%v, want %v", got, done, want)
	}
	got2, done2 := c.Result(SnapshotKey{Host: "EXAMPLE.com", Qtype: TypeA, Server: netip.MustParseAddr("8.8.8.8")}, gen2)
	if !done2 || !slicesEqual(got2.Addrs, want) {
		t.Fatalf("follower result = %+v done=%v, want same generation %v", got2, done2, want)
	}

	// Still within TTL: hit, no new generation, no query needed.
	now = now.Add(9 * time.Second)
	hit, hitGen, kind := c.Acquire(key)
	if kind != SnapshotHit || !slicesEqual(hit.Addrs, want) || hitGen != gen {
		t.Fatalf("Acquire within TTL = %v gen %d addrs %v", kind, hitGen, hit.Addrs)
	}
	if hit.TTL <= 0 || hit.TTL > time.Second {
		t.Fatalf("remaining TTL = %v, want ~1s", hit.TTL)
	}

	// Expired: a new generation.
	now = now.Add(2 * time.Second)
	_, gen3, kind := c.Acquire(key)
	if kind != SnapshotNew || gen3 == gen {
		t.Fatalf("Acquire after expiry = %v gen %d, want new generation", kind, gen3)
	}
}

func TestSnapshotCache_StorePositiveClampsTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	c := newTestCache(t, func() time.Time { return now }, 4)
	key := SnapshotKey{Host: "a.test", Qtype: TypeAAAA, Server: netip.MustParseAddr("8.8.8.8")}
	_, gen, _ := c.Acquire(key)
	c.StorePositive(key, gen, []netip.Addr{netip.MustParseAddr("::1")}, 10*time.Hour) // clamped to MaxTTL.
	now = now.Add(time.Hour + time.Second)
	if _, _, kind := c.Acquire(key); kind != SnapshotNew {
		t.Fatalf("entry outlived MaxTTL: %v", kind)
	}

	_, gen, _ = c.Acquire(key)
	c.StorePositive(key, gen, []netip.Addr{netip.MustParseAddr("::1")}, time.Millisecond) // floored to MinTTL.
	if _, _, kind := c.Acquire(key); kind != SnapshotHit {
		t.Fatalf("short TTL should be floored by MinTTL: %v", kind)
	}
}

func TestSnapshotCache_NegativeNXDOMAIN(t *testing.T) {
	now := time.Unix(1000, 0)
	c := newTestCache(t, func() time.Time { return now }, 4)
	key := SnapshotKey{Host: "nx.test", Qtype: TypeA, Server: netip.MustParseAddr("8.8.8.8")}
	_, gen, _ := c.Acquire(key)
	c.StoreNegative(key, gen, RCodeNameError, 60*time.Second)

	got, done := c.Result(key, gen)
	if !done || got.Err == nil || got.RCode != RCodeNameError {
		t.Fatalf("negative result = %+v done=%v", got, done)
	}
	hit, _, kind := c.Acquire(key)
	if kind != SnapshotHit || hit.Err == nil || hit.RCode != RCodeNameError {
		t.Fatalf("negative hit = %+v kind=%v", hit, kind)
	}
	now = now.Add(61 * time.Second)
	if _, _, kind := c.Acquire(key); kind != SnapshotNew {
		t.Fatalf("negative snapshot must expire, got %v", kind)
	}
}

func TestSnapshotCache_NODATANilError(t *testing.T) {
	c := newTestCache(t, time.Now, 4)
	key := SnapshotKey{Host: "nodata.test", Qtype: TypeA, Server: netip.MustParseAddr("8.8.8.8")}
	_, gen, _ := c.Acquire(key)
	c.StoreNegative(key, gen, RCodeSuccess, time.Minute)
	got, done := c.Result(key, gen)
	if !done || got.Err != ErrNoAnswer || got.RCode != RCodeSuccess {
		t.Fatalf("NODATA snapshot = %+v done=%v, want ErrNoAnswer", got, done)
	}
}

func TestSnapshotCache_ZeroNegativeTTLReleasesWithoutCaching(t *testing.T) {
	c := newTestCache(t, time.Now, 4)
	key := SnapshotKey{Host: "fail.test", Qtype: TypeA, Server: netip.MustParseAddr("8.8.8.8")}
	_, gen, _ := c.Acquire(key)
	c.StoreNegative(key, gen, RCodeServerFailure, 0)
	got, done := c.Result(key, gen)
	if !done || got.Err == nil {
		t.Fatalf("waiter must be released with the rcode: %+v done=%v", got, done)
	}
	// No negative snapshot left: next call starts a new query.
	if _, _, kind := c.Acquire(key); kind != SnapshotNew {
		t.Fatalf("zero-TTL failure must not cache, got %v", kind)
	}
}

func TestSnapshotCache_FailReleasesWaiters(t *testing.T) {
	c := newTestCache(t, time.Now, 4)
	key := SnapshotKey{Host: "reset.test", Qtype: TypeA, Server: netip.MustParseAddr("8.8.8.8")}
	_, gen, _ := c.Acquire(key)
	cause := errors.New("udp node reset")
	c.Fail(key, gen, cause)
	got, done := c.Result(key, gen)
	if !done || got.Err != cause {
		t.Fatalf("Fail result = %+v done=%v, want %v", got, done, cause)
	}
	// A failed generation is replaced, not served as a hit.
	_, gen2, kind := c.Acquire(key)
	if kind != SnapshotNew || gen2 == gen {
		t.Fatalf("Acquire after Fail = %v gen %d", kind, gen2)
	}
}

func TestSnapshotCache_Invalidate(t *testing.T) {
	c := newTestCache(t, time.Now, 4)
	key := SnapshotKey{Host: "a.test", Qtype: TypeA, Server: netip.MustParseAddr("8.8.8.8")}
	_, gen, _ := c.Acquire(key)
	c.Invalidate()
	if c.Len() != 0 {
		t.Fatalf("Len after Invalidate = %d", c.Len())
	}
	got, done := c.Result(key, gen)
	if !done || !errors.Is(got.Err, ErrSnapshotInvalidated) {
		t.Fatalf("Result after invalidate = %+v done=%v", got, done)
	}
	if _, _, kind := c.Acquire(key); kind != SnapshotNew {
		t.Fatalf("Acquire after invalidate = %v", kind)
	}
}

func TestSnapshotCache_BoundedEviction(t *testing.T) {
	c := newTestCache(t, time.Now, 2)
	k1 := SnapshotKey{Host: "1.test", Qtype: TypeA, Server: netip.MustParseAddr("8.8.8.8")}
	k2 := SnapshotKey{Host: "2.test", Qtype: TypeA, Server: netip.MustParseAddr("8.8.8.8")}
	k3 := SnapshotKey{Host: "3.test", Qtype: TypeA, Server: netip.MustParseAddr("8.8.8.8")}
	_, g1, k := c.Acquire(k1)
	if k != SnapshotNew {
		t.Fatal(k)
	}
	_, g2, k := c.Acquire(k2)
	if k != SnapshotNew {
		t.Fatal(k)
	}
	// Both entries are in-flight (non-evictable): third distinct key bypasses.
	_, _, k = c.Acquire(k3)
	if k != SnapshotBypass {
		t.Fatalf("full in-flight cache = %v, want bypass", k)
	}
	// Completing one makes it evictable for the third key.
	c.StorePositive(k1, g1, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, time.Minute)
	_, g3, k := c.Acquire(k3)
	if k != SnapshotNew || g3 == g1 || g3 == g2 {
		t.Fatalf("Acquire after completion = %v gen %d", k, g3)
	}
	if c.Len() != 2 {
		t.Fatalf("Len = %d, want bound 2", c.Len())
	}
}

func TestSnapshotCache_StaleCompletionIgnored(t *testing.T) {
	c := newTestCache(t, time.Now, 4)
	key := SnapshotKey{Host: "stale.test", Qtype: TypeA, Server: netip.MustParseAddr("8.8.8.8")}
	_, g1, _ := c.Acquire(key)
	c.Fail(key, g1, errors.New("first fails"))
	_, g2, _ := c.Acquire(key)
	// Late completion for the old generation must not corrupt the new one.
	c.StorePositive(key, g1, []netip.Addr{netip.MustParseAddr("9.9.9.9")}, time.Minute)
	got, done := c.Result(key, g2)
	if done {
		t.Fatalf("new generation unexpectedly done: %+v", got)
	}
}

func TestMinAnswerTTL(t *testing.T) {
	name := MustNewName("a.test.")
	m := Message{
		Answers: []Resource{
			NewResource(name, TypeCNAME, ClassINET, 30, MustNewName("b.test.").data),
			NewResource(MustNewName("b.test."), TypeA, ClassINET, 5, netip.MustParseAddr("1.2.3.4").AsSlice()),
			NewResource(name, TypeTXT, ClassINET, 1, []byte("ignore-me")),
		},
	}
	ttl, ok := m.MinAnswerTTL()
	if !ok || ttl != 5*time.Second {
		t.Fatalf("MinAnswerTTL = %v ok=%v, want 5s", ttl, ok)
	}
}

func TestNegativeTTLFromSOA(t *testing.T) {
	// SOA RDATA: MNAME, RNAME (wire names), serial, refresh, retry, expire, minimum.
	mname := MustNewName("ns.example.org.")
	rname := MustNewName("root.example.org.")
	var rdata []byte
	rdata, _ = mname.AppendTo(rdata)
	rdata, _ = rname.AppendTo(rdata)
	// serial=1 refresh=2 retry=3 expire=4 minimum=90.
	for _, v := range []uint32{1, 2, 3, 4, 90} {
		rdata = appendUint32(rdata, v)
	}
	soa := NewResource(MustNewName("example.org."), TypeSOA, ClassINET, 300, rdata) // SOA TTL 300 > minimum 90.

	got := NegativeTTL([]Resource{soa}, 30*time.Second, 10*time.Minute)
	if got != 90*time.Second {
		t.Fatalf("NegativeTTL = %v, want min(300s,90s)=90s", got)
	}
	// No SOA: fallback, clamped.
	got = NegativeTTL(nil, 30*time.Second, time.Minute)
	if got != 30*time.Second {
		t.Fatalf("fallback NegativeTTL = %v, want 30s", got)
	}
	got = NegativeTTL(nil, time.Hour, time.Minute)
	if got != time.Minute {
		t.Fatalf("NegativeTTL clamp = %v, want 1m", got)
	}
	// maxTTL zero disables caching.
	got = NegativeTTL([]Resource{soa}, 30*time.Second, 0)
	if got != 0 {
		t.Fatalf("NegativeTTL with zero max = %v, want 0", got)
	}
}

func TestSOADecodedFromCompressedMessage(t *testing.T) {
	// Full message decode path: NXDOMAIN response with a compressed SOA in
	// the authority section, as resolvers receive on the wire.
	qname := MustNewName("nx.example.org.")
	zone := MustNewName("example.org.")
	msg := Message{
		Questions: []Question{{Name: qname, Type: TypeA, Class: ClassINET}},
		Authorities: []Resource{
			// TTL 600, MINIMUM 120 => negative TTL 120.
			NewResource(zone, TypeSOA, ClassINET, 600, buildSOARData("ns.example.org.", "root.example.org.", 120)),
		},
	}
	flags := HeaderFlags(1<<15 | 1<<8 | 1<<7 | uint16(RCodeNameError))
	var buf [512]byte
	wire, err := msg.AppendTo(buf[:0], 42, flags)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Client
	if err := decoded.StartResolve(40000, 42, ResolveConfig{
		Questions:           []Question{{Name: qname, Type: TypeA, Class: ClassINET}},
		MaxAuthorityRecords: 1,
	}); err != nil {
		t.Fatal(err)
	}
	// Encapsulate moves the client to CQueryOutstanding, the state in which
	// Demux accepts the response.
	var qbuf [512]byte
	if _, err := decoded.Encapsulate(qbuf[:], 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Demux(wire, 0); err != nil {
		t.Fatal(err)
	}
	got := decoded.ResponseNegativeTTL(30*time.Second, 10*time.Minute)
	if got != 120*time.Second {
		t.Fatalf("ResponseNegativeTTL = %v, want 120s (SOA MINIMUM)", got)
	}
}

func TestSOARDataCompressedNamesExpanded(t *testing.T) {
	// Wire layout:
	//  0..11  header (QR, rcode NXDOMAIN, QD=1, NS=1)
	//  12..27 question: nx.example.org.  A IN
	//  28..   authority: SOA owner -> ptr to question name, RDATA with:
	//           MNAME = compression pointer to "example.org." at offset 15
	//           RNAME = root.example.org. (uncompressed)
	//           five uint32 fields, MINIMUM last = 120
	var wire []byte
	hdr := make([]byte, SizeHeader)
	binary.BigEndian.PutUint16(hdr[0:2], 7)
	binary.BigEndian.PutUint16(hdr[2:4], 1<<15|uint16(RCodeNameError))
	binary.BigEndian.PutUint16(hdr[4:6], 1)  // QD
	binary.BigEndian.PutUint16(hdr[8:10], 1) // NS
	wire = append(wire, hdr...)
	qname := MustNewName("nx.example.org.")
	wire, _ = qname.AppendTo(wire)
	wire = binary.BigEndian.AppendUint16(wire, uint16(TypeA))
	wire = binary.BigEndian.AppendUint16(wire, uint16(ClassINET))

	// Authority record.
	wire = append(wire, 0xC0, 0x0C) // owner: nx.example.org.
	wire = binary.BigEndian.AppendUint16(wire, uint16(TypeSOA))
	wire = binary.BigEndian.AppendUint16(wire, uint16(ClassINET))
	wire = binary.BigEndian.AppendUint32(wire, 600)
	var rdata []byte
	rdata = append(rdata, 0xC0, 15) // MNAME compressed -> example.org.
	rname := MustNewName("root.example.org.")
	rdata, _ = rname.AppendTo(rdata)
	for _, v := range []uint32{1, 7200, 3600, 1209600, 120} {
		rdata = binary.BigEndian.AppendUint32(rdata, v)
	}
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(rdata)))
	wire = append(wire, rdata...)

	var m Message
	m.LimitResourceDecoding(1, 0, 1, 0)
	_, incomplete, err := m.Decode(wire)
	if err != nil && !incomplete {
		t.Fatalf("decode: %v", err)
	}
	if len(m.Authorities) != 1 {
		t.Fatalf("authorities = %d", len(m.Authorities))
	}
	soa := &m.Authorities[0]
	if soa.Header().Type != TypeSOA {
		t.Fatalf("authority type = %v", soa.Header().Type)
	}
	minimum, ok := SOAMinimum(soa.RawData())
	if !ok {
		t.Fatal("SOAMinimum failed to parse the expanded RDATA")
	}
	if minimum != 120 {
		t.Fatalf("SOA MINIMUM = %d, want 120", minimum)
	}
	if got := NegativeTTL(m.Authorities, 30*time.Second, time.Hour); got != 120*time.Second {
		t.Fatalf("compressed-SOA negative TTL = %v, want 120s", got)
	}
}

func buildSOARData(mname, rname string, minimum uint32) []byte {
	m := MustNewName(mname)
	r := MustNewName(rname)
	var b []byte
	b, _ = m.AppendTo(b)
	b, _ = r.AppendTo(b)
	for _, v := range []uint32{1, 7200, 3600, 1209600, minimum} {
		b = appendUint32(b, v)
	}
	return b
}

func appendUint32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func slicesEqual(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
