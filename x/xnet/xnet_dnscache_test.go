package xnet

import (
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/udp"
)

const (
	dnsCacheSeed     = 4242
	dnsCacheClientIP = "10.0.0.100"
	dnsCacheServerIP = "8.8.8.8"
	dnsCacheWait     = 2 * time.Second
)

func newDNSCacheStack(t *testing.T, cfg *dns.SnapshotConfig) (client *StackAsync, server, clientAddr netip.Addr, serverMAC, clientMAC [6]byte) {
	t.Helper()
	client = new(StackAsync)
	server = netip.MustParseAddr(dnsCacheServerIP)
	clientAddr = netip.MustParseAddr(dnsCacheClientIP)
	clientMAC = [6]byte{0xde, 0xad, 0xbe, 0xef, 0, 1}
	serverMAC = [6]byte{0, 0x11, 0x22, 0x33, 0x44, 0x55}
	err := client.Reset(StackConfig{
		Hostname:        "DNSClient",
		RandSeed:        dnsCacheSeed,
		StaticAddress4:  clientAddr.As4(),
		DNSServer:       server,
		HardwareAddress: clientMAC,
		MTU:             ethernet.MaxMTU,
		DNSCache:        cfg,
	})
	if err != nil {
		t.Fatal("client Reset failed:", err)
	}
	client.SetGatewayHardwareAddr(serverMAC)
	return client, server, clientAddr, serverMAC, clientMAC
}

// drainDNSEgress repeatedly egresses until a frame is produced or the deadline
// passes. It returns a copy of the frame.
func drainDNSEgress(t *testing.T, client *StackAsync, within time.Duration) []byte {
	t.Helper()
	var buf [ethernet.MaxFrameLength]byte
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		n, err := client.EgressEthernet(buf[:])
		if err != nil {
			t.Fatal("egress:", err)
		}
		if n > 0 {
			return append([]byte(nil), buf[:n]...)
		}
		runtime.Gosched()
	}
	t.Fatal("no DNS query egressed within", within)
	return nil
}

func assertNoEgress(t *testing.T, client *StackAsync) {
	t.Helper()
	var buf [ethernet.MaxFrameLength]byte
	// Give any armed (but unexpected) query a chance to egress.
	for range 20 {
		n, err := client.EgressEthernet(buf[:])
		if err != nil {
			t.Fatal("egress:", err)
		}
		if n > 0 {
			t.Fatalf("unexpected UDP packet of %d bytes on a cache hit", n)
		}
		runtime.Gosched()
	}
}

func respondDNS(t *testing.T, client *StackAsync, query []byte, msg dns.Message, server, clientAddr netip.Addr, serverMAC, clientMAC [6]byte) {
	t.Helper()
	txid, port, err := extractDNSTxIDAndPort(query)
	if err != nil {
		t.Fatal(err)
	}
	var buf [ethernet.MaxFrameLength]byte
	pkt, err := buildDNSMsgResponsePacket(t, txid, port, msg, server, serverMAC, clientAddr, clientMAC, buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := client.IngressEthernet(pkt); err != nil {
		t.Fatal("ingress:", err)
	}
}

func respondDNSRCode(t *testing.T, client *StackAsync, query []byte, msg dns.Message, rcode dns.RCode, server, clientAddr netip.Addr, serverMAC, clientMAC [6]byte) {
	t.Helper()
	txid, port, err := extractDNSTxIDAndPort(query)
	if err != nil {
		t.Fatal(err)
	}
	var buf [ethernet.MaxFrameLength]byte
	pkt, err := buildDNSMsgResponsePacket(t, txid, port, msg, server, serverMAC, clientAddr, clientMAC, buf[:])
	if err != nil {
		t.Fatal(err)
	}
	// DNS header begins after Ethernet(14)+IPv4(20)+UDP(8); RCode is the low
	// nibble of the flags' second byte (offset 3 of the DNS header).
	const dnsOff = 14 + 20 + 8
	pkt[dnsOff+3] = (pkt[dnsOff+3] & 0xf0) | byte(rcode)
	recomputeUDPChecksum(t, pkt)
	if err := client.IngressEthernet(pkt); err != nil {
		t.Fatal("ingress:", err)
	}
}

// recomputeUDPChecksum rewrites the UDP checksum after a test mutates DNS
// payload bytes, since ingress validates it.
func recomputeUDPChecksum(t *testing.T, pkt []byte) {
	t.Helper()
	const ethHdrLen, ipHdrLen = 14, 20
	ipStart := ethHdrLen
	udpStart := ipStart + ipHdrLen
	ifrm, err := ipv4.NewFrame(pkt[ipStart:])
	if err != nil {
		t.Fatal(err)
	}
	ufrm, err := udp.NewFrame(pkt[udpStart:])
	if err != nil {
		t.Fatal(err)
	}
	var crc lneto.CRC791
	ifrm.CRCWriteUDPPseudo(&crc, uint16(ufrm.Length()))
	ufrm.SetCRC(0)
	ufrm.SetCRC(crc.PayloadSum16(ufrm.RawData()))
}

func answerMessage(t *testing.T, host string, addrs ...netip.Addr) dns.Message {
	t.Helper()
	name, err := dns.NewName(host)
	if err != nil {
		t.Fatal(err)
	}
	msg := dns.Message{
		Questions: []dns.Question{{Name: name, Type: dns.TypeA, Class: dns.ClassINET}},
	}
	for _, a := range addrs {
		msg.Answers = append(msg.Answers, dns.NewResource(name, dns.TypeA, dns.ClassINET, 300, a.AsSlice()))
	}
	return msg
}

func soaMessage(t *testing.T, host string, minimum uint32) dns.Message {
	t.Helper()
	qname, err := dns.NewName(host)
	if err != nil {
		t.Fatal(err)
	}
	zone, err := dns.NewName("example.org")
	if err != nil {
		t.Fatal(err)
	}
	var rdata []byte
	rdata, _ = zone.AppendTo(rdata)
	rdata, _ = zone.AppendTo(rdata) // RNAME = zone for simplicity.
	for _, v := range []uint32{1, 7200, 3600, 1209600, minimum} {
		rdata = append(rdata, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	return dns.Message{
		Questions:   []dns.Question{{Name: qname, Type: dns.TypeA, Class: dns.ClassINET}},
		Authorities: []dns.Resource{dns.NewResource(zone, dns.TypeSOA, dns.ClassINET, 300, rdata)},
	}
}

// TestDNSCache_HitSendsNoUDP drives the stack state machine directly: the
// second resolution within TTL returns from the snapshot without UDP.
func TestDNSCache_HitSendsNoUDP(t *testing.T) {
	var now = time.Unix(1_700_000_000, 0)
	cfg := &dns.SnapshotConfig{NegativeTTL: 30 * time.Second, Now: func() time.Time { return now }}
	client, server, clientAddr, serverMAC, clientMAC := newDNSCacheStack(t, cfg)
	const host = "example.com"
	want := netip.MustParseAddr("93.184.216.34")

	st, gen, _, err := client.dnsLookupBegin(host, dns.TypeA)
	if err != nil || st != dnsLookupLeader {
		t.Fatalf("begin = %v gen %d err %v, want leader", st, gen, err)
	}
	query := drainDNSEgress(t, client, dnsCacheWait)
	respondDNS(t, client, query, answerMessage(t, host, want), server, clientAddr, serverMAC, clientMAC)
	addrs, st, gen, done, err := client.dnsLookupPoll(host, dns.TypeA, st, gen)
	if !done || err != nil || !containsAddr(addrs, want) {
		t.Fatalf("leader poll = addrs %v done=%v err=%v", addrs, done, err)
	}

	// Second call within TTL: immediate hit, zero UDP.
	st2, _, addrs2, err := client.dnsLookupBegin(host, dns.TypeA)
	if st2 != dnsLookupHit || err != nil || !containsAddr(addrs2, want) {
		t.Fatalf("cached begin = %v err %v addrs %v", st2, err, addrs2)
	}
	assertNoEgress(t, client)

	// AAAA is a different key: miss goes to the wire.
	st3, gen3, _, err := client.dnsLookupBegin(host, dns.TypeAAAA)
	if err != nil || st3 != dnsLookupLeader {
		t.Fatalf("AAAA begin = %v err %v, want new query", st3, err)
	}
	drainDNSEgress(t, client, dnsCacheWait)
	// Release the AAAA generation (no answer in this test) before continuing.
	client.dnsLookupTimedOut(host, dns.TypeAAAA, st3, gen3)

	// Advance past the 300s positive TTL: A is queried again.
	now = now.Add(301 * time.Second)
	st4, _, _, err := client.dnsLookupBegin(host, dns.TypeA)
	if err != nil || st4 != dnsLookupLeader {
		t.Fatalf("expired begin = %v err %v, want new query", st4, err)
	}
}

// TestDNSCache_BlockingCoalesce verifies the real StackBlocking chain:
// concurrent callers for the same host share one UDP query and one result,
// and a follow-up call hits the snapshot without UDP.
func TestDNSCache_BlockingCoalesce(t *testing.T) {
	cfg := &dns.SnapshotConfig{NegativeTTL: 30 * time.Second}
	client, server, clientAddr, serverMAC, clientMAC := newDNSCacheStack(t, cfg)
	blk := client.StackBlocking(backoffYield)
	const host = "example.com"
	want := netip.MustParseAddr("93.184.216.34")

	const callers = 3
	var wg sync.WaitGroup
	type result struct {
		addrs []netip.Addr
		err   error
	}
	results := make([]result, callers)
	start := make(chan struct{})
	for i := range callers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			a, e := blk.DoLookupIP(host, 3*time.Second)
			results[i] = result{addrs: a, err: e}
		}(i)
	}
	close(start)

	// Exactly one DNS query must hit the wire.
	query := drainDNSEgress(t, client, dnsCacheWait)
	assertNoEgress(t, client)
	respondDNS(t, client, query, answerMessage(t, host, want), server, clientAddr, serverMAC, clientMAC)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("coalesced waiters did not all return")
	}
	for i, r := range results {
		if r.err != nil || !containsAddr(r.addrs, want) {
			t.Fatalf("caller %d result = %v err %v, want %v", i, r.addrs, r.err, want)
		}
	}

	// Snapshot hit through the blocking chain returns immediately.
	a2, err := blk.DoLookupIP(host, time.Second)
	if err != nil || !containsAddr(a2, want) {
		t.Fatalf("blocking hit = %v err %v", a2, err)
	}
	assertNoEgress(t, client)

	// The retrying chain shares the same snapshot too.
	a3, err := client.StackRetrying(backoffYield).DoLookupIP(host, time.Second, 2)
	if err != nil || !containsAddr(a3, want) {
		t.Fatalf("retrying hit = %v err %v", a3, err)
	}
	assertNoEgress(t, client)
}

// TestDNSCache_TimeoutReleasesAndRequeries: a leader deadline aborts the
// hardware query and releases followers; the next call starts a new query.
func TestDNSCache_TimeoutReleasesAndRequeries(t *testing.T) {
	cfg := &dns.SnapshotConfig{NegativeTTL: 30 * time.Second}
	client, _, _, _, _ := newDNSCacheStack(t, cfg)
	sleepBackoff := func(uint) time.Duration {
		time.Sleep(2 * time.Millisecond)
		return lneto.BackoffFlagNop
	}
	blk := client.StackBlocking(sleepBackoff)
	const host = "slow.example.com"

	const callers = 2
	var wg sync.WaitGroup
	errs := make([]error, callers)
	start := make(chan struct{})
	for i := range callers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = blk.DoLookupIP(host, 100*time.Millisecond)
		}(i)
	}
	close(start)
	// The single shared query goes out and never gets a response.
	drainDNSEgress(t, client, dnsCacheWait)
	waited := make(chan struct{})
	go func() { wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(3 * time.Second):
		t.Fatal("timed-out callers did not return")
	}
	for i, e := range errs {
		if e == nil {
			t.Fatalf("caller %d unexpectedly resolved without a response", i)
		}
	}

	// Timeout must have released the generation: a new call arms a new query.
	st, gen, _, err := client.dnsLookupBegin(host, dns.TypeA)
	if err != nil || st != dnsLookupLeader {
		t.Fatalf("begin after timeout = %v err %v, want a fresh leader", st, err)
	}
	drainDNSEgress(t, client, dnsCacheWait)
	_ = gen
}

// TestDNSCache_NegativeAnswers caches NXDOMAIN and NODATA for the SOA-derived
// negative TTL and re-queries once it elapses.
func TestDNSCache_NegativeAnswers(t *testing.T) {
	var now = time.Unix(1_700_000_000, 0)
	cfg := &dns.SnapshotConfig{
		NegativeTTL:    30 * time.Second,
		MaxNegativeTTL: time.Hour,
		Now:            func() time.Time { return now },
	}
	client, server, clientAddr, serverMAC, clientMAC := newDNSCacheStack(t, cfg)

	// NXDOMAIN with SOA MINIMUM 60.
	const nx = "nx.example.org"
	st, gen, _, err := client.dnsLookupBegin(nx, dns.TypeA)
	if err != nil || st != dnsLookupLeader {
		t.Fatalf("nx begin = %v err %v", st, err)
	}
	query := drainDNSEgress(t, client, dnsCacheWait)
	respondDNSRCode(t, client, query, soaMessage(t, nx, 60), dns.RCodeNameError, server, clientAddr, serverMAC, clientMAC)
	_, st, gen, done, err := client.dnsLookupPoll(nx, dns.TypeA, st, gen)
	if !done || err != dns.RCodeNameError {
		t.Fatalf("nx poll = done=%v err=%v, want RCodeNameError", done, err)
	}
	st2, _, _, err := client.dnsLookupBegin(nx, dns.TypeA)
	if st2 != dnsLookupHit || err != dns.RCodeNameError {
		t.Fatalf("nx cached = %v err %v, want cached NXDOMAIN", st2, err)
	}
	assertNoEgress(t, client)
	now = now.Add(61 * time.Second)
	st3, gen3, _, err := client.dnsLookupBegin(nx, dns.TypeA)
	if err != nil || st3 != dnsLookupLeader {
		t.Fatalf("nx after negative TTL = %v err %v, want new query", st3, err)
	}
	query = drainDNSEgress(t, client, dnsCacheWait)
	// Finish the re-queried nx generation so the single hardware client frees
	// before the NODATA lookup.
	respondDNSRCode(t, client, query, soaMessage(t, nx, 60), dns.RCodeNameError, server, clientAddr, serverMAC, clientMAC)
	_, _, _, done, err = client.dnsLookupPoll(nx, dns.TypeA, st3, gen3)
	if !done || err != dns.RCodeNameError {
		t.Fatalf("nx re-query completion = done=%v err=%v", done, err)
	}

	// NODATA: NOERROR with no answers and a SOA MINIMUM of 30.
	const nodata = "nodata.example.org"
	st, gen, _, err = client.dnsLookupBegin(nodata, dns.TypeA)
	if err != nil || st != dnsLookupLeader {
		t.Fatalf("nodata begin = %v err %v", st, err)
	}
	query = drainDNSEgress(t, client, dnsCacheWait)
	respondDNS(t, client, query, soaMessage(t, nodata, 30), server, clientAddr, serverMAC, clientMAC)
	_, st, gen, done, err = client.dnsLookupPoll(nodata, dns.TypeA, st, gen)
	if !done || err != errDNSNoAns {
		t.Fatalf("nodata poll = done=%v err=%v, want errDNSNoAns", done, err)
	}
	st2, _, _, err = client.dnsLookupBegin(nodata, dns.TypeA)
	if st2 != dnsLookupHit || err != errDNSNoAns {
		t.Fatalf("nodata cached = %v err %v, want cached NODATA", st2, err)
	}
	assertNoEgress(t, client)
}

// TestDNSCache_ServerAndAddrChangeInvalidate verifies a changed DNS server or
// local IPv4 address drops snapshots and forces a new query.
func TestDNSCache_ServerAndAddrChangeInvalidate(t *testing.T) {
	cfg := &dns.SnapshotConfig{NegativeTTL: 30 * time.Second}
	client, server, clientAddr, serverMAC, clientMAC := newDNSCacheStack(t, cfg)
	const host = "example.com"
	want := netip.MustParseAddr("93.184.216.34")

	st, gen, _, err := client.dnsLookupBegin(host, dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	query := drainDNSEgress(t, client, dnsCacheWait)
	respondDNS(t, client, query, answerMessage(t, host, want), server, clientAddr, serverMAC, clientMAC)
	if _, _, _, done, err := client.dnsLookupPoll(host, dns.TypeA, st, gen); !done || err != nil {
		t.Fatalf("leader completion: done=%v err=%v", done, err)
	}
	if st, _, _, err := client.dnsLookupBegin(host, dns.TypeA); err != nil || st != dnsLookupHit {
		t.Fatalf("expected snapshot hit, got %v err %v", st, err)
	}

	// DHCP-assigned DNS server changes: old snapshot must not survive.
	newDNS := netip.MustParseAddr("1.1.1.1")
	err = client.AssimilateDHCPResults(&DHCPResults{
		AssignedAddr4: clientAddr.As4(),
		Subnet:        netip.MustParsePrefix("10.0.0.0/24"),
		DNSServers:    []netip.Addr{newDNS},
	})
	if err != nil {
		t.Fatal(err)
	}
	st, _, _, err = client.dnsLookupBegin(host, dns.TypeA)
	if err != nil || st != dnsLookupLeader {
		t.Fatalf("after DNS server change begin = %v err %v, want new query", st, err)
	}
	query = drainDNSEgress(t, client, dnsCacheWait)
	respondDNS(t, client, query, answerMessage(t, host, want), newDNS, clientAddr, serverMAC, clientMAC)

	// Local address change also invalidates.
	if err := client.SetAddr4(netip.MustParseAddr("10.0.0.101").As4()); err != nil {
		t.Fatal(err)
	}
	st, _, _, err = client.dnsLookupBegin(host, dns.TypeA)
	if err != nil || st != dnsLookupLeader {
		t.Fatalf("after address change begin = %v err %v, want new query", st, err)
	}
	drainDNSEgress(t, client, dnsCacheWait)
}

// TestDNSCache_ValidationFailureReleasesAndDirectAPI feeds a response whose
// question section fails decoding: the leader terminates with the error and
// the next call re-queries. It also verifies the direct StartLookupIP API
// stays uncached.
func TestDNSCache_ValidationFailureReleasesAndDirectAPI(t *testing.T) {
	cfg := &dns.SnapshotConfig{NegativeTTL: 30 * time.Second}
	client, server, clientAddr, serverMAC, clientMAC := newDNSCacheStack(t, cfg)
	const host = "example.com"
	want := netip.MustParseAddr("93.184.216.34")

	st, gen, _, err := client.dnsLookupBegin(host, dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	query := drainDNSEgress(t, client, dnsCacheWait)

	// Corrupt the first question label length byte (DNS header offset 12):
	// claim a 60-byte label inside a short message so decoding fails.
	txid, port, err := extractDNSTxIDAndPort(query)
	if err != nil {
		t.Fatal(err)
	}
	var buf [ethernet.MaxFrameLength]byte
	pkt, err := buildDNSMsgResponsePacket(t, txid, port, answerMessage(t, host, want), server, serverMAC, clientAddr, clientMAC, buf[:])
	if err != nil {
		t.Fatal(err)
	}
	const dnsOff = 14 + 20 + 8
	pkt[dnsOff+12] = 60 // first question label impossibly long.
	recomputeUDPChecksum(t, pkt)
	if err := client.IngressEthernet(pkt); err == nil {
		t.Fatal("expected demux validation error, got nil")
	}
	_, st, gen, done, err := client.dnsLookupPoll(host, dns.TypeA, st, gen)
	if !done || err == nil {
		t.Fatalf("poll after bad response = done=%v err=%v, want terminal error", done, err)
	}

	// Next call re-queries: fresh generation and a UDP packet.
	st2, gen2, _, err := client.dnsLookupBegin(host, dns.TypeA)
	if err != nil || st2 != dnsLookupLeader {
		t.Fatalf("begin after validation failure = %v err %v, want new leader", st2, err)
	}
	query = drainDNSEgress(t, client, dnsCacheWait)
	respondDNS(t, client, query, answerMessage(t, host, want), server, clientAddr, serverMAC, clientMAC)
	addrs, st2, _, done, err := client.dnsLookupPoll(host, dns.TypeA, st2, gen2)
	if !done || err != nil || !containsAddr(addrs, want) {
		t.Fatalf("re-query completion = addrs %v done=%v err=%v st=%v", addrs, done, err, st2)
	}

	// Direct StartLookupIPType keeps working and bypasses the snapshot: even
	// right after a cached answer it occupies a UDP port.
	if err := client.StartLookupIP(host); err != nil {
		t.Fatal(err)
	}
	drainDNSEgress(t, client, dnsCacheWait)
}

func containsAddr(addrs []netip.Addr, want netip.Addr) bool {
	for _, a := range addrs {
		if a == want {
			return true
		}
	}
	return false
}
