package tcp

import (
	"bytes"
	"math/rand"
	"testing"
)

// newPMTUHandlers builds an established client/server pair whose egress TCP
// frame capacity emulates a 1500-byte IPv4 link MTU (TCP slice = 1500-20), so
// both peers advertise MSS 1460 and the Handler learns link budget 1500.
func newPMTUHandlers(t *testing.T) (client, server *Handler, frame []byte) {
	t.Helper()
	const (
		bufSize = 8192
		packets = 16
	)
	rng := rand.New(rand.NewSource(7))
	client, server = newHandler(t, bufSize, packets), newHandler(t, bufSize, packets)
	setupClientServer(t, rng, client, server)
	frame = make([]byte, 1480) // TCP frame capacity for IP MTU 1500.
	establish(t, client, server, frame)
	return client, server, frame
}

// drainData pumps Send until no more data is emitted, returning the ordered
// concatenation of emitted payloads and the list of payload sizes.
func drainData(t *testing.T, h *Handler, frame []byte) (stream []byte, sizes []int) {
	t.Helper()
	clear(frame)
	for {
		n, err := h.Send(frame)
		if err != nil {
			t.Fatalf("Send: %v", err)
		}
		if n == 0 {
			return stream, sizes
		}
		tfrm, err := NewFrame(frame[:n])
		if err != nil {
			t.Fatal(err)
		}
		off, _ := tfrm.OffsetAndFlags()
		payload := frame[int(off)*4 : n]
		stream = append(stream, payload...)
		sizes = append(sizes, len(payload))
		clear(frame)
	}
}

// TestHandler_PMTU4_ResegmentsUnacked is the core loop: after a smaller MTU is
// learned, every unacked byte (plus previously unsent bytes) must come out
// again, split at the new budget, without loss or duplication and without FIN.
func TestHandler_PMTU4_ResegmentsUnacked(t *testing.T) {
	client, server, frame := newPMTUHandlers(t)
	const dataLen = 4000
	stream := make([]byte, dataLen)
	for i := range stream {
		stream[i] = byte(i*7 + 1)
	}
	if n, err := client.Write(stream); err != nil || n != dataLen {
		t.Fatalf("Write n=%d err=%v", n, err)
	}

	// Initial transmission: 1460-byte segments (peer MSS), all unacked.
	firstUNA := client.scb.SendUNA()
	out, sizes1 := drainData(t, client, frame)
	if !bytes.Equal(out, stream) {
		t.Fatal("initial transmission does not match written stream")
	}
	if len(sizes1) != 3 || sizes1[0] != 1460 || sizes1[1] != 1460 || sizes1[2] != dataLen-2*1460 {
		t.Fatalf("initial sizes=%v, want 1460/1460/%d", sizes1, dataLen-2*1460)
	}
	if got := client.bufTx.BufferedSent(); got != dataLen {
		t.Fatalf("BufferedSent=%d, want %d", got, dataLen)
	}
	if client.scb.SendUNA() != firstUNA {
		t.Fatal("UNA must not move without ACKs")
	}

	// Fragmentation Needed: path MTU 576 -> data budget 536.
	const t0 = int64(1_000_000_000)
	if !client.HandlePMTU4(576, t0) {
		t.Fatal("HandlePMTU4 rejected on established connection")
	}
	if got := client.PMTU4(); got != 576 {
		t.Fatalf("PMTU4=%d, want 576", got)
	}
	if got := client.bufTx.BufferedSent(); got != 0 {
		t.Fatalf("BufferedSent after shrink=%d, want full rewind", got)
	}
	if got := client.BufferedUnsent(); got != dataLen {
		t.Fatalf("BufferedUnsent after shrink=%d, want %d", got, dataLen)
	}
	if client.scb.SendNext() != firstUNA {
		t.Fatalf("snd.NXT=%d, want rewind to UNA=%d", client.scb.SendNext(), firstUNA)
	}

	// Re-emission: every segment fits the 536 budget and covers all bytes once.
	out2, sizes2 := drainData(t, client, frame)
	if !bytes.Equal(out2, stream) {
		t.Fatal("re-segmented transmission does not match written stream (loss/dup)")
	}
	if len(sizes2) != 8 { // ceil(4000/536)=8
		t.Fatalf("resegment count=%d (%v), want 8", len(sizes2), sizes2)
	}
	for i, sz := range sizes2[:7] {
		if sz != 536 {
			t.Fatalf("segment %d size=%d, want 536", i, sz)
		}
	}
	if sizes2[7] != 4000-7*536 {
		t.Fatalf("tail size=%d, want %d", sizes2[7], 4000-7*536)
	}

	// The re-segmented bytes are exactly what the peer can accept in order:
	// a duplicate equal event must not rewind a second time.
	client.HandlePMTU4(576, t0)
	if got := client.BufferedUnsent(); got != 0 {
		t.Fatalf("BufferedUnsent=%d after duplicate equal event", got)
	}
	// Rewind once more to replay frames into the server and verify every byte
	// arrives exactly once, in order.
	client.scb.RetransmitAll()
	client.bufTx.RetransmitFromUNA()
	var received bytes.Buffer
	for {
		n, err := client.Send(frame)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		if err := server.Recv(frame[:n]); err != nil {
			t.Fatal(err)
		}
		tfrm, _ := NewFrame(frame[:n])
		hlen, _ := tfrm.OffsetAndFlags()
		received.Write(frame[int(hlen)*4 : n])
		clear(frame)
	}
	if !bytes.Equal(received.Bytes(), stream) {
		t.Fatalf("server received %d bytes, stream %d, mismatch", received.Len(), len(stream))
	}
}

// TestHandler_PMTU4_RestoreRules covers clamping to the IPv4 minimum, RFC 1191
// plateau fallback for zero MTU, trusted raise to default and clock expiry.
func TestHandler_PMTU4_RestoreRules(t *testing.T) {
	client, _, frame := newPMTUHandlers(t)
	_ = frame
	// The handshake frames already taught the Handler its link budget (1500).
	if client.pmtu4Link != 1500 {
		t.Fatalf("learned link budget=%d, want 1500", client.pmtu4Link)
	}
	const t0 = int64(2_000_000_000)

	// Below-minimum budget clamps to 68.
	client.HandlePMTU4(40, t0)
	if got := client.PMTU4(); got != ipv4MinimumMTU {
		t.Fatalf("clamp: PMTU4=%d, want %d", got, ipv4MinimumMTU)
	}
	if budget := client.pmtu4PayloadBudget(20); budget != 28 {
		t.Fatalf("min MTU payload budget=%d, want 28", budget)
	}

	// Pre-RFC1191 zero field: step to next plateau below 1500 (1492).
	client.ResetPMTU4()
	if !client.HandlePMTU4(0, t0) {
		t.Fatal("zero-MTU plateau fallback rejected")
	}
	if got := client.PMTU4(); got != 1492 {
		t.Fatalf("plateau: PMTU4=%d, want 1492", got)
	}

	// Larger trusted feedback reaching the default restores it.
	if !client.HandlePMTU4(1500, t0+1) {
		t.Fatal("raise rejected")
	}
	if got := client.PMTU4(); got != 0 {
		t.Fatalf("raise-to-default: PMTU4=%d, want 0", got)
	}

	// Clock expiry restores the default deterministically.
	client.HandlePMTU4(576, t0)
	client.PMTU4Tick(t0 + int64(10*60*1_000_000_000) - 1)
	if got := client.PMTU4(); got != 576 {
		t.Fatalf("budget expired early: %d", got)
	}
	client.PMTU4Tick(t0 + int64(10*60*1_000_000_000))
	if got := client.PMTU4(); got != 0 {
		t.Fatalf("budget did not expire: %d", got)
	}

	// Raise below the default is accepted as an intermediate budget.
	client.HandlePMTU4(576, t0)
	client.HandlePMTU4(1006, t0+1)
	if got := client.PMTU4(); got != 1006 {
		t.Fatalf("intermediate raise: PMTU4=%d, want 1006", got)
	}
}

// TestHandler_PMTU4_StateGate verifies feedback is ignored before the
// connection is synchronized.
func TestHandler_PMTU4_StateGate(t *testing.T) {
	h := new(Handler)
	if err := h.SetBuffers(make([]byte, 1500), make([]byte, 1500), 4); err != nil {
		t.Fatal(err)
	}
	if h.HandlePMTU4(576, 1) {
		t.Fatal("PMTU accepted in CLOSED state")
	}
	if h.PMTU4() != 0 {
		t.Fatal("budget changed in CLOSED state")
	}
}
