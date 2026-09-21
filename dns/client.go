package dns

import (
	"log/slog"
	"math"
	"net"
	"net/netip"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

type Client struct {
	connID          uint64
	txid            uint16
	lport           uint16
	msg             Message
	respFlags       HeaderFlags
	state           StateClientQuery
	enableRecursion bool
}

type ResolveConfig struct {
	Questions       []Question
	Additional      []Resource
	EnableRecursion bool
	// MaxResponseAnswers limits how many answer records are decoded from the
	// DNS response. If zero it defaults to the number of Questions. Answers
	// are decoded in wire order regardless of type, so a response resolved
	// through CNAMEs needs room for the CNAME records as well as the addresses.
	MaxResponseAnswers uint16
	// MaxAuthorityRecords limits how many authority-section records are
	// decoded. Zero skips the section. Set it to at least 1 to receive the
	// SOA record carried by negative responses, whose MINIMUM field gives the
	// RFC 2308 negative-caching TTL.
	MaxAuthorityRecords uint16
}

func (sudp *Client) Protocol() uint64 { return uint64(lneto.IPProtoUDP) }

func (sudp *Client) LocalPort() uint16 { return sudp.lport }

func (sudp *Client) ConnectionID() *uint64 { return &sudp.connID }

func (c *Client) StartResolve(localPort, txid uint16, cfg ResolveConfig) error {
	nd := len(cfg.Questions)
	if nd > math.MaxUint16 || nd == 0 {
		return lneto.ErrInvalidConfig
	}
	maxAns := cfg.MaxResponseAnswers
	if maxAns == 0 {
		maxAns = uint16(nd)
	}
	c.reset(localPort, txid, CQueryPending, cfg.EnableRecursion)
	c.msg.LimitResourceDecoding(uint16(nd), maxAns, cfg.MaxAuthorityRecords, 0)
	c.msg.AddQuestions(cfg.Questions)
	c.msg.AddAdditionals(cfg.Additional)
	return nil
}

func (c *Client) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	if c.isClosed() {
		return 0, net.ErrClosed
	} else if c.state != CQueryPending {
		return 0, nil
	}

	msg := &c.msg
	frame := carrierData[offsetToFrame:]
	msglen := msg.Len()
	if msglen > uint16(len(frame)) {
		return 0, errCalcLen
	}

	data, err := msg.AppendTo(frame[:0], c.txid, NewClientHeaderFlags(OpCodeQuery, c.enableRecursion))
	if err != nil {
		return 0, err
	} else if len(data) > int(msglen) {
		internal.LogAttrs(nil, slog.LevelError, "dns:unexpected-write", slog.Int("got", len(data)), slog.Int("want", int(msglen)))
		return 0, lneto.ErrBug
	}
	c.state = CQueryOutstanding
	// Unset don't frag since DNS requests go through LOTS of nodes.
	// if frameOffset >= 28 {
	// 	version := carrierData[0] >> 4
	// 	if version == 4 {
	// 		carrierData[6], carrierData[7] = 0, 0 // unset IP Flags.
	// 	}
	// }
	return len(data), nil
}

func (c *Client) Demux(carrierData []byte, frameOffset int) error {
	if c.isClosed() {
		return net.ErrClosed
	} else if c.state != CQueryOutstanding {
		return nil
	}
	frame := carrierData[frameOffset:]
	f, err := NewFrame(frame)
	if err != nil {
		return err
	}
	flags := f.Flags()
	if f.TxID() != c.txid || !flags.IsResponse() {
		return nil // Not meant for our client.
	}
	c.respFlags = flags
	c.state = CQueryDone
	msg := &c.msg
	_, incompleteButOK, err := msg.Decode(frame)
	if err != nil && !incompleteButOK {
		return err
	}
	return nil
}

func (c *Client) isClosed() bool {
	return c.state == CQueryIdle || c.state == CQueryAborted
}

// IsClosed reports whether the client has no query in flight (idle or aborted).
func (c *Client) IsClosed() bool { return c.isClosed() }

func (c *Client) ResponseCopyTo(dst *Message) (done bool, err error) {
	if !c.respFlags.IsResponse() {
		return false, nil
	}
	dst.CopyFrom(c.msg)
	rcode := c.respFlags.ResponseCode()
	if rcode != 0 {
		return true, rcode
	}
	return true, nil
}

func (c *Client) ResponseAnswerLookup(dst []netip.Addr, host string) (uint16, error) {
	if !c.respFlags.IsResponse() {
		return 0, nil
	}
	rcode := c.respFlags.ResponseCode()
	if rcode != 0 {
		return 0, rcode
	}
	return c.msg.WriteAnswers(dst, host)
}

func (c *Client) ResponseFlags() (HeaderFlags, bool) {
	return c.respFlags, c.respFlags.IsResponse()
}

// ResponseMinAnswerTTL returns the minimum TTL of the response's A/AAAA and
// CNAME answer records, used as the lifetime of a positive snapshot.
func (c *Client) ResponseMinAnswerTTL() (time.Duration, bool) {
	if !c.respFlags.IsResponse() {
		return 0, false
	}
	return c.msg.MinAnswerTTL()
}

// ResponseNegativeTTL derives the RFC 2308 negative-caching TTL of the
// response from its SOA authority record, using fallback when the response
// carries no usable SOA and clamping the result to maxTTL.
func (c *Client) ResponseNegativeTTL(fallback, maxTTL time.Duration) time.Duration {
	if !c.respFlags.IsResponse() {
		return 0
	}
	return NegativeTTL(c.msg.Authorities, fallback, maxTTL)
}

func (c *Client) Abort() {
	c.reset(0, 0, CQueryAborted, false)
}

func (c *Client) reset(lport, txid uint16, state StateClientQuery, enableRecursion bool) {
	*c = Client{
		connID:          c.connID + 1,
		lport:           lport,
		txid:            txid,
		msg:             c.msg,
		state:           state,
		enableRecursion: enableRecursion,
	}
	c.msg.Reset()
}
