package htlcswitch

import (
	"encoding/binary"
	"io"

	"github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/lnwire"
)

// NetworkHop indicates the blockchain network that is intended to be the next
// hop for a forwarded HTLC. The existence of this field within the
// ForwardingInfo struct enables the ability for HTLC to cross chain-boundaries
// at will.
type NetworkHop uint8

const (
	// BitcoinHop denotes that an HTLC is to be forwarded along the Bitcoin
	// link with the specified short channel ID.
	BitcoinHop NetworkHop = iota

	// LitecoinHop denotes that an HTLC is to be forwarded along the
	// Litecoin link with the specified short channel ID.
	LitecoinHop
)

// String returns the string representation of the target NetworkHop.
func (c NetworkHop) String() string {
	switch c {
	case BitcoinHop:
		return "Bitcoin"
	case LitecoinHop:
		return "Litecoin"
	default:
		return "Kekcoin"
	}
}

var (
	// exitHop is a special "hop" which denotes that an incoming HTLC is
	// meant to pay finally to the receiving node.
	exitHop lnwire.ShortChannelID
)

// ForwardingInfo contains all the information that is necessary to forward and
// incoming HTLC to the next hop encoded within a valid HopIterator instance.
// Forwarding links are to use this information to authenticate the information
// received within the incoming HTLC, to ensure that the prior hop didn't
// tamper with the end-to-end routing information at all.
type ForwardingInfo struct {
	// Network is the target blockchain network that the HTLC will travel
	// over next.
	Network NetworkHop

	// NextHop is the channel ID of the next hop. The received HTLC should
	// be forwarded to this particular channel in order to continue the
	// end-to-end route.
	NextHop lnwire.ShortChannelID

	// AmountToForward is the amount of milli-satoshis that the receiving
	// node should forward to the next hop.
	AmountToForward lnwire.MilliSatoshi

	// OutgoingCTLV is the specified value of the CTLV timelock to be used
	// in the outgoing HTLC.
	OutgoingCTLV uint32

	// TODO(roasbeef): modify sphinx logic to not just discard the
	// remaining bytes, instead should include the rest as excess
}

// HopIterator is an interface that abstracts away the routing information
// included in HTLC's which includes the entirety of the payment path of an
// HTLC. This interface provides two basic method which carry out: how to
// interpret the forwarding information encoded within the HTLC packet, and hop
// to encode the forwarding information for the _next_ hop.
type HopIterator interface {
	// ForwardingInstructions returns the set of fields that detail exactly
	// _how_ this hop should forward the HTLC to the next hop.
	// Additionally, the information encoded within the returned
	// ForwardingInfo is to be used by each hop to authenticate the
	// information given to it by the prior hop.
	ForwardingInstructions() ForwardingInfo

	// EncodeNextHop encodes the onion packet destined for the next hop
	// into the passed io.Writer.
	EncodeNextHop(w io.Writer) error

	// OnionPacket returns the original onion packet used to generate the
	// secret keys for this instance.
	OnionPacket() *sphinx.OnionPacket
}

// sphinxHopIterator is the Sphinx implementation of hop iterator which uses
// onion routing to encode the payment route  in such a way so that node might
// see only the next hop in the route..
type sphinxHopIterator struct {
	// ogPacket is the original packet from which the processed packet is
	// derived.
	ogPacket *sphinx.OnionPacket

	// processedPacket is the outcome of processing an onion packet. It
	// includes the information required to properly forward the packet to
	// the next hop.
	processedPacket *sphinx.ProcessedPacket

	// nextPacket is the decoded onion packet for the _next_ hop.
	nextPacket *sphinx.OnionPacket
}

// makeSphinxHopIterator converts a processed packet returned from a sphinx
// router and converts it into an hop iterator for usage in the link.
func makeSphinxHopIterator(ogPacket *sphinx.OnionPacket,
	packet *sphinx.ProcessedPacket) *sphinxHopIterator {

	return &sphinxHopIterator{
		ogPacket:        ogPacket,
		processedPacket: packet,
		nextPacket:      packet.NextPacket,
	}
}

// A compile time check to ensure sphinxHopIterator implements the HopIterator
// interface.
var _ HopIterator = (*sphinxHopIterator)(nil)

// Encode encodes iterator and writes it to the writer.
//
// NOTE: Part of the HopIterator interface.
func (r *sphinxHopIterator) EncodeNextHop(w io.Writer) error {
	return r.nextPacket.Encode(w)
}

// ForwardingInstructions returns the set of fields that detail exactly _how_
// this hop should forward the HTLC to the next hop.  Additionally, the
// information encoded within the returned ForwardingInfo is to be used by each
// hop to authenticate the information given to it by the prior hop.
//
// NOTE: Part of the HopIterator interface.
func (r *sphinxHopIterator) ForwardingInstructions() ForwardingInfo {
	fwdInst := r.processedPacket.ForwardingInstructions

	var nextHop lnwire.ShortChannelID
	switch r.processedPacket.Action {
	case sphinx.ExitNode:
		nextHop = exitHop
	case sphinx.MoreHops:
		s := binary.BigEndian.Uint64(fwdInst.NextAddress[:])
		nextHop = lnwire.NewShortChanIDFromInt(s)
	}

	return ForwardingInfo{
		Network:         BitcoinHop,
		NextHop:         nextHop,
		AmountToForward: lnwire.MilliSatoshi(fwdInst.ForwardAmount),
		OutgoingCTLV:    fwdInst.OutgoingCltv,
	}
}

func (r *sphinxHopIterator) OnionPacket() *sphinx.OnionPacket {
	return r.ogPacket
}

// OnionProcessor is responsible for keeping all sphinx dependent parts inside
// and expose only decoding function. With such approach we give freedom for
// subsystems which wants to decode sphinx path to not be dependable from
// sphinx at all.
//
// NOTE: The reason for keeping decoder separated from hop iterator is too
// maintain the hop iterator abstraction. Without it the structures which using
// the hop iterator should contain sphinx router which makes their creations in
// tests dependent from the sphinx internal parts.
type OnionProcessor struct {
	router *sphinx.Router
}

// NewOnionProcessor creates new instance of decoder.
func NewOnionProcessor(router *sphinx.Router) *OnionProcessor {
	return &OnionProcessor{router}
}

func (p *OnionProcessor) Start() error {
	return p.router.Start()
}

func (p *OnionProcessor) Stop() error {
	p.router.Stop()
	return nil
}

// DecodeHopIterator attempts to decode a valid sphinx packet from the passed io.Reader
// instance using the rHash as the associated data when checking the relevant
// MACs during the decoding process.
func (p *OnionProcessor) DecodeHopIterator(r io.Reader, rHash []byte) (HopIterator,
	lnwire.FailCode) {

	onionPkt := &sphinx.OnionPacket{}
	if err := onionPkt.Decode(r); err != nil {
		switch err {
		case sphinx.ErrInvalidOnionVersion:
			return nil, lnwire.CodeInvalidOnionVersion
		case sphinx.ErrInvalidOnionKey:
			return nil, lnwire.CodeInvalidOnionKey
		default:
			log.Errorf("unable to decode onion packet: %v", err)
			return nil, lnwire.CodeInvalidOnionKey
		}
	}

	// Attempt to process the Sphinx packet. We include the payment hash of
	// the HTLC as it's authenticated within the Sphinx packet itself as
	// associated data in order to thwart attempts a replay attacks. In the
	// case of a replay, an attacker is *forced* to use the same payment
	// hash twice, thereby losing their money entirely.
	sphinxPacket, err := p.router.ProcessOnionPacket(onionPkt, rHash)
	if err != nil {
		switch err {
		case sphinx.ErrInvalidOnionVersion:
			return nil, lnwire.CodeInvalidOnionVersion
		case sphinx.ErrInvalidOnionHMAC:
			return nil, lnwire.CodeInvalidOnionHmac
		case sphinx.ErrInvalidOnionKey:
			return nil, lnwire.CodeInvalidOnionKey
		default:
			log.Errorf("unable to process onion packet: %v", err)
			return nil, lnwire.CodeInvalidOnionKey
		}
	}

	return makeSphinxHopIterator(onionPkt, sphinxPacket), lnwire.CodeNone
}

func (p *OnionProcessor) DecodeHopIterators(id []byte, rs []io.Reader,
	rHashes [][]byte) ([]HopIterator, []lnwire.FailCode) {

	batchSize := len(rs)

	var (
		onionPkts = make([]sphinx.OnionPacket, batchSize)
		iterators = make([]HopIterator, batchSize)
		failcodes = make([]lnwire.FailCode, batchSize)
	)

	tx := p.router.BeginTxn(id, batchSize)

	for i, r := range rs {
		onionPkt := &onionPkts[i]
		err := onionPkt.Decode(r)
		switch err {
		case nil:
			// success

		case sphinx.ErrInvalidOnionVersion:
			failcodes[i] = lnwire.CodeInvalidOnionVersion
			continue

		case sphinx.ErrInvalidOnionKey:
			failcodes[i] = lnwire.CodeInvalidOnionKey
			continue

		default:
			log.Errorf("unable to decode onion packet: %v", err)
			failcodes[i] = lnwire.CodeTemporaryChannelFailure
			continue
		}

		err = tx.ProcessOnionPacket(uint16(i), onionPkt, rHashes[i])
		switch err {
		case nil:
			// success

		case sphinx.ErrInvalidOnionVersion:
			failcodes[i] = lnwire.CodeInvalidOnionVersion
			continue

		case sphinx.ErrInvalidOnionHMAC:
			failcodes[i] = lnwire.CodeInvalidOnionHmac
			continue

		case sphinx.ErrInvalidOnionKey:
			failcodes[i] = lnwire.CodeInvalidOnionKey
			continue

		default:
			log.Errorf("unable to process onion packet: %v", err)
			failcodes[i] = lnwire.CodeTemporaryChannelFailure
			continue
		}
	}

	// With that batch created, we will now attempt to write the shared
	// secrets to disk. This operation will returns the set of indices that
	// were detected as replays, and the computed sphinx packets for all
	// indices that did not fail the above loop. Only indices that are not
	// in the replay set should be considered valid, as they are
	// opportunistically computed.
	packets, replays, err := tx.Commit()
	if err != nil {
		// If we failed to commit the batch to the secret share log, we
		// will mark all not-yet-failed channels with a temporary
		// channel failure and exit since we cannot proceed.
		for i, fcode := range failcodes {
			// Skip any indexes that already failed onion decoding.
			if fcode != lnwire.CodeNone {
				continue
			}

			log.Errorf("unable to process onion packet: %v", err)
			failcodes[i] = lnwire.CodeTemporaryChannelFailure
		}

		return iterators, failcodes
	}

	// Otherwise, the commit was successful. Now we will post process any
	// remaining packets, additionally failing any that were included in the
	// replay set.
	for i, fcode := range failcodes {
		// Skip any indexes that already failed onion decoding.
		if fcode != lnwire.CodeNone {
			continue
		}

		// If this index is contained in the replay set, mark it with a
		// temporary channel failure error code. We infer that the
		// offending error was due to a replayed packet because this
		// index was found in the replay set.
		if replays.Contains(uint16(i)) {
			log.Errorf("unable to process onion packet: %v",
				sphinx.ErrReplayedPacket)
			failcodes[i] = lnwire.CodeTemporaryChannelFailure
			continue
		}

		// Finally, construct a hop iterator from our processed sphinx
		// packet, simultaneously caching the original onion packet.
		iterators[i] = makeSphinxHopIterator(&onionPkts[i], &packets[i])
	}

	return iterators, failcodes
}

// ExtractErrorEncrypter takes an io.Reader which should contain the onion
// packet as original received by a forwarding node and creates an
// ErrorEncrypter instance using the derived shared secret. In the case that en
// error occurs, a lnwire failure code detailing the parsing failure will be
// returned.
func (p *OnionProcessor) ExtractErrorEncrypter(onionPkt *sphinx.OnionPacket) (
	ErrorEncrypter, lnwire.FailCode) {

	onionObfuscator, err := sphinx.NewOnionErrorEncrypter(p.router,
		onionPkt.EphemeralKey)
	if err != nil {
		switch err {
		case sphinx.ErrInvalidOnionVersion:
			return nil, lnwire.CodeInvalidOnionVersion
		case sphinx.ErrInvalidOnionHMAC:
			return nil, lnwire.CodeInvalidOnionHmac
		case sphinx.ErrInvalidOnionKey:
			return nil, lnwire.CodeInvalidOnionKey
		default:
			log.Errorf("unable to process onion packet: %v", err)
			return nil, lnwire.CodeInvalidOnionKey
		}
	}

	return &SphinxErrorEncrypter{
		OnionErrorEncrypter: onionObfuscator,
		ogPacket:            onionPkt,
	}, lnwire.CodeNone
}
