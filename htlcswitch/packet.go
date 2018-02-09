package htlcswitch

import (
	"encoding/binary"
	"io"

	"github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnwire"
)

// htlcPacket is a wrapper around htlc lnwire update, which adds additional
// information which is needed by this package.
type htlcPacket struct {
	// fwdIndex represents the persistent forwarding index assigned by the
	// switch.
	fwdIndex uint64

	// destNode is the first-hop destination of a local created HTLC add
	// message.
	destNode [33]byte

	// incomingChanID is the ID of the channel that we have received an incoming
	// HTLC on.
	incomingChanID lnwire.ShortChannelID

	// outgoingChanID is the ID of the channel that we have offered or will
	// offer an outgoing HTLC on.
	outgoingChanID lnwire.ShortChannelID

	// incomingHTLCID is the ID of the HTLC that we have received from the peer
	// on the incoming channel.
	incomingHTLCID uint64

	// outgoingHTLCID is the ID of the HTLC that we offered to the peer on the
	// outgoing channel.
	outgoingHTLCID uint64

	// sourceRef...
	sourceRef *channeldb.AddRef

	// destRef...
	destRef *channeldb.SettleFailRef

	// amount is the value of the HTLC that is being created or modified.
	amount lnwire.MilliSatoshi

	// htlc lnwire message type of which depends on switch request type.
	htlc lnwire.Message

	// obfuscator contains the necessary state to allow the switch to wrap
	// any forwarded errors in an additional layer of encryption.
	obfuscator ErrorEncrypter

	// localFailure is set to true if an HTLC fails for a local payment before
	// the first hop. In this case, the failure reason is simply encoded, not
	// encrypted with any shared secret.
	localFailure bool

	// isRouted is set to true if the incomingChanID and incomingHTLCID fields
	// of a forwarded fail packet are already set and do not need to be looked
	// up in the circuit map.
	isRouted bool

	// isResolution is set to true if this packet was actually an incoming
	// resolution message from an outside sub-system. We'll treat these as
	// if they emanated directly from the switch. As a result, we'll
	// encrypt all errors related to this packet as if we were the first
	// hop.
	isResolution bool
}

func (h *htlcPacket) Encode(w io.Writer) error {
	var scratch [8]byte

	binary.BigEndian.PutUint64(scratch[:], h.fwdIndex)
	if _, err := w.Write(scratch[:]); err != nil {
		return err
	}

	if _, err := w.Write(h.destNode[:]); err != nil {
		return err
	}

	inChanID := h.incomingChanID.ToUint64()
	binary.BigEndian.PutUint64(scratch[:], inChanID)
	if _, err := w.Write(scratch[:]); err != nil {
		return err
	}

	outChanID := h.outgoingChanID.ToUint64()
	binary.BigEndian.PutUint64(scratch[:], outChanID)
	if _, err := w.Write(scratch[:]); err != nil {
		return err
	}

	binary.BigEndian.PutUint64(scratch[:], h.incomingHTLCID)
	if _, err := w.Write(scratch[:]); err != nil {
		return err
	}

	binary.BigEndian.PutUint64(scratch[:], h.outgoingHTLCID)
	if _, err := w.Write(scratch[:]); err != nil {
		return err
	}

	binary.BigEndian.PutUint64(scratch[:], uint64(h.amount))
	if _, err := w.Write(scratch[:]); err != nil {
		return err
	}

	if _, err := lnwire.WriteMessage(w, h.htlc, 0); err != nil {
		return err
	}

	if err := h.obfuscator.Encode(w); err != nil {
		return err
	}

	err := binary.Write(w, binary.BigEndian, h.localFailure)
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.BigEndian, h.isRouted)
	if err != nil {
		return err
	}

	return nil
}

func (h *htlcPacket) Decode(r io.Reader) error {
	var scratch [8]byte

	if _, err := r.Read(scratch[:]); err != nil {
		return err
	}
	h.fwdIndex = binary.BigEndian.Uint64(scratch[:])

	if _, err := r.Read(h.destNode[:]); err != nil {
		return err
	}

	if _, err := r.Read(scratch[:]); err != nil {
		return err
	}
	h.incomingChanID = lnwire.NewShortChanIDFromInt(
		binary.BigEndian.Uint64(scratch[:]),
	)

	if _, err := r.Read(scratch[:]); err != nil {
		return err
	}
	h.outgoingChanID = lnwire.NewShortChanIDFromInt(
		binary.BigEndian.Uint64(scratch[:]),
	)

	if _, err := r.Read(scratch[:]); err != nil {
		return err
	}
	h.incomingHTLCID = binary.BigEndian.Uint64(scratch[:])

	if _, err := r.Read(scratch[:]); err != nil {
		return err
	}
	h.outgoingHTLCID = binary.BigEndian.Uint64(scratch[:])

	if _, err := r.Read(scratch[:]); err != nil {
		return err
	}
	h.amount = lnwire.MilliSatoshi(
		binary.BigEndian.Uint64(scratch[:]),
	)

	htlc, err := lnwire.ReadMessage(r, 0)
	if err != nil {
		return err
	}
	h.htlc = htlc

	h.obfuscator = &SphinxErrorEncrypter{
		OnionErrorEncrypter: &sphinx.OnionErrorEncrypter{},
	}
	if err := h.obfuscator.Decode(r); err != nil {
		return err
	}

	err = binary.Read(r, binary.BigEndian, &h.localFailure)
	if err != nil {
		return err
	}

	err = binary.Read(r, binary.BigEndian, &h.isRouted)
	if err != nil {
		return err
	}

	return nil
}
