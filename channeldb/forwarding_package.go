package channeldb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/boltdb/bolt"
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/lnwire"
)

type FwdState byte

const (
	FwdStateLockedIn FwdState = iota
	FwdStateProcessed
	FwdStateFullyAcked
	FwdStateCompleted
)

var (
	fwdPackagesKey      = []byte("fwd-packages")
	addBucketKey        = []byte("add-updates")
	failSettleBucketKey = []byte("fail-settle-updates")
	forwardedAddsKey    = []byte("forwarded-adds")
	ackFilterKey        = []byte("ack-filter-key")
)

type PkgFilter struct {
	nels   uint16
	filter []byte
}

func NewPkgFilter(nels int) *PkgFilter {
	filterLen := (nels + 7) / 8

	return &PkgFilter{
		nels:   uint16(nels),
		filter: make([]byte, filterLen),
	}
}

func (f *PkgFilter) Count() uint16 {
	return f.nels
}

func (f *PkgFilter) Size() uint16 {
	return (f.nels + 7) / 8
}

func (f *PkgFilter) Set(i uint16) {
	byt := i / 8
	bit := i % 8

	// Set the i-th bit in the filter.
	f.filter[byt] = f.filter[byt] | byte(1<<(7-bit))
}

func (f *PkgFilter) Contains(i uint16) bool {
	byt := i / 8
	bit := i % 8

	shiftedBit := (f.filter[byt] >> (7 - bit)) & 0x01

	return shiftedBit == 0x01
}

func (f *PkgFilter) IsFull() bool {
	rem := f.nels % 8
	for i, b := range f.filter {
		// Batch validate all except the last byte, unless there are no
		// trailing bits.
		if i < len(f.filter)-1 || rem == 0 {
			if b != 0xFF {
				return false
			}
		}

		// Otherwise check that the filter contains all remaining bits.
		for j := uint16(0); j < rem; j++ {
			idx := uint16(8*i) + j
			if !f.Contains(idx) {
				return false
			}

		}
	}

	return true
}

func (f *PkgFilter) Encode(w io.Writer) error {
	if err := binary.Write(w, binary.BigEndian, f.nels); err != nil {
		return err
	}

	_, err := w.Write(f.filter)

	return err
}

func (f *PkgFilter) Decode(r io.Reader) error {
	if err := binary.Read(r, binary.BigEndian, &f.nels); err != nil {
		return err
	}

	f.filter = make([]byte, f.Size())
	_, err := io.ReadFull(r, f.filter)

	return err
}

type FwdPkg struct {
	Source lnwire.ShortChannelID
	Height uint64

	State        FwdState
	Adds         []LogUpdate
	ExportedAdds map[uint16]struct{}
	AckFilter    *PkgFilter

	SettleFails []LogUpdate
}

func NewFwdPkg(source lnwire.ShortChannelID, height uint64,
	addUpdates, failSettleUpdates []LogUpdate) *FwdPkg {

	return &FwdPkg{
		Source:      source,
		Height:      height,
		State:       FwdStateLockedIn,
		Adds:        addUpdates,
		SettleFails: failSettleUpdates,
		AckFilter:   NewPkgFilter(len(addUpdates)),
	}
}

func (f *FwdPkg) ID() []byte {
	var id = make([]byte, 16)
	byteOrder.PutUint64(id[:8], f.Source.ToUint64())
	byteOrder.PutUint64(id[8:], f.Height)
	return id
}

func (f *FwdPkg) String() string {
	return fmt.Sprintf("%T(src=%v, height=%v, nadds=%v, nfailsettles=%v)",
		f, f.Source, f.Height, len(f.Adds), len(f.SettleFails))
}

type AddRef struct {
	Height uint64
	Index  uint16
}

type SettleFailRef struct {
	Source lnwire.ShortChannelID
	Height uint64
	Index  uint16
}

type FwdPkgReader interface {
	LoadFwdPkg(*bolt.Tx, uint64) (*FwdPkg, error)
	LoadFwdPkgs(*bolt.Tx) ([]*FwdPkg, error)
}

type FwdPkgWriter interface {
	AddFwdPkg(*bolt.Tx, *FwdPkg) error
	AckAddHtlcs(*bolt.Tx, ...AddRef) error
	SetExportedAdds(*bolt.Tx, uint64, map[uint16]struct{}) error
}

type FwdPkgRemover interface {
	RemoveHtlcs(*bolt.Tx, ...SettleFailRef) error
	RemovePkg(*bolt.Tx, uint64) error
}

type FwdPackager interface {
	FwdPkgReader
	FwdPkgWriter
	FwdPkgRemover
}

type Packager struct {
	source lnwire.ShortChannelID
}

func NewPackager(source lnwire.ShortChannelID) *Packager {
	return &Packager{
		source: source,
	}
}

func (*Packager) AddFwdPkg(tx *bolt.Tx, fwdPkg *FwdPkg) error {
	fwdPkgBkt, err := tx.CreateBucketIfNotExists(fwdPackagesKey)
	if err != nil {
		return err
	}

	source := makeLogKey(fwdPkg.Source.ToUint64())
	sourceBkt, err := fwdPkgBkt.CreateBucketIfNotExists(source[:])
	if err != nil {
		return err
	}

	heightKey := makeLogKey(fwdPkg.Height)
	heightBkt, err := sourceBkt.CreateBucketIfNotExists(heightKey[:])
	if err != nil {
		return err
	}

	// Write ADD updates we received at this commit height.
	addBkt, err := heightBkt.CreateBucketIfNotExists(addBucketKey)
	if err != nil {
		return err
	}

	for i := range fwdPkg.Adds {
		err = putLogUpdate(addBkt, uint16(i), &fwdPkg.Adds[i])
		if err != nil {
			return err
		}
	}

	// Persist the initialized pkg filter, which will be used to determine
	// when we can remove this forwarding package from disk.
	var ackFilterBuf bytes.Buffer
	if err := fwdPkg.AckFilter.Encode(&ackFilterBuf); err != nil {
		return err
	}

	if err := heightBkt.Put(ackFilterKey, ackFilterBuf.Bytes()); err != nil {
		return err
	}

	// Write SETTLE/FAIL updates we received at this commit height.
	failSettleBkt, err := heightBkt.CreateBucketIfNotExists(failSettleBucketKey)
	if err != nil {
		return err
	}

	for i := range fwdPkg.SettleFails {
		err = putLogUpdate(failSettleBkt, uint16(i), &fwdPkg.SettleFails[i])
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *Packager) LoadFwdPkg(tx *bolt.Tx, height uint64) (*FwdPkg, error) {
	fwdPkgBkt := tx.Bucket(fwdPackagesKey)
	if fwdPkgBkt == nil {
		return nil, nil
	}

	return p.loadFwdPkg(fwdPkgBkt, height)
}

func (p *Packager) loadFwdPkg(fwdPkgBkt *bolt.Bucket, height uint64) (*FwdPkg, error) {
	sourceKey := makeLogKey(p.source.ToUint64())
	sourceBkt := fwdPkgBkt.Bucket(sourceKey[:])
	if sourceBkt == nil {
		return nil, nil
	}

	heightKey := makeLogKey(height)
	heightBkt := sourceBkt.Bucket(heightKey[:])
	if heightBkt == nil {
		return nil, nil
	}

	// Load ADDs from disk.
	addBkt := heightBkt.Bucket(addBucketKey)
	if addBkt == nil {
		return nil, nil
	}

	adds, err := loadHtlcs(addBkt)
	if err != nil {
		return nil, err
	}

	// Load ack filter from disk.
	ackFilterBytes := heightBkt.Get(ackFilterKey)
	if ackFilterBytes == nil {
		return nil, ErrCorruptedFwdPkg
	}
	ackFilterReader := bytes.NewReader(ackFilterBytes)

	ackFilter := &PkgFilter{}
	if err := ackFilter.Decode(ackFilterReader); err != nil {
		return nil, err
	}

	// Load SETTLE/FAILs from disk.
	failSettleBkt := heightBkt.Bucket(failSettleBucketKey)
	if failSettleBkt == nil {
		return nil, nil
	}

	failSettles, err := loadHtlcs(failSettleBkt)
	if err != nil {
		return nil, err
	}

	// Initialize the fwding package, which always starts in the
	// FwdStateLockedIn. We can determine what state the package was left in
	// by examining constraints on the information loaded from disk.
	fwdPkg := &FwdPkg{
		Source:      p.source,
		State:       FwdStateLockedIn,
		Height:      height,
		Adds:        adds,
		SettleFails: failSettles,
		AckFilter:   ackFilter,
	}

	// Check to see if we have written the set exported filter adds to
	// disk. If we haven't, processing of this package was never started, or
	// failed during the last attempt.
	exportedAddsBytes := heightBkt.Get(forwardedAddsKey)
	if exportedAddsBytes == nil {
		fwdPkg.ExportedAdds = make(map[uint16]struct{})
		return fwdPkg, nil
	}

	// Otherwise, a complete round of processing was completed, and we
	// advance the package to FwdStateProcessed.
	fwdPkg.ExportedAdds = bytesToUint16Set(exportedAddsBytes)
	fwdPkg.State = FwdStateProcessed

	// If not every add has been acked in this package, we still need to
	// reprocess it in order to make sure the unacked adds get added to the
	// switch or go back to the remote peer. Indexes already in the ack
	// filter will be ignored during reprocessing.
	if !fwdPkg.AckFilter.IsFull() {
		return fwdPkg, nil
	}

	// Otherwise, all adds have been acknowledged.
	fwdPkg.State = FwdStateFullyAcked

	// If every add has been acked, it is safe to remove this package iff
	// all other settles and fails that originate from it have also been
	// added to an outgoing commit txn. If so, we advance the pkg to
	// FwdStateCompleted to signal that it can be removed from disk
	// entirely.
	if len(fwdPkg.SettleFails) == 0 {
		fwdPkg.State = FwdStateCompleted
	}

	return fwdPkg, nil
}

// LoadFwdPkgs scans the forwarding log for any packages that haven't been
// processed, and returns their deserialized log updates in map indexed by the
// remote commitment height at which the updates were locked in.
func (p *Packager) LoadFwdPkgs(tx *bolt.Tx) ([]*FwdPkg, error) {
	fwdPkgBkt := tx.Bucket(fwdPackagesKey)
	if fwdPkgBkt == nil {
		return nil, nil
	}

	sourceKey := makeLogKey(p.source.ToUint64())
	sourceBkt := fwdPkgBkt.Bucket(sourceKey[:])
	if sourceBkt == nil {
		return nil, nil
	}

	var heights []uint64
	if err := sourceBkt.ForEach(func(k, _ []byte) error {
		if len(k) != 8 {
			return nil
		}

		heights = append(heights, byteOrder.Uint64(k))

		return nil
	}); err != nil {
		return nil, err
	}

	var fwdPkgs []*FwdPkg
	for _, height := range heights {
		fwdPkg, err := p.loadFwdPkg(fwdPkgBkt, height)
		if err != nil {
			return nil, err
		}

		fwdPkgs = append(fwdPkgs, fwdPkg)
	}

	return fwdPkgs, nil
}

func loadHtlcs(bkt *bolt.Bucket) ([]LogUpdate, error) {
	var htlcs []LogUpdate
	if err := bkt.ForEach(func(_, v []byte) error {
		var htlc LogUpdate
		if err := htlc.Decode(bytes.NewReader(v)); err != nil {
			return err
		}

		htlcs = append(htlcs, htlc)

		return nil
	}); err != nil {
		return nil, err
	}

	return htlcs, nil
}

// SetExportedAdds writes the set of indexes corresponding to Adds at the
// `height` that are to be forwarded to the switch. Calling this method causes
// the forwarding package at `height` to be in FwdStateProcessed. We write this
// forwarding decision so that we always arrive at the same behavior for HTLCs
// leaving this channel. After a restart, we skip validation of these Adds,
// since they are assumed to have already been validated, and make the switch or
// outgoing link responsible for handling replays.
func (p *Packager) SetExportedAdds(tx *bolt.Tx, height uint64,
	forwardedAdds map[uint16]struct{}) error {

	fwdPkgBkt := tx.Bucket(fwdPackagesKey)
	if fwdPkgBkt == nil {
		return nil
	}

	source := makeLogKey(p.source.ToUint64())
	sourceBkt := fwdPkgBkt.Bucket(source[:])
	if sourceBkt == nil {
		return nil
	}

	heightKey := makeLogKey(height)
	heightBkt := sourceBkt.Bucket(heightKey[:])
	if heightBkt == nil {
		return nil
	}

	forwardedAddsBytes := heightBkt.Get(forwardedAddsKey)
	if forwardedAddsBytes != nil {
		return nil
	}

	forwardedAddsBytes = uint16SetToBytes(forwardedAdds)

	return heightBkt.Put(forwardedAddsKey, forwardedAddsBytes)
}

func (p *Packager) AckAddHtlcs(tx *bolt.Tx, addRefs ...AddRef) error {
	if len(addRefs) == 0 {
		return nil
	}

	fwdPkgBkt := tx.Bucket(fwdPackagesKey)
	if fwdPkgBkt == nil {
		return ErrCorruptedFwdPkg
	}

	sourceKey := makeLogKey(p.source.ToUint64())
	sourceBkt := fwdPkgBkt.Bucket(sourceKey[:])
	if sourceBkt == nil {
		return nil
	}

	// Organize the forward references such that we just get a single slice
	// of indexes for each unique height.
	var heightDiffs = make(map[uint64][]uint16)
	for _, addRef := range addRefs {
		if indexes, ok := heightDiffs[addRef.Height]; ok {
			indexes = append(indexes, addRef.Index)
		} else {
			heightDiffs[addRef.Height] = []uint16{addRef.Index}
		}
	}

	for height, indexes := range heightDiffs {
		err := ackAddHtlcsAtHeight(sourceBkt, height, indexes)
		if err != nil {
			return err
		}
	}

	return nil
}

func ackAddHtlcsAtHeight(sourceBkt *bolt.Bucket, height uint64,
	indexes []uint16) error {

	heightKey := makeLogKey(height)
	heightBkt := sourceBkt.Bucket(heightKey[:])
	if heightBkt == nil {
		return nil
	}

	// Load ack filter from disk.
	ackFilterBytes := heightBkt.Get(ackFilterKey)
	if ackFilterBytes == nil {
		return ErrCorruptedFwdPkg
	}

	ackFilter := &PkgFilter{}
	ackFilterReader := bytes.NewReader(ackFilterBytes)
	if err := ackFilter.Decode(ackFilterReader); err != nil {
		return err
	}

	// Update the ack filter for this height.
	for _, index := range indexes {
		ackFilter.Set(index)
	}

	// Write the resulting filter to disk.
	var ackFilterBuf bytes.Buffer
	if err := ackFilter.Encode(&ackFilterBuf); err != nil {
		return err
	}

	return heightBkt.Put(ackFilterKey, ackFilterBuf.Bytes())
}

func (*Packager) RemoveHtlcs(tx *bolt.Tx, settleFailRefs ...SettleFailRef) error {
	if len(settleFailRefs) == 0 {
		return nil
	}

	fwdPkgBkt := tx.Bucket(fwdPackagesKey)
	if fwdPkgBkt == nil {
		return ErrCorruptedFwdPkg
	}

	// Organize the forward references such that we just get a single slice
	// of indexes for each unique height.
	var destHeightDiffs = make(map[lnwire.ShortChannelID]map[uint64][]uint16)
	for _, settleFailRef := range settleFailRefs {
		destHeights, ok := destHeightDiffs[settleFailRef.Source]
		if !ok {
			destHeights = make(map[uint64][]uint16)
			destHeightDiffs[settleFailRef.Source] = destHeights
		}

		if heightIndexes, ok := destHeights[settleFailRef.Height]; ok {
			heightIndexes = append(heightIndexes,
				settleFailRef.Index)
		} else {
			destHeights[settleFailRef.Height] =
				[]uint16{settleFailRef.Index}
		}
	}

	for dest, destHeights := range destHeightDiffs {
		destKey := makeLogKey(dest.ToUint64())
		destBkt := fwdPkgBkt.Bucket(destKey[:])
		if destBkt == nil {
			return nil
		}

		for height, indexes := range destHeights {
			err := removeHtlcsAtHeight(destBkt, height, indexes)
			if err != nil {
				return err
			}
		}

	}

	return nil
}

func removeHtlcsAtHeight(destBkt *bolt.Bucket, height uint64,
	indexes []uint16) error {

	heightKey := makeLogKey(height)
	heightBkt := destBkt.Bucket(heightKey[:])
	if heightBkt == nil {
		return nil
	}

	// Update the ack filter for this height.
	for _, index := range indexes {
		if err := heightBkt.Delete(uint16Key(index)); err != nil {
			return err
		}
	}

	return nil
}

func (p *Packager) RemovePkg(tx *bolt.Tx, height uint64) error {
	fwdPkgBkt := tx.Bucket(fwdPackagesKey)
	if fwdPkgBkt == nil {
		return nil
	}

	sourceBytes := makeLogKey(p.source.ToUint64())

	return fwdPkgBkt.Delete(sourceBytes[:])
}

func putLogUpdate(bkt *bolt.Bucket, idx uint16, htlc *LogUpdate) error {
	var b bytes.Buffer
	if err := htlc.Encode(&b); err != nil {
		return err
	}

	return bkt.Put(uint16Key(idx), b.Bytes())
}

var (
	errBucketNotEmpty  = errors.New("bucket is not empty")
	ErrFwdPkgNotEmpty  = errors.New("fwding package is not empty")
	ErrCorruptedFwdPkg = errors.New("fwding package has invalid on-disk structure")
)

func isBucketEmpty(bkt *bolt.Bucket) error {
	return bkt.ForEach(func(_, _ []byte) error {
		return errBucketNotEmpty
	})
}

// uint16Key writes the provided 16-bit unsigned integer to a 2-byte slice.
func uint16Key(i uint16) []byte {
	var key = make([]byte, 2)
	byteOrder.PutUint16(key, i)
	return key
}

// uint16FromKey reconstructs a 16-bit unsigned integer from a 2-byte slice.
func uint16FromKey(key []byte) uint16 {
	return byteOrder.Uint16(key)
}

// uint16SetToBytes serializes a slice of uint16s into a slice of bytes.
func uint16SetToBytes(u16s map[uint16]struct{}) []byte {
	var bs = make([]byte, 2*len(u16s))
	var i int
	for b := range u16s {
		bs[i] = byte(b >> 8)
		bs[i+1] = byte(b)
		i += 2
	}

	return bs
}

// bytesToUint16s deserializes a byte slice back into a slice of uint16s. This
// method assumes the length of the provided byte slice is even.
func bytesToUint16Set(bs []byte) map[uint16]struct{} {
	nels := len(bs) / 2
	var u16Set = make(map[uint16]struct{}, nels)
	for i := 0; i < nels; i++ {
		idx := uint16(bs[2*i]<<8) | uint16(bs[2*i+1])
		u16Set[idx] = struct{}{}
	}

	return u16Set
}

// Compile-time constraint to ensure that packager implements the public
// Packager interface.
var _ FwdPackager = (*Packager)(nil)
