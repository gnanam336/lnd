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

// ErrCorruptedFwdPkg signals that the on-disk structure of the forwarding
// package has potentially been mangled.
var ErrCorruptedFwdPkg = errors.New("fwding package db has been corrupted")

// FwdState is an enum used to describe the lifecycle of a FwdPkg.
type FwdState byte

const (
	// FwdStateLockedIn is the starting state for all forwarding packages.
	// Packages in this state have not yet committed to the exact set of
	// Adds to forward to the switch.
	FwdStateLockedIn FwdState = iota

	// FwdStateProcessed marks the state in which all Adds have been
	// locally processed and the forwarding decision to the switch has been
	// persisted.
	FwdStateProcessed

	// FwdStateFullyAcked indicates the that all Adds in this forwarding
	// package have received a corresponding settle or fail that has been
	// included in an outgoing commitment txn.
	FwdStateFullyAcked

	// FwdStateCompleted signals that all Adds have been acked, and that all
	// settles and fails have been delivered to their sources. Packages in
	// this state can be removed permanently.
	FwdStateCompleted
)

var (
	// fwdPackagesKey is the root-level bucket that all forwarding packages
	// are written. This bucket is further subdivided based on the short
	// channel ID of each channel.
	fwdPackagesKey = []byte("fwd-packages")

	// addBucketKey the bucket to which all Add log updates are written.
	addBucketKey = []byte("add-updates")

	// failSettleBucketKey the bucket to which all Settle/Fail log updates
	// are written.
	failSettleBucketKey = []byte("fail-settle-updates")

	// fwdFilterKey is a key used to write the set of Adds that passed
	// validation and are to be forwarded to the switch.
	// NOTE: The presence of this key within a forwarding package indicates
	// that the package has reached FwdStateProcessed.
	fwdFilterKey = []byte("fwd-filter-key")

	// ackFilterKey is a key used to access the PkgFilter indicating which
	// Adds have received an Settle/Fail. This response may come from a
	// number of sources, including: exitHop settle/fails, switch failures,
	// chain arbiter interjections, as well as settle/fails from the
	// next hop in the route.
	ackFilterKey = []byte("ack-filter-key")
)

// PkgFilter is used to compactly represent a particular subset of the Adds in a
// forwarding package. Each filter is represented as a simple, statically-sized
// bitvector, where the elements are intended to be the indices of the Adds as
// they are written in the FwdPkg.
type PkgFilter struct {
	nels   uint16
	filter []byte
}

// NewPkgFilter initializes an empty PkgFilter supporting `nels` elements.
func NewPkgFilter(nels int) *PkgFilter {
	filterLen := (nels + 7) / 8

	return &PkgFilter{
		nels:   uint16(nels),
		filter: make([]byte, filterLen),
	}
}

// Count returns the number of elements represented by this PkgFilter.
func (f *PkgFilter) Count() uint16 {
	return f.nels
}

// Set marks the `i`-th element as included by this filter.
// NOTE: It is assumed that i is always less than nels.
func (f *PkgFilter) Set(i uint16) {
	byt := i / 8
	bit := i % 8

	// Set the i-th bit in the filter.
	// TODO(conner): ignore if > nels to prevent panic?
	f.filter[byt] = f.filter[byt] | byte(1<<(7-bit))
}

// Contains queries the filter for membership of index `i`.
// NOTE: It is assumed that i is always less than nels.
func (f *PkgFilter) Contains(i uint16) bool {
	byt := i / 8
	bit := i % 8

	// Read the i-th bit in the filter.
	// TODO(conner): ignore if > nels to prevent panic?
	shiftedBit := (f.filter[byt] >> (7 - bit)) & 0x01

	return shiftedBit == 0x01
}

// Equal checks two PkgFilters for equality.
func (f *PkgFilter) Equal(f2 *PkgFilter) bool {
	if f == f2 {
		return true
	}
	if f.nels != f2.nels {
		return false
	}
	if len(f.filter) != len(f2.filter) {
		return false
	}
	for i, b := range f.filter {
		if b != f2.filter[i] {
			return false
		}
	}

	return true
}

// IsFull returns true if every element in the filter has been Set, and false
// otherwise.
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

// Size returns number of bytes produced when the PkgFilter is serialized.
func (f *PkgFilter) Size() uint16 {
	return 2 + (f.nels+7)/8
}

// Encode writes the filter to the provided io.Writer.
func (f *PkgFilter) Encode(w io.Writer) error {
	if err := binary.Write(w, binary.BigEndian, f.nels); err != nil {
		return err
	}

	_, err := w.Write(f.filter)

	return err
}

// Decode reads the filter from the provided io.Reader.
func (f *PkgFilter) Decode(r io.Reader) error {
	if err := binary.Read(r, binary.BigEndian, &f.nels); err != nil {
		return err
	}

	f.filter = make([]byte, f.Size()-2)
	_, err := io.ReadFull(r, f.filter)

	return err
}

// FwdPkg records all adds, settles, and fails that were locked in as a result
// of the remote peer sending us a revocation. Each package is identified by
// the short chanid and remote commitment height corresponding to the revocation
// that locked in the HTLCs. For everything expect a locally initiated payment,
// settles and fails in a forwarding package must have corresponding Add in
// another package, and can be removed individually once the source link has
// received the fail/settle.
//
// Adds cannot be removed, as we need to present the same batch of Adds to
// properly handle replay protection. Instead, we use a PkgFilter to mark that
// we have finished processing a particular Add. A FwdPkg should only  be
// deleted after the AckFilter is full and all settles and fails have been
// persistently removed.
type FwdPkg struct {
	// Source identifies the channel that wrote this forwarding package.
	Source lnwire.ShortChannelID

	// Height is the height of the remote commitment chain that locked in
	// this forwarding package.
	Height uint64

	// State signals the persistent condition of the package and directs how
	// to reprocess the package in the event of failures.
	State FwdState

	// Adds contains all add messages which need to be processed and
	// forwarded to the switch. Adds does not change over the life of a
	// forwarding package.
	Adds []LogUpdate

	// FwdFilter a filter containing the indices of all Adds that were
	// forwarded to the switch.
	FwdFilter *PkgFilter

	// AckFilter a filter containing the indices of all Adds for which the
	// source has received a settle or fail and is reflected in the next
	// commitment txn. A package should not be removed until IsFull()
	// returns true.
	AckFilter *PkgFilter

	// SettleFails contains all settle and fail messages that should be
	// forwarded to the switch.
	SettleFails []LogUpdate
}

// NewFwdPkg initializes a new forwarding package in FwdStateLockedIn. This
// should be used to create a package at the time of we receive a revocation.
func NewFwdPkg(source lnwire.ShortChannelID, height uint64,
	addUpdates, failSettleUpdates []LogUpdate) *FwdPkg {

	return &FwdPkg{
		Source:      source,
		Height:      height,
		State:       FwdStateLockedIn,
		Adds:        addUpdates,
		FwdFilter:   NewPkgFilter(len(addUpdates)),
		AckFilter:   NewPkgFilter(len(addUpdates)),
		SettleFails: failSettleUpdates,
	}
}

// ID returns an unique identifier for this package, used to ensure that sphinx
// replay processing of this batch is idempotent.
func (f *FwdPkg) ID() []byte {
	var id = make([]byte, 16)
	byteOrder.PutUint64(id[:8], f.Source.ToUint64())
	byteOrder.PutUint64(id[8:], f.Height)
	return id
}

// String returns a human-readable description of the forwarding package.
func (f *FwdPkg) String() string {
	return fmt.Sprintf("%T(src=%v, height=%v, nadds=%v, nfailsettles=%v)",
		f, f.Source, f.Height, len(f.Adds), len(f.SettleFails))
}

// AddRef is used to acknowledge a Add in particular FwdPkg. The short channel
// ID is assumed to be that of the packager.
type AddRef struct {
	Height uint64
	Index  uint16
}

// SettleFailRef is used to locate a Settle/Fail in another channel's FwdPkg. A
// channel does not remove its own Settle/Fail htlcs, so the source is provided
// to locate a db bucket belonging another channel.
type SettleFailRef struct {
	Source lnwire.ShortChannelID
	Height uint64
	Index  uint16
}

// FwdPkgWriter exposes methods used by channel to create and update forwarding
// packages.
type FwdPkgWriter interface {
	AddFwdPkg(*bolt.Tx, *FwdPkg) error
	SetFwdFilter(*bolt.Tx, uint64, *PkgFilter) error
	AckAddHtlcs(*bolt.Tx, ...AddRef) error
	RemoveHtlcs(*bolt.Tx, ...SettleFailRef) error
}

// FwdPkgReader facilitates loading active forwarding packages from disk.
type FwdPkgReader interface {
	LoadFwdPkgs(*bolt.Tx) ([]*FwdPkg, error)
}

// FwdPkgRemover permits the ability to delete a forwarding package that has
// been processed completely.
type FwdPkgRemover interface {
	RemovePkg(*bolt.Tx, uint64) error
}

// FwdPackager supports all operations required to modify fwd packages, such as
// creation, updates, reading, and removal. The interfaces are broken down in
// this way to support future delegation of the subinterfaces.
type FwdPackager interface {
	FwdPkgWriter
	FwdPkgReader
	FwdPkgRemover
}

// Packager is used by a channel to manage the lifecycle of its forwarding
// packages. The packager is tied to a particular source channel ID, allowing it
// to create and edit its own packages. Each packager also has the ability to
// remove fail/settle htlcs that correspond to an add contained in one of
// source's packages.
type Packager struct {
	source lnwire.ShortChannelID
}

// NewPackager creates a new packager for a single channel.
func NewPackager(source lnwire.ShortChannelID) *Packager {
	return &Packager{
		source: source,
	}
}

// AddFwdPkg writes a newly locked in forwarding package to disk.
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

	// Write SETTLE/FAIL updates we received at this commit height.
	failSettleBkt, err := heightBkt.CreateBucketIfNotExists(failSettleBucketKey)
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

	for i := range fwdPkg.SettleFails {
		err = putLogUpdate(failSettleBkt, uint16(i), &fwdPkg.SettleFails[i])
		if err != nil {
			return err
		}
	}

	return nil
}

// putLogUpdate encodes writes an htlc under the provided index.
func putLogUpdate(bkt *bolt.Bucket, idx uint16, htlc *LogUpdate) error {
	var b bytes.Buffer
	if err := htlc.Encode(&b); err != nil {
		return err
	}

	return bkt.Put(uint16Key(idx), b.Bytes())
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

// loadFwPkg reads the packager's fwd pkg at a given height, and determines the
// appropriate FwdState.
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
	fwdFilterBytes := heightBkt.Get(fwdFilterKey)
	if fwdFilterBytes == nil {
		fwdPkg.FwdFilter = NewPkgFilter(len(adds))
		return fwdPkg, nil
	}

	fwdFilterReader := bytes.NewReader(fwdFilterBytes)
	fwdPkg.FwdFilter = &PkgFilter{}
	if err := fwdPkg.FwdFilter.Decode(fwdFilterReader); err != nil {
		return nil, err
	}

	// Otherwise, a complete round of processing was completed, and we
	// advance the package to FwdStateProcessed.
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

// loadHtlcs retrieves all serialized htlcs in a bucket, returning
// them in order of the indexes they were written under.
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

// SetFwdFilter writes the set of indexes corresponding to Adds at the
// `height` that are to be forwarded to the switch. Calling this method causes
// the forwarding package at `height` to be in FwdStateProcessed. We write this
// forwarding decision so that we always arrive at the same behavior for HTLCs
// leaving this channel. After a restart, we skip validation of these Adds,
// since they are assumed to have already been validated, and make the switch or
// outgoing link responsible for handling replays.
func (p *Packager) SetFwdFilter(tx *bolt.Tx, height uint64,
	fwdFilter *PkgFilter) error {

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

	forwardedAddsBytes := heightBkt.Get(fwdFilterKey)
	if forwardedAddsBytes != nil {
		return nil
	}

	var b bytes.Buffer
	if err := fwdFilter.Encode(&b); err != nil {
		return err
	}

	return heightBkt.Put(fwdFilterKey, b.Bytes())
}

// AckAddHtlcs accepts a list of references to add htlcs, and updates the
// AckAddFilter of those forwarding packages to indicate that a settle or fail
// has been received in response to the add.
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
	heightDiffs := make(map[uint64][]uint16)
	for _, addRef := range addRefs {
		if indexes, ok := heightDiffs[addRef.Height]; ok {
			indexes = append(indexes, addRef.Index)
		} else {
			heightDiffs[addRef.Height] = []uint16{addRef.Index}
		}
	}

	// Load each height bucket once and remove all acked htlcs at that
	// height.
	for height, indexes := range heightDiffs {
		err := ackAddHtlcsAtHeight(sourceBkt, height, indexes)
		if err != nil {
			return err
		}
	}

	return nil
}

// ackAddHtlcsAtHeight updates the AddAckFilter of a single forwarding package
// with a list of indexes, writing the resulting filter back in its place.
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

// RemoveHtlcs persistently deletes settles or fails from a remote forwarding
// package. This should only be called after the source of the Add has locked in
// the settle/fail, or it becomes otherwise safe to forgo retransmitting the
// settle/fail after a restart.
func (*Packager) RemoveHtlcs(tx *bolt.Tx, settleFailRefs ...SettleFailRef) error {
	if len(settleFailRefs) == 0 {
		return nil
	}

	fwdPkgBkt := tx.Bucket(fwdPackagesKey)
	if fwdPkgBkt == nil {
		return ErrCorruptedFwdPkg
	}

	// Organize the forward references such that we just get a single slice
	// of indexes for each unique destination-height pair.
	destHeightDiffs := make(map[lnwire.ShortChannelID]map[uint64][]uint16)
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

	// With the references organized by destination and height, we now load
	// each remote bucket, and remove any settle/fail htlcs.
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

// removeHtlcsAtHeight given a destination bucket, removes the provided indexes
// at particular a height.
func removeHtlcsAtHeight(destBkt *bolt.Bucket, height uint64,
	indexes []uint16) error {

	heightKey := makeLogKey(height)
	heightBkt := destBkt.Bucket(heightKey[:])
	if heightBkt == nil {
		return nil
	}

	// Remove the htlcs at this height based on the provided indexes.
	for _, index := range indexes {
		if err := heightBkt.Delete(uint16Key(index)); err != nil {
			return err
		}
	}

	return nil
}

// RemovePkg deletes the forwarding package at the given height from the
// packager's source bucket.
func (p *Packager) RemovePkg(tx *bolt.Tx, height uint64) error {
	fwdPkgBkt := tx.Bucket(fwdPackagesKey)
	if fwdPkgBkt == nil {
		return nil
	}

	sourceBytes := makeLogKey(p.source.ToUint64())
	sourceBkt := fwdPkgBkt.Bucket(sourceBytes[:])
	if sourceBkt == nil {
		return ErrCorruptedFwdPkg
	}

	heightKey := makeLogKey(height)

	return sourceBkt.DeleteBucket(heightKey[:])
}

// uint16Key writes the provided 16-bit unsigned integer to a 2-byte slice.
func uint16Key(i uint16) []byte {
	key := make([]byte, 2)
	byteOrder.PutUint16(key, i)
	return key
}

// uint16FromKey reconstructs a 16-bit unsigned integer from a 2-byte slice.
func uint16FromKey(key []byte) uint16 {
	return byteOrder.Uint16(key)
}

// Compile-time constraint to ensure that Packager implements the public
// FwdPackager interface.
var _ FwdPackager = (*Packager)(nil)
