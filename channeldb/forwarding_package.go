package channeldb

import (
	"bytes"

	"github.com/boltdb/bolt"
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/lnwire"
)

type FwdState byte

const (
	FwdStateLockedIn FwdState = iota
	FwdStateProcessed
)

var (
	fwdSourceKey    = []byte("fwd-source")
	htlcBucketKey   = []byte("htlcs")
	rejectedAddsKey = []byte("rejected-adds")
)

type FwdPkg struct {
	SeqNum       uint64
	Source       lnwire.ShortChannelID
	State        FwdState
	Htlcs        []LogUpdate
	RejectedAdds map[uint16]struct{}
}

type FwdRef struct {
	SeqNum uint64
	Index  uint16
}

type Packager interface {
	AddFwdPkg(*bolt.Bucket, *FwdPkg) error
	LoadFwdPkg(*bolt.Bucket, uint64) (*FwdPkg, error)
	FilterPkg(*bolt.Bucket, uint64, []uint16) error
	RemoveHtlc(*bolt.Bucket, FwdRef) error
	RemovePkg(*bolt.Bucket, uint64) error
}

type packager struct{}

func NewPackager() *packager {
	return &packager{}
}

func (packager) AddFwdPkg(bkt *bolt.Bucket, fwdPkg *FwdPkg) error {
	seqNumKey := makeLogKey(fwdPkg.SeqNum)
	fwdPkgBkt, err := bkt.CreateBucketIfNotExists(seqNumKey[:])
	if err != nil {
		return err
	}

	source := makeLogKey(fwdPkg.Source.ToUint64())
	if err := fwdPkgBkt.Put(fwdSourceKey, source[:]); err != nil {
		return err
	}

	htlcBkt, err := fwdPkgBkt.CreateBucketIfNotExists(htlcBucketKey)
	if err != nil {
		return err
	}

	for i := range fwdPkg.Htlcs {
		err = putLogUpdate(htlcBkt, uint16(i), &fwdPkg.Htlcs[i])
		if err != nil {
			return err
		}
	}

	return nil
}

func (packager) LoadFwdPkg(bkt *bolt.Bucket, seqNum uint64) (*FwdPkg, error) {
	seqNumKey := makeLogKey(seqNum)
	fwdPkgBkt := bkt.Bucket(seqNumKey[:])
	if fwdPkgBkt == nil {
		// TODO(conner) return bkt not found
		return nil, nil
	}

	fwdPkg := &FwdPkg{}

	sourceBytes := fwdPkgBkt.Get(fwdSourceKey)
	if sourceBytes == nil {
		// TODO(conner) return invalid fwd pkg
		return nil, nil
	}
	sourceUint64 := byteOrder.Uint64(sourceBytes)
	fwdPkg.Source = lnwire.NewShortChanIDFromInt(sourceUint64)

	htlcBkt := fwdPkgBkt.Bucket(htlcBucketKey)
	if htlcBkt != nil {
		htlcs, err := loadHtlcs(htlcBkt)
		if err != nil {
			return nil, err
		}
		fwdPkg.Htlcs = htlcs
	}

	rejectedAddBytes := fwdPkgBkt.Get(rejectedAddsKey)
	if rejectedAddBytes == nil {
		fwdPkg.State = FwdStateLockedIn
		fwdPkg.RejectedAdds = make(map[uint16]struct{})
	} else {
		fwdPkg.State = FwdStateProcessed
		fwdPkg.RejectedAdds = bytesToUint16Set(rejectedAddBytes)
	}

	return fwdPkg, nil
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

func (packager) FilterPkg(bkt *bolt.Bucket, seqNum uint64,
	rejectedAdds []uint16) error {

	seqNumKey := makeLogKey(seqNum)
	fwdPkgBkt := bkt.Bucket(seqNumKey[:])
	if fwdPkgBkt == nil {
		// TODO(conner) return bkt not found
		return nil
	}

	rejectedAddsBytes := uint16sToBytes(rejectedAdds)

	return fwdPkgBkt.Put(rejectedAddsKey, rejectedAddsBytes)
}

func (packager) RemoveHtlc(bkt *bolt.Bucket, ref FwdRef) error {
	seqNumKey := makeLogKey(ref.SeqNum)
	fwdPkgBkt := bkt.Bucket(seqNumKey[:])
	if fwdPkgBkt == nil {
		// TODO(conner) return bkt not found
		return nil
	}

	htlcBkt, err := fwdPkgBkt.CreateBucketIfNotExists(htlcBucketKey)
	if err != nil {
		return err
	}

	logIdxKey := uint16Key(ref.Index)
	if err := htlcBkt.Delete(logIdxKey); err != nil {
		return err
	}

	if err := isBucketEmpty(htlcBkt); err != nil {
		return nil
	}

	return fwdPkgBkt.Delete(htlcBucketKey)
}

func (packager) RemovePkg(bkt *bolt.Bucket, pkgIdx uint64) error {
	pkgIdxKey := makeLogKey(pkgIdx)
	fwdPkgBkt := bkt.Bucket(pkgIdxKey[:])
	if fwdPkgBkt == nil {
		// TODO(conner) return bkt not found
		return nil
	}

	htlcBkt := fwdPkgBkt.Bucket(htlcBucketKey)
	if htlcBkt == nil {
		return nil
	}

	if err := isBucketEmpty(htlcBkt); err != nil {
		return ErrFwdPkgNotEmpty
	}

	return bkt.Delete(pkgIdxKey[:])
}

func putLogUpdate(bkt *bolt.Bucket, idx uint16, htlc *LogUpdate) error {
	var b bytes.Buffer
	if err := htlc.Encode(&b); err != nil {
		return err
	}

	return bkt.Put(uint16Key(idx), b.Bytes())
}

var (
	errBucketNotEmpty = errors.New("bucket is not empty")
	ErrFwdPkgNotEmpty = errors.New("fwding package is not empty")
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

// uint16sToBytes serializes a slice of uint16s into a slice of bytes.
func uint16sToBytes(u16s []uint16) []byte {
	var bs = make([]byte, 2*len(u16s))
	for i, b := range u16s {
		bs[2*i] = byte(b >> 8)
		bs[2*i+1] = byte(b)
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
var _ Packager = (*packager)(nil)
