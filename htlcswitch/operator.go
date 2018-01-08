package htlcswitch

import (
	"bytes"
	"io"

	"github.com/boltdb/bolt"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnwire"
)

/*
type OperatorStore interface {
	LockInHtlcs(*bolt.Tx, ...channeldb.LogUpdate) error
	ProcesLockedInHtlcs(*bolt.Tx, ...uint64) error
	AckLockedInHtlcs(*bolt.Tx, ...channeldb.LogUpdate) error
	AckLockedInHtlcIndexes(*bolt.Tx, ...uint64) error
}
*/

var (
	sourceKey     = []byte("source")
	htlcBucketKey = []byte("htlcs")
)

type FwdPkg struct {
	Index  uint64
	Source lnwire.ShortChannelID
	Htlcs  []channeldb.LogUpdate
}

type FwdRef struct {
	PkgIndex uint64
	LogIndex uint64
}

type Operator interface {
}

type Packager struct {
	AddFwdPkg  func(*bolt.Bucket, *FwdPkg) error
	LoadFwdPkg func(*bolt.Bucket, uint64) error
	RemoveHtlc func(*bolt.Bucket, FwdRef) error
	RemovePkg  func(*bolt.Bucket, uint64) error
}

func (*Packager) AddFwdPkg(bkt *bolt.Bucket, fwdPkg *FwdPkg) error {
	idxKey := uint64Key(fwdPkg.Index)
	fwdPkgBkt, err := bkt.CreateBucketIfNotExists(idxKey)
	if err != nil {
		return nil, err
	}

	source := uint64Key(fwdPkg.Source.ToUint64())
	if err := fwdPkgBkt.Put(sourceKey, source); err != nil {
		return err
	}

	htlcBkt, err := fwdPkgBkt.CreateBucketIfNotExists(htlcBucketKey)
	if err != nil {
		return err
	}

	for i := range fwdPkg.Htlcs {
		if err := putHtlc(htlcBkt, &fwdPkg.Htlcs[i]); err != nil {
			return err
		}
	}

	return nil
}

func (*Packager) LoadFwdPkg(bkt *bolt.Bucket, pkgIdx uint64) (*FwdPkg, error) {
	pkgIdxKey := uint64Key(ref.PkgIndex)
	fwdPkgBkt := bkt.Bucket(pkgIdxKey)
	if fwdPkgBkt == nil {
		// TODO(conner) return bkt not found
		return nil
	}

	fwdPkg := &FwdPkg{}

	sourceBytes := fwdPkgBkt.Get(sourceKey)
	if sourceBytes == nil {
		// TODO(conner) return invalid fwd pkg
		return nil
	}
	fwdPkg.Source = lnwire.NewShortChanIDFromInt(uint64FromKey(sourceBytes))

	htlcBkt := fwdPkgBkt.Get(htlcBucketKey)
	if htlcBkt != nil {
		htlcs, err := loadHtlcs(htlcBkt)
		if err != nil {
			return err
		}
		fwdPkg.Htlcs = htlcs
	}

	return fwdPkg, nil
}

func loadHtlcs(bkt *bolt.Bucket) ([]channeldb.LogUpdate, error) {
	var htlcs []channeldb.LogUpdate
	if err := bkt.ForEach(func(k, v []byte) error {
		logIdx := uint64FromKey(k)

		var htlc channeldb.LogUpdate
		if err := htlc.Decode(v); err != nil {
			return err
		}
		htlc.LogIndex = logIdx

		htlcs = append(htlcs, htlc)

		return nil
	}); err != nil {
		return nil, err
	}

	return htlcs, nil
}

func (*Packager) RemoveHtlc(bkt *bolt.Bucket, ref FwdRef) error {
	pkgIdxKey := uint64Key(ref.PkgIndex)
	fwdPkgBkt := bkt.Bucket(pkgIdxKey)
	if fwdPkgBkt == nil {
		// TODO(conner) return bkt not found
		return nil
	}

	htlcBkt, err := fwdPkgBkt.CreateBucketIfNotExists(htlcBucketKey)
	if err != nil {
		return err
	}

	logIdxKey := uint64Key(ref.LogIndex)
	if err := htlcBkt.Delete(logIdxKey); err != nil {
		return err
	}

	if err := isBucketEmpty(htlcBkt); err != nil {
		return nil
	}

	return fwdPkgBkt.Delete(htlcBucketKey)
}

func (*Packager) RemovePkg(bkt *bolt.Bucket, pkgIdx uint64) error {
	pkgIdxKey := uint64Key(pkgIdx)
	fwdPkgBkt := bkt.Bucket(pkgIdxKey)
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

func putHtlc(bkt *bolt.Bucket, htlc *channeldb.LogUpdate) error {
	logKey := uint64Key(htlc.LogIndex)

	var b bytes.Buffer
	if err := htlc.Encode(&b); err != nil {
		return err
	}

	return bkt.Put(logKey, b.Bytes())
}

func getHtlc(bkt *bolt.Bucket, idx uint64) (*channeldb.LogUpdate, error) {
	logIndexKey := uint64Key(idx)

	htlcBytes := bkt.Get(logIndexKey[:])
	if htlcBytes == nil {
		// TODO(conner) return not found error
		return nil, nil
	}

	htlc := new(channeldb.LogUpdate)
	if err := htlc.Decode(bytes.NewReader(htlcBytes)); err != nil {
		return nil, err
	}
	htlc.LogIndex = idx

	return htlc, nil
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

// uint64Key writes the provided 64-bit unsigned integer to an 8-byte array.
func uint64Key(i uint64) []byte {
	var key = make([]byte, 8)
	byteOrder.PutUint64(key, i)
	return key
}

// uint64FromKey writes the provided 64-bit unsigned integer to an 8-byte array.
func uint64FromKey(key []byte) uint64 {
	return byteOrder.Uint64(key)
}
