package channeldb_test

import (
	"bytes"
	"testing"

	"github.com/lightningnetwork/lnd/channeldb"
)

// TestPkgFilterBruteForce tests the behavior of a pkg filter up to size 1000,
// which is greater than the number of HTLCs we permit on a commitment txn.
// This should encapsulate every potential filter used in practice.
func TestPkgFilterBruteForce(t *testing.T) {
	checkPkgFilterRange(t, 1000)
}

// TestPkgFilterRand uses a random permutation to verify the proper behavior of
// the pkg filter if the entries are not inserted in-order.
func TestPkgFilterRand(t *testing.T) {
	checkPkgFilterRand(t, 3, 17)
}

// checkPkgFilterRand checks the behavior of a pkg filter by randomly inserting
// indices and asserting the invariants. The order in which indices are inserted
// is parameterized by a base `b` coprime to `p`, and using modular
// exponentiation to generate all elements in [1,p).
func checkPkgFilterRand(t *testing.T, b, p uint16) {
	f := channeldb.NewPkgFilter(int(p))
	var j = b
	for i := uint16(1); i < p; i++ {
		if f.Contains(j) {
			t.Fatalf("pkg filter contains %d-%d "+
				"before being added", i, j)
		}

		f.Set(j)
		checkPkgFilterEncodeDecode(t, i, f)

		if !f.Contains(j) {
			t.Fatalf("pkg filter missing %d-%d "+
				"after being added", i, j)
		}

		if i < p-1 && f.IsFull() {
			t.Fatalf("pkg filter %d already full", i)
		}
		checkPkgFilterEncodeDecode(t, i, f)

		j = (b * j) % p
	}

	// Set 0 independently, since it will never be emitted by the generator.
	f.Set(0)
	checkPkgFilterEncodeDecode(t, p, f)

	if !f.IsFull() {
		t.Fatalf("pkg filter count=%d not full", p)
	}
	checkPkgFilterEncodeDecode(t, p, f)
}

// checkPkgFilterRange verifies the behavior of a pkg filter when doing a linear
// insertion of `high` elements. This is primarily to test that IsFull functions
// properly for all relevant sizes of `high`.
func checkPkgFilterRange(t *testing.T, high int) {
	for i := uint16(0); i < uint16(high); i++ {
		f := channeldb.NewPkgFilter(int(i))

		if f.Count() != i {
			t.Fatalf("pkg filter count=%d is actually %d",
				i, f.Count())
		}
		checkPkgFilterEncodeDecode(t, i, f)

		for j := uint16(0); j < i; j++ {
			if f.Contains(j) {
				t.Fatalf("pkg filter count=%d contains %d "+
					"before being added", i, j)
			}

			f.Set(j)
			checkPkgFilterEncodeDecode(t, i, f)

			if !f.Contains(j) {
				t.Fatalf("pkg filter count=%d missing %d "+
					"after being added", i, j)
			}

			if j < i-1 && f.IsFull() {
				t.Fatalf("pkg filter count=%d already full", i)
			}
		}

		if !f.IsFull() {
			t.Fatalf("pkg filter count=%d not full", i)
		}
		checkPkgFilterEncodeDecode(t, i, f)
	}
}

// checkPkgFilterEncodeDecode tests the serialization of a pkg filter by:
//   1) writing it to a buffer
//   2) verifying the number of bytes written matches the filter's Size()
//   3) reconstructing the filter decoding the bytes
//   4) checking that the two filters are the same according to Equal
func checkPkgFilterEncodeDecode(t *testing.T, i uint16, f *channeldb.PkgFilter) {
	var b bytes.Buffer
	if err := f.Encode(&b); err != nil {
		t.Fatalf("unable to serialize pkg filter: %v", err)
	}

	// +2 for uint16 length
	size := uint16(len(b.Bytes()))
	if size != f.Size() {
		t.Fatalf("pkg filter count=%d serialized size differs, "+
			"Size(): %d, len(bytes): %v", i, f.Size(), size)
	}

	reader := bytes.NewReader(b.Bytes())

	f2 := &channeldb.PkgFilter{}
	if err := f2.Decode(reader); err != nil {
		t.Fatalf("unable to deserialize pkg filter: %v", err)
	}

	if !f.Equal(f2) {
		t.Fatalf("pkg filter count=%v does is not equal "+
			"after deserialization, want: %v, got %v",
			i, f, f2)
	}
}
