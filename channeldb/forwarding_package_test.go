package channeldb_test

import (
	"bytes"
	"testing"

	"github.com/lightningnetwork/lnd/channeldb"
)

func TestPkgFilterBruteForce(t *testing.T) {
	checkPkgFilterRange(t, 0, 1000)
}

func TestPkgFilterRand(t *testing.T) {
	checkPkgFilterRand(t, 17)
}

func checkPkgFilterRand(t *testing.T, p uint16) {
	f := channeldb.NewPkgFilter(int(p))
	var j = uint16(3)
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

		j = (3 * j) % p
	}

	f.Set(0)

	checkPkgFilterEncodeDecode(t, p, f)

	if !f.IsFull() {
		t.Fatalf("pkg filter count=%d not full", p)
	}

	checkPkgFilterEncodeDecode(t, p, f)
}

func checkPkgFilterRange(t *testing.T, low, high int) {
	for i := uint16(low); i < uint16(high); i++ {
		f := channeldb.NewPkgFilter(int(i))

		if f.Count() != i {
			t.Fatalf("pkg filter count=%d is actually %d",
				i, f.Count())
		}

		checkPkgFilterEncodeDecode(t, i, f)

		for j := uint16(low); j < i; j++ {
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
